package PVE::QMPClient;

use strict;
use warnings;
use PVE::QemuServer;
use IO::Multiplex;
use POSIX qw(EINTR EAGAIN);
use JSON;
use Time::HiRes qw(usleep gettimeofday tv_interval);
use Scalar::Util qw(weaken);
use PVE::IPCC;

use Data::Dumper;

# Qemu Monitor Protocol (QMP) client.
#
# This implementation uses IO::Multiplex (libio-multiplex-perl) and
# allows you to issue qmp and qga commands to different VMs in parallel.

# Note: qemu can onyl handle 1 connection, so we close connections asap

sub new {
    my ($class, $eventcb) = @_;

    my $mux = new IO::Multiplex;

    my $self = bless {
	mux => $mux,
	queue_lookup => {}, # $fh => $queue_info
	queue_info => {},
    }, $class;

    $self->{eventcb} = $eventcb if $eventcb;

    $mux->set_callback_object($self);

    # make sure perl doesn't believe this is a circular reference as we
    # delete mux in DESTROY
    weaken($mux->{_object});

    return $self;
}

# Note: List of special QGA command. Those commands can close the connection
# without sending a response.

my $qga_allow_close_cmds = {
    'guest-shutdown' => 1,
    'guest-suspend-ram' => 1,
    'guest-suspend-disk' => 1,
    'guest-suspend-hybrid' => 1,
};

my $push_cmd_to_queue = sub {
    my ($self, $vmid, $cmd) = @_;

    my $execute = $cmd->{execute} || die "no command name specified";

    my $qga = ($execute =~ /^guest\-+/) ? 1 : 0;
 
    my $sname = PVE::QemuServer::qmp_socket($vmid, $qga);

    $self->{queue_info}->{$sname} = { qga => $qga, vmid => $vmid, sname => $sname, cmds => [] } 
        if !$self->{queue_info}->{$sname};

    push @{$self->{queue_info}->{$sname}->{cmds}}, $cmd;

    return $self->{queue_info}->{$sname};
};

# add a single command to the queue for later execution
# with queue_execute()
sub queue_cmd {
    my ($self, $vmid, $callback, $execute, %params) = @_;

    my $cmd = {};
    $cmd->{execute} = $execute;
    $cmd->{arguments} = \%params;
    $cmd->{callback} = $callback;

    &$push_cmd_to_queue($self, $vmid, $cmd);

    return undef;
}

# execute a single command
sub cmd {
    my ($self, $vmid, $cmd, $timeout) = @_;

    my $result;

    my $callback = sub {
	my ($vmid, $resp) = @_;
	$result = $resp->{'return'};
	$result = { error => $resp->{'error'} } if !defined($result) && $resp->{'error'};
    };

    die "no command specified" if !($cmd && $cmd->{execute});

    $cmd->{callback} = $callback;
    $cmd->{arguments} = {} if !defined($cmd->{arguments});

    my $queue_info = &$push_cmd_to_queue($self, $vmid, $cmd);

    if (!$timeout) {
	# hack: monitor sometime blocks
	if ($cmd->{execute} eq 'query-migrate') {
	    $timeout = 60*60; # 1 hour
	} elsif ($cmd->{execute} =~ m/^(eject|change)/) {
	    $timeout = 60; # note: cdrom mount command is slow
	} elsif ($cmd->{execute} eq 'guest-fsfreeze-freeze') {
	    # freeze syncs all guest FS, if we kill it it stays in an unfreezable
	    # locked state with high probability, so use an generous timeout
	    $timeout = 60*60; # 1 hour
	} elsif ($cmd->{execute} eq 'guest-fsfreeze-thaw') {
	    # thaw has no possible long blocking actions, either it returns
	    # instantly or never (dead locked)
	    $timeout = 10;
	} elsif ($cmd->{execute} eq 'savevm-start' ||
		 $cmd->{execute} eq 'savevm-end' ||
		 $cmd->{execute} eq 'query-backup' ||
		 $cmd->{execute} eq 'query-block-jobs' ||
		 $cmd->{execute} eq 'block-job-cancel' ||
		 $cmd->{execute} eq 'block-job-complete' ||
		 $cmd->{execute} eq 'backup-cancel' ||
		 $cmd->{execute} eq 'query-savevm' ||
		 $cmd->{execute} eq 'delete-drive-snapshot' || 
		 $cmd->{execute} eq 'guest-shutdown' ||
		 $cmd->{execute} eq 'snapshot-drive'  ) {
	    $timeout = 10*60; # 10 mins ?
	} else {
	    $timeout = 3; # default
	}
    }

    $self->queue_execute($timeout, 2);

    die "VM $vmid qmp command '$cmd->{execute}' failed - $queue_info->{error}"
	if defined($queue_info->{error});

    return $result;
};

my $cmdid_seq = 0;
my $cmdid_seq_qga = 0;

my $next_cmdid = sub {
    my ($qga) = @_;

    if($qga){
	$cmdid_seq_qga++;
	return "$$"."0".$cmdid_seq_qga;
    } else {
	$cmdid_seq++;
	return "$$:$cmdid_seq";
    }
};

my $lookup_queue_info = sub {
    my ($self, $fh, $noerr) = @_;

    my $queue_info = $self->{queue_lookup}->{$fh};    
    if (!$queue_info) {
	warn "internal error - unable to lookup queue info" if !$noerr;
	return undef;
    }
    return $queue_info;
};

my $close_connection = sub {
    my ($self, $queue_info) = @_;

    if (my $fh = delete $queue_info->{fh}) {
	delete $self->{queue_lookup}->{$fh};
	$self->{mux}->close($fh);
    } 
};

my $open_connection = sub {
    my ($self, $queue_info, $timeout) = @_;

    die "duplicate call to open" if defined($queue_info->{fh});

    my $vmid = $queue_info->{vmid};
    my $qga = $queue_info->{qga};

    my $sname = PVE::QemuServer::qmp_socket($vmid, $qga);

    $timeout = 1 if !$timeout;

    my $fh;
    my $starttime = [gettimeofday];
    my $count = 0;

    my $sotype = $qga ? 'qga' : 'qmp';

    for (;;) {
	$count++;
	$fh = IO::Socket::UNIX->new(Peer => $sname, Blocking => 0, Timeout => 1);
	last if $fh;
	if ($! != EINTR && $! != EAGAIN) {
	    die "unable to connect to VM $vmid $sotype socket - $!\n";
	}
	my $elapsed = tv_interval($starttime, [gettimeofday]);
	if ($elapsed >= $timeout) {
	    die "unable to connect to VM $vmid $sotype socket - timeout after $count retries\n";
	}
	usleep(100000);
    }

    $queue_info->{fh} = $fh;

    $self->{queue_lookup}->{$fh} = $queue_info;

    $self->{mux}->add($fh);
    $self->{mux}->set_timeout($fh, $timeout);

    return $fh;
};

my $check_queue = sub {
    my ($self) = @_;

    my $running = 0;

    foreach my $sname (keys %{$self->{queue_info}}) {
	my $queue_info = $self->{queue_info}->{$sname};
	my $fh = $queue_info->{fh};
	next if !$fh;

	my $qga = $queue_info->{qga};

	if ($queue_info->{error}) {
	    &$close_connection($self, $queue_info);
	    next;
	}

	if ($queue_info->{current}) { # command running, waiting for response
	    $running++;
	    next;
	}

	if (!scalar(@{$queue_info->{cmds}})) { # no more commands
	    &$close_connection($self, $queue_info);
	    next;
	}

	eval {

	    my $cmd = $queue_info->{current} = shift @{$queue_info->{cmds}};
	    $cmd->{id} = &$next_cmdid($qga);

	    my $fd = -1;
	    if ($cmd->{execute} eq 'add-fd' || $cmd->{execute} eq 'getfd') {
		$fd = $cmd->{arguments}->{fd};
		delete $cmd->{arguments}->{fd};
	    }

	    my $qmpcmd;

	    if ($qga) {

		$qmpcmd = to_json({ execute => 'guest-sync-delimited', 
				    arguments => { id => int($cmd->{id})}}) .
		    to_json({ execute => $cmd->{execute}, arguments => $cmd->{arguments}});

	    } else {

		$qmpcmd = to_json({
		    execute => $cmd->{execute},
		    arguments => $cmd->{arguments},
		    id => $cmd->{id}});
	    }

	    if ($fd >= 0) {
		my $ret = PVE::IPCC::sendfd(fileno($fh), $fd, $qmpcmd);
		die "sendfd failed" if $ret < 0;
	    } else {
		$self->{mux}->write($fh, $qmpcmd);
	    }
	};
	if (my $err = $@) {
	    $queue_info->{error} = $err;
	} else {
	    $running++;
	}
    }

    $self->{mux}->endloop() if !$running;

    return $running;
};

# execute all queued command

sub queue_execute {
    my ($self, $timeout, $noerr) = @_;

    $timeout = 3 if !$timeout;

    # open all necessary connections
    foreach my $sname (keys %{$self->{queue_info}}) {
	my $queue_info = $self->{queue_info}->{$sname};
	next if !scalar(@{$queue_info->{cmds}}); # no commands
	
	$queue_info->{error} = undef;
	$queue_info->{current} = undef;

	eval {  
	    &$open_connection($self, $queue_info, $timeout);

	    if (!$queue_info->{qga}) {
		my $cap_cmd = { execute => 'qmp_capabilities', arguments => {} };
		unshift @{$queue_info->{cmds}}, $cap_cmd;
	    }
	};
	if (my $err = $@) {
	    $queue_info->{error} = $err;
	}
    }

    my $running;

    for (;;) {

	$running = &$check_queue($self);

	last if !$running;

	$self->{mux}->loop;
    }

    # make sure we close everything
    my $errors = '';
    foreach my $sname (keys %{$self->{queue_info}}) {
	my $queue_info = $self->{queue_info}->{$sname};
	&$close_connection($self, $queue_info);
	if ($queue_info->{error}) {
	    if ($noerr) {
		warn $queue_info->{error} if $noerr < 2;
	    } else {
		$errors .= $queue_info->{error}
	    }
	}
    }

    $self->{queue_info} = $self->{queue_lookup} = {};

    die $errors if $errors;
}

sub mux_close {
    my ($self, $mux, $fh) = @_;

    my $queue_info = &$lookup_queue_info($self, $fh, 1); 
    return if !$queue_info;

    $queue_info->{error} = "client closed connection\n" 
	if !$queue_info->{error};
}

# mux_input is called when input is available on one of the descriptors.
sub mux_input {
    my ($self, $mux, $fh, $input) = @_;

    my $queue_info = &$lookup_queue_info($self, $fh); 
    return if !$queue_info;

    my $sname = $queue_info->{sname};    
    my $vmid = $queue_info->{vmid};    
    my $qga = $queue_info->{qga};

    my $curcmd = $queue_info->{current};
    die "unable to lookup current command for VM $vmid ($sname)\n" if !$curcmd;
 
    my $raw;

    if ($qga) {
	return if $$input !~ s/^.*\xff([^\n]+}\r?\n[^\n]+})\r?\n(.*)$/$2/so;
	$raw = $1;
    } else {
	return if $$input !~ s/^(.*})\r?\n(.*)$/$2/so;
	$raw = $1;
    }

    eval {
	my @jsons = split("\n", $raw);

	if ($qga) {

	    die "response is not complete" if @jsons != 2 ;

	    my $obj = from_json($jsons[0]);

	    my $cmdid = $obj->{'return'};
	    die "received responsed without command id\n" if !$cmdid;

	    # skip results fro previous commands
	    return if $cmdid < $curcmd->{id};
	    
	    if ($curcmd->{id} ne $cmdid) {
		die "got wrong command id '$cmdid' (expected $curcmd->{id})\n";
	    }

	    delete $queue_info->{current};

	    $obj = from_json($jsons[1]);

	    if (my $callback = $curcmd->{callback}) {
		&$callback($vmid, $obj);
	    }

	    return;
	}

	foreach my $json (@jsons) {
	    my $obj = from_json($json);
	    next if defined($obj->{QMP}); # skip monitor greeting

	    if (exists($obj->{error}->{desc})) {
		my $desc = $obj->{error}->{desc};
		chomp $desc;
		die "$desc\n" if $desc !~ m/Connection can not be completed immediately/;
		next;
	    }

	    if (defined($obj->{event})) {
		if (my $eventcb = $self->{eventcb}) {
		    &$eventcb($obj);
		}
		next;
	    }

	    my $cmdid = $obj->{id};
	    die "received responsed without command id\n" if !$cmdid;

	    if ($curcmd->{id} ne $cmdid) {
		die "got wrong command id '$cmdid' (expected $curcmd->{id})\n";
	    }

	    delete $queue_info->{current};

	    if (my $callback = $curcmd->{callback}) {
		&$callback($vmid, $obj);
	    }
	}
    };
    if (my $err = $@) {
	$queue_info->{error} = $err;
    }

    &$check_queue($self);
}

# This gets called every second to update player info, etc...
sub mux_timeout {
    my ($self, $mux, $fh) = @_;

    if (my $queue_info = &$lookup_queue_info($self, $fh)) { 
	$queue_info->{error} = "got timeout\n";
	$self->{mux}->inbuffer($fh, ''); # clear to avoid warnings
    }

    &$check_queue($self);
}

sub mux_eof {
    my ($self, $mux, $fh, $input) = @_;

    my $queue_info = &$lookup_queue_info($self, $fh);
    return if !$queue_info;

    my $sname = $queue_info->{sname};    
    my $vmid = $queue_info->{vmid};    
    my $qga = $queue_info->{qga};
  
    my $curcmd = $queue_info->{current};
    die "unable to lookup current command for VM $vmid ($sname)\n" if !$curcmd;

    if ($qga && $qga_allow_close_cmds->{$curcmd->{execute}}) {

	return if $$input !~ s/^.*\xff([^\n]+})\r?\n(.*)$/$2/so;

	my $raw = $1;

	eval {
	    my $obj = from_json($raw);

	    my $cmdid = $obj->{'return'};
	    die "received responsed without command id\n" if !$cmdid;

	    delete $queue_info->{current};

	    if (my $callback = $curcmd->{callback}) {
		&$callback($vmid, undef);
	    }
	};
	if (my $err = $@) {
	    $queue_info->{error} = $err;
	}

	&$close_connection($self, $queue_info);

	if (scalar(@{$queue_info->{cmds}}) && !$queue_info->{error}) {
	    $queue_info->{error} = "Got EOF but command queue is not empty.\n";
	}
    }
}

1;
