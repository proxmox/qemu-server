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
# allows you to issue qmp commands to different VMs in parallel.

# Note: kvm can onyl handle 1 connection, so we close connections asap

sub new {
    my ($class, $eventcb) = @_;

    my $mux = new IO::Multiplex;

    my $self = bless {
	mux => $mux,
	fhs => {}, # $vmid => fh
	fhs_lookup => {}, # $fh => $vmid
	queue => {},
	current => {},
	errors => {},
    }, $class;

    $self->{eventcb} = $eventcb if $eventcb;

    $mux->set_callback_object($self);

    # make sure perl doesn't believe this is a circular reference as we
    # delete mux in DESTROY
    weaken($mux->{_object});

    return $self;
}

# add a single command to the queue for later execution
# with queue_execute()
sub queue_cmd {
    my ($self, $vmid, $callback, $execute, %params) = @_;

    my $cmd = {};
    $cmd->{execute} = $execute;
    $cmd->{arguments} = \%params;
    $cmd->{callback} = $callback;

    push @{$self->{queue}->{$vmid}}, $cmd;
}

# execute a single command
sub cmd {
    my ($self, $vmid, $cmd, $timeout) = @_;

    my $result;

    my $callback = sub {
	my ($vmid, $resp) = @_;
	$result = $resp->{'return'};
    };

    die "no command specified" if !($cmd &&  $cmd->{execute});

    $cmd->{callback} = $callback;
    $cmd->{arguments} = {} if !defined($cmd->{arguments});

    $self->{queue}->{$vmid} = [ $cmd ];

    if (!$timeout) {
	# hack: monitor sometime blocks
	if ($cmd->{execute} eq 'query-migrate') {
	    $timeout = 60*60; # 1 hour
	} elsif ($cmd->{execute} =~ m/^(eject|change)/) {
	    $timeout = 60; # note: cdrom mount command is slow
	} elsif ($cmd->{execute} eq 'savevm-start' ||
		 $cmd->{execute} eq 'savevm-end' ||
		 $cmd->{execute} eq 'query-backup' ||
		 $cmd->{execute} eq 'query-block-jobs' ||
		 $cmd->{execute} eq 'backup-cancel' ||
		 $cmd->{execute} eq 'query-savevm' ||
		 $cmd->{execute} eq 'delete-drive-snapshot' ||
		 $cmd->{execute} eq 'snapshot-drive'  ) {
	    $timeout = 10*60; # 10 mins ?
	} else {
	    $timeout = 3; # default
	}
    }

    $self->queue_execute($timeout);

    my $cmdstr = $cmd->{execute} || '';
    die "VM $vmid qmp command '$cmdstr' failed - $self->{errors}->{$vmid}"
	if defined($self->{errors}->{$vmid});

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

my $close_connection = sub {
    my ($self, $vmid) = @_;

    my $fh = $self->{fhs}->{$vmid};
    return if !$fh;

    delete $self->{fhs}->{$vmid};
    delete $self->{fhs_lookup}->{$fh};

    $self->{mux}->close($fh);
};

my $open_connection = sub {
    my ($self, $vmid, $timeout, $qga) = @_;

    my $sname = PVE::QemuServer::qmp_socket($vmid, $qga);

    $timeout = 1 if !$timeout;

    my $fh;
    my $starttime = [gettimeofday];
    my $count = 0;
    for (;;) {
	$count++;
	$fh = IO::Socket::UNIX->new(Peer => $sname, Blocking => 0, Timeout => 1);
	last if $fh;
	if ($! != EINTR && $! != EAGAIN) {
	    die "unable to connect to VM $vmid socket - $!\n";
	}
	my $elapsed = tv_interval($starttime, [gettimeofday]);
	if ($elapsed >= $timeout) {
	    die "unable to connect to VM $vmid socket - timeout after $count retries\n";
	}
	usleep(100000);
    }

    $self->{fhs}->{$vmid} = $fh;
    $self->{fhs_lookup}->{$fh} = $vmid;
    $self->{mux}->add($fh);

    return $fh;
};

my $check_queue = sub {
    my ($self) = @_;

    my $running = 0;

    foreach my $vmid (keys %{$self->{queue}}) {
	my $fh = $self->{fhs}->{$vmid};
	next if !$fh;

	if ($self->{errors}->{$vmid}) {
	    &$close_connection($self, $vmid);
	    next;
	}

	if ($self->{current}->{$vmid}) { # command running, waiting for response
	    $running++;
	    next;
	}

	if (!scalar(@{$self->{queue}->{$vmid}})) { # no more commands for the VM
	    &$close_connection($self, $vmid);
	    next;
	}

	eval {

	    my $cmd = $self->{current}->{$vmid} = shift @{$self->{queue}->{$vmid}};
	    $cmd->{id} = &$next_cmdid($cmd->{qga});

	    my $fd = -1;
	    if ($cmd->{execute} eq 'add-fd' || $cmd->{execute} eq 'getfd') {
		$fd = $cmd->{arguments}->{fd};
		delete $cmd->{arguments}->{fd};
	    }

	    my $qmpcmd = undef;

	    if($self->{current}->{$vmid}->{qga}){

		my $qmpcmdid =to_json({
		    execute => 'guest-sync',
		    arguments => { id => int($cmd->{id})}});

		$qmpcmd = to_json({
		    execute => $cmd->{execute},
		    arguments => $cmd->{arguments}});

		$qmpcmd = $qmpcmdid.$qmpcmd;

	    }else{

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
	    $self->{errors}->{$vmid} = $err;
	} else {
	    $running++;
	}
    }

    $self->{mux}->endloop() if !$running;

    return $running;
};

# execute all queued command
sub queue_execute {
    my ($self, $timeout) = @_;

    $timeout = 3 if !$timeout;

    $self->{current} = {};
    $self->{errors} = {};

    # open all necessary connections
    foreach my $vmid (keys %{$self->{queue}}) {
	next if !scalar(@{$self->{queue}->{$vmid}}); # no commands for the VM

	if ($self->{queue}->{$vmid}[0]->{execute} =~ /^guest\-+/){
	    $self->{queue}->{$vmid}[0]->{qga} = "1";
	}

	eval {  
	    my $fh = &$open_connection($self, $vmid, $timeout, $self->{queue}->{$vmid}[0]->{qga});

	    if(!$self->{queue}->{$vmid}[0]->{qga}){
		my $cmd = { execute => 'qmp_capabilities', arguments => {} };
		unshift @{$self->{queue}->{$vmid}}, $cmd;
	    }

	    $self->{mux}->set_timeout($fh, $timeout);
	};
	if (my $err = $@) {
	    warn $err;
	    $self->{errors}->{$vmid} = $err;
	}
    }

    my $running;

    for (;;) {

	$running = &$check_queue($self);

	last if !$running;

	$self->{mux}->loop;
    }

    # make sure we close everything
    foreach my $vmid (keys %{$self->{fhs}}) {
	&$close_connection($self, $vmid);
    }

    $self->{queue} = $self->{current} = $self->{fhs} = $self->{fhs_lookup} = {};
}

sub mux_close {
    my ($self, $mux, $fh) = @_;

    my $vmid = $self->{fhs_lookup}->{$fh} || 'undef';
    return if !defined($vmid);

    $self->{errors}->{$vmid} = "client closed connection\n" if !$self->{errors}->{$vmid};
}

# mux_input is called when input is available on one of
# the descriptors.
sub mux_input {
    my ($self, $mux, $fh, $input) = @_;

    my $vmid = $self->{fhs_lookup}->{$fh};    
    if (!$vmid) {
	warn "internal error - unable to lookup vmid";
	return;
    }
 
    my $curcmd = $self->{current}->{$vmid};
    die "unable to lookup current command for VM $vmid\n" if !$curcmd;

    my $raw;

    if ($curcmd->{qga}) {
	return if $$input !~ s/^([^\n]+}\n[^\n]+})\n(.*)$/$2/so;
	$raw = $1;
    } else {
	return if $$input !~ s/^([^\n]+})\r?\n(.*)$/$2/so;
	$raw = $1;
    }

    eval {
	my @jsons = split("\n", $raw);

	if ($curcmd->{qga}) {

	    die "response is not complete" if @jsons != 2 ;

	    my $obj = from_json($jsons[0]);
	    my $cmdid = $obj->{return};
	    die "received responsed without command id\n" if !$cmdid;

	    delete $self->{current}->{$vmid};

	    if ($curcmd->{id} ne $cmdid) {
		die "got wrong command id '$cmdid' (expected $curcmd->{id})\n";
	    }

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

	    my $curcmd = $self->{current}->{$vmid};
	    die "unable to lookup current command for VM $vmid\n" if !$curcmd;

	    delete $self->{current}->{$vmid};

	    if ($curcmd->{id} ne $cmdid) {
		die "got wrong command id '$cmdid' (expected $curcmd->{id})\n";
	    }

	    if (my $callback = $curcmd->{callback}) {
		&$callback($vmid, $obj);
	    }
	}
    };
    if (my $err = $@) {
	$self->{errors}->{$vmid} = $err;
    }

    &$check_queue($self);
}

# This gets called every second to update player info, etc...
sub mux_timeout {
    my ($self, $mux, $fh) = @_;

    if (my $vmid = $self->{fhs_lookup}->{$fh}) {
	$self->{errors}->{$vmid} = "got timeout\n";
    }

    &$check_queue($self);
}

1;
