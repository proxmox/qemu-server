package PVE::QMPClient;

use strict;
#use PVE::SafeSyslog;
use PVE::QemuServer;
use IO::Multiplex;
use POSIX qw(EINTR EAGAIN);
use JSON;
use Time::HiRes qw(usleep gettimeofday tv_interval);

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
my $next_cmdid = sub {
    $cmdid_seq++;
    return "$$:$cmdid_seq";
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
    my ($self, $vmid) = @_;

    my $sname = PVE::QemuServer::qmp_socket($vmid);

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
	if ($elapsed > 1) {
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
	    $cmd->{id} = &$next_cmdid();

	    my $qmpcmd = to_json({
		execute => $cmd->{execute},
		arguments => $cmd->{arguments},
		id => $cmd->{id}});

	    $self->{mux}->write($fh, $qmpcmd);
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

	eval {
	    my $fh = &$open_connection($self, $vmid);
	    my $cmd = { execute => 'qmp_capabilities', arguments => {} };
	    unshift @{$self->{queue}->{$vmid}}, $cmd;
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

# mux_input is called when input is available on one of
# the descriptors.
sub mux_input {
    my ($self, $mux, $fh, $input) = @_;

    return if $$input !~ m/}\r\n$/;

    my $raw = $$input;

    # Remove the input from the input buffer.
    $$input = '';

    my $vmid = $self->{fhs_lookup}->{$fh};
    if (!$vmid) {
	warn "internal error - unable to lookup vmid";
	return;
    }

    eval {
	my @jsons = split("\n", $raw);

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
