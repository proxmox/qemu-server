#!/usr/bin/perl -w

package PVE::QMPClient;

use strict;
#use PVE::SafeSyslog;
use PVE::QemuServer;
use IO::Multiplex;
use JSON;
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
    my ($self, $vmid, $cmd) = @_;

    my $result;

    my $callback = sub {
	my ($vmid, $resp) = @_;
	$result = $resp->{'return'};
    };

    $cmd->{callback} = $callback;
    $cmd->{arguments} = {} if !defined($cmd->{arguments});

    $self->{queue}->{$vmid} = [ $cmd ];

    $self->queue_execute();

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

    print "CLOSE SOCKET to $vmid\n";

};

my $open_connection = sub {
    my ($self, $vmid) = @_;

    my $sname = PVE::QemuServer::qmp_socket($vmid);

    my $fh = IO::Socket::UNIX->new(Peer => $sname, Blocking => 0, Timeout => 1) ||
	die "unable to connect to VM $vmid socket - $!\n";

    print "OPEN SOCKET to $vmid \n";

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

	    print "WRITECMD:$vmid: $qmpcmd\n";
	    $self->{mux}->write($fh, $qmpcmd);
	};
	if (my $err = $@) {
	    $self->{errors}->{$vmid} = $err;
	    # fixme: close fh?
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

    print "start exec queue\n";

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

    print "end exec queue $running\n";

}

# mux_input is called when input is available on one of
# the descriptors.
sub mux_input {
    my ($self, $mux, $fh, $input) = @_;

    print "GOT: $$input\n";
 
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

	    # die $obj->{error}->{desc} if defined($obj->{error}->{desc});
 
	    #print "GOTOBJ: " . Dumper($obj);

	    # we do not need events for now
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

	print "GOT timeout for $vmid\n";

	$self->{errors}->{$vmid} = "got timeout\n";
    }

    &$check_queue($self);
}



package test;

use strict;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::QemuServer;
use PVE::Cluster;
use Data::Dumper;

initlog($0);

$ENV{'PATH'} = '/sbin:/bin:/usr/sbin:/usr/bin';

die "please run as root\n" if $> != 0;

PVE::INotify::inotify_init();

my $nodename = PVE::INotify::nodename();

sub vm_qmp_command {
    my ($vmid, $cmd, $nocheck) = @_;

    my $res;

    eval {
	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid, $nocheck);

	my $qmpclient = PVE::QMPClient->new();

	$res = $qmpclient->cmd($vmid, $cmd);

    };
    if (my $err = $@) {
	syslog("err", "VM $vmid qmp command failed - $err");
	die $err;
    }

    return $res;
}

# print Dumper(vm_qmp_command(100, { execute => 'query-status' }));

sub update_qemu_stats {
    
    print "start update\n";

    my $ctime = time();

    my $vmstatus = PVE::QemuServer::vmstatus();

    my $qmpclient = PVE::QMPClient->new();

    my $res = {};

    my $blockstatscb = sub {
	my ($vmid, $resp) = @_;
	my $data = $resp->{'return'} || [];
	my $totalrdbytes = 0;
	my $totalwrbytes = 0;
	for my $blockstat (@$data) {
	    $totalrdbytes = $totalrdbytes + $blockstat->{stats}->{rd_bytes};
	    $totalwrbytes = $totalwrbytes + $blockstat->{stats}->{wr_bytes};
	}
	$res->{$vmid}->{diskread} = $totalrdbytes;
	$res->{$vmid}->{diskwrite} = $totalwrbytes;
    };

    my $statuscb = sub {
	my ($vmid, $resp) = @_;
	$qmpclient->queue_cmd($vmid, $blockstatscb, 'query-blockstats');

	my $status = 'unknown';
	if (!defined($status = $resp->{'return'}->{status})) {
	    warn "unable to get VM status\n";
	    return;
	}

	$res->{$vmid}->{status} = $resp->{'return'}->{status};
    };

    foreach my $vmid (keys %$vmstatus) {
	my $d = $vmstatus->{$vmid};
	my $data;
	if ($d->{pid}) { # running

	    $qmpclient->queue_cmd($vmid, $statuscb, 'query-status');

	}
    }
    print "start loop\n";
    $qmpclient->queue_execute();
    print "end loop\n";
    print Dumper($res);
    foreach my $vmid (keys %{$qmpclient->{errors}}) {
	my $msg = "qmp error on VM $vmid: $qmpclient->{errors}->{$vmid}";
	chomp $msg;
	warn "$msg\n";
    }

    print "end update\n";
}

for(;;) {
    PVE::Cluster::cfs_update();
    update_qemu_stats();
    sleep(3);
}
