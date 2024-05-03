package PVE::QemuServer::Monitor;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::QemuServer::Helpers;
use PVE::QMPClient;

use base 'Exporter';
our @EXPORT_OK = qw(
mon_cmd
);

sub qmp_cmd {
    my ($vmid, $cmd) = @_;

    my $res;

    my $timeout;
    if ($cmd->{arguments}) {
	$timeout = delete $cmd->{arguments}->{timeout};
    }

    eval {
	die "VM $vmid not running\n" if !PVE::QemuServer::Helpers::vm_running_locally($vmid);
	my $sname = PVE::QemuServer::Helpers::qmp_socket($vmid);
	if (-e $sname) { # test if VM is reasonably new and supports qmp/qga
	    my $qmpclient = PVE::QMPClient->new();

	    $res = $qmpclient->cmd($vmid, $cmd, $timeout);
	} else {
	    die "unable to open monitor socket\n";
	}
    };
    if (my $err = $@) {
	syslog("err", "VM $vmid qmp command failed - $err");
	die $err;
    }

    return $res;
}

sub mon_cmd {
    my ($vmid, $execute, %params) = @_;

    my $cmd = { execute => $execute, arguments => \%params };

    return qmp_cmd($vmid, $cmd);
}

sub hmp_cmd {
    my ($vmid, $cmdline, $timeout) = @_;

    my $cmd = {
	execute => 'human-monitor-command',
	arguments => { 'command-line' => $cmdline, timeout => $timeout },
    };

    return qmp_cmd($vmid, $cmd);
}

1;
