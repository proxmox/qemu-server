package PVE::QemuServer::Agent;

use strict;
use warnings;
use PVE::QemuServer;
use base 'Exporter';

our @EXPORT_OK = qw(
check_agent_error
agent_available
agent_cmd
);

sub check_agent_error {
    my ($result, $errmsg, $noerr) = @_;

    $errmsg //= '';
    my $error = '';
    if (ref($result) eq 'HASH' && $result->{error} && $result->{error}->{desc}) {
	$error = "Agent Error: $result->{error}->{desc}\n";
    } elsif (!defined($result)) {
	$error = "Agent Error: $errmsg\n";
    }

    if ($error) {
	die $error if !$noerr;

	warn $error;
	return undef;
    }

    return 1;
}

sub agent_available {
    my ($vmid, $conf, $noerr) = @_;

    eval {
	die "No Qemu Guest Agent\n" if !defined($conf->{agent});
	die "VM $vmid is not running\n" if !PVE::QemuServer::check_running($vmid);
	die "Qemu Guest Agent is not running\n" if !PVE::QemuServer::qga_check_running($vmid, 1);
    };

    if (my $err = $@) {
	die $err if !$noerr;
	return undef;
    }

    return 1;
}

# loads config, checks if available, executes command, checks for errors
sub agent_cmd {
    my ($vmid, $cmd, $params, $errormsg, $noerr) = @_;

    my $conf = PVE::QemuConfig->load_config($vmid); # also checks if VM exists
    agent_available($vmid, $conf, $noerr);

    my $res = PVE::QemuServer::vm_mon_cmd($vmid, "guest-$cmd", %$params);
    check_agent_error($res, $errormsg, $noerr);

    return $res;
}

1;
