package PVE::QemuServer::Agent;

use strict;
use warnings;

use JSON;
use MIME::Base64 qw(decode_base64 encode_base64);

use PVE::QemuServer;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;

use base 'Exporter';

our @EXPORT_OK = qw(
    check_agent_error
    agent_cmd
);

sub check_agent_error {
    my ($result, $errmsg, $noerr) = @_;

    $errmsg //= '';
    my $error = '';
    if (ref($result) eq 'HASH' && $result->{error} && $result->{error}->{desc}) {
        $error = "Agent error: $result->{error}->{desc}\n";
    } elsif (!defined($result)) {
        $error = "Agent error: $errmsg\n";
    }

    if ($error) {
        die $error if !$noerr;

        warn $error;
        return;
    }

    return 1;
}

sub assert_agent_available {
    my ($vmid, $conf) = @_;

    die "No QEMU guest agent configured\n" if !defined($conf->{agent});
    die "VM $vmid is not running\n" if !PVE::QemuServer::Helpers::vm_running_locally($vmid);
    die "QEMU guest agent is not running\n" if !PVE::QemuServer::qga_check_running($vmid, 1);
}

# loads config, checks if available, executes command, checks for errors
sub agent_cmd {
    my ($vmid, $conf, $cmd, $params, $errormsg) = @_;

    assert_agent_available($vmid, $conf);

    my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, "guest-$cmd", %$params);
    check_agent_error($res, $errormsg);

    return $res;
}

sub qemu_exec {
    my ($vmid, $conf, $input_data, $cmd) = @_;

    my $args = {
        'capture-output' => JSON::true,
    };

    if ($cmd) {
        $args->{path} = shift @$cmd;
        $args->{arg} = $cmd;
    }

    $args->{'input-data'} = encode_base64($input_data, '') if defined($input_data);

    die "command or input-data (or both) required\n"
        if !defined($args->{'input-data'}) && !defined($args->{path});

    my $errmsg = "can't execute command";
    if ($cmd) {
        $errmsg .= " ($args->{path} $args->{arg})";
    }
    if (defined($input_data)) {
        $errmsg .= " (input-data given)";
    }

    my $res = agent_cmd($vmid, $conf, "exec", $args, $errmsg);

    return $res;
}

sub qemu_exec_status {
    my ($vmid, $conf, $pid) = @_;

    my $res =
        agent_cmd($vmid, $conf, "exec-status", { pid => $pid }, "can't get exec status for '$pid'");

    if ($res->{'out-data'}) {
        my $decoded = eval { decode_base64($res->{'out-data'}) };
        warn $@ if $@;
        if (defined($decoded)) {
            $res->{'out-data'} = $decoded;
        }
    }

    if ($res->{'err-data'}) {
        my $decoded = eval { decode_base64($res->{'err-data'}) };
        warn $@ if $@;
        if (defined($decoded)) {
            $res->{'err-data'} = $decoded;
        }
    }

    # convert JSON::Boolean to 1/0
    foreach my $d (keys %$res) {
        if (JSON::is_bool($res->{$d})) {
            $res->{$d} = ($res->{$d}) ? 1 : 0;
        }
    }

    return $res;
}

1;
