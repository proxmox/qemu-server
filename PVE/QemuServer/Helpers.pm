package PVE::QemuServer::Helpers;

use strict;
use warnings;

use PVE::INotify;

my $nodename = PVE::INotify::nodename();

# Paths and directories

our $var_run_tmpdir = "/var/run/qemu-server";
mkdir $var_run_tmpdir;

sub qmp_socket {
    my ($vmid, $qga) = @_;
    my $sockettype = $qga ? 'qga' : 'qmp';
    return "${var_run_tmpdir}/$vmid.$sockettype";
}

sub pidfile_name {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.pid";
}

sub vnc_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.vnc";
}

1;
