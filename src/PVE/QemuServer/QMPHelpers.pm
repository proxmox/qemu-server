package PVE::QemuServer::QMPHelpers;

use warnings;
use strict;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor qw(mon_cmd);

use base 'Exporter';

our @EXPORT_OK = qw(
    qemu_deviceadd
    qemu_devicedel
    qemu_objectadd
    qemu_objectdel
);

sub nbd_stop {
    my ($vmid) = @_;

    mon_cmd($vmid, 'nbd-server-stop', timeout => 25);
}

sub qemu_deviceadd {
    my ($vmid, $devicefull) = @_;

    $devicefull = "driver=" . $devicefull;

    PVE::QemuServer::Monitor::hmp_cmd($vmid, "device_add $devicefull", 25);
}

sub qemu_devicedel {
    my ($vmid, $deviceid) = @_;

    PVE::QemuServer::Monitor::hmp_cmd($vmid, "device_del $deviceid", 25);
}

sub qemu_objectadd {
    my ($vmid, $objectid, $qomtype, %args) = @_;

    mon_cmd($vmid, "object-add", id => $objectid, "qom-type" => $qomtype, %args);

    return 1;
}

sub qemu_objectdel {
    my ($vmid, $objectid) = @_;

    mon_cmd($vmid, "object-del", id => $objectid);

    return 1;
}

# dies if a) VM not running or not existing b) Version query failed
# So, any defined return value is valid, any invalid state can be caught by eval
sub runs_at_least_qemu_version {
    my ($vmid, $major, $minor, $extra) = @_;

    my $v = PVE::QemuServer::Monitor::mon_cmd($vmid, 'query-version');
    die "could not query currently running version for VM $vmid\n" if !defined($v);
    $v = $v->{qemu};

    return PVE::QemuServer::Helpers::version_cmp(
        $v->{major}, $major, $v->{minor}, $minor, $v->{micro}, $extra,
    ) >= 0;
}

1;
