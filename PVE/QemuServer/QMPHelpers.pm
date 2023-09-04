package PVE::QemuServer::QMPHelpers;

use warnings;
use strict;

use PVE::QemuServer::Monitor qw(mon_cmd);

use base 'Exporter';

our @EXPORT_OK = qw(
qemu_deviceadd
qemu_devicedel
qemu_objectadd
qemu_objectdel
);

sub qemu_deviceadd {
    my ($vmid, $devicefull) = @_;

    $devicefull = "driver=".$devicefull;
    my %options =  split(/[=,]/, $devicefull);

    mon_cmd($vmid, "device_add" , %options);
}

sub qemu_devicedel {
    my ($vmid, $deviceid) = @_;

    my $ret = mon_cmd($vmid, "device_del", id => $deviceid);
}

sub qemu_objectadd {
    my ($vmid, $objectid, $qomtype) = @_;

    mon_cmd($vmid, "object-add", id => $objectid, "qom-type" => $qomtype);

    return 1;
}

sub qemu_objectdel {
    my ($vmid, $objectid) = @_;

    mon_cmd($vmid, "object-del", id => $objectid);

    return 1;
}

1;
