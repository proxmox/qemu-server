package PVE::QemuConfig;

use strict;
use warnings;

use base qw(PVE::AbstractConfig);

my $nodename = PVE::INotify::nodename();

mkdir "/etc/pve/nodes/$nodename";
my $confdir = "/etc/pve/nodes/$nodename/qemu-server";
mkdir $confdir;

my $lock_dir = "/var/lock/qemu-server";
mkdir $lock_dir;

my $MAX_UNUSED_DISKS = 8;

# BEGIN implemented abstract methods from PVE::AbstractConfig

sub guest_type {
    return "VM";
}

sub __config_max_unused_disks {
    my ($class) =@_;

    return $MAX_UNUSED_DISKS;
}

sub config_file_lock {
    my ($class, $vmid) = @_;

    return "$lock_dir/lock-$vmid.conf";
}

sub cfs_config_path {
    my ($class, $vmid, $node) = @_;

    $node = $nodename if !$node;
    return "nodes/$node/qemu-server/$vmid.conf";
}

# END implemented abstract methods from PVE::AbstractConfig

1;
