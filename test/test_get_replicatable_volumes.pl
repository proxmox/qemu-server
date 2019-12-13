#!/usr/bin/perl

use strict;
use warnings;

use lib ('..');

use Data::Dumper;

use PVE::Storage;
use PVE::QemuConfig;

use Test::More;

my $storecfg = {
    ids => {
	local => {
	    type => 'dir',
	    shared => 0,
	    content => {
		'iso' => 1,
		'backup' => 1,
		'images' => 1,
		'rootdir' => 1
	    },
	    path => "/var/lib/vz",
	},
	'local-zfs' => {
	    type => 'zfspool',
	    pool => 'nonexistent-testpool',
	    shared => 0,
	    content => {
		'images' => 1,
		'rootdir' => 1
	    },
	},
    },
};


my $vmid = 900;

my $rawconf = "scsi0: non-existent-store:vm-103-disk-1,size=8G\n";
my $conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

my $volumes;
my $expect;

my $test_name = "test non existent storage";

eval {  $volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0); };
is($@, "storage 'non-existent-store' does not exist\n", $test_name);


$test_name = "test with disk from other VM (not owner)";

$rawconf = "scsi0: local:103/vm-103-disk-1.qcow2,size=8G\n";
$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
is_deeply($volumes, {}, $test_name);


$test_name = "test missing replicate feature";

$rawconf = "scsi0: local:$vmid/vm-$vmid-disk-1.qcow2,size=8G\n";
$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

eval { $volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0); };
is($@, "missing replicate feature on volume 'local:900/vm-900-disk-1.qcow2'\n", $test_name);


$test_name = "test raw path disk with replicate enabled";

$rawconf = "scsi0: /dev/disk/abcdefg,size=8G\n";
$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

eval { $volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0); };
is($@, "unable to replicate local file/device '/dev/disk/abcdefg'\n", $test_name);


$test_name = "test raw path disk with replicate disabled";

$rawconf = "scsi0: /dev/disk/abcdefg,size=8G,replicate=0\n";
$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
is_deeply($volumes, {}, $test_name);


$test_name = "test CDROM with iso file";

$rawconf = "ide2: local:iso/pve-cd.iso,media=cdrom\n";
$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
is_deeply($volumes, {}, $test_name);


$test_name = "test CDROM with access to physical 'cdrom' device";

$rawconf = "ide2: cdrom,media=cdrom\n";
$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);

$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
is_deeply($volumes, {}, $test_name);


$test_name = "test hidden volid in snapshot";

$rawconf = <<__EOD__;
memory: 1024
scsi0: local-zfs:vm-$vmid-disk-2,size=8G
[snap1]
memory: 512 
scsi0: local-zfs:vm-$vmid-disk-1,size=8G    
__EOD__

$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);
$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
$expect = {
    "local-zfs:vm-$vmid-disk-1" => 1,
    "local-zfs:vm-$vmid-disk-2" => 1,
};
is_deeply($volumes, $expect, $test_name);


$test_name = "test volid with different replicate setting in snapshot";
$rawconf = <<__EOD__;
memory: 1024
scsi0: local-zfs:vm-$vmid-disk-1,size=8G,replicate=0
[snap1]
memory: 512 
scsi0: local-zfs:vm-$vmid-disk-1,size=8G
__EOD__

$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);
$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
$expect = {
    "local-zfs:vm-$vmid-disk-1" => 1,
};
is_deeply($volumes, $expect, $test_name);


$test_name = "test vm with replicatable unused volumes";

$rawconf = <<__EOD__;
scsi0: local-zfs:vm-$vmid-disk-1,size=8G
unused1: local-zfs:vm-$vmid-disk-2
unused5: local-zfs:vm-$vmid-disk-3
__EOD__

$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);
$volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0);
$expect = {
    "local-zfs:vm-$vmid-disk-1" => 1,
    "local-zfs:vm-$vmid-disk-2" => 1,
    "local-zfs:vm-$vmid-disk-3" => 1,
};
is_deeply($volumes, $expect, $test_name);


$test_name = "test vm with non-replicatable unused volumes";
$rawconf = <<__EOD__;
scsi0: local-zfs:vm-$vmid-disk-1,size=8G
unused1: local:$vmid/vm-$vmid-disk-2.raw
__EOD__

$conf = PVE::QemuServer::parse_vm_config("/qemu-server/$vmid.conf", $rawconf);
eval { $volumes = PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 0); };
is($@, "missing replicate feature on volume 'local:900/vm-900-disk-2.raw'\n", $test_name);

    
done_testing();
exit(0);
