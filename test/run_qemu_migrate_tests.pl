#!/usr/bin/perl

use strict;
use warnings;

use JSON;
use Test::More;
use Test::MockModule;

use PVE::JSONSchema;
use PVE::Tools qw(file_set_contents file_get_contents run_command);

my $QM_LIB_PATH = '..';
my $MIGRATE_LIB_PATH = '..';
my $RUN_DIR_PATH = './MigrationTest/run/';

# test configuration shared by all tests

my $replication_config = {
    'ids' => {
	'105-0' => {
	    'guest' => '105',
	    'id' => '105-0',
	    'jobnum' => '0',
	    'source' => 'pve0',
	    'target' => 'pve2',
	    'type' => 'local'
	},
    },
    'order' => {
	'105-0' => 1,
    }
};

my $storage_config = {
    ids => {
	local => {
	    content => {
		images => 1,
	    },
	    path => "/var/lib/vz",
	    type => "dir",
	    shared => 0,
	},
	"local-lvm" => {
	    content => {
		images => 1,
	    },
	    nodes => {
		pve0 => 1,
		pve1 => 1,
	    },
	    type => "lvmthin",
	    thinpool => "data",
	    vgname => "pve",
	},
	"local-zfs" => {
	    content => {
		images => 1,
		rootdir => 1,
	    },
	    pool => "rpool/data",
	    sparse => 1,
	    type => "zfspool",
	},
	"rbd-store" => {
	    monhost => "127.0.0.42,127.0.0.21,::1",
	    content => {
		images => 1,
	    },
	    type => "rbd",
	    pool => "cpool",
	    username => "admin",
	    shared => 1,
	},
	"local-dir" => {
	    content => {
		images => 1,
	    },
	    path => "/some/dir/",
	    type => "dir",
	},
	"other-dir" => {
	    content => {
		images => 1,
	    },
	    path => "/some/other/dir/",
	    type => "dir",
	},
    },
};

my $vm_configs = {
     105 => {
	'bootdisk' => 'scsi0',
	'cores' => 1,
	'ide0' => 'local-zfs:vm-105-disk-1,size=103M',
	'ide2' => 'none,media=cdrom',
	'memory' => 512,
	'name' => 'Copy-of-VM-newapache',
	'net0' => 'virtio=4A:A3:E4:4C:CF:F0,bridge=vmbr0,firewall=1',
	'numa' => 0,
	'ostype' => 'l26',
	'parent' => 'ohsnap',
	'pending' => {},
	'scsi0' => 'local-zfs:vm-105-disk-0,size=4G',
	'scsihw' => 'virtio-scsi-pci',
	'smbios1' => 'uuid=1ddfe18b-77e0-47f6-a4bd-f1761bf6d763',
	'snapshots' => {
	    'ohsnap' => {
		'bootdisk' => 'scsi0',
		'cores' => 1,
		'ide2' => 'none,media=cdrom',
		'memory' => 512,
		'name' => 'Copy-of-VM-newapache',
		'net0' => 'virtio=4A:A3:E4:4C:CF:F0,bridge=vmbr0,firewall=1',
		'numa' => 0,
		'ostype' => 'l26',
		'scsi0' => 'local-zfs:vm-105-disk-0,size=4G',
		'scsihw' => 'virtio-scsi-pci',
		'smbios1' => 'uuid=1ddfe18b-77e0-47f6-a4bd-f1761bf6d763',
		'snaptime' => 1580976924,
		'sockets' => 1,
		'startup' => 'order=2',
		'vmgenid' => '4eb1d535-9381-4ddc-a8aa-af50c4d9177b'
	    },
	},
	'sockets' => 1,
	'startup' => 'order=2',
	'vmgenid' => '4eb1d535-9381-4ddc-a8aa-af50c4d9177b',
    },
    149 => {
	'agent' => '0',
	'bootdisk' => 'scsi0',
	'cores' => 1,
	'hotplug' => 'disk,network,usb,memory,cpu',
	'ide2' => 'none,media=cdrom',
	'memory' => 4096,
	'name' => 'asdf',
	'net0' => 'virtio=52:5D:7E:62:85:97,bridge=vmbr1',
	'numa' => 1,
	'ostype' => 'l26',
	'scsi0' => 'local-lvm:vm-149-disk-0,format=raw,size=4G',
	'scsi1' => 'local-dir:149/vm-149-disk-0.qcow2,format=qcow2,size=1G',
	'scsihw' => 'virtio-scsi-pci',
	'snapshots' => {},
	'smbios1' => 'uuid=e980bd43-a405-42e2-b5f4-31efe6517460',
	'sockets' => 1,
	'startup' => 'order=2',
	'vmgenid' => '36c6c50c-6ef5-4adc-9b6f-6ba9c8071db0',
    },
    341 => {
	'arch' => 'aarch64',
	'bootdisk' => 'scsi0',
	'cores' => 1,
	'efidisk0' => 'local-lvm:vm-341-disk-0',
	'ide2' => 'none,media=cdrom',
	'ipconfig0' => 'ip=103.214.69.10/25,gw=103.214.69.1',
	'memory' => 4096,
	'name' => 'VM1033',
	'net0' => 'virtio=4E:F1:82:6D:D7:4B,bridge=vmbr0,firewall=1,rate=10',
	'numa' => 0,
	'ostype' => 'l26',
	'scsi0' => 'rbd-store:vm-341-disk-0,size=1G',
	'scsihw' => 'virtio-scsi-pci',
	'snapshots' => {},
	'smbios1' => 'uuid=e01e4c73-46f1-47c8-af79-288fdf6b7462',
	'sockets' => 2,
	'vmgenid' => 'af47c000-eb0c-48e8-8991-ca4593cd6916',
    },
    1033 => {
	'bootdisk' => 'scsi0',
	'cores' => 1,
	'ide0' => 'rbd-store:vm-1033-cloudinit,media=cdrom,size=4M',
	'ide2' => 'none,media=cdrom',
	'ipconfig0' => 'ip=103.214.69.10/25,gw=103.214.69.1',
	'memory' => 4096,
	'name' => 'VM1033',
	'net0' => 'virtio=4E:F1:82:6D:D7:4B,bridge=vmbr0,firewall=1,rate=10',
	'numa' => 0,
	'ostype' => 'l26',
	'scsi0' => 'rbd-store:vm-1033-disk-1,size=1G',
	'scsihw' => 'virtio-scsi-pci',
	'snapshots' => {},
	'smbios1' => 'uuid=e01e4c73-46f1-47c8-af79-288fdf6b7462',
	'sockets' => 2,
	'vmgenid' => 'af47c000-eb0c-48e8-8991-ca4593cd6916',
    },
    4567 => {
	'bootdisk' => 'scsi0',
	'cores' => 1,
	'ide2' => 'none,media=cdrom',
	'memory' => 512,
	'name' => 'snapme',
	'net0' => 'virtio=A6:D1:F1:EB:7B:C2,bridge=vmbr0,firewall=1',
	'numa' => 0,
	'ostype' => 'l26',
	'parent' => 'snap1',
	'pending' => {},
	'scsi0' => 'local-dir:4567/vm-4567-disk-0.qcow2,size=4G',
	'scsihw' => 'virtio-scsi-pci',
	'smbios1' => 'uuid=2925fdec-a066-4228-b46b-eef8662f5e74',
	'snapshots' => {
	    'snap1' => {
		'bootdisk' => 'scsi0',
		'cores' => 1,
		'ide2' => 'none,media=cdrom',
		'memory' => 512,
		'name' => 'snapme',
		'net0' => 'virtio=A6:D1:F1:EB:7B:C2,bridge=vmbr0,firewall=1',
		'numa' => 0,
		'ostype' => 'l26',
		'runningcpu' => 'kvm64,enforce,+kvm_pv_eoi,+kvm_pv_unhalt,+lahf_lm,+sep',
		'runningmachine' => 'pc-i440fx-5.0+pve0',
		'scsi0' => 'local-dir:4567/vm-4567-disk-0.qcow2,size=4G',
		'scsihw' => 'virtio-scsi-pci',
		'smbios1' => 'uuid=2925fdec-a066-4228-b46b-eef8662f5e74',
		'snaptime' => 1595928799,
		'sockets' => 1,
		'startup' => 'order=2',
		'vmgenid' => '932b227a-8a39-4ede-955a-dbd4bc4385ed',
		'vmstate' => 'local-dir:4567/vm-4567-state-snap1.raw',
	    },
	    'snap2' => {
		'bootdisk' => 'scsi0',
		'cores' => 1,
		'ide2' => 'none,media=cdrom',
		'memory' => 512,
		'name' => 'snapme',
		'net0' => 'virtio=A6:D1:F1:EB:7B:C2,bridge=vmbr0,firewall=1',
		'numa' => 0,
		'ostype' => 'l26',
		'parent' => 'snap1',
		'runningcpu' => 'kvm64,enforce,+kvm_pv_eoi,+kvm_pv_unhalt,+lahf_lm,+sep',
		'runningmachine' => 'pc-i440fx-5.0+pve0',
		'scsi0' => 'local-dir:4567/vm-4567-disk-0.qcow2,size=4G',
		'scsi1' => 'local-zfs:vm-4567-disk-0,size=1G',
		'scsihw' => 'virtio-scsi-pci',
		'smbios1' => 'uuid=2925fdec-a066-4228-b46b-eef8662f5e74',
		'snaptime' => 1595928871,
		'sockets' => 1,
		'startup' => 'order=2',
		'vmgenid' => '932b227a-8a39-4ede-955a-dbd4bc4385ed',
		'vmstate' => 'local-dir:4567/vm-4567-state-snap2.raw',
	    },
	},
	'sockets' => 1,
	'startup' => 'order=2',
	'unused0' => 'local-zfs:vm-4567-disk-0',
	'vmgenid' => 'e698e60c-9278-4dd9-941f-416075383f2a',
	},
};

my $source_vdisks = {
    'local-dir' => [
	{
	    'ctime' => 1589439681,
	    'format' => 'qcow2',
	    'parent' => undef,
	    'size' => 1073741824,
	    'used' => 335872,
	    'vmid' => '149',
	    'volid' => 'local-dir:149/vm-149-disk-0.qcow2',
	},
	{
	    'ctime' => 1595928898,
	    'format' => 'qcow2',
	    'parent' => undef,
	    'size' => 4294967296,
	    'used' => 1811664896,
	    'vmid' => '4567',
	    'volid' => 'local-dir:4567/vm-4567-disk-0.qcow2',
	},
	{
	    'ctime' => 1595928800,
	    'format' => 'raw',
	    'parent' => undef,
	    'size' => 274666496,
	    'used' => 274669568,
	    'vmid' => '4567',
	    'volid' => 'local-dir:4567/vm-4567-state-snap1.raw',
	},
	{
	    'ctime' => 1595928872,
	    'format' => 'raw',
	    'parent' => undef,
	    'size' => 273258496,
	    'used' => 273260544,
	    'vmid' => '4567',
	    'volid' => 'local-dir:4567/vm-4567-state-snap2.raw',
	},
    ],
    'local-lvm' => [
	{
	    'ctime' => '1589277334',
	    'format' => 'raw',
	    'size' => 4294967296,
	    'vmid' => '149',
	    'volid' => 'local-lvm:vm-149-disk-0',
	},
	{
	    'ctime' => '1589277334',
	    'format' => 'raw',
	    'size' => 4194304,
	    'vmid' => '341',
	    'volid' => 'local-lvm:vm-341-disk-0',
	},
    ],
    'local-zfs' => [
	{
	    'ctime' => '1589277334',
	    'format' => 'raw',
	    'size' => 4294967296,
	    'vmid' => '105',
	    'volid' => 'local-zfs:vm-105-disk-0',
	},
	{
	    'ctime' => '1589277334',
	    'format' => 'raw',
	    'size' => 108003328,
	    'vmid' => '105',
	    'volid' => 'local-zfs:vm-105-disk-1',
	},
	{
	    'format' => 'raw',
	    'name' => 'vm-4567-disk-0',
	    'parent' => undef,
	    'size' => 1073741824,
	    'vmid' => '4567',
	    'volid' => 'local-zfs:vm-4567-disk-0',
	},
    ],
    'rbd-store' => [
	{
	    'ctime' => '1589277334',
	    'format' => 'raw',
	    'size' => 1073741824,
	    'vmid' => '1033',
	    'volid' => 'rbd-store:vm-1033-disk-1',
	},
	{
	    'ctime' => '1589277334',
	    'format' => 'raw',
	    'size' => 1073741824,
	    'vmid' => '1033',
	    'volid' => 'rbd-store:vm-1033-cloudinit',
	},
    ],
};

my $default_expected_calls_online = {
    move_config_to_node => 1,
    ssh_qm_start => 1,
    vm_stop => 1,
};

my $default_expected_calls_offline = {
    move_config_to_node => 1,
};

my $replicated_expected_calls_online = {
    %{$default_expected_calls_online},
    transfer_replication_state => 1,
    switch_replication_job_target => 1,
};

my $replicated_expected_calls_offline = {
    %{$default_expected_calls_offline},
    transfer_replication_state => 1,
    switch_replication_job_target => 1,
};

# helpers

sub get_patched_config {
    my ($vmid, $patch) = @_;

    my $new_config = { %{$vm_configs->{$vmid}} };
    patch_config($new_config, $patch) if defined($patch);

    return $new_config;
}

sub patch_config {
    my ($config, $patch) = @_;

    foreach my $key (keys %{$patch}) {
	if ($key eq 'snapshots' && defined($patch->{$key})) {
	    my $new_snapshot_configs = {};
	    foreach my $snap (keys %{$patch->{snapshots}}) {
		my $new_snapshot_config = { %{$config->{snapshots}->{$snap}} };
		patch_config($new_snapshot_config, $patch->{snapshots}->{$snap});
		$new_snapshot_configs->{$snap} = $new_snapshot_config;
	    }
	    $config->{snapshots} = $new_snapshot_configs;
	} elsif (defined($patch->{$key})) {
	    $config->{$key} = $patch->{$key};
	} else { # use undef value for deletion
	    delete $config->{$key};
	}
    }
}

sub local_volids_for_vm {
    my ($vmid) = @_;

    my $res = {};
    foreach my $storeid (keys %{$source_vdisks}) {
	next if $storage_config->{ids}->{$storeid}->{shared};
	$res = {
	    %{$res},
	    map { $_->{vmid} eq $vmid ? ($_->{volid} => 1) : () } @{$source_vdisks->{$storeid}}
	};
    }
    return $res;
}

my $tests = [
# each test consists of the following:
# name           - unique name for the test which also serves as a dir name and
#                  gets passed to make, so don't use whitespace or slash
# target         - hostname of target node
# vmid           - ID of the VM to migrate
# opts           - options for the migrate() call
# target_volids  - hash of volids on the target at the beginning
# vm_status      - hash with running, runningmachine and optionally runningcpu
# expected_calls - hash whose keys are calls which are required
#                  to be made if the migration gets far enough
# expect_die     - expect the migration call to fail, and an error message
#                  matching the specified text in the log
# expected       - hash consisting of:
#                  source_volids    - hash of volids expected on the source
#                  target_volids    - hash of volids expected on the target
#                  vm_config        - vm configuration hash
#                  vm_status        - hash with running, runningmachine and optionally runningcpu
    {
	# NOTE get_efivars_size is mocked and returns 128K
	name => '341_running_efidisk_targetstorage_dir',
	target => 'pve1',
	vmid => 341,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	    targetstorage => 'local-dir',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-dir:341/vm-341-disk-10.raw' => 1,
	    },
	    vm_config => get_patched_config(341, {
		efidisk0 => 'local-dir:341/vm-341-disk-10.raw,format=raw,size=128K',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	# NOTE get_efivars_size is mocked and returns 128K
	name => '341_running_efidisk',
	target => 'pve1',
	vmid => 341,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-lvm:vm-341-disk-10' => 1,
	    },
	    vm_config => get_patched_config(341, {
		efidisk0 => 'local-lvm:vm-341-disk-10,format=raw,size=128K',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_vdisk_alloc_and_pvesm_free_fail',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	fail_config => {
	    vdisk_alloc => 'local-dir:149/vm-149-disk-11.qcow2',
	    pvesm_free => 'local-lvm:vm-149-disk-10',
	},
	expected_calls => {},
	expect_die => "remote command failed with exit code",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {
		'local-lvm:vm-149-disk-10' => 1,
	    },
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_vdisk_alloc_fail',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	fail_config => {
	    vdisk_alloc => 'local-lvm:vm-149-disk-10',
	},
	expected_calls => {},
	expect_die => "remote command failed with exit code",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {},
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_vdisk_free_fail',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	opts => {
	    'with-local-disks' => 1,
	},
	fail_config => {
	    'vdisk_free' => 'local-lvm:vm-149-disk-0',
	},
	expected_calls => $default_expected_calls_offline,
	expect_die => "vdisk_free 'local-lvm:vm-149-disk-0' error",
	expected => {
	    source_volids => {
		'local-lvm:vm-149-disk-0' => 1,
	    },
	    target_volids => local_volids_for_vm(149),
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_replicated_run_replication_fail',
	target => 'pve2',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	target_volids => local_volids_for_vm(105),
	fail_config => {
	    run_replication => 1,
	},
	expected_calls => {},
	expect_die => 'run_replication error',
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => local_volids_for_vm(105),
	    vm_config => $vm_configs->{105},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '1033_running_query_migrate_fail',
	target => 'pve2',
	vmid => 1033,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	},
	fail_config => {
	    'query-migrate' => 1,
	},
	expected_calls => {},
	expect_die => 'online migrate failure - aborting',
	expected => {
	    source_volids => {},
	    target_volids => {},
	    vm_config => $vm_configs->{1033},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '4567_targetstorage_dirotherdir',
	target => 'pve1',
	vmid => 4567,
	vm_status => {
	    running => 0,
	},
	opts => {
	    targetstorage => 'local-dir:other-dir,local-zfs:local-zfs',
	},
	storage_migrate_map => {
	    'local-dir:4567/vm-4567-disk-0.qcow2' => '4567/vm-4567-disk-0.qcow2',
	    'local-dir:4567/vm-4567-state-snap1.raw' => '4567/vm-4567-state-snap1.raw',
	    'local-dir:4567/vm-4567-state-snap2.raw' => '4567/vm-4567-state-snap2.raw',
	},
	expected_calls => $default_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => {
		'other-dir:4567/vm-4567-disk-0.qcow2' => 1,
		'other-dir:4567/vm-4567-state-snap1.raw' => 1,
		'other-dir:4567/vm-4567-state-snap2.raw' => 1,
		'local-zfs:vm-4567-disk-0' => 1,
	    },
	    vm_config => get_patched_config(4567, {
		'scsi0' => 'other-dir:4567/vm-4567-disk-0.qcow2,size=4G',
		snapshots => {
		    snap1 => {
			'scsi0' => 'other-dir:4567/vm-4567-disk-0.qcow2,size=4G',
			'vmstate' => 'other-dir:4567/vm-4567-state-snap1.raw',
		    },
		    snap2 => {
			'scsi0' => 'other-dir:4567/vm-4567-disk-0.qcow2,size=4G',
			'scsi1' => 'local-zfs:vm-4567-disk-0,size=1G',
			'vmstate' => 'other-dir:4567/vm-4567-state-snap2.raw',
		    },
		},
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '4567_running',
	target => 'pve1',
	vmid => 4567,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-i440fx-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	expected_calls => {},
	expect_die => 'online storage migration not possible if snapshot exists',
	expected => {
	    source_volids => local_volids_for_vm(4567),
	    target_volids => {},
	    vm_config => $vm_configs->{4567},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-i440fx-5.0+pve0',
	    },
	},
    },
    {
	name => '4567_offline',
	target => 'pve1',
	vmid => 4567,
	vm_status => {
	    running => 0,
	},
	expected_calls => $default_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => local_volids_for_vm(4567),
	    vm_config => $vm_configs->{4567},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	# FIXME: Maybe add orphaned drives as unused?
	name => '149_running_orphaned_disk_targetstorage_zfs',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	    targetstorage => 'local-zfs',
	},
	config_patch => {
	    scsi1 => undef,
	},
	storage_migrate_map => {
	    'local-dir:149/vm-149-disk-0.qcow2' => 'vm-149-disk-0',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-zfs:vm-149-disk-10' => 1,
		'local-zfs:vm-149-disk-0' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-zfs:vm-149-disk-10,format=raw,size=4G',
		scsi1 => undef,
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	# FIXME: Maybe add orphaned drives as unused?
	name => '149_running_orphaned_disk',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	config_patch => {
	    scsi1 => undef,
	},
	storage_migrate_map => {
	    'local-dir:149/vm-149-disk-0.qcow2' => '149/vm-149-disk-0.qcow2',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-lvm:vm-149-disk-10' => 1,
		'local-dir:149/vm-149-disk-0.qcow2' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-lvm:vm-149-disk-10,format=raw,size=4G',
		scsi1 => undef,
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	# FIXME: This test is not (yet) a realistic situation, because
	# storage_migrate currently never changes the format (AFAICT)
	# But if such migrations become possible, we need to either update
	# the 'format' property or simply remove it for drives migrated
	# with storage_migrate (the property is optional, so it shouldn't be a problem)
	name => '149_targetstorage_map_lvmzfs_defaultlvm',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	opts => {
	    targetstorage => 'local-lvm:local-zfs,local-lvm',
	},
	storage_migrate_map => {
	    'local-lvm:vm-149-disk-0' => 'vm-149-disk-0',
	    'local-dir:149/vm-149-disk-0.qcow2' => 'vm-149-disk-0',
	},
	expected_calls => $default_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-zfs:vm-149-disk-0' => 1,
		'local-lvm:vm-149-disk-0' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-zfs:vm-149-disk-0,format=raw,size=4G',
		scsi1 => 'local-lvm:vm-149-disk-0,format=qcow2,size=1G',
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	# FIXME same as for the previous test
	name => '149_targetstorage_map_dirzfs_lvmdir',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	    targetstorage => 'local-dir:local-zfs,local-lvm:local-dir',
	},
	storage_migrate_map => {
	    'local-lvm:vm-149-disk-0' => '149/vm-149-disk-0.raw',
	    'local-dir:149/vm-149-disk-0.qcow2' => 'vm-149-disk-0',
	},
	expected_calls => $default_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-dir:149/vm-149-disk-0.raw' => 1,
		'local-zfs:vm-149-disk-0' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-dir:149/vm-149-disk-0.raw,format=raw,size=4G',
		scsi1 => 'local-zfs:vm-149-disk-0,format=qcow2,size=1G',
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '149_running_targetstorage_map_lvmzfs_defaultlvm',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	    targetstorage => 'local-lvm:local-zfs,local-lvm',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-zfs:vm-149-disk-10' => 1,
		'local-lvm:vm-149-disk-11' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-zfs:vm-149-disk-10,format=raw,size=4G',
		scsi1 => 'local-lvm:vm-149-disk-11,format=raw,size=1G',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_targetstorage_map_lvmzfs_dirdir',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	    targetstorage => 'local-lvm:local-zfs,local-dir:local-dir',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-zfs:vm-149-disk-10' => 1,
		'local-dir:149/vm-149-disk-11.qcow2' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-zfs:vm-149-disk-10,format=raw,size=4G',
		scsi1 => 'local-dir:149/vm-149-disk-11.qcow2,format=qcow2,size=1G',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_targetstorage_zfs',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	    targetstorage => 'local-zfs',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-zfs:vm-149-disk-10' => 1,
		'local-zfs:vm-149-disk-11' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-zfs:vm-149-disk-10,format=raw,size=4G',
		scsi1 => 'local-zfs:vm-149-disk-11,format=raw,size=1G',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_wrong_size',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	config_patch => {
	    scsi0 => 'local-lvm:vm-149-disk-0,size=123T',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-lvm:vm-149-disk-10' => 1,
		'local-dir:149/vm-149-disk-11.qcow2' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-lvm:vm-149-disk-10,format=raw,size=4G',
		scsi1 => 'local-dir:149/vm-149-disk-11.qcow2,format=qcow2,size=1G',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_missing_size',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	config_patch => {
	    scsi0 => 'local-lvm:vm-149-disk-0',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-lvm:vm-149-disk-10' => 1,
		'local-dir:149/vm-149-disk-11.qcow2' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-lvm:vm-149-disk-10,format=raw,size=4G',
		scsi1 => 'local-dir:149/vm-149-disk-11.qcow2,format=qcow2,size=1G',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '105_local_device_shared',
	target => 'pve1',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    ide2 => '/dev/sde,shared=1',
	},
	expected_calls => $default_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => local_volids_for_vm(105),
	    vm_config => get_patched_config(105, {
		ide2 => '/dev/sde,shared=1',
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_local_device_in_snapshot',
	target => 'pve1',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    snapshots => {
		ohsnap => {
		    ide2 => '/dev/sde',
		},
	    },
	},
	expected_calls => {},
	expect_die => "can't migrate local disk '/dev/sde': local file/device",
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => {},
	    vm_config => get_patched_config(105, {
		snapshots => {
		    ohsnap => {
			ide2 => '/dev/sde',
		    },
		},
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_local_device',
	target => 'pve1',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    ide2 => '/dev/sde',
	},
	expected_calls => {},
	expect_die => "can't migrate local disk '/dev/sde': local file/device",
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => {},
	    vm_config => get_patched_config(105, {
		ide2 => '/dev/sde',
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_cdrom_in_snapshot',
	target => 'pve1',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    snapshots => {
		ohsnap => {
		    ide2 => 'cdrom,media=cdrom',
		},
	    },
	},
	expected_calls => {},
	expect_die => "can't migrate local cdrom drive (referenced in snapshot - ohsnap",
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => {},
	    vm_config => get_patched_config(105, {
		snapshots => {
		    ohsnap => {
			ide2 => 'cdrom,media=cdrom',
		    },
		},
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_cdrom',
	target => 'pve1',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    ide2 => 'cdrom,media=cdrom',
	},
	expected_calls => {},
	expect_die => "can't migrate local cdrom drive",
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => {},
	    vm_config => get_patched_config(105, {
		ide2 => 'cdrom,media=cdrom',
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '149_running_missing_option_withlocaldisks',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	},
	expected_calls => {},
	expect_die => "can't live migrate attached local disks without with-local-disks option",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {},
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_missing_option_online',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    'with-local-disks' => 1,
	},
	expected_calls => {},
	expect_die => "can't migrate running VM without --online",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {},
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '1033_running_customcpu',
	target => 'pve1',
	vmid => 1033,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	    runningcpu => 'host,+kvm_pv_eoi,+kvm_pv_unhalt',
	},
	opts => {
	    online => 1,
	},
	config_patch => {
	    cpu => 'custom-mycpu',
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {},
	    vm_config => get_patched_config(1033, {
		cpu => 'custom-mycpu',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
		runningcpu => 'host,+kvm_pv_eoi,+kvm_pv_unhalt',
	    },
	},
    },
    {
	name => '105_replicated_to_non_replication_target',
	target => 'pve1',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	target_volids => {},
	expected_calls => $replicated_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => local_volids_for_vm(105),
	    vm_config => $vm_configs->{105},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_running_replicated',
	target => 'pve2',
	vmid => 105,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-i440fx-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	target_volids => local_volids_for_vm(105),
	expected_calls => {},
	expect_die => "online storage migration not possible if snapshot exists",
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => local_volids_for_vm(105),
	    vm_config => $vm_configs->{105},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-i440fx-5.0+pve0',
	    },
	},
    },
    {
	name => '105_replicated',
	target => 'pve2',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	target_volids => local_volids_for_vm(105),
	expected_calls => $replicated_expected_calls_offline,
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => local_volids_for_vm(105),
	    vm_config => $vm_configs->{105},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '105_running_replicated_without_snapshot',
	target => 'pve2',
	vmid => 105,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-i440fx-5.0+pve0',
	},
	config_patch => {
	    snapshots => undef,
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	target_volids => local_volids_for_vm(105),
	expected_calls => {
	    %{$replicated_expected_calls_online},
	    'block-dirty-bitmap-add-drive-scsi0' => 1,
	    'block-dirty-bitmap-add-drive-ide0' => 1,
	},
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => local_volids_for_vm(105),
	    vm_config => get_patched_config(105, {
		snapshots => {},
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-i440fx-5.0+pve0',
	    },
	},
    },
    {
	name => '105_replicated_without_snapshot',
	target => 'pve2',
	vmid => 105,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    snapshots => undef,
	},
	opts => {
	    online => 1,
	},
	target_volids => local_volids_for_vm(105),
	expected_calls => $replicated_expected_calls_offline,
	expected => {
	    source_volids => local_volids_for_vm(105),
	    target_volids => local_volids_for_vm(105),
	    vm_config => get_patched_config(105, {
		snapshots => {},
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '1033_running',
	target => 'pve2',
	vmid => 1033,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {},
	    vm_config => $vm_configs->{1033},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_locked',
	target => 'pve2',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	config_patch => {
	    lock => 'locked',
	},
	expected_calls => {},
	expect_die => "VM is locked",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {},
	    vm_config => get_patched_config(149, {
		lock => 'locked',
	    }),
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '149_storage_not_available',
	target => 'pve2',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	expected_calls => {},
	expect_die => "storage 'local-lvm' is not available on node 'pve2'",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {},
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	name => '149_running',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	expected_calls => $default_expected_calls_online,
	expected => {
	    source_volids => {},
	    target_volids => {
		'local-lvm:vm-149-disk-10' => 1,
		'local-dir:149/vm-149-disk-11.qcow2' => 1,
	    },
	    vm_config => get_patched_config(149, {
		scsi0 => 'local-lvm:vm-149-disk-10,format=raw,size=4G',
		scsi1 => 'local-dir:149/vm-149-disk-11.qcow2,format=qcow2,size=1G',
	    }),
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_running_drive_mirror_fail',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 1,
	    runningmachine => 'pc-q35-5.0+pve0',
	},
	opts => {
	    online => 1,
	    'with-local-disks' => 1,
	},
	expected_calls => {},
	expect_die => "qemu_drive_mirror 'scsi1' error",
	fail_config => {
	    'qemu_drive_mirror' => 'scsi1',
	},
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {},
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 1,
		runningmachine => 'pc-q35-5.0+pve0',
	    },
	},
    },
    {
	name => '149_offline',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	opts => {
	    'with-local-disks' => 1,
	},
	expected_calls => $default_expected_calls_offline,
	expected => {
	    source_volids => {},
	    target_volids => local_volids_for_vm(149),
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 0,
	    },
	},
    },
    {
	# FIXME also cleanup remote disks when failing this early
	name => '149_storage_migrate_fail',
	target => 'pve1',
	vmid => 149,
	vm_status => {
	    running => 0,
	},
	opts => {
	    'with-local-disks' => 1,
	},
	fail_config => {
	    'storage_migrate' => 'local-lvm:vm-149-disk-0',
	},
	expected_calls => {},
	expect_die => "storage_migrate 'local-lvm:vm-149-disk-0' error",
	expected => {
	    source_volids => local_volids_for_vm(149),
	    target_volids => {
		'local-dir:149/vm-149-disk-0.qcow2' => 1,
	    },
	    vm_config => $vm_configs->{149},
	    vm_status => {
		running => 0,
	    },
	},
    },
];

my $single_test_name = shift;

if (defined($single_test_name) && $single_test_name eq 'DUMP_NAMES') {
    my $output = '';
    foreach my $test (@{$tests}) {
	$output .= $test->{name} . ' ';
    }
    print "$output\n";
    exit 0;
}

mkdir $RUN_DIR_PATH;

foreach my $test (@{$tests}) {
    my $name = $test->{name};
    next if defined($single_test_name) && $name ne $single_test_name;

    my $run_dir = "${RUN_DIR_PATH}/${name}";

    mkdir $run_dir;
    file_set_contents("${run_dir}/replication_config", to_json($replication_config));
    file_set_contents("${run_dir}/storage_config", to_json($storage_config));
    file_set_contents("${run_dir}/source_vdisks", to_json($source_vdisks));

    my $expect_die = $test->{expect_die};
    my $expected = $test->{expected};

    my $source_volids = local_volids_for_vm($test->{vmid});
    my $target_volids = $test->{target_volids} // {};

    my $config_patch = $test->{config_patch};
    my $vm_config = get_patched_config($test->{vmid}, $test->{config_patch});

    my $fail_config = $test->{fail_config} // {};
    my $storage_migrate_map = $test->{storage_migrate_map} // {};

    if (my $targetstorage = $test->{opts}->{targetstorage}) {
	$test->{opts}->{storagemap} = PVE::JSONSchema::parse_idmap($targetstorage, 'pve-storage-id');
    }

    my $migrate_params = {
	target => $test->{target},
	vmid => $test->{vmid},
	opts => $test->{opts},
    };

    file_set_contents("${run_dir}/nbd_info", to_json({}));
    file_set_contents("${run_dir}/source_volids", to_json($source_volids));
    file_set_contents("${run_dir}/target_volids", to_json($target_volids));
    file_set_contents("${run_dir}/vm_config", to_json($vm_config));
    file_set_contents("${run_dir}/vm_status", to_json($test->{vm_status}));
    file_set_contents("${run_dir}/expected_calls", to_json($test->{expected_calls}));
    file_set_contents("${run_dir}/fail_config", to_json($fail_config));
    file_set_contents("${run_dir}/storage_migrate_map", to_json($storage_migrate_map));
    file_set_contents("${run_dir}/migrate_params", to_json($migrate_params));

    $ENV{QM_LIB_PATH} = $QM_LIB_PATH;
    $ENV{RUN_DIR_PATH} = $run_dir;
    my $exitcode = run_command([
	'/usr/bin/perl',
	"-I${MIGRATE_LIB_PATH}",
	"-I${MIGRATE_LIB_PATH}/test",
	"${MIGRATE_LIB_PATH}/test/MigrationTest/QemuMigrateMock.pm",
    ], noerr => 1, errfunc => sub {print "#$name - $_[0]\n"} );

    if (defined($expect_die) && $exitcode) {
	my $log = file_get_contents("${run_dir}/log");
	my @lines = split /\n/, $log;

	my $matched = 0;
	foreach my $line (@lines) {
	    $matched = 1 if $line =~ m/^err:.*\Q${expect_die}\E/;
	    $matched = 1 if $line =~ m/^warn:.*\Q${expect_die}\E/;
	}
	if (!$matched) {
	    fail($name);
	    note("expected error message is not present in log");
	}
    } elsif (defined($expect_die) && !$exitcode) {
	fail($name);
	note("mocked migrate call didn't fail, but it was expected to - check log");
    } elsif (!defined($expect_die) && $exitcode) {
	fail($name);
	note("mocked migrate call failed, but it was not expected - check log");
    }

    my $expected_calls = decode_json(file_get_contents("${run_dir}/expected_calls"));
    foreach my $call (keys %{$expected_calls}) {
	fail($name);
	note("expected call '$call' was not made");
    }

    if (!defined($expect_die)) {
	my $nbd_info = decode_json(file_get_contents("${run_dir}/nbd_info"));
	foreach my $drive (keys %{$nbd_info}) {
	    fail($name);
	    note("drive '$drive' was not mirrored");
	}
    }

    my $actual = {
	source_volids => decode_json(file_get_contents("${run_dir}/source_volids")),
	target_volids => decode_json(file_get_contents("${run_dir}/target_volids")),
	vm_config => decode_json(file_get_contents("${run_dir}/vm_config")),
	vm_status => decode_json(file_get_contents("${run_dir}/vm_status")),
    };

    is_deeply($actual, $expected, $name);
}

done_testing();
