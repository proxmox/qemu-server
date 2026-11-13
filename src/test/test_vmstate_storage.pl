#!/usr/bin/perl

use strict;
use warnings;

use lib ('..');

use Test::MockModule;
use Test::More;

use PVE::QemuConfig;
use PVE::QemuServer;

my $storecfg = {
    ids => {
        local => { type => 'dir', path => '/var/lib/vz', content => { iso => 1, backup => 1 } },
        lvm => { type => 'lvm', content => { images => 1, rootdir => 1 } },
        nfs =>
            { type => 'nfs', path => '/mnt/pve/nfs', shared => 1, content => { images => 1 } },
        disks => { type => 'lvm', content => { 'vm-vol' => 1 } },
        'shared-disks' => { type => 'rbd', shared => 1, content => { 'vm-vol' => 1 } },
        both => { type => 'lvm', content => { 'vm-vol' => 1, 'vm-state' => 1 } },
        states => { type => 'dir', path => '/srv/states', content => { 'vm-state' => 1 } },
    },
};

my $refused = "storage 'disks' does not allow VM state volumes\n";

# each test is comprised of the following array keys:
# [0] => description
# [1] => VM configuration
# [2] => state storage that is requested explicitly, if any
# [3] => the storage that the state volume gets allocated on, or the error
my $tests = [
    ['storage of a disk', "scsi0: lvm:vm-100-disk-0\n", undef, 'lvm'],
    [
        'shared storage of a disk is preferred',
        "scsi0: lvm:vm-100-disk-0\nscsi1: nfs:100/vm-100-disk-1.qcow2\n",
        undef,
        'nfs',
    ],
    [
        'disk storage that does not allow states is skipped',
        "scsi0: disks:vm-100-disk-0\nscsi1: lvm:vm-100-disk-1\n",
        undef,
        'lvm',
    ],
    [
        'shared disk storage that does not allow states is skipped',
        "scsi0: shared-disks:vm-100-disk-0\nscsi1: lvm:vm-100-disk-1\n",
        undef,
        'lvm',
    ],
    ['disk storage that also allows states', "scsi0: both:vm-100-disk-0\n", undef, 'both'],
    ['fallback for a VM without disks', "memory: 512\n", undef, 'local'],
    [
        'fallback if no disk storage allows states',
        "scsi0: disks:vm-100-disk-0\n",
        undef,
        'local',
    ],
    [
        'state storage of the VM configuration',
        "vmstatestorage: states\nscsi0: lvm:vm-100-disk-0\n",
        undef,
        'states',
    ],
    [
        'state storage of the VM configuration does not allow states',
        "vmstatestorage: disks\nscsi0: lvm:vm-100-disk-0\n",
        undef,
        $refused,
    ],
    ['requested storage', "scsi0: lvm:vm-100-disk-0\n", 'states', 'states'],
    ['requested storage without VM content', "scsi0: lvm:vm-100-disk-0\n", 'local', 'local'],
    [
        'requested storage does not allow states',
        "scsi0: lvm:vm-100-disk-0\n",
        'disks',
        $refused,
    ],
];

my $mock_machine = Test::MockModule->new('PVE::QemuServer::Machine');
$mock_machine->redefine(get_current_qemu_machine => sub { return 'pc-i440fx-10.0'; });
my $mock_helpers = Test::MockModule->new('PVE::QemuServer::Helpers');
$mock_helpers->redefine(vm_running_locally => sub { return 1; });
my $mock_cpu = Test::MockModule->new('PVE::QemuServer::CPUConfig');
$mock_cpu->redefine(get_cpu_from_running_vm => sub { return 'kvm64'; });
my $mock_network = Test::MockModule->new('PVE::QemuServer::Network');
$mock_network->redefine(get_nets_host_mtu => sub { return ''; });
my $mock_storage = Test::MockModule->new('PVE::Storage');
$mock_storage->redefine(vdisk_alloc => sub { return "$_[1]:state"; });

for my $test ($tests->@*) {
    my ($description, $raw, $statestorage, $expected) = $test->@*;

    my $conf = PVE::QemuServer::parse_vm_config("/qemu-server/100.conf", $raw);
    my $volid = eval {
        PVE::QemuConfig->__snapshot_save_vmstate(
            100, $conf, 'snap', $storecfg, $statestorage, 1,
        );
    };
    my $got = defined($volid) ? PVE::Storage::parse_volume_id($volid) : $@;

    is($got, $expected, $description);
}

done_testing();
