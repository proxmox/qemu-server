package QemuServerTest::CommandLineMocks;

# Mocks for generating the QEMU command line of a VM config in tests, shared
# between the test scripts for the command line itself and for hotplugging. The
# environment (storage configuration, PCI devices, mappings, ...) is fixed,
# while a few properties of the host can be set per test via set_test_env().
# Also contains helpers that are useful and needed by multiple test harnesses.

use v5.36;

use JSON qw(decode_json);
use Socket qw(AF_INET AF_INET6);
use Test::MockModule;

use PVE::INotify;
use PVE::Mapping::PCI;
use PVE::Mapping::USB;
use PVE::ProcFSTools;
use PVE::Storage::RBDPlugin;
use PVE::Storage::ZFSPlugin;
use PVE::Storage;
use PVE::SysFSTools;
use PVE::Tools;

use PVE::QemuServer::CPUConfig;
use PVE::QemuServer::Drive;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Memory;
use PVE::QemuServer::OVMF;
use PVE::QemuServer::PCI;
use PVE::QemuServer;

use base 'Exporter';

our @EXPORT_OK = qw(
    get_storage_config
    get_test_qemu_version
    set_test_env
);

# can be overwritten by individual tests
my $real_qemu_version = PVE::QemuServer::Helpers::kvm_user_version();

# the properties of the host for the current test, see set_test_env()
my $test_env = {};

my $storage_config = {
    ids => {
        local => {
            content => {
                images => 1,
                iso => 1,
            },
            path => '/var/lib/vz',
            type => 'dir',
            shared => 0,
        },
        localsnapext => {
            content => {
                images => 1,
            },
            path => '/var/lib/vzsnapext',
            type => 'dir',
            shared => 0,
            'snapshot-as-volume-chain' => 1,
        },
        noimages => {
            content => {
                iso => 1,
            },
            path => '/var/lib/vz',
            type => 'dir',
        },
        'btrfs-store' => {
            content => {
                images => 1,
            },
            path => '/butter/bread',
            type => 'btrfs',
        },
        'cifs-store' => {
            shared => 1,
            path => '/mnt/pve/cifs-store',
            username => 'guest',
            server => '127.0.0.42',
            type => 'cifs',
            share => 'CIFShare',
            content => {
                images => 1,
                iso => 1,
            },
        },
        'rbd-store' => {
            monhost => '127.0.0.42,127.0.0.21,::1',
            fsid => 'fc4181a6-56eb-4f68-b452-8ba1f381ca2a',
            content => {
                images => 1,
            },
            type => 'rbd',
            pool => 'cpool',
            username => 'admin',
            shared => 1,
        },
        'krbd-store' => {
            monhost => '127.0.0.42,127.0.0.21,::1',
            fsid => 'fc4181a6-56eb-4f68-b452-8ba1f381ca2a',
            content => {
                images => 1,
            },
            type => 'rbd',
            pool => 'cpool',
            username => 'admin',
            shared => 1,
            krbd => 1,
        },
        'zfs-over-iscsi-store' => {
            type => 'zfs',
            iscsiprovider => "comstar",
            lio_tpg => "tpg1",
            portal => "127.0.0.1",
            target => "iqn.2019-10.org.test:foobar",
            pool => "tank",
            content => {
                images => 1,
            },
        },
        'lvm-store' => {
            vgname => 'veegee',
            type => 'lvm',
            content => {
                images => 1,
            },
        },
        'local-lvm' => {
            vgname => 'pve',
            bwlimit => 'restore=1024',
            type => 'lvmthin',
            thinpool => 'data',
            content => {
                images => 1,
            },
        },
    },
};

my $pci_devs = [
    "0000:00:02.0",
    "0000:00:43.1",
    "0000:00:f4.0",
    "0000:00:ff.1",
    "0000:0f:f2.0",
    "0000:d0:13.0",
    "0000:d0:15.1",
    "0000:d0:15.2",
    "0000:d0:17.0",
    "0000:f0:42.0",
    "0000:f0:43.0",
    "0000:f0:43.1",
    "1234:f0:43.1",
    "0000:01:00.4",
    "0000:01:00.5",
    "0000:01:00.6",
    "0000:07:10.0",
    "0000:07:10.1",
    "0000:07:10.4",
];

my $pci_map_config = {
    ids => {
        someGpu => {
            type => 'pci',
            mdev => 1,
            map => [
                'node=localhost,path=0000:01:00.4,id=10de:2231,iommugroup=1',
                'node=localhost,path=0000:01:00.5,id=10de:2231,iommugroup=1',
                'node=localhost,path=0000:01:00.6,id=10de:2231,iommugroup=1',
            ],
        },
        someNic => {
            type => 'pci',
            map => [
                'node=localhost,path=0000:07:10.0,id=8086:1520,iommugroup=2',
                'node=localhost,path=0000:07:10.1,id=8086:1520,iommugroup=2',
                'node=localhost,path=0000:07:10.4,id=8086:1520,iommugroup=2',
            ],
        },
    },
};

my $usb_map_config = {};

my $cpu_hw_capabilities = {
    # Gathered from an AMD EPYC 9475F running kernel 6.11.11-2-pve
    'amd-turin-9005' =>
        '{ "amd-sev": { "cbitpos": 51, "reduced-phys-bits": 6, "sev-support": true,'
        . ' "sev-support-es": true, "sev-support-snp": true } }',
    # TODO: others?
};

# Set the properties of the (mocked) host for the following test, fields are:
#   qemu_version: version of the installed QEMU binary (defaults to the real version)
#   host_arch: x86_64 | aarch64 (defaults to x86_64)
#   host-cpu-vendor: AuthenticAMD | GenuineIntel | etc. (defaults to GenuineIntel)
#   hw_capabilities: a CPU from $cpu_hw_capabilities above or a raw JSON string
sub set_test_env($env) {
    $test_env = $env;
    $test_env->{qemu_version} //= $real_qemu_version // '2.12';
    $test_env->{host_arch} //= 'x86_64';
    $test_env->{'host-cpu-vendor'} //= 'GenuineIntel';
}

sub get_test_qemu_version() {
    return $test_env->{qemu_version};
}

sub get_storage_config() {
    return $storage_config;
}

# Use 'our' for the mocker objects, since they need to stay alive after loading. Using 'my' here
# would free them after loading the module and negate the mocking.

our $procfs_tools_module = Test::MockModule->new('PVE::ProcFSTools');
$procfs_tools_module->mock(
    read_cpuinfo => sub {
        my $res = $procfs_tools_module->original('read_cpuinfo')->();
        my $vendor = $test_env->{'host-cpu-vendor'};
        $res->{vendor} = $vendor;
        return $res;
    },
);

our $qemu_server_module;
$qemu_server_module = Test::MockModule->new('PVE::QemuServer');
$qemu_server_module->mock(
    kvm_user_version => sub {
        return get_test_qemu_version();
    },
    kvm_version => sub {
        return get_test_qemu_version();
    },
    kernel_has_vhost_net => sub {
        return 1; # TODO: make this per-test configurable?
    },
    get_iscsi_initiator_name => sub {
        return 'iqn.1993-08.org.debian:01:aabbccddeeff';
    },
    cleanup_pci_devices => {
        # do nothing
    },
);

our $qemu_server_ovmf_module = Test::MockModule->new("PVE::QemuServer::OVMF");
$qemu_server_ovmf_module->mock(
    file_exists => sub {
        my ($path) = @_;
        return 1;
    },
    file_get_size => sub {
        my ($path) = @_;
        if ($path =~ m/OVMF(32)?_(SEV_)?VARS_4M/) {
            return 528 * 1024;
        } elsif ($path =~ m/OVMF_VARS/) {
            return 128 * 1024;
        } elsif ($path =~ m/AAVMF_VARS/) {
            return 64 * 1024 * 1024;
        } elsif ($path =~ m/RISCV_VIRT_VARS/) {
            return 32 * 1024 * 1024;
        } else {
            die "unknown ovmf vars image '$path' - implement me";
        }
    },
);

our $storage_module = Test::MockModule->new("PVE::Storage");
$storage_module->mock(
    activate_volumes => sub {
        return;
    },
    deactivate_volumes => sub {
        return;
    },
    volume_snapshot_info => sub {
        my ($cfg, $volid) = @_;

        my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

        my $snapshots = {};
        if ($storeid eq 'localsnapext') {
            $snapshots = {
                current => {
                    file => 'var/lib/vzsnapext/images/8006/vm-8006-disk-0.qcow2',
                    parent => 'snap2',
                },
                snap2 => {
                    file => '/var/lib/vzsnapext/images/8006/snap2-vm-8006-disk-0.qcow2',
                    parent => 'snap1',
                },
                snap1 => {
                    file => '/var/lib/vzsnapext/images/8006/snap1-vm-8006-disk-0.qcow2',
                },
            };
        } elsif ($storeid eq 'lvm-store') {
            $snapshots = {
                current => {
                    file => '/dev/veegee/vm-8006-disk-0.qcow2',
                    parent => 'snap2',
                },
                snap2 => {
                    file => '/dev/veegee/snap2-vm-8006-disk-0.qcow2',
                    parent => 'snap1',
                },
                snap1 => {
                    file => '/dev/veegee/snap1-vm-8006-disk-0.qcow2',
                },
            };
        }
        return $snapshots;
    },
);

our $file_stat_module = Test::MockModule->new("File::stat");
$file_stat_module->mock(
    stat => sub {
        my ($path) = @_;
        my $st = $file_stat_module->original('stat')->($0);
        $st->[2] = 25008 if $path =~ m!/dev/!; # block device
        return $st;
    },
);

our $zfsplugin_module = Test::MockModule->new("PVE::Storage::ZFSPlugin");
$zfsplugin_module->mock(
    zfs_get_lu_name => sub {
        return "foobar";
    },
    zfs_get_lun_number => sub {
        return "0";
    },
);

our $rbdplugin_module = Test::MockModule->new("PVE::Storage::RBDPlugin");
$rbdplugin_module->mock(
    rbd_volume_config_set => sub {
        return;
    },
);

our $qemu_server_helpers;
$qemu_server_helpers = Test::MockModule->new('PVE::QemuServer::Helpers');
$qemu_server_helpers->mock(
    get_host_phys_address_bits => sub {
        return 46;
    },
);

our $qemu_server_memory;
$qemu_server_memory = Test::MockModule->new('PVE::QemuServer::Memory');
$qemu_server_memory->mock(
    hugepages_chunk_size_supported => sub {
        return 1;
    },
    host_numanode_exists => sub {
        my ($id) = @_;
        return 1;
    },
);

our $pve_common_tools;
$pve_common_tools = Test::MockModule->new('PVE::Tools');
$pve_common_tools->mock(
    next_vnc_port => sub {
        my ($family, $address) = @_;

        return '5900';
    },
    next_spice_port => sub {
        my ($family, $address) = @_;

        return '61000';
    },
    getaddrinfo_all => sub {
        my ($hostname, @opts) = @_;
        die "need stable hostname" if $hostname ne 'localhost';
        return (
            {
                addr => Socket::pack_sockaddr_in(0, Socket::INADDR_LOOPBACK),
                family => AF_INET, # IPv4
                protocol => 6,
                socktype => 1,
            },
        );
    },
    get_host_arch => sub {
        return $test_env->{host_arch};
    },
);

our $pve_common_file;
$pve_common_file = Test::MockModule->new('PVE::File');
$pve_common_file->mock(
    file_copy => sub {
        my ($filename, $dst, $max, $perm) = @_;
        if ($dst =~ m|^/run/qemu-server/efidisk|) {
            return;
        }
        return $pve_common_file->original('file_copy')->($filename, $dst, $max, $perm);
    },
);

our $pve_cpuconfig;
$pve_cpuconfig = Test::MockModule->new('PVE::QemuServer::CPUConfig');
$pve_cpuconfig->mock(
    load_custom_cpu_model_config => sub {
        # mock custom CPU model config
        return PVE::QemuServer::CPUConfig->parse_config(
            "cpu-models.conf",
            <<EOF,

# "qemu64" is also a default CPU, used here to test that this doesn't matter
cpu-model: qemu64
    reported-model athlon
    flags +aes;+avx;-kvm_pv_unhalt
    hv-vendor-id testvend
    phys-bits 40

cpu-model: alldefault

EOF
        );
    },
    get_hw_capabilities => sub {
        my $hw_capabilities_raw;
        if (!defined($test_env->{hw_capabilities})) {
            # default to barebone uncapable HW
            $hw_capabilities_raw =
                '{"amd-sev":{"cbitpos":0,"reduced-phys-bits":0,"sev-support":false,'
                . '"sev-support-es":false,"sev-support-snp":false}}';
        } elsif (my $cpu_hw_caps = $cpu_hw_capabilities->{ lc($test_env->{hw_capabilities}) }) {
            $hw_capabilities_raw = $cpu_hw_caps;
        } else {
            $hw_capabilities_raw = $test_env->{hw_capabilities};
        }

        my $hw_capabilities = decode_json($hw_capabilities_raw);
        return $hw_capabilities;
    },
);

our $pve_common_network;
$pve_common_network = Test::MockModule->new('PVE::Network');
$pve_common_network->mock(
    read_bridge_mtu => sub {
        my ($bridge_name) = @_;

        if ($bridge_name eq 'vxlan_bridge') {
            return 1450;
        }

        return 1500;
    },
);

our $pve_common_inotify;
$pve_common_inotify = Test::MockModule->new('PVE::INotify');
$pve_common_inotify->mock(
    nodename => sub {
        return 'localhost';
    },
);

our $pve_common_sysfstools;
$pve_common_sysfstools = Test::MockModule->new('PVE::SysFSTools');
$pve_common_sysfstools->mock(
    lspci => sub {
        my ($filter, $verbose) = @_;

        return [
            map { { id => $_ } }
            grep {
                !defined($filter)
                    || (!ref($filter) && $_ =~ m/^(0000:)?\Q$filter\E/)
                    || (ref($filter) eq 'CODE' && $filter->({ id => $_ }))
            } sort @$pci_devs
        ];
    },
    pci_device_info => sub {
        my ($path, $noerr) = @_;

        if ($path =~ m/^0000:01:00/) {
            return {
                mdev => 1,
                iommugroup => 1,
                mdev => 1,
                vendor => "0x10de",
                device => "0x2231",
            };
        } elsif ($path =~ m/^0000:07:10/) {
            return {
                iommugroup => 2,
                vendor => "0x8086",
                device => "0x1520",
            };
        } else {
            return {};
        }
    },
);

our $qemu_drive_module;
$qemu_drive_module = Test::MockModule->new('PVE::QemuServer::Drive');
$qemu_drive_module->mock(
    get_cdrom_path => sub {
        return "/dev/cdrom";
    },
);

our $mapping_usb_module = Test::MockModule->new("PVE::Mapping::USB");
$mapping_usb_module->mock(
    config => sub {
        return $usb_map_config;
    },
);

our $mapping_pci_module = Test::MockModule->new("PVE::Mapping::PCI");
$mapping_pci_module->mock(
    config => sub {
        return $pci_map_config;
    },
);

our $pci_module = Test::MockModule->new("PVE::QemuServer::PCI");
$pci_module->mock(
    reserve_pci_usage => sub {
        die "reserve_pci_usage should not be called for 'qm showcmd'\n";
    },
    create_nvidia_device => sub {
        die "create_nvidia_device should not be called for 'qm showcmd'\n";
    },
);

1;
