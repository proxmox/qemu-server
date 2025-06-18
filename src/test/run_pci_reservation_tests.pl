#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

my $vmid = 8006;

use Test::MockModule;
use Test::More;

use PVE::Mapping::PCI;

use PVE::QemuServer::PCI;

my $pci_devs = [
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

my $tests = [
    {
        name => 'reservation-is-respected',
        conf => {
            hostpci0 => 'mapping=someNic',
            hostpci1 => 'mapping=someGpu,mdev=some-model',
            hostpci2 => 'mapping=someNic',
        },
        expected => {
            hostpci0 => { ids => [{ id => '0000:07:10.0' }] },
            hostpci1 => {
                ids => [
                    { id => '0000:01:00.4' }, { id => '0000:01:00.5' },
                    { id => '0000:01:00.6' },
                ],
                mdev => 'some-model',
            },
            hostpci2 => { ids => [{ id => '0000:07:10.4' }] },
        },
    },
];

plan tests => scalar($tests->@*);

my $pve_common_inotify;
$pve_common_inotify = Test::MockModule->new('PVE::INotify');
$pve_common_inotify->mock(
    nodename => sub {
        return 'localhost';
    },
);

my $pve_common_sysfstools;
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

my $mapping_pci_module = Test::MockModule->new("PVE::Mapping::PCI");
$mapping_pci_module->mock(
    config => sub {
        return $pci_map_config;
    },
);

my $pci_module = Test::MockModule->new("PVE::QemuServer::PCI");
$pci_module->mock(
    reserve_pci_usage => sub {
        my ($ids, $vmid, $timeout, $pid, $dryrun) = @_;

        $ids = [$ids] if !ref($ids);

        for my $id (@$ids) {
            if ($id eq "0000:07:10.1") {
                die "reserved";
            }
        }

        return undef;
    },
    create_nvidia_device => sub {
        return 1;
    },
);

for my $test ($tests->@*) {
    my ($name, $conf, $expected) = $test->@{qw(name conf expected)};
    my $pci_devices;
    eval {
        my $devices = PVE::QemuServer::PCI::parse_hostpci_devices($conf);
        use JSON;
        $pci_devices = PVE::QemuServer::PCI::choose_hostpci_devices($devices, $vmid);
    };
    if (my $err = $@) {
        is($err, $expected, $name);
    } elsif ($pci_devices) {
        is_deeply($pci_devices, $expected, $name);
    } else {
        fail($name);
        note("no result");
    }
}

done_testing();
