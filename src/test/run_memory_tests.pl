#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::QemuServer::Memory;

my $memory_module = Test::MockModule->new('PVE::QemuServer::Memory');
$memory_module->mock('host_numanode_exists', sub { return 1; });
$memory_module->mock('hugepages_chunk_size_supported', sub { return 1; });

my $tests = [
    ['0', '0', 1],
    ['9', '9', 1],
    ['0;1', '0,1', 0],
    ['0;10', '0,10', 0],
    ['0;1;10', '0,1,10', 0],
    ['1;2', '1,2', 0],
    ['0-1', '0-1', 0],
    ['0;1-2', '0,1-2', 0],
];

for my $test (@$tests) {
    my ($hostnodes, $expected, $single_node) = @$test;

    subtest "host nodes $hostnodes" => sub {
        my $numa_config = "cpus=0,memory=1024,hostnodes=$hostnodes,policy=bind";
        my $numa = PVE::QemuServer::Memory::parse_numa($numa_config);
        is(
            PVE::QemuServer::Memory::print_numa_hostnodes($numa->{hostnodes}),
            $expected,
            'preserve node and range separators',
        );

        my $conf = {
            numa => 1,
            memory => 1024,
            hugepages => 2,
            numa0 => $numa_config,
        };
        my $topology = eval { PVE::QemuServer::Memory::hugepages_topology($conf, 0); };
        if ($single_node) {
            is($@, '', 'accept a single host node for hugepages');
            is_deeply($topology, { 2 => { $hostnodes => 512 } }, 'use the requested host node');
        } else {
            like(
                $@,
                qr/^more than 1 hostnode value in numa node is not supported when hugepages are enabled/,
                'reject host node lists and ranges for hugepages',
            );
        }
    };
}

done_testing();
