#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::QemuServer::Network;

my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    cfs_read_file => sub {
        my ($filename) = @_;
        die "unexpected read of $filename\n" if $filename ne 'datacenter.cfg';
        return { mac_prefix => 'BC:24:11' };
    },
);

subtest 'missing MAC addresses of network devices are added' => sub {
    my $with_mac = 'virtio=BC:24:11:00:00:01,bridge=vmbr0';
    my $conf = { name => 'vm100', net0 => $with_mac, net1 => 'virtio,bridge=vmbr0,firewall=1' };

    ok(PVE::QemuServer::Network::add_missing_macs($conf), 'reports the added MAC address');
    is($conf->{net0}, $with_mac, 'existing MAC address is kept');
    my $net1 = PVE::QemuServer::Network::parse_net($conf->{net1}, 1);
    like($net1->{macaddr}, qr/^BC:24:11(?::[0-9A-F]{2}){3}$/i, 'MAC address uses the prefix');
    is($net1->{firewall}, 1, 'other properties are kept');
    is($conf->{name}, 'vm100', 'other options are kept');

    my $net1_string = $conf->{net1};
    ok(!PVE::QemuServer::Network::add_missing_macs($conf), 'reports nothing if all are set');
    is($conf->{net1}, $net1_string, 'added MAC address stays');
};

subtest 'unparseable and undefined network devices are left unchanged' => sub {
    my $conf = { net0 => 'invalid', net1 => undef };

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_; };
    local $@ = 'prior error';

    ok(!PVE::QemuServer::Network::add_missing_macs($conf), 'reports nothing added');
    is($conf->{net0}, 'invalid', 'unparseable device is kept');
    is($conf->{net1}, undef, 'undefined device stays undefined');
    is($@, 'prior error', 'caller $@ is preserved');
    is(scalar(@warnings), 1, 'warns once for the unparseable device only');
};

done_testing();
