#!/usr/bin/perl

use strict;
use warnings;

use lib qw(.. .);

use Test::MockModule;
use Test::More;

use PVE::API2::Qemu;
use PVE::QemuConfig;

my $conf;
my $config_mock = Test::MockModule->new('PVE::QemuConfig');
$config_mock->redefine(load_config => sub { return {%$conf} });

my $can_config_cloudinit;
my $rpcenv = bless {}, 'PVE::RPCEnvironment::Test';
sub PVE::RPCEnvironment::Test::get_user { return 'user@pve'; }

sub PVE::RPCEnvironment::Test::check {
    my ($self, $user, $path, $privs, $noerr) = @_;
    die "unexpected check for $user on $path\n" if $user ne 'user@pve' || $path ne '/vms/100';
    return 1 if $privs->[0] eq 'VM.Audit';
    return 1 if $can_config_cloudinit && $privs->[0] eq 'VM.Config.Cloudinit';
    return 0 if $noerr;
    die "permission check failed\n";
}
my $rpc_mock = Test::MockModule->new('PVE::RPCEnvironment');
$rpc_mock->redefine(get => sub { $rpcenv });

my sub dump_config {
    my ($type) = @_;
    return PVE::API2::Qemu->cloudinit_generated_config_dump(
        { node => 'node', vmid => 100, type => $type },
    );
}

my $base_conf = {
    name => 'vm',
    ostype => 'win11',
    ciuser => 'Administrator',
    ipconfig0 => 'ip=dhcp',
    net0 => 'virtio=BC:24:11:00:00:01,bridge=vmbr0',
};

$conf = { %$base_conf, cipassword => 'Secret1!' };
$can_config_cloudinit = 0;
like(dump_config('user'), qr/^password: \*{10}$/m, 'user data: password masked for auditor');
ok(defined(eval { dump_config('network') }), 'network config: available to auditor');
eval { dump_config('meta') };
like($@, qr/Permission check failed.*VM\.Config\.Cloudinit/, 'meta data: refused for auditor');

$conf = { %$base_conf, cipassword => '' };
eval { dump_config('meta') };
like($@, qr/Permission check failed/, 'meta data: refused for auditor with empty password set');

$conf = {%$base_conf};
ok(defined(eval { dump_config('meta') }), 'meta data: available to auditor without password');

$conf = { %$base_conf, cipassword => 'Secret1!' };
$can_config_cloudinit = 1;
like(dump_config('user'), qr/^password: Secret1!$/m, 'user data: password shown with privilege');
ok(defined(eval { dump_config('meta') }), 'meta data: available with privilege');

done_testing();
