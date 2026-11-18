#!/usr/bin/perl

# Tests the target side of a remote migration: the migration tunnel endpoint gets commands like the
# source sends them and works on a fake cluster filesystem, see QemuServerTest::FakeCFS.

use v5.36;

use lib qw(.. .);

use Test::MockModule;
use Test::More;

use PVE::RPCEnvironment;

use PVE::QemuServer;
use PVE::QemuServer::Helpers;

use QemuServerTest::FakeCFS;
use QemuServerTest::MTunnel qw(run_mtunnel);

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->set_user('root@pam');

my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
$rpcenv_module->mock(check => sub { return 1; });
$QemuServerTest::FakeCFS::cluster_module->mock(check_cfs_quorum => sub { return 1; });
my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock(config => sub { return {}; });
my $replication_config_module = Test::MockModule->new('PVE::ReplicationConfig');
$replication_config_module->mock(
    new => sub { return bless {}, 'PVE::ReplicationConfig'; },
    check_for_existing_jobs => sub { return; },
);
my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
$qemu_server_module->mock(check_running => sub { return 0; });

sub configs { return $QemuServerTest::FakeCFS::configs; }

my $config_cmd = { cmd => 'config', conf => "cores: 2\nmemory: 1024\nname: source\n" };
my $cleanup_cmd = { cmd => 'quit', cleanup => 1 };

subtest 'a failed command is logged and reported to the source' => sub {
    QemuServerTest::FakeCFS::reset();

    my $invalid = { cmd => 'config', conf => "memory: 1024\nno-such-option: 1\n" };
    my ($replies, $output, $err) = run_mtunnel(100, [$invalid, $cleanup_cmd]);
    is($err, '', 'tunnel exits normally');
    ok(!$replies->[0]->{success}, 'command fails');
    like(
        $replies->[0]->{msg},
        qr/^failed to handle 'config' command - /,
        'source gets the error',
    );
    like($output, qr/^failed to handle 'config' command - /m, 'target task logs it');
    ok($replies->[1]->{success}, 'cleanup on quit succeeds');
    ok(!defined(configs()->{100}), 'reservation is removed by the cleanup');
};

subtest 'tunnel end before the config arrived removes the reservation' => sub {
    QemuServerTest::FakeCFS::reset();

    my ($replies, $output, $err) = run_mtunnel(100, [{ cmd => 'version' }]);
    like($err, qr/mtunnel exited unexpectedly/, 'tunnel fails');
    like(
        $output,
        qr/^tunnel closed before the config arrived, cleaning up$/m,
        'cleanup is logged',
    );
    ok(!defined(configs()->{100}), 'reservation is removed');
};

subtest 'tunnel end after the config arrived keeps the VM' => sub {
    QemuServerTest::FakeCFS::reset();

    my ($replies, $output, $err) = run_mtunnel(100, [$config_cmd]);
    like($err, qr/mtunnel exited unexpectedly/, 'tunnel fails');
    ok($replies->[0]->{success}, 'config command succeeded');
    unlike($output, qr/cleaning up/, 'no cleanup');
    like(configs()->{100}, qr/^lock: migrate$/m, 'config is kept');
};

subtest 'no connection: socket and reservation are removed' => sub {
    QemuServerTest::FakeCFS::reset();

    my ($replies, $output, $err) = run_mtunnel(100, undef);
    is($err, "Exiting mtunnel\n", 'tunnel fails');
    ok(!-e PVE::QemuServer::Helpers::mtunnel_socket(100), 'socket is removed');
    ok(!defined(configs()->{100}), 'reservation is removed');
};

done_testing();
