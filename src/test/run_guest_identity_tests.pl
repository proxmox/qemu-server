#!/usr/bin/perl

# Tests the guest identity of VM configs through the real config class methods, with a fake cluster
# filesystem, see QemuServerTest::FakeCFS.

use v5.36;

use lib qw(.. .);

use File::Temp qw(tempdir);
use Test::MockModule;
use Test::More;

use PVE::JSONSchema;
use PVE::RPCEnvironment;

use PVE::QemuConfig;
use PVE::QemuConfig::NoWrite;
use PVE::QemuMigrate;
use PVE::QemuServer;
use PVE::QemuServer::MetaInfo;

use PVE::API2::Qemu;

use QemuServerTest::FakeCFS;
use QemuServerTest::MTunnel qw(run_mtunnel);
use QemuServerTest::Utils qw(capture_output);

my $UID_A = 'abcdefghijklmnopqrst';
my $UID_B = 'bbbbbbbbbbbbbbbbbbbb';

my $helpers_module = Test::MockModule->new('PVE::QemuServer::Helpers');
$helpers_module->mock(kvm_user_version => sub { return '10.1.2'; });

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->set_user('root@pam');

my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
$rpcenv_module->mock(
    check => sub { return 1; },
    check_vm_perm => sub { return 1; },
    fork_worker => sub {
        my ($self, $type, $id, $user, $code) = @_;
        $code->('UPID:test');
        return 'UPID:test';
    },
);
$QemuServerTest::FakeCFS::cluster_module->mock(check_cfs_quorum => sub { return 1; });
my $network_module = Test::MockModule->new('PVE::QemuServer::Network');
$network_module->mock(create_ifaces_ipams_ips => sub { return; });

sub configs { return $QemuServerTest::FakeCFS::configs; }
sub generated_uid { return QemuServerTest::FakeCFS::generated_uid(@_); }
sub stored_identity { return QemuServerTest::FakeCFS::stored_identity(@_); }

sub load_meta($vmid) {
    return PVE::QemuServer::MetaInfo::parse_meta_info(PVE::QemuConfig->load_config($vmid)->{meta});
}

subtest 'meta format' => sub {
    my $meta =
        'creation-qemu=10.1.2,ctime=1700000000,rtime=1700000000123,uid=abcdefghijklmnopqrst';

    is_deeply(
        PVE::QemuServer::MetaInfo::parse_meta_info($meta),
        {
            'creation-qemu' => '10.1.2',
            ctime => 1700000000,
            rtime => 1700000000123,
            uid => $UID_A,
        },
        'identity members get parsed',
    );
    is(
        PVE::JSONSchema::print_property_string(
            PVE::QemuServer::MetaInfo::parse_meta_info($meta),
            $PVE::QemuServer::MetaInfo::meta_info_fmt,
        ),
        $meta,
        'printing the parsed property gives the same string',
    );
};

subtest 'identities are enabled, but not for writing temporary configs' => sub {
    QemuServerTest::FakeCFS::reset();

    ok(PVE::QemuConfig->__identity_enabled(), 'enabled for PVE::QemuConfig');

    my $conf = { name => 'template-cmd' };
    PVE::QemuConfig::NoWrite->mark_config($conf);
    eval { PVE::QemuConfig->write_config(100, $conf) };
    is($@, "refusing to write temporary configuration\n", 'NoWrite refuses');
    eval { PVE::QemuConfig::NoWrite->write_config(100, $conf) };
    is(
        $@,
        "refusing to write temporary configuration\n",
        'NoWrite refuses when called directly',
    );
    is_deeply(configs(), {}, 'nothing written');
    is($QemuServerTest::FakeCFS::generated, 0, 'no identity generated');
};

subtest 'config writes keep the stored identity' => sub {
    QemuServerTest::FakeCFS::reset();

    PVE::QemuConfig->write_config(100, { memory => 512, meta => "rtime=1,uid=$UID_B" });
    is_deeply(
        stored_identity(100),
        { uid => generated_uid(1), rtime => 1700000000000 },
        'first write ignores a carried identity and generates one',
    );
    like(configs()->{100}, qr/^meta: rtime=1700000000000,uid=\w+$/m,
        'written as meta property');

    $QemuServerTest::FakeCFS::now_ms = 1800000000000;

    my $conf = PVE::QemuConfig->load_config(100);
    $conf->{meta} = "creation-qemu=9.2.0,ctime=1600000000,rtime=1,uid=$UID_B";
    PVE::QemuConfig->write_config(100, $conf);
    is_deeply(
        load_meta(100),
        {
            'creation-qemu' => '9.2.0',
            ctime => 1600000000,
            rtime => 1700000000000,
            uid => generated_uid(1),
        },
        'foreign identity replaced by the stored one, other members kept',
    );

    $conf = PVE::QemuConfig->load_config(100);
    delete $conf->{meta};
    PVE::QemuConfig->write_config(100, $conf);
    is_deeply(
        load_meta(100),
        { rtime => 1700000000000, uid => generated_uid(1) },
        'identity kept when the property is gone',
    );

    configs()->{101} = "memory: 512\nmeta: creation-qemu=8.0.2,ctime=1500000000\n";
    $conf = PVE::QemuConfig->load_config(101);
    $conf->{name} = 'old';
    PVE::QemuConfig->write_config(101, $conf);
    is_deeply(
        load_meta(101),
        {
            'creation-qemu' => '8.0.2',
            ctime => 1500000000,
            rtime => 1800000000000,
            uid => generated_uid(2),
        },
        'existing guest without identity gets one on its first write',
    );
};

subtest 'create' => sub {
    QemuServerTest::FakeCFS::reset();

    my $storage_module = Test::MockModule->new('PVE::Storage');
    $storage_module->mock(config => sub { return {}; });
    my $replication_state_module = Test::MockModule->new('PVE::ReplicationState');
    $replication_state_module->mock(delete_guest_states => sub { return; });

    capture_output(sub {
        PVE::API2::Qemu->create_vm({ node => 'localhost', vmid => 100, memory => 512 });
    });

    my $reserved = $QemuServerTest::FakeCFS::written->{100}->[0];
    like(
        $reserved,
        qr/^meta: rtime=1700000000000,uid=\w+$/m,
        'reservation stores a new identity',
    );
    my $meta = load_meta(100);
    is_deeply(
        [$meta->@{qw(creation-qemu uid rtime)}],
        ['10.1.2', generated_uid(1), 1700000000000],
        'final config keeps the reserved identity next to the creation info',
    );
    ok($meta->{ctime}, 'creation time set');
};

subtest 'clone' => sub {
    QemuServerTest::FakeCFS::reset();

    my $disk = "scsi0: local:100/vm-100-disk-0.raw,size=4G\n";
    my $source = "memory: 512\nmeta: creation-qemu=9.2.0,ctime=1600000000,"
        . "rtime=1600000000000,uid=$UID_A\nname: source\n$disk";
    # like a VM left behind by a restore of a backup with uid B, with another pending change
    $source .= "\n[PENDING]\nmemory: 1024\nmeta: uid=$UID_B\n";
    # a snapshot can carry any identity
    configs()->{100} =
        "$source\n[snap]\nmemory: 256\nmeta: rtime=1,uid=$UID_B\n${disk}snaptime: 1600000001\n";

    my $storage_module = Test::MockModule->new('PVE::Storage');
    $storage_module->mock(
        activate_volumes => sub { return; },
        config => sub {
            return {
                ids => {
                    local =>
                        { type => 'dir', path => '/var/lib/vz', content => { images => 1 } },
                },
            };
        },
        deactivate_volumes => sub { return; },
        get_bandwidth_limit => sub { return undef; },
        volume_has_feature => sub { return 1; },
    );
    my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
    $qemu_server_module->mock(
        check_running => sub { return 0; },
        clone_disk => sub {
            my ($storecfg, $source, $dest) = @_;
            return { file => "local:$dest->{vmid}/vm-$dest->{vmid}-disk-0.raw", size => '4G' };
        },
    );
    my $firewall_module = Test::MockModule->new('PVE::Firewall');
    $firewall_module->mock(clone_vmfw_conf => sub { return; });

    my $output = capture_output(sub {
        PVE::API2::Qemu->clone_vm({ node => 'localhost', vmid => 100, newid => 300 });
        PVE::API2::Qemu->clone_vm(
            { node => 'localhost', vmid => 100, newid => 301, snapname => 'snap' });
    });

    is(stored_identity(300)->{uid}, generated_uid(1), 'clone has a new uid');
    is_deeply(
        load_meta(300),
        {
            'creation-qemu' => '9.2.0',
            ctime => 1600000000,
            rtime => 1700000000000,
            uid => generated_uid(1),
        },
        'clone keeps the creation info of its source',
    );
    is_deeply(
        load_meta(301),
        { rtime => 1700000000000, uid => generated_uid(2) },
        'clone of a snapshot has a new uid as well',
    );
    is(stored_identity(100)->{uid}, $UID_A, 'source keeps its uid');

    my $writes = $QemuServerTest::FakeCFS::written->{300};
    ok(scalar(grep { m/^scsi0: local:300\//m } $writes->@*) >= 2,
        'clone writes the disk first');
    ok(!scalar(grep { m/uid=$UID_B/ } $writes->@*),
        'no write of the clone has the pending uid');
    like(
        $output,
        qr/pending changes for 'memory', discarding for clone/,
        'other pending changes are discarded as before',
    );
    unlike(configs()->{300}, qr/^\[PENDING\]/m, 'clone has no pending section');
    like(configs()->{100}, qr/^meta: uid=$UID_B$/m, 'source keeps its pending uid');
};

subtest 'importovf' => sub {
    QemuServerTest::FakeCFS::reset();

    require PVE::CLI::qm;

    my $tmpdir = tempdir('importovf-XXXXXX', DIR => '.', CLEANUP => 1);
    my $manifest = "$tmpdir/test.ovf";
    PVE::Tools::file_set_contents($manifest, "<ovf/>\n");

    my $storage_module = Test::MockModule->new('PVE::Storage');
    $storage_module->mock(
        config => sub { return {}; },
        storage_check_enabled => sub { return {}; },
    );
    my $ovf_module = Test::MockModule->new('PVE::GuestImport::OVF');
    $ovf_module->mock(
        parse_ovf => sub {
            return { qm => { name => 'imported', memory => 1024, cores => 2 }, disks => [] };
        },
    );

    PVE::CLI::qm->importovf({ vmid => 100, manifest => $manifest, storage => 'local' });

    my $conf = PVE::QemuConfig->load_config(100);
    is($conf->{name}, 'imported', 'config imported');
    ok(!defined($conf->{lock}), 'create lock removed');
    is_deeply(
        stored_identity(100),
        { uid => generated_uid(1), rtime => 1700000000000 },
        'imported VM got a new identity on reservation and kept it',
    );
};

subtest 'remote migration, target side' => sub {
    QemuServerTest::FakeCFS::reset();

    my $cluster_module = Test::MockModule->new('PVE::Cluster');
    $cluster_module->mock(check_cfs_quorum => sub { return 1; });
    my $storage_module = Test::MockModule->new('PVE::Storage');
    $storage_module->mock(config => sub { return {}; });
    my $replication_config_module = Test::MockModule->new('PVE::ReplicationConfig');
    $replication_config_module->mock(
        new => sub { return bless {}, 'PVE::ReplicationConfig'; },
        check_for_existing_jobs => sub { return; },
    );
    my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
    $qemu_server_module->mock(check_running => sub { return 0; });

    my $source_conf = "cores: 2\nmemory: 1024\nmeta: creation-qemu=9.2.0,ctime=1600000000,"
        . "rtime=1600000000000,uid=$UID_A\nname: source\n";
    # like the source sends it
    my $identity_cmd = { cmd => 'identity', uid => $UID_A, 'allow-new-uid' => 0 };
    my $config_cmd = { cmd => 'config', conf => $source_conf };
    my $quit_cmd = { cmd => 'quit', cleanup => 0 };
    my $cleanup_cmd = { cmd => 'quit', cleanup => 1 };

    $QemuServerTest::FakeCFS::now_ms = 1800000000000;
    my ($replies, $output, $err) =
        run_mtunnel(100, [$identity_cmd, $config_cmd, $config_cmd, $identity_cmd, $quit_cmd]);
    is($err, '', 'tunnel exits normally');
    like(
        $replies->[3]->{msg},
        qr/the uid can only be adopted once, before the config arrives/,
        'identity command after the config fails',
    );

    ok($replies->[0]->{success}, 'identity command succeeds');
    is_deeply(
        $replies->[0]->{identity},
        { result => 'adopted', uid => $UID_A, requested => $UID_A },
        'identity command returns the adopted identity',
    );
    like(
        $output,
        qr/^guest identity: adopted uid $UID_A from the source guest$/m,
        'target task logs it',
    );
    my $writes = $QemuServerTest::FakeCFS::written->{100};
    ok(
        $writes->[1] =~ m/^lock: create$/m && $writes->[1] =~ m/^meta: .*uid=$UID_A$/m,
        'uid is adopted right after the reservation',
    );
    ok($replies->[1]->{success}, 'config command succeeds');
    ok(!exists($replies->[1]->{identity}), 'config command adopts nothing');
    ok(!$replies->[2]->{success}, 'repeated config command fails');
    is_deeply(
        load_meta(100),
        {
            'creation-qemu' => '9.2.0',
            ctime => 1600000000,
            rtime => 1800000000000,
            uid => $UID_A,
        },
        'config write keeps the uid, other members come from the source',
    );
    ok($replies->[4]->{success}, 'tunnel quits');

    QemuServerTest::FakeCFS::reset();
    $QemuServerTest::FakeCFS::other_guests->{300} = "rtime=1,uid=$UID_A";
    ($replies, $output, $err) = run_mtunnel(101, [$identity_cmd, $cleanup_cmd]);
    is($err, '', 'uid in use: tunnel exits normally');
    ok(!$replies->[0]->{success}, 'uid in use: identity command fails');
    is(
        $replies->[0]->{msg},
        "failed to handle 'identity' command - guest 300 in the target cluster already has the"
            . " uid '$UID_A' of this guest - use 'allow-new-uid' to migrate it with a new uid\n",
        'uid in use: error explains the refusal',
    );
    is(
        scalar($QemuServerTest::FakeCFS::written->{101}->@*),
        1,
        'uid in use: nothing written besides the reservation',
    );
    ok($replies->[1]->{success}, 'uid in use: cleanup on quit succeeds');
    ok(!defined(configs()->{101}), 'uid in use: reservation removed by the cleanup');

    QemuServerTest::FakeCFS::reset();
    $QemuServerTest::FakeCFS::other_guests->{300} = "rtime=1,uid=$UID_A";
    ($replies, $output, $err) = run_mtunnel(
        101, [{ $identity_cmd->%*, 'allow-new-uid' => 1 }, $config_cmd, $quit_cmd],
    );
    is($err, '', 'uid in use, allow-new-uid: tunnel exits normally');
    is_deeply(
        $replies->[0]->{identity},
        {
            result => 'in-use',
            uid => generated_uid(1),
            requested => $UID_A,
            'in-use-by' => 300,
        },
        'uid in use, allow-new-uid: result is returned',
    );
    my $kept = generated_uid(1);
    like(
        $output,
        qr/^guest identity: source guest uid $UID_A is in use by guest 300, keeping uid $kept$/m,
        'uid in use, allow-new-uid: target task logs it',
    );
    ok($replies->[1]->{success}, 'uid in use, allow-new-uid: config command succeeds');
    unlike(
        $output,
        qr/the source sent no uid/,
        'uid in use, allow-new-uid: no note about a source without uid',
    );
    is(stored_identity(101)->{uid}, $kept, 'uid in use, allow-new-uid: new uid stays');

    QemuServerTest::FakeCFS::reset();
    ($replies) = run_mtunnel(105, [{ cmd => 'version' }, $cleanup_cmd]);
    is($replies->[0]->{api}, $PVE::QemuMigrate::WS_TUNNEL_VERSION, 'version: tunnel version');
    is($replies->[0]->{api} - $replies->[0]->{age}, 2, 'version: version 2 accepted');

    # like a source with tunnel version 2
    QemuServerTest::FakeCFS::reset();
    ($replies, $output) = run_mtunnel(102, [$config_cmd, $quit_cmd]);
    ok($replies->[0]->{success}, 'source without identity command: config command succeeds');
    is(
        stored_identity(102)->{uid},
        generated_uid(1),
        'source without identity command: new uid, not the one of the config',
    );
    my $new_uid = generated_uid(1);
    like(
        $output,
        qr/^guest identity: the source sent no uid, .* has the new uid $new_uid$/m,
        'source without identity command: target task logs the new uid',
    );
    like(
        $output,
        qr/^guest identity: .* a migration back there gets refused$/m,
        'source without identity command: and that the guest cannot migrate back',
    );

    QemuServerTest::FakeCFS::reset();
    my $config_without_uid =
        { cmd => 'config', conf => $source_conf =~ s/,rtime=\d+,uid=\w+//r };
    ($replies) = run_mtunnel(102, [$config_without_uid, $quit_cmd]);
    ok($replies->[0]->{success}, 'source without uid: config command succeeds');
    is(stored_identity(102)->{uid}, generated_uid(1), 'source without uid: new uid');

    QemuServerTest::FakeCFS::reset();
    $QemuServerTest::FakeCFS::lock_domain_error =
        "cfs-lock 'domain-guest-identity' error: no quorum!\n";
    ($replies, $output, $err) = run_mtunnel(103, [$identity_cmd, $cleanup_cmd]);
    is($err, '', 'adopting fails: tunnel exits normally');
    ok(!$replies->[0]->{success}, 'adopting fails: identity command fails');
    is(
        $replies->[0]->{msg},
        "failed to handle 'identity' command - unable to adopt the uid of the source guest"
            . " - cfs-lock 'domain-guest-identity' error: no quorum!\n",
        'adopting fails: error explains the failure',
    );
    ok($replies->[1]->{success}, 'adopting fails: cleanup on quit succeeds');
    ok(!defined(configs()->{103}), 'adopting fails: reservation removed by the cleanup');
};

subtest 'remote migration, source side' => sub {
    QemuServerTest::FakeCFS::reset();

    # the source reads the firewall config of the VM from /etc/pve, use a VMID the host lacks
    my $vmid = 999999999;
    my $source_conf = "cores: 2\nmemory: 1024\nmeta: rtime=1600000000000,uid=$UID_A\n";
    configs()->{$vmid} = $source_conf;

    my ($commands, $reply, $cleanup, $log) = ([], undef, undef, '');
    my $tunnel_module = Test::MockModule->new('PVE::Tunnel');
    $tunnel_module->mock(
        write_tunnel => sub {
            my ($tunnel, $timeout, $command, $params) = @_;
            push $commands->@*, { command => $command, timeout => $timeout, params => $params };
            die $reply if !ref($reply);
            return $reply;
        },
        finish_tunnel => sub {
            (undef, $cleanup) = @_;
        },
    );
    my $migrate_module = Test::MockModule->new('PVE::QemuMigrate');
    $migrate_module->mock(fork_websocket_tunnel => sub { return { version => 3, age => 1 }; });
    my $abstract_migrate_module = Test::MockModule->new('PVE::AbstractMigrate');
    $abstract_migrate_module->mock(log => sub { $log .= "$_[1]: $_[2]\n"; });
    $QemuServerTest::FakeCFS::qemu_config_module->mock(cleanup_fleecing_images => sub { });
    my $helpers_module = Test::MockModule->new('PVE::QemuMigrate::Helpers');
    $helpers_module->mock(check_local_resources => sub { return ([], {}, {}); });
    my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
    $qemu_server_module->mock(check_running => sub { return 0; });
    my $storage_module = Test::MockModule->new('PVE::Storage');
    $storage_module->mock(config => sub { return {}; });
    my $replication_config_module = Test::MockModule->new('PVE::ReplicationConfig');
    $replication_config_module->mock(
        new => sub { return bless {}, 'PVE::ReplicationConfig'; },
        find_local_replication_job => sub { return; },
        check_for_existing_jobs => sub { return; },
    );

    my $new_migration = sub($opts = {}) {
        return bless {
            opts => { remote => { vmid => 300 }, $opts->%* },
            node => 'remote-node',
            vmid => $vmid,
            local_volumes => {},
            volume_map => {},
            storecfg => {},
            },
            'PVE::QemuMigrate';
    };
    my $prepare = sub($self) {
        ($commands, $cleanup, $log) = ([], undef, '');
        my $output = '';
        open(my $out_fh, '>', \$output);
        my $oldfh = select($out_fh);
        eval { $self->prepare($vmid) };
        my $err = $@;
        select($oldfh);
        close($out_fh);
        return $err;
    };

    $reply =
        { success => 1, identity => { result => 'adopted', uid => $UID_A, requested => $UID_A } };
    my $self = $new_migration->();
    is($prepare->($self), '', 'uid free on the target: prepare succeeds');
    is_deeply(
        $commands,
        [{
            command => 'identity',
            timeout => 60,
            params => { uid => $UID_A, 'allow-new-uid' => 0 },
        }],
        'uid free on the target: only the uid is sent before anything else',
    );
    like(
        $log,
        qr/^info: guest identity: the migrated guest keeps uid $UID_A$/m,
        'uid free on the target: source task logs the outcome',
    );
    ok($self->{tunnel}, 'uid free on the target: tunnel is kept for the migration');
    ok(!defined($cleanup), 'uid free on the target: no cleanup');

    $reply = {
        success => 1,
        identity =>
            { result => 'in-use', uid => $UID_B, requested => $UID_A, 'in-use-by' => 300 },
    };
    $self = $new_migration->({ 'allow-new-uid' => 1 });
    is($prepare->($self), '', 'allow-new-uid: prepare succeeds');
    is($commands->[0]->{params}->{'allow-new-uid'}, 1, 'allow-new-uid: option is sent');
    my $in_use = "guest identity: guest 300 in the target cluster has uid $UID_A, the migrated"
        . " guest gets the new uid $UID_B";
    like($log, qr/^info: \Q$in_use\E$/m, 'allow-new-uid: source task logs the new uid');

    $reply =
        "error - tunnel command 'identity' failed - failed to handle 'identity' command -"
        . " guest 300 in the target cluster already has the uid '$UID_A' of this guest - use"
        . " 'allow-new-uid' to migrate it with a new uid\n";
    $self = $new_migration->();
    is($prepare->($self), $reply, 'uid in use: prepare fails with the error of the target');
    is(scalar($commands->@*), 1, 'uid in use: nothing else is sent');
    is($cleanup, 1, 'uid in use: target is asked to clean up');
    ok(!$self->{tunnel}, 'uid in use: tunnel is not kept');

    # a target with a newer version has accepted the uid at this point
    $reply = { success => 1, identity => { result => 'future', uid => $UID_A } };
    $self = $new_migration->();
    is($prepare->($self), '', 'unknown outcome does not fail the migration');
    like(
        $log,
        qr/^warn: guest identity: unknown result 'future' of the target$/m,
        'it is logged',
    );

    my $without_uid = "cores: 2\nmemory: 1024\n";
    configs()->{$vmid} = $without_uid;
    for my $case (
        [{ version => 2, age => 0 }, "Remote tunnel endpoint too old, upgrade required\n"],
        [
            { version => 4, age => 0 },
            "Remote tunnel endpoint not compatible, upgrade required\n",
        ],
    ) {
        my ($remote, $expected) = $case->@*;
        my $what = "target with tunnel version $remote->{version}";
        $migrate_module->mock(fork_websocket_tunnel => sub { return $remote; });
        $self = $new_migration->();
        is($prepare->($self), $expected, "$what: refused");
        is_deeply($commands, [], "$what: nothing is sent");
        is($cleanup, 1, "$what: target is asked to clean up");
        is(configs()->{$vmid}, $without_uid, "$what: source config is unchanged");
    }
    $migrate_module->mock(fork_websocket_tunnel => sub { return { version => 3, age => 1 }; });

    $self = $new_migration->();
    is($prepare->($self), '', 'source without uid: prepare succeeds');
    my $assigned = stored_identity($vmid)->{uid};
    is($assigned, generated_uid(1), 'source without uid: gets one first');
    is($commands->[0]->{params}->{uid}, $assigned, 'source without uid: and sends it');

    # a member of a newer version makes the parser drop the whole property
    configs()->{$vmid} =
        "cores: 2\nmemory: 1024\nmeta: future=1,rtime=1600000000000,uid=$UID_A\n";
    $self = $new_migration->();
    {
        local $SIG{__WARN__} = sub { };
        is($prepare->($self), '', 'meta the parser drops: prepare succeeds');
    }
    is($commands->[0]->{params}->{uid}, $UID_A, 'meta the parser drops: stored uid is sent');

    configs()->{$vmid} = $source_conf;
    $reply = { success => 1 };
    $self = $new_migration->();
    $self->{tunnel} = {};
    ($commands, $log) = ([], '');
    my $output = '';
    {
        open(my $out_fh, '>', \$output);
        my $oldfh = select($out_fh);
        eval { $self->phase1_remote($vmid) };
        is($@, '', 'config sent');
        select($oldfh);
        close($out_fh);
    }
    is($commands->[0]->{command}, 'config', 'config command');
    like(
        $commands->[0]->{params}->{conf},
        qr/^meta: rtime=1600000000000,uid=$UID_A$/m,
        'source config sent with its uid',
    );
    unlike($log, qr/guest identity/, 'config reply has no identity to log');

    $QemuServerTest::FakeCFS::qemu_config_module->unmock('cleanup_fleecing_images');
};

done_testing();
