#!/usr/bin/perl

# Tests API handlers of PVE::API2::Qemu up to the point where they would access the guest config,
# for checks that only depend on the parameters.

use strict;
use warnings;

use lib qw(..);

use Storable qw(dclone);
use Test::MockModule;
use Test::More;

use PVE::API2::Qemu;
use PVE::CLI::qmrestore;
use PVE::GuestIdentity;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock(config => sub { return {}; });

my $replication_config_module = Test::MockModule->new('PVE::ReplicationConfig');
$replication_config_module->mock(
    new => sub { return bless {}, 'PVE::ReplicationConfig'; },
    check_for_existing_jobs => sub { return; },
);

my $qemu_config_module = Test::MockModule->new('PVE::QemuConfig');

# the checks of most tests come before the config gets loaded
sub mock_unreachable_config {
    $qemu_config_module->mock(
        load_config => sub { die "reached load_config\n"; },
        lock_config => sub { die "reached lock_config\n"; },
    );
    $qemu_config_module->unmock('write_config') if $qemu_config_module->is_mocked('write_config');
}
mock_unreachable_config();

my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
$qemu_server_module->mock(check_running => sub { return 0; });

# Proxmox VE versions the cluster nodes report, undef for none
my $node_versions = {};

my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    check_cfs_quorum => sub { return 1; },
    check_node_exists => sub { return 1; },
    remote_node_ip => sub { return '192.0.2.2'; },
    get_node_pvecfg_version => sub {
        my ($node) = @_;
        return $node_versions->{$node};
    },
);

# Returns the error of calling the API method $method with $param, either the parameter errors as
# hash or the error message.
sub api_error {
    my ($method, $param) = @_;

    eval { PVE::API2::Qemu->$method({ node => 'localhost', vmid => 100, $param->%* }); };
    my $err = $@;

    return ref($err) ? $err->{errors} : $err;
}

my $not_in_schema =
    'property is not defined in schema and the schema does not allow additional properties';

for my $user ('root@pam', 'user@pve') {
    $rpcenv->set_user($user);

    for my $method ('update_vm', 'update_vm_async') {
        is_deeply(
            api_error($method, { delete => 'meta' }),
            { delete => "option 'meta' is read-only" },
            "$method: $user cannot delete 'meta'",
        );
        is_deeply(
            api_error($method, { delete => 'name,meta' }),
            { delete => "option 'meta' is read-only" },
            "$method: $user cannot delete 'meta' together with other options",
        );
        is_deeply(
            api_error($method, { revert => 'meta' }),
            { revert => "option 'meta' is read-only" },
            "$method: $user cannot revert 'meta'",
        );
        is_deeply(
            api_error($method, { meta => 'ctime=1700000000' }),
            { meta => $not_in_schema },
            "$method: $user cannot set 'meta'",
        );
    }

    is_deeply(
        api_error('create_vm', { meta => 'ctime=1700000000' }),
        { meta => $not_in_schema },
        "create_vm: $user cannot set 'meta'",
    );
    is_deeply(
        api_error(
            'create_vm',
            { archive => 'local:backup/vzdump-qemu-100.vma.zst', meta => 'ctime=1700000000' },
        ),
        { meta => $not_in_schema },
        "create_vm: $user cannot override 'meta' of a restored backup",
    );
}

$rpcenv->set_user('root@pam');

is(
    api_error('update_vm', { delete => 'name' }),
    "reached load_config\n",
    'update_vm: deleting other options passes the parameter checks',
);
is(
    api_error('update_vm', { revert => 'name' }),
    "reached load_config\n",
    'update_vm: reverting other options passes the parameter checks',
);

is_deeply(
    api_error('create_vm', { 'allow-identity-mismatch' => 1 }),
    { archive => "missing property required by 'allow-identity-mismatch'" },
    "create_vm: 'allow-identity-mismatch' only for restores",
);
my $qmrestore_param = PVE::CLI::qmrestore->map_method_by_name('qmrestore')->{parameters};
is(
    $qmrestore_param->{properties}->{'allow-identity-mismatch'}->{type},
    'boolean',
    "qmrestore has 'allow-identity-mismatch'",
);

subtest 'pending changes of meta are dropped' => sub {
    my $meta = 'creation-qemu=10.1.2,ctime=1762000000';
    my $stored;

    $qemu_config_module->mock(
        load_config => sub { return dclone($stored); },
        lock_config => sub {
            my ($class, $vmid, $code, @param) = @_;
            return $code->(@param);
        },
        write_config => sub {
            my ($class, $vmid, $conf) = @_;
            $stored = dclone($conf);
        },
    );
    my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
    $qemu_server_module->mock(check_running => sub { return 0; });

    for my $pending ({ meta => 'creation-qemu=8.0.2,ctime=1500000000' }, { delete => 'meta' }) {
        my $what = join(',', map { "$_: $pending->{$_}" } sort keys $pending->%*);
        $stored = { name => 'old', meta => $meta, pending => $pending, snapshots => {} };

        my $warnings = '';
        local $SIG{__WARN__} = sub { $warnings .= $_[0]; };
        PVE::API2::Qemu->update_vm({ node => 'localhost', vmid => 100, name => 'new' });

        is($stored->{name}, 'new', "other change applied ($what)");
        is($stored->{meta}, $meta, "meta unchanged ($what)");
        is_deeply($stored->{pending}, {}, "pending change of meta dropped ($what)");
        like(
            $warnings,
            qr/^ignoring pending change of read-only option 'meta'$/m,
            "dropped change is logged ($what)",
        );
    }

    mock_unreachable_config();
};

my $min_version = PVE::GuestIdentity::MIN_PVE_MANAGER_VERSION;
# the version of the target node, and the error if it gets refused as it would drop the identity
my $node_cases = [
    [$min_version, undef],
    ['10.0.0', undef],
    [
        '9.2.0',
        "node 'pve2' runs Proxmox VE 9.2.0, keeping the guest identity requires $min_version or"
            . " newer - upgrade the node first\n",
    ],
    # a node that did not report its version yet is accepted
    [undef, undef],
];

# the stored config of a VM with and one without guest identity
my $raw_with_identity = "meta: creation-qemu=10.1.0,ctime=1700000000,rtime=1700000000000,"
    . "uid=gaytemzugu3doobzmfrg\nmemory: 512\n";
my $raw_without_identity = "meta: creation-qemu=10.1.0,ctime=1700000000\nmemory: 512\n";

for my $case ($node_cases->@*) {
    my ($version, $refused) = $case->@*;
    $node_versions->{pve2} = $version;
    my $what = 'target node with ' . ($version // 'no') . ' version';

    is(
        api_error('clone_vm', { newid => 101, target => 'pve2' }),
        $refused // "reached load_config\n",
        "clone_vm: $what",
    );
}

subtest 'migration only refuses nodes that drop the identity of a VM that has one' => sub {
    my $raw_config;
    # the paths of the config files read for the stored identity
    my $read_paths = [];
    $cluster_module->mock(
        get_config => sub { push $read_paths->@*, $_[0]; return $raw_config; });
    $qemu_config_module->mock(
        load_config => sub { return { memory => 512 }; },
        check_lock => sub { die "reached check_lock\n"; },
    );

    for my $case ($node_cases->@*) {
        my ($version, $refused) = $case->@*;
        $node_versions->{pve2} = $version;
        my $what = 'target node with ' . ($version // 'no') . ' version';

        $raw_config = $raw_with_identity;
        for my $online (0, 1) {
            is(
                api_error('migrate_vm', { target => 'pve2', online => $online }),
                $refused // "reached check_lock\n",
                "VM with identity, " . ($online ? 'online' : 'offline') . ", $what",
            );
        }

        $raw_config = $raw_without_identity;
        is(
            api_error('migrate_vm', { target => 'pve2' }),
            "reached check_lock\n",
            "VM without identity, $what",
        );
    }

    $cluster_module->unmock('get_config');
    $qemu_config_module->unmock('check_lock');
    mock_unreachable_config();

    my @other = grep { !m{^nodes/[^/]+/qemu-server/100\.conf\z} } $read_paths->@*;
    ok(scalar($read_paths->@*) && !@other, 'only the config file of the VM is read')
        or diag(explain($read_paths));
};

$node_versions->{pve2} = undef;
is(
    api_error('clone_vm', { newid => 101 }),
    "reached load_config\n",
    'clone_vm: no check without target node',
);

subtest 'migration preconditions' => sub {
    my $nodes = ['localhost', 'pve2', 'pve3', 'pve4'];
    $cluster_module->mock(get_nodelist => sub { return $nodes; });
    my $inotify_module = Test::MockModule->new('PVE::INotify');
    $inotify_module->mock(nodename => sub { return 'localhost'; });

    $qemu_config_module->mock(load_config => sub { return { memory => 512 }; });
    my $migrate_helpers_module = Test::MockModule->new('PVE::QemuMigrate::Helpers');
    $migrate_helpers_module->mock(
        check_local_resources => sub {
            return ([], {}, { map { $_ => [] } $nodes->@* });
        },
    );
    my $ha_config_module = Test::MockModule->new('PVE::HA::Config');
    $ha_config_module->mock(vm_is_ha_managed => sub { return 0; });

    $node_versions->@{ 'pve2', 'pve3', 'pve4' } = ($min_version, '9.2.0', undef);

    my $raw_config = $raw_without_identity;
    $cluster_module->mock(get_config => sub { return $raw_config; });

    my $res = PVE::API2::Qemu->migrate_vm_precondition({ node => 'localhost', vmid => 100 });
    is_deeply(
        $res->{allowed_nodes},
        ['pve2', 'pve3', 'pve4'],
        'a VM without identity can go to every node',
    );

    $raw_config = $raw_with_identity;
    $res = PVE::API2::Qemu->migrate_vm_precondition({ node => 'localhost', vmid => 100 });

    is_deeply(
        $res->{allowed_nodes},
        ['pve2', 'pve4'],
        'node keeping the identity and node without version are allowed',
    );
    is_deeply(
        $res->{not_allowed_nodes}->{pve3},
        {
            'guest-identity-unsupported' => {
                version => '9.2.0',
                'required-version' => $min_version,
            },
        },
        'node with an older version is not allowed',
    );

    my $returns = PVE::API2::Qemu->map_method_by_name('migrate_vm_precondition')->{returns};
    # every reason of a node must be documented
    my $strict = dclone($returns);
    my $node_schema = $strict->{properties}->{not_allowed_nodes}->{additionalProperties};
    $node_schema->{additionalProperties} = 0;
    eval { PVE::JSONSchema::validate($res, $strict) };
    is($@, '', 'result matches the schema, including the reasons of each node');
    my $undocumented = { $res->%*, not_allowed_nodes => { pve3 => { 'other-reason' => 1 } } };
    eval { PVE::JSONSchema::validate($undocumented, $strict) };
    like($@, qr/other-reason/, 'an undocumented reason does not');

    $cluster_module->unmock('get_nodelist', 'get_config');
    mock_unreachable_config();
};

subtest 'clone target nodes' => sub {
    my $inotify_module = Test::MockModule->new('PVE::INotify');
    $inotify_module->mock(nodename => sub { return 'pve1'; });

    $qemu_config_module->mock(
        load_config => sub { return { memory => 512 }; },
        has_feature => sub { return 1; },
    );
    $qemu_server_module->mock(
        shared_nodes => sub {
            return { map { $_ => 1 } 'pve1', 'pve2', 'pve3', 'pve4' };
        },
    );

    # a clone on the same node needs no check, so the old version of the local node does not matter
    $node_versions->@{ 'pve1', 'pve2', 'pve3', 'pve4' } =
        ('9.2.0', $min_version, '9.2.0', undef);

    # the local node is the one the handler runs on, whatever name the API path used for it
    for my $node ('pve1', 'localhost') {
        my $res =
            PVE::API2::Qemu->vm_feature({ node => $node, vmid => 100, feature => 'clone' });
        is_deeply(
            [sort $res->{nodes}->@*],
            ['pve1', 'pve2', 'pve4'],
            "node '$node': only nodes that keep the identity or report no version are offered",
        );
    }

    # the web interface polls the snapshot feature, which needs no version lookups
    my $lookups = 0;
    my $node_identity_unsupported = \&PVE::GuestIdentity::node_identity_unsupported;
    my $guest_identity_module = Test::MockModule->new('PVE::GuestIdentity');
    $guest_identity_module->mock(
        node_identity_unsupported => sub {
            $lookups++;
            return $node_identity_unsupported->(@_);
        },
    );
    my $res =
        PVE::API2::Qemu->vm_feature({ node => 'pve1', vmid => 100, feature => 'snapshot' });
    is_deeply([sort $res->{nodes}->@*], ['pve1', 'pve2', 'pve3', 'pve4'], 'snapshot: nodes');
    is($lookups, 0, 'snapshot: no version lookup');
    $guest_identity_module->unmock('node_identity_unsupported');

    $qemu_server_module->unmock('shared_nodes');
    $qemu_config_module->unmock('has_feature');
    mock_unreachable_config();
};

subtest 'status' => sub {
    my $vm_conf;
    $qemu_config_module->mock(load_config => sub { return $vm_conf; });
    $qemu_server_module->mock(
        vmstatus => sub { return { 100 => { vmid => 100, status => 'stopped' } }; });
    my $ha_config_module = Test::MockModule->new('PVE::HA::Config');
    $ha_config_module->mock(get_service_status => sub { return { managed => 0 }; });

    my $returns = PVE::API2::Qemu->map_method_by_name('vm_status')->{returns};

    $vm_conf =
        { meta => 'creation-qemu=10.1.2,ctime=1,rtime=1700000000000,uid=abcdefghijklmnopqrst' };
    my $status = PVE::API2::Qemu->vm_status({ node => 'localhost', vmid => 100 });
    is($status->{uid}, 'abcdefghijklmnopqrst', 'uid returned');
    eval { PVE::JSONSchema::validate($status, $returns) };
    is($@, '', 'result matches the schema');

    $vm_conf = { meta => 'creation-qemu=10.1.2,ctime=1' };
    $status = PVE::API2::Qemu->vm_status({ node => 'localhost', vmid => 100 });
    ok(!exists($status->{uid}), 'no uid for config without identity');

    mock_unreachable_config();
    $qemu_server_module->unmock('vmstatus');
};

done_testing();
