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

done_testing();
