package MigrationTest::Shared;

use strict;
use warnings;

use JSON;
use Test::MockModule;
use Socket qw(AF_INET);

use PVE::QemuConfig;
use PVE::Tools qw(file_set_contents file_get_contents lock_file_full);

my $RUN_DIR_PATH = $ENV{RUN_DIR_PATH} or die "no RUN_DIR_PATH set\n";

my $storage_config = decode_json(file_get_contents("${RUN_DIR_PATH}/storage_config"));
my $replication_config = decode_json(file_get_contents("${RUN_DIR_PATH}/replication_config"));
my $fail_config = decode_json(file_get_contents("${RUN_DIR_PATH}/fail_config"));
my $migrate_params = decode_json(file_get_contents("${RUN_DIR_PATH}/migrate_params"));
my $test_vmid = $migrate_params->{vmid};

# helpers

sub add_target_volid {
    my ($volid) = @_;

    lock_file_full("${RUN_DIR_PATH}/target_volids.lock", undef, 0, sub {
	my $target_volids = decode_json(file_get_contents("${RUN_DIR_PATH}/target_volids"));
	die "target volid already present " if defined($target_volids->{$volid});
	$target_volids->{$volid} = 1;
	file_set_contents("${RUN_DIR_PATH}/target_volids", to_json($target_volids));
    });
    die $@ if $@;
}

sub remove_target_volid {
    my ($volid) = @_;

    lock_file_full("${RUN_DIR_PATH}/target_volids.lock", undef, 0, sub {
	my $target_volids = decode_json(file_get_contents("${RUN_DIR_PATH}/target_volids"));
	die "target volid does not exist " if !defined($target_volids->{$volid});
	delete $target_volids->{$volid};
	file_set_contents("${RUN_DIR_PATH}/target_volids", to_json($target_volids));
    });
    die $@ if $@;
}

my $mocked_cfs_read_file = sub {
    my ($file) = @_;

    if ($file eq 'datacenter.cfg') {
	return {};
    } elsif ($file eq 'replication.cfg') {
	return $replication_config;
    }
    die "cfs_read_file (mocked) - implement me: $file\n";
};

# mocked modules

our $cluster_module = Test::MockModule->new("PVE::Cluster");
$cluster_module->mock(
    cfs_read_file => $mocked_cfs_read_file,
    check_cfs_quorum => sub {
	return 1;
    },
);

our $ha_config_module = Test::MockModule->new("PVE::HA::Config");
$ha_config_module->mock(
    vm_is_ha_managed => sub {
	return 0;
    },
);

our $qemu_config_module = Test::MockModule->new("PVE::QemuConfig");
$qemu_config_module->mock(
    assert_config_exists_on_node => sub {
	return;
    },
    load_config => sub {
	my ($class, $vmid, $node) = @_;
	die "trying to load wrong config: '$vmid'\n" if $vmid ne $test_vmid;
	return decode_json(file_get_contents("${RUN_DIR_PATH}/vm_config"));
    },
    lock_config => sub { # no use locking here because lock is local to node
	my ($self, $vmid, $code, @param) = @_;
	return $code->(@param);
    },
    write_config => sub {
	my ($class, $vmid, $conf) = @_;
	die "trying to write wrong config: '$vmid'\n" if $vmid ne $test_vmid;
	file_set_contents("${RUN_DIR_PATH}/vm_config", to_json($conf));
    },
);

our $qemu_server_cloudinit_module = Test::MockModule->new("PVE::QemuServer::Cloudinit");
$qemu_server_cloudinit_module->mock(
    generate_cloudinitconfig => sub {
	return;
    },
);

our $qemu_server_module = Test::MockModule->new("PVE::QemuServer");
$qemu_server_module->mock(
    clear_reboot_request => sub {
	return 1;
    },
    get_efivars_size => sub {
	 return 128 * 1024;
    },
);

our $replication_module = Test::MockModule->new("PVE::Replication");
$replication_module->mock(
    run_replication => sub {
	die "run_replication error" if $fail_config->{run_replication};

	my $vm_config = PVE::QemuConfig->load_config($test_vmid);
	return PVE::QemuConfig->get_replicatable_volumes(
	    $storage_config,
	    $test_vmid,
	    $vm_config,
	);
    },
);

our $replication_config_module = Test::MockModule->new("PVE::ReplicationConfig");
$replication_config_module->mock(
    cfs_read_file => $mocked_cfs_read_file,
);

our $storage_module = Test::MockModule->new("PVE::Storage");
$storage_module->mock(
    activate_volumes => sub {
	return 1;
    },
    deactivate_volumes => sub {
	return 1;
    },
    config => sub {
	return $storage_config;
    },
    get_bandwitdth_limit => sub {
	return 123456;
    },
);

our $systemd_module = Test::MockModule->new("PVE::Systemd");
$systemd_module->mock(
    wait_for_unit_removed => sub {
	return;
    },
    enter_systemd_scope => sub {
	return;
    },
);

my $migrate_port_counter = 60000;

our $tools_module = Test::MockModule->new("PVE::Tools");
$tools_module->mock(
    get_host_address_family => sub {
	return AF_INET;
    },
    next_migrate_port => sub {
	return $migrate_port_counter++;
    },
);

1;
