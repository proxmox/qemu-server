package MigrationTest::QmMock;

use strict;
use warnings;

use JSON;
use Test::MockModule;

use MigrationTest::Shared;

use PVE::API2::Qemu;
use PVE::Storage;
use PVE::Tools qw(file_set_contents file_get_contents);

use PVE::CLIHandler;
use base qw(PVE::CLIHandler);

my $RUN_DIR_PATH = $ENV{RUN_DIR_PATH} or die "no RUN_DIR_PATH set\n";

my $target_volids = decode_json(file_get_contents("${RUN_DIR_PATH}/target_volids"));
my $fail_config = decode_json(file_get_contents("${RUN_DIR_PATH}/fail_config"));
my $migrate_params = decode_json(file_get_contents("${RUN_DIR_PATH}/migrate_params"));
my $nodename = $migrate_params->{target};

my $kvm_exectued = 0;
my $forcemachine;

sub setup_environment {
    my $rpcenv = PVE::RPCEnvironment::init('MigrationTest::QmMock', 'cli');
}

# mock RPCEnvironment directly

sub get_user {
    return 'root@pam';
}

sub fork_worker {
    my ($self, $dtype, $id, $user, $function, $background) = @_;
    $function->(123456);
    return '123456';
}

# mocked modules

my $inotify_module = Test::MockModule->new("PVE::INotify");
$inotify_module->mock(
    nodename => sub {
       return $nodename;
    },
);

$MigrationTest::Shared::qemu_server_module->mock(
    nodename => sub {
	return $nodename;
    },
    config_to_command => sub {
	return [ 'mocked_kvm_command' ];
    },
    vm_start_nolock => sub {
	my ($storecfg, $vmid, $conf, $params, $migrate_opts) = @_;
	$forcemachine = $params->{forcemachine}
	    or die "mocked vm_start_nolock - expected 'forcemachine' parameter\n";
	$MigrationTest::Shared::qemu_server_module->original('vm_start_nolock')->(@_);
    },
);

my $qemu_server_helpers_module = Test::MockModule->new("PVE::QemuServer::Helpers");
$qemu_server_helpers_module->mock(
    vm_running_locally => sub {
	return $kvm_exectued;
    },
);

our $qemu_server_machine_module = Test::MockModule->new("PVE::QemuServer::Machine");
$qemu_server_machine_module->mock(
    get_current_qemu_machine => sub {
	return wantarray ? ($forcemachine, 0) : $forcemachine;
    },
);

# to make sure we get valid and predictable names
my $disk_counter = 10;

$MigrationTest::Shared::storage_module->mock(
    vdisk_alloc => sub {
	my ($cfg, $storeid, $vmid, $fmt, $name, $size) = @_;

	die "vdisk_alloc (mocked) - name is not expected to be set - implement me\n"
	    if defined($name);

	my $name_without_extension = "vm-${vmid}-disk-${disk_counter}";
	$disk_counter++;

	my $volid;
	my $scfg = PVE::Storage::storage_config($cfg, $storeid);
	if ($scfg->{path}) {
	    $volid = "${storeid}:${vmid}/${name_without_extension}.${fmt}";
	} else {
	    $volid = "${storeid}:${name_without_extension}";
	}

	PVE::Storage::parse_volume_id($volid);

	die "vdisk_alloc '$volid' error\n" if $fail_config->{vdisk_alloc}
					   && $fail_config->{vdisk_alloc} eq $volid;

	MigrationTest::Shared::add_target_volid($volid);

	return $volid;
    },
);

$MigrationTest::Shared::qemu_server_module->mock(
    mon_cmd => sub {
	my ($vmid, $command, %params) = @_;

	if ($command eq 'nbd-server-start') {
	    return;
	} elsif ($command eq 'block-export-add') {
	    return;
	} elsif ($command eq 'query-block') {
	    return [];
	} elsif ($command eq 'qom-set') {
	    return;
	}
	die "mon_cmd (mocked) - implement me: $command";
    },
    run_command => sub {
	my ($cmd_full, %param) = @_;

	my $cmd_msg = to_json($cmd_full);

	my $cmd = shift @{$cmd_full};

	if ($cmd eq '/bin/systemctl') {
	    return;
	} elsif ($cmd eq 'mocked_kvm_command') {
	    $kvm_exectued = 1;
	    return 0;
	}
	die "run_command (mocked) - implement me: ${cmd_msg}";
    },
    set_migration_caps => sub {
	return;
    },
    vm_migrate_alloc_nbd_disks => sub{
	my $nbd = $MigrationTest::Shared::qemu_server_module->original('vm_migrate_alloc_nbd_disks')->(@_);
	file_set_contents("${RUN_DIR_PATH}/nbd_info", to_json($nbd));
	return $nbd;
    },
);

our $cmddef = {
    start => [ "PVE::API2::Qemu", 'vm_start', ['vmid'], { node => $nodename } ],
};

MigrationTest::QmMock->run_cli_handler();

1;
