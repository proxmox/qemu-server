package MigrationTest::QemuMigrateMock;

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
my $QM_LIB_PATH = $ENV{QM_LIB_PATH} or die "no QM_LIB_PATH set\n";

my $source_volids = decode_json(file_get_contents("${RUN_DIR_PATH}/source_volids"));
my $source_vdisks = decode_json(file_get_contents("${RUN_DIR_PATH}/source_vdisks"));
my $vm_status = decode_json(file_get_contents("${RUN_DIR_PATH}/vm_status"));
my $expected_calls = decode_json(file_get_contents("${RUN_DIR_PATH}/expected_calls"));
my $fail_config = decode_json(file_get_contents("${RUN_DIR_PATH}/fail_config"));
my $storage_migrate_map = decode_json(file_get_contents("${RUN_DIR_PATH}/storage_migrate_map"));
my $migrate_params = decode_json(file_get_contents("${RUN_DIR_PATH}/migrate_params"));

my $test_vmid = $migrate_params->{vmid};
my $test_target = $migrate_params->{target};
my $test_opts = $migrate_params->{opts};
my $current_log = '';

my $vm_stop_executed = 0;

# mocked modules

my $inotify_module = Test::MockModule->new("PVE::INotify");
$inotify_module->mock(
    nodename => sub {
       return 'pve0';
    },
);

$MigrationTest::Shared::qemu_config_module->mock(
    move_config_to_node => sub {
	my ($self, $vmid, $target) = @_;
	die "moving wrong config: '$vmid'\n" if $vmid ne $test_vmid;
	die "moving config to wrong node: '$target'\n" if $target ne $test_target;
	delete $expected_calls->{move_config_to_node};
    },
);

my $tunnel_module = Test::MockModule->new("PVE::Tunnel");
$tunnel_module->mock(
    finish_tunnel => sub {
	delete $expected_calls->{'finish_tunnel'};
	return;
    },
    write_tunnel => sub {
	my ($tunnel, $timeout, $command) = @_;

	if ($command =~ m/^resume (\d+)$/) {
	    my $vmid = $1;
	    die "resuming wrong VM '$vmid'\n" if $vmid ne $test_vmid;
	    return;
	}
	die "write_tunnel (mocked) - implement me: $command\n";
    },
);

my $qemu_migrate_module = Test::MockModule->new("PVE::QemuMigrate");
$qemu_migrate_module->mock(
    fork_tunnel => sub {
	die "fork_tunnel (mocked) - implement me\n"; # currently no call should lead here
    },
    read_tunnel => sub {
	die "read_tunnel (mocked) - implement me\n"; # currently no call should lead here
    },
    start_remote_tunnel => sub {
	my ($self, $raddr, $rport, $ruri, $unix_socket_info) = @_;
	$expected_calls->{'finish_tunnel'} = 1;
	$self->{tunnel} =  {
	    writer => "mocked",
	    reader => "mocked",
	    pid => 123456,
	    version => 1,
	};
    },
    log => sub {
	my ($self, $level, $message) = @_;
	$current_log .= "$level: $message\n";
    },
    mon_cmd => sub {
	my ($vmid, $command, %params) = @_;

	if ($command eq 'nbd-server-start') {
	    return;
	} elsif ($command eq 'block-dirty-bitmap-add') {
	    my $drive = $params{node};
	    delete $expected_calls->{"block-dirty-bitmap-add-${drive}"};
	    return;
	} elsif ($command eq 'block-dirty-bitmap-remove') {
	    return;
	} elsif ($command eq 'query-migrate') {
	    return { status => 'failed' } if $fail_config->{'query-migrate'};
	    return { status => 'completed' };
	} elsif ($command eq 'migrate') {
	    return;
	} elsif ($command eq 'migrate-set-parameters') {
	    return;
	} elsif ($command eq 'migrate_cancel') {
	    return;
	}
	die "mon_cmd (mocked) - implement me: $command";
    },
    transfer_replication_state => sub {
	delete $expected_calls->{transfer_replication_state};
    },
    switch_replication_job_target => sub {
	delete $expected_calls->{switch_replication_job_target};
    },
);

$MigrationTest::Shared::qemu_server_module->mock(
    kvm_user_version => sub {
	return "5.0.0";
    },
    qemu_blockjobs_cancel => sub {
	return;
    },
    qemu_drive_mirror => sub {
	my ($vmid, $drive, $dst_volid, $vmiddst, $is_zero_initialized, $jobs, $completion, $qga, $bwlimit, $src_bitmap) = @_;

	die "drive_mirror with wrong vmid: '$vmid'\n" if $vmid ne $test_vmid;
	die "qemu_drive_mirror '$drive' error\n" if $fail_config->{qemu_drive_mirror}
						 && $fail_config->{qemu_drive_mirror} eq $drive;

	my $nbd_info = decode_json(file_get_contents("${RUN_DIR_PATH}/nbd_info"));
	die "target does not expect drive mirror for '$drive'\n"
	    if !defined($nbd_info->{$drive});
	delete $nbd_info->{$drive};
	file_set_contents("${RUN_DIR_PATH}/nbd_info", to_json($nbd_info));
    },
    qemu_drive_mirror_monitor => sub {
	my ($vmid, $vmiddst, $jobs, $completion, $qga) = @_;

	if ($fail_config->{qemu_drive_mirror_monitor} &&
	    $fail_config->{qemu_drive_mirror_monitor} eq $completion) {
	    die "qemu_drive_mirror_monitor '$completion' error\n";
	}
	return;
    },
    set_migration_caps => sub {
	return;
    },
    vm_stop => sub {
	$vm_stop_executed = 1;
	delete $expected_calls->{'vm_stop'};
    },
);

my $qemu_server_cpuconfig_module = Test::MockModule->new("PVE::QemuServer::CPUConfig");
$qemu_server_cpuconfig_module->mock(
    get_cpu_from_running_vm => sub {
	die "invalid test: if you specify a custom CPU model you need to " .
	    "specify runningcpu as well\n" if !defined($vm_status->{runningcpu});
	return $vm_status->{runningcpu};
    }
);

my $qemu_server_helpers_module = Test::MockModule->new("PVE::QemuServer::Helpers");
$qemu_server_helpers_module->mock(
    vm_running_locally => sub {
	return $vm_status->{running} && !$vm_stop_executed;
    },
);

my $qemu_server_machine_module = Test::MockModule->new("PVE::QemuServer::Machine");
$qemu_server_machine_module->mock(
    qemu_machine_pxe => sub {
	die "invalid test: no runningmachine specified\n"
	    if !defined($vm_status->{runningmachine});
	return $vm_status->{runningmachine};
    },
);

my $ssh_info_module = Test::MockModule->new("PVE::SSHInfo");
$ssh_info_module->mock(
    get_ssh_info => sub {
	my ($node, $network_cidr) = @_;
	return {
	    ip => '1.2.3.4',
	    name => $node,
	    network => $network_cidr,
	};
    },
);

$MigrationTest::Shared::storage_module->mock(
    storage_migrate => sub {
	my ($cfg, $volid, $target_sshinfo, $target_storeid, $opts, $logfunc) = @_;

	die "storage_migrate '$volid' error\n" if $fail_config->{storage_migrate}
					       && $fail_config->{storage_migrate} eq $volid;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

	die "invalid test: need to add entry for '$volid' to storage_migrate_map\n"
	    if $storeid ne $target_storeid && !defined($storage_migrate_map->{$volid});

	my $target_volname = $storage_migrate_map->{$volid} // $opts->{target_volname} // $volname;
	my $target_volid = "${target_storeid}:${target_volname}";
	MigrationTest::Shared::add_target_volid($target_volid);

	return $target_volid;
    },
    vdisk_list => sub { # expects vmid to be set
	my ($cfg, $storeid, $vmid, $vollist) = @_;

	my @storeids = defined($storeid) ? ($storeid) : keys %{$source_vdisks};

	my $res = {};
	foreach my $storeid (@storeids) {
	    my $list_for_storeid = $source_vdisks->{$storeid};
	    my @list_for_vm = grep { $_->{vmid} eq $vmid } @{$list_for_storeid};
	    $res->{$storeid} = \@list_for_vm;
	}
	return $res;
    },
    vdisk_free => sub {
	my ($scfg, $volid) = @_;

	PVE::Storage::parse_volume_id($volid);

	die "vdisk_free '$volid' error\n" if defined($fail_config->{vdisk_free})
					  && $fail_config->{vdisk_free} eq $volid;

	delete $source_volids->{$volid};
    },
);

$MigrationTest::Shared::tools_module->mock(
    get_host_address_family => sub {
	die "get_host_address_family (mocked) - implement me\n"; # currently no call should lead here
    },
    next_migrate_port => sub {
	die "next_migrate_port (mocked) - implement me\n"; # currently no call should lead here
    },
    run_command => sub {
	my ($cmd_tail, %param) = @_;

	my $cmd_msg = to_json($cmd_tail);

	my $cmd = shift @{$cmd_tail};

	if ($cmd eq '/usr/bin/ssh') {
	    while (scalar(@{$cmd_tail})) {
		$cmd = shift @{$cmd_tail};
		if ($cmd eq '/bin/true') {
		    return 0;
		} elsif ($cmd eq 'qm') {
		    $cmd = shift @{$cmd_tail};
		    if ($cmd eq 'start') {
			delete $expected_calls->{ssh_qm_start};

			delete $vm_status->{runningmachine};
			delete $vm_status->{runningcpu};

			my @options = ( @{$cmd_tail} );
			while (scalar(@options)) {
			    my $opt = shift @options;
			    if ($opt eq '--machine') {
				$vm_status->{runningmachine} = shift @options;
			    } elsif ($opt eq '--force-cpu') {
				$vm_status->{runningcpu} = shift @options;
			    }
			}

			return $MigrationTest::Shared::tools_module->original('run_command')->([
			    '/usr/bin/perl',
			    "-I${QM_LIB_PATH}",
			    "-I${QM_LIB_PATH}/test",
			    "${QM_LIB_PATH}/test/MigrationTest/QmMock.pm",
			    'start',
			    @{$cmd_tail},
			    ], %param);

		    } elsif ($cmd eq 'nbdstop') {
			delete $expected_calls->{ssh_nbdstop};
			return 0;
		    } elsif ($cmd eq 'resume') {
			return 0;
		    } elsif ($cmd eq 'unlock') {
			my $vmid = shift @{$cmd_tail};;
			die "unlocking wrong vmid: $vmid\n" if $vmid ne $test_vmid;
			PVE::QemuConfig->remove_lock($vmid);
			return 0;
		    } elsif ($cmd eq 'stop') {
			return 0;
		    }
		    die "run_command (mocked) ssh qm command - implement me: ${cmd_msg}";
		} elsif ($cmd eq 'pvesm') {
		    $cmd = shift @{$cmd_tail};
		    if ($cmd eq 'free') {
			my $volid = shift @{$cmd_tail};
			PVE::Storage::parse_volume_id($volid);
			return 1 if $fail_config->{ssh_pvesm_free}
				 && $fail_config->{ssh_pvesm_free} eq $volid;
			MigrationTest::Shared::remove_target_volid($volid);
			return 0;
		    }
		    die "run_command (mocked) ssh pvesm command - implement me: ${cmd_msg}";
		}
	    }
	    die "run_command (mocked) ssh command - implement me: ${cmd_msg}";
	}
	die "run_command (mocked) - implement me: ${cmd_msg}";
    },
);

eval { PVE::QemuMigrate->migrate($test_target, undef, $test_vmid, $test_opts) };
my $error = $@;

file_set_contents("${RUN_DIR_PATH}/source_volids", to_json($source_volids));
file_set_contents("${RUN_DIR_PATH}/vm_status", to_json($vm_status));
file_set_contents("${RUN_DIR_PATH}/expected_calls", to_json($expected_calls));
file_set_contents("${RUN_DIR_PATH}/log", $current_log);

die $error if $error;

1;
