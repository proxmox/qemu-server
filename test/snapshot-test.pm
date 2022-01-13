package PVE::QemuServer; ## no critic

use strict;
use warnings;

use lib qw(..);

use PVE::Storage;
use PVE::Storage::Plugin;
use PVE::QemuServer;
use PVE::QemuConfig;
use PVE::Tools;
use PVE::ReplicationConfig;

use Test::MockModule;
use Test::More;

my $activate_storage_possible = 1;
my $nodename;
my $snapshot_possible;
my $vol_snapshot_possible = {};
my $vol_snapshot_delete_possible = {};
my $vol_snapshot_rollback_possible = {};
my $vol_snapshot_rollback_enabled = {};
my $vol_snapshot = {};
my $vol_snapshot_delete = {};
my $vol_snapshot_rollback = {};
my $running;
my $freeze_possible;
my $stop_possible;
my $save_vmstate_works;
my $vm_mon = {};

# Mocked methods

sub mocked_volume_snapshot {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    if ($vol_snapshot_possible->{$volid}) {
	if (defined($vol_snapshot->{$volid})) {
	    $vol_snapshot->{$volid} .= ",$snapname";
	} else {
	    $vol_snapshot->{$volid} = $snapname;
	}
	return 1;
    } else {
	die "volume snapshot disabled\n";
    }
}

sub mocked_volume_snapshot_delete {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    if ($vol_snapshot_delete_possible->{$volid}) {
	if (defined($vol_snapshot_delete->{$volid})) {
	    $vol_snapshot_delete->{$volid} .= ",$snapname";
	} else {
	    $vol_snapshot_delete->{$volid} = $snapname;
	}
	return 1;
    } else {
	die "volume snapshot delete disabled\n";
    }
}

sub mocked_volume_snapshot_rollback {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    if ($vol_snapshot_rollback_enabled->{$volid}) {
	if (defined($vol_snapshot_rollback->{$volid})) {
	    $vol_snapshot_rollback->{$volid} .= ",$snapname";
	} else {
	    $vol_snapshot_rollback->{$volid} = $snapname;
	}
	return 1;
    } else {
	die "volume snapshot rollback disabled\n";
    }
}

sub mocked_volume_rollback_is_possible {
    my ($storecfg, $volid, $snapname) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "volid undefined\n"
	if !defined($volid);
    die "snapname undefined\n"
	if !defined($snapname);
    return $vol_snapshot_rollback_possible->{$volid}
	if ($vol_snapshot_rollback_possible->{$volid});
    die "volume_rollback_is_possible failed\n";
}

sub mocked_activate_storage {
    my ($storecfg, $storeid) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "storage activation failed\n"
	if !$activate_storage_possible;
    return;
}

sub mocked_activate_volumes {
    my ($storecfg, $volumes) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "wrong volume - fake vmstate expected!\n"
	if ((scalar @$volumes != 1) || @$volumes[0] ne "somestorage:state-volume");
    return;
}

sub mocked_deactivate_volumes {
    my ($storecfg, $volumes) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "wrong volume - fake vmstate expected!\n"
	if ((scalar @$volumes != 1) || @$volumes[0] ne "somestorage:state-volume");
    return;
}

sub mocked_vdisk_free {
    my ($storecfg, $vmstate) = @_;
    die "Storage config not mocked! aborting\n"
	if defined($storecfg);
    die "wrong vdisk - fake vmstate expected!\n"
	if ($vmstate ne "somestorage:state-volume");
    return;
}

sub mocked_run_command {
    my ($cmd, %param) = @_;
    my $cmdstring;
    if (my $ref = ref($cmd)) {
	$cmdstring = PVE::Tools::cmd2string($cmd);
	if ($cmdstring =~ m/.*\/qemu-(un)?freeze.*/) {
	    return 1 if $freeze_possible;
	    die "qemu-[un]freeze disabled\n";
	}
	if ($cmdstring =~ m/.*\/qemu-stop.*--kill.*/) {
	    if ($stop_possible) {
		$running = 0;
		return 1;
	    } else {
		return 0;
	    }
	}
    }
    die "unexpected run_command call: '$cmdstring', aborting\n";
}

# Testing methods

sub test_file {
    my ($exp_fn, $real_fn) = @_;
    my $ret;
    eval {
	$ret = system("diff -u '$exp_fn' '$real_fn'");
    };
    die if $@;
    return !$ret;
}

sub testcase_prepare {
    my ($vmid, $snapname, $save_vmstate, $comment, $exp_err) = @_;
    subtest "Preparing snapshot '$snapname' for vm '$vmid'" => sub {
	plan tests => 2;
	$@ = undef;
	eval {
	    PVE::QemuConfig->__snapshot_prepare($vmid, $snapname, $save_vmstate, $comment);
	};
	is($@, $exp_err, "\$@ correct");
	ok(test_file("snapshot-expected/prepare/qemu-server/$vmid.conf", "snapshot-working/prepare/qemu-server/$vmid.conf"), "config file correct");
    };
}

sub testcase_commit {
    my ($vmid, $snapname, $exp_err) = @_;
    subtest "Committing snapshot '$snapname' for vm '$vmid'" => sub {
	plan tests => 2;
	$@ = undef;
	eval {
	    PVE::QemuConfig->__snapshot_commit($vmid, $snapname);
	};
	is($@, $exp_err, "\$@ correct");
	ok(test_file("snapshot-expected/commit/qemu-server/$vmid.conf", "snapshot-working/commit/qemu-server/$vmid.conf"), "config file correct");
    }
}

sub testcase_create {
    my ($vmid, $snapname, $save_vmstate, $comment, $exp_err, $exp_vol_snap, $exp_vol_snap_delete) = @_;
    subtest "Creating snapshot '$snapname' for vm '$vmid'" => sub {
	plan tests => 4;
	$vol_snapshot = {};
	$vol_snapshot_delete = {};
	$exp_vol_snap = {} if !defined($exp_vol_snap);
	$exp_vol_snap_delete = {} if !defined($exp_vol_snap_delete);
	$@ = undef;
	eval {
	    PVE::QemuConfig->snapshot_create($vmid, $snapname, $save_vmstate, $comment);
	};
	is($@, $exp_err, "\$@ correct");
	is_deeply($vol_snapshot, $exp_vol_snap, "created correct volume snapshots");
	is_deeply($vol_snapshot_delete, $exp_vol_snap_delete, "deleted correct volume snapshots");
	ok(test_file("snapshot-expected/create/qemu-server/$vmid.conf", "snapshot-working/create/qemu-server/$vmid.conf"), "config file correct");
    };
}

sub testcase_delete {
    my ($vmid, $snapname, $force, $exp_err, $exp_vol_snap_delete) = @_;
    subtest "Deleting snapshot '$snapname' of vm '$vmid'" => sub {
	plan tests => 3;
	$vol_snapshot_delete = {};
	$exp_vol_snap_delete = {} if !defined($exp_vol_snap_delete);
	$@ = undef;
	eval {
	    PVE::QemuConfig->snapshot_delete($vmid, $snapname, $force);
	};
	is($@, $exp_err, "\$@ correct");
	is_deeply($vol_snapshot_delete, $exp_vol_snap_delete, "deleted correct volume snapshots");
	ok(test_file("snapshot-expected/delete/qemu-server/$vmid.conf", "snapshot-working/delete/qemu-server/$vmid.conf"), "config file correct");
    };
}

sub testcase_rollback {
    my ($vmid, $snapname, $exp_err, $exp_vol_snap_rollback) = @_;
    subtest "Rolling back to snapshot '$snapname' of vm '$vmid'" => sub {
	plan tests => 3;
	$vol_snapshot_rollback = {};
	$running = 1;
	$exp_vol_snap_rollback = {} if !defined($exp_vol_snap_rollback);
	$@ = undef;
	eval {
	    PVE::QemuConfig->snapshot_rollback($vmid, $snapname);
	};
	is($@, $exp_err, "\$@ correct");
	is_deeply($vol_snapshot_rollback, $exp_vol_snap_rollback, "rolled back to correct volume snapshots");
	ok(test_file("snapshot-expected/rollback/qemu-server/$vmid.conf", "snapshot-working/rollback/qemu-server/$vmid.conf"), "config file correct");
    };
}

# BEGIN mocked PVE::QemuConfig methods
sub config_file_lock {
    return "snapshot-working/pve-test.lock";
}

sub cfs_config_path {
    my ($class, $vmid, $node) = @_;

    $node = $nodename if !$node;
    return "snapshot-working/$node/qemu-server/$vmid.conf";
}

sub load_config {
    my ($class, $vmid, $node) = @_;

    my $filename = $class->cfs_config_path($vmid, $node);

    my $raw = PVE::Tools::file_get_contents($filename);

    my $conf = PVE::QemuServer::parse_vm_config($filename, $raw);
    return $conf;
}

sub write_config {
    my ($class, $vmid, $conf) = @_;

    my $filename = $class->cfs_config_path($vmid);

    if ($conf->{snapshots}) {
	foreach my $snapname (keys %{$conf->{snapshots}}) {
	    $conf->{snapshots}->{$snapname}->{snaptime} = "1234567890"
		if $conf->{snapshots}->{$snapname}->{snaptime};
	}
    }

    my $raw = PVE::QemuServer::write_vm_config($filename, $conf);

    PVE::Tools::file_set_contents($filename, $raw);
}

sub has_feature {
    my ($class, $feature, $conf, $storecfg, $snapname, $running, $backup_only) = @_;
    return $snapshot_possible;
}

sub __snapshot_save_vmstate {
    my ($class, $vmid, $conf, $snapname, $storecfg) = @_;
    die "save_vmstate failed\n"
	if !$save_vmstate_works;

    my $snap = $conf->{snapshots}->{$snapname};
    $snap->{vmstate} = "somestorage:state-volume";
    $snap->{runningmachine} = "somemachine"
}

sub assert_config_exists_on_node {
    my ($vmid, $node) = @_;
    return -f cfs_config_path("PVE::QemuConfig", $vmid, $node);
}
# END mocked PVE::QemuConfig methods

# BEGIN mocked PVE::QemuServer::Helpers methods

sub vm_running_locally {
    return $running;
}

# END mocked PVE::QemuServer::Helpers methods

# BEGIN mocked PVE::QemuServer::Monitor methods

sub qmp_cmd {
    my ($vmid, $cmd) = @_;

    my $exec = $cmd->{execute};
    if ($exec eq "delete-drive-snapshot") {
	return;
    }
    if ($exec eq "guest-ping") {
	die "guest-ping disabled\n"
	    if !$vm_mon->{guest_ping};
	return;
    }
    if ($exec eq "guest-fsfreeze-freeze" || $exec eq "guest-fsfreeze-thaw") {
	die "freeze disabled\n"
	    if !$freeze_possible;
	return;
    }
    if ($exec eq "savevm-start") {
	die "savevm-start disabled\n"
	    if !$vm_mon->{savevm_start};
	return;
    }
    if ($exec eq "savevm-end") {
	die "savevm-end disabled\n"
	    if !$vm_mon->{savevm_end};
	return;
    }
    if ($exec eq "query-savevm") {
	return {
	    "status" => "completed",
	    "bytes" => 1024*1024*1024,
	    "total-time" => 5000,
        };
    }
    die "unexpected vm_qmp_command!\n";
}

# END mocked PVE::QemuServer::Monitor methods

# BEGIN redefine PVE::QemuServer methods

sub do_snapshots_with_qemu {
    return 0;
}

sub vm_start {
    my ($storecfg, $vmid, $params, $migrate_opts) = @_;

    die "Storage config not mocked! aborting\n"
	if defined($storecfg);

    die "statefile and forcemachine must be both defined or undefined! aborting\n"
	if defined($params->{statefile}) xor defined($params->{forcemachine});

    return;
}

sub vm_stop {
    my ($storecfg, $vmid, $skiplock, $nocheck, $timeout, $shutdown, $force, $keepActive, $migratedfrom) = @_;

    $running = 0
	if $stop_possible;

    return;
}

sub set_migration_caps {} # ignored

# END redefine PVE::QemuServer methods

PVE::Tools::run_command("rm -rf snapshot-working");
PVE::Tools::run_command("cp -a snapshot-input snapshot-working");

my $qemu_helpers_module = Test::MockModule->new('PVE::QemuServer::Helpers');
$qemu_helpers_module->mock('vm_running_locally', \&vm_running_locally);

my $qemu_monitor_module = Test::MockModule->new('PVE::QemuServer::Monitor');
$qemu_monitor_module->mock('qmp_cmd', \&qmp_cmd);

my $qemu_config_module = Test::MockModule->new('PVE::QemuConfig');
$qemu_config_module->mock('config_file_lock', \&config_file_lock);
$qemu_config_module->mock('cfs_config_path', \&cfs_config_path);
$qemu_config_module->mock('load_config', \&load_config);
$qemu_config_module->mock('write_config', \&write_config);
$qemu_config_module->mock('has_feature', \&has_feature);
$qemu_config_module->mock('__snapshot_save_vmstate', \&__snapshot_save_vmstate);
$qemu_config_module->mock('assert_config_exists_on_node', \&assert_config_exists_on_node);

# ignore existing replication config
my $repl_config_module = Test::MockModule->new('PVE::ReplicationConfig');
$repl_config_module->mock('new' => sub { return bless {}, "PVE::ReplicationConfig" });
$repl_config_module->mock('check_for_existing_jobs' => sub { return });

my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock('config', sub { return; });
$storage_module->mock('path', sub { return "/some/store/statefile/path"; });
$storage_module->mock('activate_storage', \&mocked_activate_storage);
$storage_module->mock('activate_volumes', \&mocked_activate_volumes);
$storage_module->mock('deactivate_volumes', \&mocked_deactivate_volumes);
$storage_module->mock('vdisk_free', \&mocked_vdisk_free);
$storage_module->mock('volume_snapshot', \&mocked_volume_snapshot);
$storage_module->mock('volume_snapshot_delete', \&mocked_volume_snapshot_delete);
$storage_module->mock('volume_snapshot_rollback', \&mocked_volume_snapshot_rollback);
$storage_module->mock('volume_rollback_is_possible', \&mocked_volume_rollback_is_possible);

$running = 1;
$freeze_possible = 1;
$save_vmstate_works = 1;

printf("\n");
printf("Running prepare tests\n");
printf("\n");
$nodename = "prepare";

printf("\n");
printf("Setting has_feature to return true\n");
printf("\n");
$snapshot_possible = 1;

printf("Successful snapshot_prepare with no existing snapshots\n");
testcase_prepare("101", "test", 0, "test comment", '');

printf("Successful snapshot_prepare with no existing snapshots, including vmstate\n");
testcase_prepare("102", "test", 1, "test comment", '');

printf("Successful snapshot_prepare with one existing snapshot\n");
testcase_prepare("103", "test2", 0, "test comment", "");

printf("Successful snapshot_prepare with one existing snapshot, including vmstate\n");
testcase_prepare("104", "test2", 1, "test comment", "");

printf("Expected error for snapshot_prepare on locked container\n");
testcase_prepare("200", "test", 0, "test comment", "VM is locked (snapshot)\n");

printf("Expected error for snapshot_prepare with duplicate snapshot name\n");
testcase_prepare("201", "test", 0, "test comment", "snapshot name 'test' already used\n");

$save_vmstate_works = 0;

printf("Expected error for snapshot_prepare with failing save_vmstate\n");
testcase_prepare("202", "test", 1, "test comment", "save_vmstate failed\n");

$save_vmstate_works = 1;

printf("\n");
printf("Setting has_feature to return false\n");
printf("\n");
$snapshot_possible = 0;

printf("Expected error for snapshot_prepare if snapshots not possible\n");
testcase_prepare("300", "test", 0, "test comment", "snapshot feature is not available\n");

printf("\n");
printf("Running commit tests\n");
printf("\n");
$nodename = "commit";

printf("\n");
printf("Setting has_feature to return true\n");
printf("\n");
$snapshot_possible = 1;

printf("Successful snapshot_commit with one prepared snapshot\n");
testcase_commit("101", "test", "");

printf("Successful snapshot_commit with one committed and one prepared snapshot\n");
testcase_commit("102", "test2", "");

printf("Expected error for snapshot_commit with no snapshot lock\n");
testcase_commit("201", "test", "missing snapshot lock\n");

printf("Expected error for snapshot_commit with invalid snapshot name\n");
testcase_commit("202", "test", "snapshot 'test' does not exist\n");

printf("Expected error for snapshot_commit with invalid snapshot state\n");
testcase_commit("203", "test", "wrong snapshot state\n");

$vol_snapshot_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_possible->{"local:snapshotable-disk-2"} = 1;
$vol_snapshot_possible->{"local:snapshotable-disk-3"} = 1;
$vol_snapshot_delete_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_delete_possible->{"local:snapshotable-disk-3"} = 1;
$vol_snapshot_rollback_enabled->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_rollback_enabled->{"local:snapshotable-disk-2"} = 1;
$vol_snapshot_rollback_enabled->{"local:snapshotable-disk-3"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-1"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-2"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-3"} = 1;
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-4"} = 1;
$vm_mon->{guest_ping} = 1;
$vm_mon->{savevm_start} = 1;
$vm_mon->{savevm_end} = 1;

# possible, but fails
$vol_snapshot_rollback_possible->{"local:snapshotable-disk-4"} = 1;


#printf("\n");
#printf("Setting up Mocking for PVE::Tools\n");
#my $tools_module = Test::MockModule->new('PVE::Tools');
#$tools_module->mock('run_command' => \&mocked_run_command);
#printf("\trun_command() mocked\n");
#
$nodename = "create";
printf("\n");
printf("Running create tests\n");
printf("\n");

printf("Successful snapshot_create with no existing snapshots\n");
testcase_create("101", "test", 0, "test comment", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_create with no existing snapshots, including vmstate\n");
testcase_create("102", "test", 1, "test comment", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_create with one existing snapshots\n");
testcase_create("103", "test2", 0, "test comment", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_create with one existing snapshots, including vmstate\n");
testcase_create("104", "test2", 1, "test comment", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_create with multiple mps\n");
testcase_create("105", "test", 0, "test comment", "", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-2" => "test", "local:snapshotable-disk-3" => "test" });

$freeze_possible = 0;
printf("Successful snapshot_create with no existing snapshots and broken freeze\n");
testcase_create("106", "test", 1, "test comment", "", { "local:snapshotable-disk-1" => "test" });
$freeze_possible = 1;

printf("Expected error for snapshot_create when volume snapshot is not possible\n");
testcase_create("201", "test", 0, "test comment", "volume snapshot disabled\n\n");

printf("Expected error for snapshot_create when volume snapshot is not possible for one drive\n");
testcase_create("202", "test", 0, "test comment", "volume snapshot disabled\n\n", { "local:snapshotable-disk-1" => "test" }, { "local:snapshotable-disk-1" => "test" });

$vm_mon->{savevm_start} = 0;
printf("Expected error for snapshot_create when Qemu mon command 'savevm-start' fails\n");
testcase_create("203", "test", 0, "test comment", "savevm-start disabled\n\n");
$vm_mon->{savevm_start} = 1;

printf("Successful snapshot_create with no existing snapshots but set machine type\n");
testcase_create("301", "test", 1, "test comment", "", { "local:snapshotable-disk-1" => "test" });

$activate_storage_possible = 0;

printf("Expected error for snapshot_create when storage activation is not possible\n");
testcase_create("303", "test", 1, "test comment", "storage activation failed\n\n");

$activate_storage_possible = 1;

$nodename = "delete";
printf("\n");
printf("Running delete tests\n");
printf("\n");

printf("Successful snapshot_delete of only existing snapshot\n");
testcase_delete("101", "test", 0, "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_delete of leaf snapshot\n");
testcase_delete("102", "test2", 0, "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_delete of root snapshot\n");
testcase_delete("103", "test", 0, "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_delete of intermediate snapshot\n");
testcase_delete("104", "test2", 0, "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_delete with broken volume_snapshot_delete and force=1\n");
testcase_delete("105", "test", 1, "");

printf("Successful snapshot_delete with mp broken volume_snapshot_delete and force=1\n");
testcase_delete("106", "test", 1, "", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-3" => "test" });

printf("Expected error when snapshot_delete fails with broken volume_snapshot_delete and force=0\n");
testcase_delete("201", "test", 0, "volume snapshot delete disabled\n");

printf("Expected error when snapshot_delete fails with broken mp volume_snapshot_delete and force=0\n");
testcase_delete("202", "test", 0, "volume snapshot delete disabled\n", { "local:snapshotable-disk-1" => "test" });

printf("Expected error for snapshot_delete with locked config\n");
testcase_delete("203", "test", 0, "VM is locked (backup)\n");

$activate_storage_possible = 0;

printf("Expected error for snapshot_delete when storage activation is not possible\n");
testcase_delete("204", "test", 0, "storage activation failed\n");

$activate_storage_possible = 1;

$nodename = "rollback";
printf("\n");
printf("Running rollback tests\n");
printf("\n");

$stop_possible = 1;

printf("Successful snapshot_rollback to only existing snapshot\n");
testcase_rollback("101", "test", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_rollback to leaf snapshot\n");
testcase_rollback("102", "test2", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_rollback to root snapshot\n");
testcase_rollback("103", "test", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_rollback to intermediate snapshot\n");
testcase_rollback("104", "test2", "", { "local:snapshotable-disk-1" => "test2" });

printf("Successful snapshot_rollback with multiple mp\n");
testcase_rollback("105", "test", "", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-2" => "test", "local:snapshotable-disk-3" => "test" });

printf("Successful snapshot_rollback to only existing snapshot, with saved vmstate and machine config\n");
testcase_rollback("106", "test", "", { "local:snapshotable-disk-1" => "test" });

printf("Expected error for snapshot_rollback with non-existing snapshot\n");
testcase_rollback("201", "test2", "snapshot 'test2' does not exist\n");

printf("Expected error for snapshot_rollback if volume rollback not possible\n");
testcase_rollback("202", "test", "volume_rollback_is_possible failed\n");

printf("Expected error for snapshot_rollback with incomplete snapshot\n");
testcase_rollback("203", "test", "unable to rollback to incomplete snapshot (snapstate = delete)\n");

printf("Expected error for snapshot_rollback with lock\n");
testcase_rollback("204", "test", "VM is locked (backup)\n");

$stop_possible = 0;

printf("Expected error for snapshot_rollback with unkillable container\n");
testcase_rollback("205", "test", "unable to rollback vm 205: vm is running\n");

$stop_possible = 1;

printf("Expected error for snapshot_rollback with mp rollback_is_possible failure\n");
testcase_rollback("206", "test", "volume_rollback_is_possible failed\n");

printf("Expected error for snapshot_rollback with mp rollback failure (results in inconsistent state)\n");
testcase_rollback("207", "test", "volume snapshot rollback disabled\n", { "local:snapshotable-disk-1" => "test", "local:snapshotable-disk-2" => "test" });

printf("Successful snapshot_rollback with saved vmstate and machine config only in snapshot\n");
testcase_rollback("301", "test", "", { "local:snapshotable-disk-1" => "test" });

printf("Successful snapshot_rollback with saved vmstate and machine config and runningmachine \n");
testcase_rollback("302", "test", "", { "local:snapshotable-disk-1" => "test" });

$activate_storage_possible = 0;

printf("Expected error for snapshot_rollback when storage activation is not possible\n");
testcase_rollback("303", "test", "storage activation failed\n");

$activate_storage_possible = 1;

done_testing();

1;
