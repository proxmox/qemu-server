package PVE::QemuConfig;

use strict;
use warnings;

use PVE::AbstractConfig;
use PVE::INotify;
use PVE::QemuServer;
use PVE::Storage;
use PVE::Tools;

use base qw(PVE::AbstractConfig);

my $nodename = PVE::INotify::nodename();

mkdir "/etc/pve/nodes/$nodename";
my $confdir = "/etc/pve/nodes/$nodename/qemu-server";
mkdir $confdir;

my $lock_dir = "/var/lock/qemu-server";
mkdir $lock_dir;

my $MAX_UNUSED_DISKS = 8;

# BEGIN implemented abstract methods from PVE::AbstractConfig

sub guest_type {
    return "VM";
}

sub __config_max_unused_disks {
    my ($class) = @_;

    return $MAX_UNUSED_DISKS;
}

sub config_file_lock {
    my ($class, $vmid) = @_;

    return "$lock_dir/lock-$vmid.conf";
}

sub cfs_config_path {
    my ($class, $vmid, $node) = @_;

    $node = $nodename if !$node;
    return "nodes/$node/qemu-server/$vmid.conf";
}

sub has_feature {
    my ($class, $feature, $conf, $storecfg, $snapname, $running, $backup_only) = @_;

    my $err;
    PVE::QemuServer::foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	return if PVE::QemuServer::drive_is_cdrom($drive);
	return if $backup_only && defined($drive->{backup}) && !$drive->{backup};
	my $volid = $drive->{file};
	$err = 1 if !PVE::Storage::volume_has_feature($storecfg, $feature, $volid, $snapname, $running);
   });

    return $err ? 0 : 1;
}

sub get_replicatable_volumes {
    my ($class, $storecfg, $vmid, $conf, $cleanup, $noerr) = @_;

    my $volhash = {};

    my $test_volid = sub {
	my ($volid, $attr) = @_;

	return if $attr->{cdrom};

	return if !$cleanup && !$attr->{replicate};

	if ($volid =~ m|^/|) {
	    return if !$attr->{replicate};
	    return if $cleanup || $noerr;
	    die "unable to replicate local file/device '$volid'\n";
	}

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, $noerr);
	return if !$storeid;

	my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	return if $scfg->{shared};

	my ($path, $owner, $vtype) = PVE::Storage::path($storecfg, $volid);
	return if !$owner || ($owner != $vmid);

	if ($vtype ne 'images') {
	    return if $cleanup || $noerr;
	    die "unable to replicate volume '$volid', type '$vtype'\n";
	}

	if (!PVE::Storage::volume_has_feature($storecfg, 'replicate', $volid)) {
	    return if $cleanup || $noerr;
	    die "missing replicate feature on volume '$volid'\n";
	}

	$volhash->{$volid} = 1;
    };

    PVE::QemuServer::foreach_volid($conf, $test_volid);

    # add 'unusedX' volumes to volhash
    foreach my $key (keys %$conf) {
	if ($key =~ m/^unused/) {
	    $test_volid->($conf->{$key}, { replicate => 1 });
	}
    }

    return $volhash;
}

sub __snapshot_save_vmstate {
    my ($class, $vmid, $conf, $snapname, $storecfg) = @_;

    my $snap = $conf->{snapshots}->{$snapname};

    # first, use explicitly configured storage
    my $target = $conf->{vmstatestorage};

    if (!$target) {
	my ($shared, $local);
	PVE::QemuServer::foreach_storage_used_by_vm($conf, sub {
	    my ($sid) = @_;
	    my $scfg = PVE::Storage::storage_config($storecfg, $sid);
	    my $dst = $scfg->{shared} ? \$shared : \$local;
	    $$dst = $sid if !$$dst || $scfg->{path}; # prefer file based storage
	});

	# second, use shared storage where VM has at least one disk
	# third, use local storage where VM has at least one disk
	# fall back to local storage
	$target = $shared // $local // 'local';
    }

    my $driver_state_size = 500; # assume 32MB is enough to safe all driver state;
    # we abort live save after $conf->{memory}, so we need at max twice that space
    my $size = $conf->{memory}*2 + $driver_state_size;

    my $name = "vm-$vmid-state-$snapname";
    my $scfg = PVE::Storage::storage_config($storecfg, $target);
    $name .= ".raw" if $scfg->{path}; # add filename extension for file base storage
    $snap->{vmstate} = PVE::Storage::vdisk_alloc($storecfg, $target, $vmid, 'raw', $name, $size*1024);
    # always overwrite machine if we save vmstate. This makes sure we
    # can restore it later using correct machine type
    $snap->{machine} = PVE::QemuServer::get_current_qemu_machine($vmid);
}

sub __snapshot_check_running {
    my ($class, $vmid) = @_;
    return PVE::QemuServer::check_running($vmid);
}

sub __snapshot_check_freeze_needed {
    my ($class, $vmid, $config, $save_vmstate) = @_;

    my $running = $class->__snapshot_check_running($vmid);
    if (!$save_vmstate) {
	return ($running, $running && $config->{agent} && PVE::QemuServer::qga_check_running($vmid));
    } else {
	return ($running, 0);
    }
}

sub __snapshot_freeze {
    my ($class, $vmid, $unfreeze) = @_;

    if ($unfreeze) {
	eval { PVE::QemuServer::vm_mon_cmd($vmid, "guest-fsfreeze-thaw"); };
	warn "guest-fsfreeze-thaw problems - $@" if $@;
    } else {
	eval { PVE::QemuServer::vm_mon_cmd($vmid, "guest-fsfreeze-freeze"); };
	warn "guest-fsfreeze-freeze problems - $@" if $@;
    }
}

sub __snapshot_create_vol_snapshots_hook {
    my ($class, $vmid, $snap, $running, $hook) = @_;

    if ($running) {
	my $storecfg = PVE::Storage::config();

	if ($hook eq "before") {
	    if ($snap->{vmstate}) {
		my $path = PVE::Storage::path($storecfg, $snap->{vmstate});
		PVE::Storage::activate_volumes($storecfg, [$snap->{vmstate}]);

		PVE::QemuServer::vm_mon_cmd($vmid, "savevm-start", statefile => $path);
		for(;;) {
		    my $stat = PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "query-savevm");
		    if (!$stat->{status}) {
			die "savevm not active\n";
		    } elsif ($stat->{status} eq 'active') {
			sleep(1);
			next;
		    } elsif ($stat->{status} eq 'completed') {
			last;
		    } else {
			die "query-savevm returned status '$stat->{status}'\n";
		    }
		}
	    } else {
		PVE::QemuServer::vm_mon_cmd($vmid, "savevm-start");
	    }
	} elsif ($hook eq "after") {
	    eval { 
		PVE::QemuServer::vm_mon_cmd($vmid, "savevm-end");
		PVE::Storage::deactivate_volumes($storecfg, [$snap->{vmstate}]) if $snap->{vmstate};
	    };
	    warn $@ if $@;
	} elsif ($hook eq "after-freeze") {
	    # savevm-end is async, we need to wait
	    for (;;) {
		my $stat = PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "query-savevm");
		if (!$stat->{bytes}) {
		    last;
		} else {
		    print "savevm not yet finished\n";
		    sleep(1);
		    next;
		}
	    }
	}
    }
}

sub __snapshot_create_vol_snapshot {
    my ($class, $vmid, $ds, $drive, $snapname) = @_;

    return if PVE::QemuServer::drive_is_cdrom($drive);

    my $volid = $drive->{file};
    my $device = "drive-$ds";
    my $storecfg = PVE::Storage::config();

    PVE::QemuServer::qemu_volume_snapshot($vmid, $device, $storecfg, $volid, $snapname);
}

sub __snapshot_delete_remove_drive {
    my ($class, $snap, $remove_drive) = @_;

    if ($remove_drive eq 'vmstate') {
	delete $snap->{$remove_drive};
    } else {
	my $drive = PVE::QemuServer::parse_drive($remove_drive, $snap->{$remove_drive});
	return if PVE::QemuServer::drive_is_cdrom($drive);

	my $volid = $drive->{file};
	delete $snap->{$remove_drive};
	$class->add_unused_volume($snap, $volid);
    }
}

sub __snapshot_delete_vmstate_file {
    my ($class, $snap, $force) = @_;

    my $storecfg = PVE::Storage::config();

    eval {  PVE::Storage::vdisk_free($storecfg, $snap->{vmstate}); };
    if (my $err = $@) {
	die $err if !$force;
	warn $err;
    }
}

sub __snapshot_delete_vol_snapshot {
    my ($class, $vmid, $ds, $drive, $snapname, $unused) = @_;

    return if PVE::QemuServer::drive_is_cdrom($drive);
    my $storecfg = PVE::Storage::config();
    my $volid = $drive->{file};
    my $device = "drive-$ds";

    PVE::QemuServer::qemu_volume_snapshot_delete($vmid, $device, $storecfg, $volid, $snapname);

    push @$unused, $volid;
}

sub __snapshot_rollback_vol_possible {
    my ($class, $drive, $snapname) = @_;

    return if PVE::QemuServer::drive_is_cdrom($drive);

    my $storecfg = PVE::Storage::config();
    my $volid = $drive->{file};

    PVE::Storage::volume_rollback_is_possible($storecfg, $volid, $snapname);
}

sub __snapshot_rollback_vol_rollback {
    my ($class, $drive, $snapname) = @_;

    return if PVE::QemuServer::drive_is_cdrom($drive);

    my $storecfg = PVE::Storage::config();
    PVE::Storage::volume_snapshot_rollback($storecfg, $drive->{file}, $snapname);
}

sub __snapshot_rollback_vm_stop {
    my ($class, $vmid) = @_;

    my $storecfg = PVE::Storage::config();
    PVE::QemuServer::vm_stop($storecfg, $vmid, undef, undef, 5, undef, undef);
}

sub __snapshot_rollback_vm_start {
    my ($class, $vmid, $vmstate, $forcemachine) = @_;

    my $storecfg = PVE::Storage::config();
    my $statefile = PVE::Storage::path($storecfg, $vmstate);
    PVE::QemuServer::vm_start($storecfg, $vmid, $statefile, undef, undef, undef, $forcemachine);
}

sub __snapshot_rollback_get_unused {
    my ($class, $conf, $snap) = @_;

    my $unused = [];

    $class->__snapshot_foreach_volume($conf, sub {
	my ($vs, $volume) = @_;

	return if PVE::QemuServer::drive_is_cdrom($volume);

	my $found = 0;
	my $volid = $volume->{file};

	$class->__snapshot_foreach_volume($snap, sub {
	    my ($ds, $drive) = @_;

	    return if $found;
	    return if PVE::QemuServer::drive_is_cdrom($drive);

	    $found = 1
		if ($drive->{file} && $drive->{file} eq $volid);
	});

	push @$unused, $volid if !$found;
    });

    return $unused;
}

sub __snapshot_foreach_volume {
    my ($class, $conf, $func) = @_;

    PVE::QemuServer::foreach_drive($conf, $func);
}
# END implemented abstract methods from PVE::AbstractConfig

1;
