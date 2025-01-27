package PVE::VZDump::QemuServer;

use strict;
use warnings;

use File::Basename;
use File::Path;
use IO::File;
use IPC::Open3;
use JSON;
use POSIX qw(EINTR EAGAIN);

use PVE::Cluster qw(cfs_read_file);
use PVE::INotify;
use PVE::IPCC;
use PVE::JSONSchema;
use PVE::PBSClient;
use PVE::RESTEnvironment qw(log_warn);
use PVE::QMPClient;
use PVE::Storage::Plugin;
use PVE::Storage::PBSPlugin;
use PVE::Storage;
use PVE::Tools;
use PVE::VZDump;
use PVE::Format qw(render_duration render_bytes);

use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Drive qw(checked_volume_format);
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Machine;
use PVE::QemuServer::Monitor qw(mon_cmd);

use base qw (PVE::VZDump::Plugin);

sub new {
    my ($class, $vzdump) = @_;

    PVE::VZDump::check_bin('qm');

    my $self = bless { vzdump => $vzdump }, $class;

    $self->{vmlist} = PVE::QemuServer::vzlist();
    $self->{storecfg} = PVE::Storage::config();

    return $self;
};

sub type {
    return 'qemu';
}

sub vmlist {
    my ($self) = @_;
    return [ keys %{$self->{vmlist}} ];
}

sub prepare {
    my ($self, $task, $vmid, $mode) = @_;

    my $running = PVE::QemuServer::Helpers::vm_running_locally($vmid);

    if ($running && (my $status = mon_cmd($vmid, 'query-backup'))) {
	if ($status->{status} && $status->{status} eq 'active') {
	    $self->log('warn', "left-over backup job still running inside QEMU - canceling now");
	    mon_cmd($vmid, 'backup-cancel');
	}
    }

    $task->{disks} = [];

    my $conf = $self->{vmlist}->{$vmid} = PVE::QemuConfig->load_config($vmid);

    $self->loginfo("VM Name: $conf->{name}")
	if defined($conf->{name});

    $self->{vm_was_running} = $running ? 1 : 0;
    $self->{vm_was_paused} = 0;
    if ($running && PVE::QemuServer::vm_is_paused($vmid, 0)) {
	# Do not treat a suspended VM as paused, as it would cause us to skip
	# fs-freeze even if the VM wakes up before we reach qga_fs_freeze.
	$self->{vm_was_paused} = 1;
    }

    $task->{hostname} = $conf->{name};

    my $hostname = PVE::INotify::nodename();

    my $vollist = [];
    my $drivehash = {};
    my $backup_volumes = PVE::QemuConfig->get_backup_volumes($conf);

    foreach my $volume (@{$backup_volumes}) {
	my $name = $volume->{key};
	my $volume_config = $volume->{volume_config};
	my $volid = $volume_config->{file};

	if (!$volume->{included}) {
	    $self->loginfo("exclude disk '$name' '$volid' ($volume->{reason})");
	    next;
	} else {
	    my $log = "include disk '$name' '$volid'";
	    if (defined(my $size = $volume_config->{size})) {
		my $readable_size = PVE::JSONSchema::format_size($size);
		$log .= " $readable_size";
	    }
	    $self->loginfo($log);
	}

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	push @$vollist, $volid if $storeid;
	$drivehash->{$name} = $volume->{volume_config};
    }

    PVE::Storage::activate_volumes($self->{storecfg}, $vollist);

    foreach my $ds (sort keys %$drivehash) {
	my $drive = $drivehash->{$ds};

	my $volid = $drive->{file};
	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	my $path = $volid;
	if ($storeid) {
	    $path = PVE::Storage::path($self->{storecfg}, $volid);
	}
	next if !$path;

	my ($size, $format);
	if ($storeid) {
	    # The call in list context can be expensive for certain plugins like RBD, just get size
	    $size = eval { PVE::Storage::volume_size_info($self->{storecfg}, $volid, 5) };
	    die "cannot determine size of volume '$volid' - $@\n" if $@;

	    $format = checked_volume_format($self->{storecfg}, $volid);
	} else {
	    ($size, $format) = eval {
		PVE::Storage::volume_size_info($self->{storecfg}, $volid, 5);
	    };
	    die "cannot determine size and format of volume '$volid' - $@\n" if $@;
	}

	my $diskinfo = {
	    path => $path,
	    volid => $volid,
	    storeid => $storeid,
	    size => $size,
	    format => $format,
	    virtdev => $ds,
	    qmdevice => "drive-$ds",
	};

	if ($ds eq 'tpmstate0') {
	    # TPM drive only exists for backup, which is reflected in the name
	    $diskinfo->{qmdevice} = 'drive-tpmstate0-backup';
	    $task->{tpmpath} = $path;
	}

	if (-b $path) {
	    $diskinfo->{type} = 'block';
	} else {
	    $diskinfo->{type} = 'file';
	}

	push @{$task->{disks}}, $diskinfo;
    }
}

sub vm_status {
    my ($self, $vmid) = @_;

    my $running = PVE::QemuServer::check_running($vmid) ? 1 : 0;

    return wantarray ? ($running, $running ? 'running' : 'stopped') : $running;
}

sub lock_vm {
    my ($self, $vmid) = @_;

    PVE::QemuConfig->set_lock($vmid, 'backup');
}

sub unlock_vm {
    my ($self, $vmid) = @_;

    PVE::QemuConfig->remove_lock($vmid, 'backup');
}

sub stop_vm {
    my ($self, $task, $vmid) = @_;

    my $opts = $self->{vzdump}->{opts};

    my $wait = $opts->{stopwait} * 60;
    # send shutdown and wait
    $self->cmd ("qm shutdown $vmid --skiplock --keepActive --timeout $wait");
}

sub start_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("qm start $vmid --skiplock");
}

sub suspend_vm {
    my ($self, $task, $vmid) = @_;

    return if $self->{vm_was_paused};

    $self->cmd ("qm suspend $vmid --skiplock");
}

sub resume_vm {
    my ($self, $task, $vmid) = @_;

    return if $self->{vm_was_paused};

    $self->cmd ("qm resume $vmid --skiplock");
}

sub assemble {
    my ($self, $task, $vmid) = @_;

    my $conffile = PVE::QemuConfig->config_file($vmid);

    my $outfile = "$task->{tmpdir}/qemu-server.conf";
    my $firewall_src = "/etc/pve/firewall/$vmid.fw";
    my $firewall_dest = "$task->{tmpdir}/qemu-server.fw";

    my $outfd = IO::File->new(">$outfile") or die "unable to open '$outfile' - $!\n";
    my $conffd = IO::File->new($conffile, 'r') or die "unable to open '$conffile' - $!\n";

    my $found_snapshot;
    my $found_pending;
    my $found_special;
    while (defined (my $line = <$conffd>)) {
	next if $line =~ m/^\#vzdump\#/; # just to be sure
	next if $line =~ m/^\#qmdump\#/; # just to be sure
	if ($line =~ m/^\[(.*)\]\s*$/) {
	    if ($1 =~ m/^PENDING$/i) {
		$found_pending = 1;
	    } elsif ($1 =~ m/^special:.*$/) {
		$found_special = 1;
	    } else {
		$found_snapshot = 1;
	    }
	}
	# skip all snapshots, pending changes and special sections
	next if $found_snapshot || $found_pending || $found_special;

	if ($line =~ m/^unused\d+:\s*(\S+)\s*/) {
	    $self->loginfo("skip unused drive '$1' (not included into backup)");
	    next;
	}
	next if $line =~ m/^lock:/ || $line =~ m/^parent:/;

	print $outfd $line;
    }

    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block' || $di->{type} eq 'file') {
	    my $storeid = $di->{storeid} || '';
	    my $format = $di->{format} || '';
	    print $outfd "#qmdump#map:$di->{virtdev}:$di->{qmdevice}:$storeid:$format:\n";
	} else {
	    die "internal error";
	}
    }

    if ($found_special) {
	$self->loginfo("special config section found (not included into backup)");
    }
    if ($found_snapshot) {
	$self->loginfo("snapshots found (not included into backup)");
    }
    if ($found_pending) {
	$self->loginfo("pending configuration changes found (not included into backup)");
    }

    PVE::Tools::file_copy($firewall_src, $firewall_dest) if -f $firewall_src;
}

sub archive {
    my ($self, $task, $vmid, $filename, $comp) = @_;

    my $opts = $self->{vzdump}->{opts};
    my $scfg = $opts->{scfg};

    if ($self->{vzdump}->{opts}->{pbs}) {
	$self->archive_pbs($task, $vmid);
    } else {
	$self->archive_vma($task, $vmid, $filename, $comp);
    }
}

my $bitmap_action_to_human = sub {
    my ($self, $info) = @_;

    my $action = $info->{action};

    if ($action eq "not-used") {
	return "disabled (no support)";
    } elsif ($action eq "not-used-removed") {
	return "disabled (old bitmap cleared)";
    } elsif ($action eq "new") {
	return "created new";
    } elsif ($action eq "used") {
	if ($info->{dirty} == 0) {
	    return "OK (drive clean)";
	} else {
	    my $size = render_bytes($info->{size}, 1);
	    my $dirty = render_bytes($info->{dirty}, 1);
	    return "OK ($dirty of $size dirty)";
	}
    } elsif ($action eq "invalid") {
	return "existing bitmap was invalid and has been cleared";
    } else {
	return "unknown";
    }
};

my $query_backup_status_loop = sub {
    my ($self, $vmid, $job_uuid, $qemu_support) = @_;

    my $starttime = time ();
    my $last_time = $starttime;
    my ($last_percent, $last_total, $last_target, $last_zero, $last_transferred) = (-1, 0, 0, 0, 0);
    my ($transferred, $reused);

    my $get_mbps = sub {
	my ($mb, $delta) = @_;
	return "0 B/s" if $mb <= 0;
	my $bw = int(($mb / $delta));
	return render_bytes($bw, 1) . "/s";
    };

    my $target = 0;
    my $last_reused = 0;
    my $has_query_bitmap = $qemu_support && $qemu_support->{'query-bitmap-info'};
    my $is_template = PVE::QemuConfig->is_template($self->{vmlist}->{$vmid});
    if ($has_query_bitmap) {
	my $total = 0;
	my $bitmap_info = mon_cmd($vmid, 'query-pbs-bitmap-info');
	for my $info (sort { $a->{drive} cmp $b->{drive} } @$bitmap_info) {
	    if (!$is_template) {
		my $text = $bitmap_action_to_human->($self, $info);
		my $drive = $info->{drive};
		$drive =~ s/^drive-//; # for consistency
		$self->loginfo("$drive: dirty-bitmap status: $text");
	    }
	    $target += $info->{dirty};
	    $total += $info->{size};
	    $last_reused += $info->{size} - $info->{dirty};
	}
	if ($target < $total) {
	    my $total_h = render_bytes($total, 1);
	    my $target_h = render_bytes($target, 1);
	    $self->loginfo("using fast incremental mode (dirty-bitmap), $target_h dirty of $total_h total");
	}
    }

    my $last_finishing = 0;
    while(1) {
	my $status = mon_cmd($vmid, 'query-backup');

	my $total = $status->{total} || 0;
	my $dirty = $status->{dirty};
	$target = (defined($dirty) && $dirty < $total) ? $dirty : $total if !$has_query_bitmap;
	$transferred = $status->{transferred} || 0;
	$reused = $status->{reused};
	my $percent = $target ? int(($transferred * 100)/$target) : 100;
	my $zero = $status->{'zero-bytes'} || 0;

	die "got unexpected uuid\n" if !$status->{uuid} || ($status->{uuid} ne $job_uuid);

	my $ctime = time();
	my $duration = $ctime - $starttime;

	my $rbytes = $transferred - $last_transferred;
	my $wbytes;
	if ($reused) {
	    # reused includes zero bytes for PBS
	    $wbytes = $rbytes - ($reused - $last_reused);
	} else {
	    $wbytes = $rbytes - ($zero - $last_zero);
	}

	my $timediff = ($ctime - $last_time) || 1; # fixme
	my $mbps_read = $get_mbps->($rbytes, $timediff);
	my $mbps_write = $get_mbps->($wbytes, $timediff);
	my $target_h = render_bytes($target, 1);
	my $transferred_h = render_bytes($transferred, 1);

	my $statusline = sprintf("%3d%% ($transferred_h of $target_h) in %s"
	    .", read: $mbps_read, write: $mbps_write", $percent, render_duration($duration));

	my $res = $status->{status} || 'unknown';
	if ($res ne 'active') {
	    if ($last_percent < 100) {
		$self->loginfo($statusline);
	    }
	    if ($res ne 'done') {
		die (($status->{errmsg} || "unknown error") . "\n") if $res eq 'error';
		die "got unexpected status '$res'\n";
	    }
	    $last_target = $target if $target;
	    $last_total = $total if $total;
	    $last_zero = $zero if $zero;
	    $last_transferred = $transferred if $transferred;
	    last;
	}
	if ($percent != $last_percent && ($timediff > 2)) {
	    $self->loginfo($statusline);
	    $last_percent = $percent;
	    $last_target = $target if $target;
	    $last_total = $total if $total;
	    $last_zero = $zero if $zero;
	    $last_transferred = $transferred if $transferred;
	    $last_time = $ctime;
	    $last_reused = $reused;

	    if (!$last_finishing && $status->{finishing}) {
		$self->loginfo("Waiting for server to finish backup validation...");
	    }
	    $last_finishing = $status->{finishing};
	}
	sleep(1);
    }

    my $duration = time() - $starttime;

    if ($last_zero) {
	my $zero_per = $last_target ? int(($last_zero * 100)/$last_target) : 0;
	my $zero_h = render_bytes($last_zero);
	$self->loginfo("backup is sparse: $zero_h (${zero_per}%) total zero data");
    }
    if ($reused) {
	my $reused_h = render_bytes($reused);
	my $reuse_per = int($reused * 100 / $last_total);
	$self->loginfo("backup was done incrementally, reused $reused_h (${reuse_per}%)");
    }
    if ($transferred) {
	my $transferred_h = render_bytes($transferred);
	if ($duration) {
	    my $mbps = $get_mbps->($transferred, $duration);
	    $self->loginfo("transferred $transferred_h in $duration seconds ($mbps)");
	} else {
	    $self->loginfo("transferred $transferred_h in <1 seconds");
	}
    }

    return {
	total => $last_total,
	reused => $reused,
    };
};

my $attach_tpmstate_drive = sub {
    my ($self, $task, $vmid) = @_;

    return if !$task->{tpmpath};

    # unconditionally try to remove the tpmstate-named drive - it only exists
    # for backing up, and avoids errors if left over from some previous event
    eval { PVE::QemuServer::qemu_drivedel($vmid, "tpmstate0-backup"); };

    $self->loginfo('attaching TPM drive to QEMU for backup');

    my $drive = "file=$task->{tpmpath},if=none,read-only=on,id=drive-tpmstate0-backup";
    $drive =~ s/\\/\\\\/g;
    my $ret = PVE::QemuServer::Monitor::hmp_cmd($vmid, "drive_add auto \"$drive\"", 60);
    die "attaching TPM drive failed - $ret\n" if $ret !~ m/OK/s;
};

my $detach_tpmstate_drive = sub {
    my ($task, $vmid) = @_;
    return if !$task->{tpmpath} || !PVE::QemuServer::check_running($vmid);
    eval { PVE::QemuServer::qemu_drivedel($vmid, "tpmstate0-backup"); };
};

my sub add_backup_performance_options {
    my ($qmp_param, $perf, $qemu_support) = @_;

    return if !$perf || scalar(keys $perf->%*) == 0;

    if (!$qemu_support) {
	my $settings_string = join(', ', sort keys $perf->%*);
	log_warn("ignoring setting(s): $settings_string - issue checking if supported");
	return;
    }

    if (defined($perf->{'max-workers'})) {
	if ($qemu_support->{'backup-max-workers'}) {
	    $qmp_param->{'max-workers'} = int($perf->{'max-workers'});
	} else {
	    log_warn("ignoring 'max-workers' setting - not supported by running QEMU");
	}
    }
}

sub get_and_check_pbs_encryption_config {
    my ($self) = @_;

    my $opts = $self->{vzdump}->{opts};
    my $scfg = $opts->{scfg};

    my $keyfile = PVE::Storage::PBSPlugin::pbs_encryption_key_file_name($scfg, $opts->{storage});
    my $master_keyfile = PVE::Storage::PBSPlugin::pbs_master_pubkey_file_name($scfg, $opts->{storage});

    if (-e $keyfile) {
	if (-e $master_keyfile) {
	    $self->loginfo("enabling encryption with master key feature");
	    return ($keyfile, $master_keyfile);
	} elsif ($scfg->{'master-pubkey'}) {
	    die "master public key configured but no key file found\n";
	} else {
	    $self->loginfo("enabling encryption");
	    return ($keyfile, undef);
	}
    } else {
	my $encryption_fp = $scfg->{'encryption-key'};
	die "encryption configured ('$encryption_fp') but no encryption key file found!\n"
	    if $encryption_fp;
	if (-e $master_keyfile) {
	    $self->log(
		'warn',
		"backup target storage is configured with master-key, but no encryption key set!"
		." Ignoring master key settings and creating unencrypted backup."
	    );
	}
	return (undef, undef);
    }
    die "internal error - unhandled case for getting & checking PBS encryption ($keyfile, $master_keyfile)!";
}

my sub cleanup_fleecing_images {
    my ($self, $disks) = @_;

    for my $di ($disks->@*) {
	if (my $volid = $di->{'fleece-volid'}) {
	    eval { PVE::Storage::vdisk_free($self->{storecfg}, $volid); };
	    $self->log('warn', "error removing fleecing image '$volid' - $@") if $@;
	}
    }
}

my sub allocate_fleecing_images {
    my ($self, $disks, $vmid, $fleecing_storeid, $format) = @_;

    die "internal error - no fleecing storage specified\n" if !$fleecing_storeid;

    # TODO what about potential left-over images from a failed attempt? Just
    # auto-remove? While unlikely, could conflict with manually created image from user...

    eval {
	my $n = 0; # counter for fleecing image names

	for my $di ($disks->@*) {
	    next if $di->{virtdev} =~ m/^(?:tpmstate|efidisk)\d$/; # too small to be worth it
	    if ($di->{type} eq 'block' || $di->{type} eq 'file') {
		my $scfg = PVE::Storage::storage_config($self->{storecfg}, $fleecing_storeid);
		my $name = "vm-$vmid-fleece-$n";
		$name .= ".$format" if $scfg->{path};

		my $size = PVE::Tools::convert_size($di->{size}, 'b' => 'kb');

		$di->{'fleece-volid'} = PVE::Storage::vdisk_alloc(
		    $self->{storecfg}, $fleecing_storeid, $vmid, $format, $name, $size);

		$n++;
	    } else {
		die "implement me (type '$di->{type}')";
	    }
	}
    };
    if (my $err = $@) {
	cleanup_fleecing_images($self, $disks);
	die $err;
    }
}

my sub detach_fleecing_images {
    my ($disks, $vmid) = @_;

    return if !PVE::QemuServer::Helpers::vm_running_locally($vmid);

    for my $di ($disks->@*) {
	if (my $volid = $di->{'fleece-volid'}) {
	    my $devid = "$di->{qmdevice}-fleecing";
	    $devid =~ s/^drive-//; # re-added by qemu_drivedel()
	    eval { PVE::QemuServer::qemu_drivedel($vmid, $devid) };
	}
    }
}

my sub attach_fleecing_images {
    my ($self, $disks, $vmid, $format) = @_;

    # unconditionally try to remove potential left-overs from a previous backup
    detach_fleecing_images($disks, $vmid);

    my $vollist = [ map { $_->{'fleece-volid'} } grep { $_->{'fleece-volid'} } $disks->@* ];
    PVE::Storage::activate_volumes($self->{storecfg}, $vollist);

    for my $di ($disks->@*) {
	if (my $volid = $di->{'fleece-volid'}) {
	    $self->loginfo("$di->{qmdevice}: attaching fleecing image $volid to QEMU");

	    my $path = PVE::Storage::path($self->{storecfg}, $volid);
	    my $devid = "$di->{qmdevice}-fleecing";
	    my $drive = "file=$path,if=none,id=$devid,format=$format,discard=unmap";
	    # Specify size explicitly, to make it work if storage backend rounded up size for
	    # fleecing image when allocating.
	    $drive .= ",size=$di->{size}" if $format eq 'raw';
	    $drive =~ s/\\/\\\\/g;
	    my $ret = PVE::QemuServer::Monitor::hmp_cmd($vmid, "drive_add auto \"$drive\"", 60);
	    die "attaching fleecing image $volid failed - $ret\n" if $ret !~ m/OK/s;
	}
    }
}

my sub check_and_prepare_fleecing {
    my ($self, $vmid, $fleecing_opts, $disks, $is_template, $qemu_support) = @_;

    # Even if the VM was started specifically for fleecing, it's possible that the VM is resumed and
    # then starts doing IO. For VMs that are not resumed the fleecing images will just stay empty,
    # so there is no big cost.

    my $use_fleecing = $fleecing_opts && $fleecing_opts->{enabled} && !$is_template;

    if ($use_fleecing && !defined($qemu_support->{'backup-fleecing'})) {
	$self->log(
	    'warn',
	    "running QEMU version does not support backup fleecing - continuing without",
	);
	$use_fleecing = 0;
    }

    if ($use_fleecing) {
	my ($default_format, $valid_formats) = PVE::Storage::storage_default_format(
	    $self->{storecfg}, $fleecing_opts->{storage});
	my $format = scalar(grep { $_ eq 'qcow2' } $valid_formats->@*) ? 'qcow2' : 'raw';

	allocate_fleecing_images($self, $disks, $vmid, $fleecing_opts->{storage}, $format);
	attach_fleecing_images($self, $disks, $vmid, $format);
    }

    return $use_fleecing;
}

sub archive_pbs {
    my ($self, $task, $vmid) = @_;

    my $conffile = "$task->{tmpdir}/qemu-server.conf";
    my $firewall = "$task->{tmpdir}/qemu-server.fw";

    my $opts = $self->{vzdump}->{opts};
    my $scfg = $opts->{scfg};

    my $starttime = time();

    my $fingerprint = $scfg->{fingerprint};
    my $repo = PVE::PBSClient::get_repository($scfg);
    my $password = PVE::Storage::PBSPlugin::pbs_get_password($scfg, $opts->{storage});
    my ($keyfile, $master_keyfile) = $self->get_and_check_pbs_encryption_config();

    my $diskcount = scalar(@{$task->{disks}});
    # proxmox-backup-client can only handle raw files and block devs, so only use it (directly) for
    # disk-less VMs
    if (!$diskcount) {
	$self->loginfo("backup contains no disks");

	local $ENV{PBS_PASSWORD} = $password;
	local $ENV{PBS_FINGERPRINT} = $fingerprint if defined($fingerprint);
	my $cmd = [
	    '/usr/bin/proxmox-backup-client',
	    'backup',
	    '--repository', $repo,
	    '--backup-type', 'vm',
	    '--backup-id', "$vmid",
	    '--backup-time', $task->{backup_time},
	];
	if (defined(my $ns = $scfg->{namespace})) {
	    push @$cmd, '--ns', $ns;
	}
	if (defined($keyfile)) {
	    push @$cmd, '--keyfile', $keyfile;
	    push @$cmd, '--master-pubkey-file', $master_keyfile if defined($master_keyfile);
	}

	push @$cmd, "qemu-server.conf:$conffile";
	push @$cmd, "fw.conf:$firewall" if -e $firewall;

	$self->loginfo("starting template backup");
	$self->loginfo(join(' ', @$cmd));

	$self->cmd($cmd);

	return;
    }

    # get list early so we die on unknown drive types before doing anything
    my $devlist = _get_task_devlist($task);

    $self->enforce_vm_running_for_backup($vmid);
    $self->{qmeventd_fh} = PVE::QemuServer::register_qmeventd_handle($vmid);

    my $backup_job_uuid;
    eval {
	$SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = $SIG{PIPE} = sub {
	    die "interrupted by signal\n";
	};

	my $qemu_support = eval { mon_cmd($vmid, "query-proxmox-support") };
	my $err = $@;
	if (!$qemu_support || $err) {
	    die "query-proxmox-support returned empty value\n" if !$err;
	    if ($err =~ m/The command query-proxmox-support has not been found/) {
		die "PBS backups are not supported by the running QEMU version. Please make "
		  . "sure you've installed the latest version and the VM has been restarted.\n";
	    } else {
		die "QMP command query-proxmox-support failed - $err\n";
	    }
	}

	# pve-qemu supports it since 5.2.0-1 (PVE 6.4), so safe to die since PVE 8
	die "master key configured but running QEMU version does not support master keys\n"
	    if !defined($qemu_support->{'pbs-masterkey'}) && defined($master_keyfile);

	$attach_tpmstate_drive->($self, $task, $vmid);

	my $is_template = PVE::QemuConfig->is_template($self->{vmlist}->{$vmid});

	$task->{'use-fleecing'} = check_and_prepare_fleecing(
	    $self, $vmid, $opts->{fleecing}, $task->{disks}, $is_template, $qemu_support);

	my $fs_frozen = $self->qga_fs_freeze($task, $vmid);

	my $params = {
	    format => "pbs",
	    'backup-file' => $repo,
	    'backup-id' => "$vmid",
	    'backup-time' => $task->{backup_time},
	    password => $password,
	    devlist => $devlist,
	    'config-file' => $conffile,
	};
	$params->{fleecing} = JSON::true if $task->{'use-fleecing'};

	if (defined(my $ns = $scfg->{namespace})) {
	    $params->{'backup-ns'} = $ns;
	}

	$params->{speed} = $opts->{bwlimit}*1024 if $opts->{bwlimit};
	add_backup_performance_options($params, $opts->{performance}, $qemu_support);

	$params->{fingerprint} = $fingerprint if defined($fingerprint);
	$params->{'firewall-file'} = $firewall if -e $firewall;

	$params->{encrypt} = defined($keyfile) ? JSON::true : JSON::false;
	if (defined($keyfile)) {
	    $params->{keyfile} = $keyfile;
	    $params->{"master-keyfile"} = $master_keyfile if defined($master_keyfile);
	}

	$params->{'use-dirty-bitmap'} = JSON::true
	    if $qemu_support->{'pbs-dirty-bitmap'} && !$is_template;

	$params->{timeout} = 125; # give some time to connect to the backup server

	my $res = eval { mon_cmd($vmid, "backup", %$params) };
	my $qmperr = $@;
	$backup_job_uuid = $res->{UUID} if $res;

	if ($fs_frozen) {
	    $self->qga_fs_thaw($vmid);
	}

	die $qmperr if $qmperr;
	die "got no uuid for backup task\n" if !defined($backup_job_uuid);

	$self->loginfo("started backup task '$backup_job_uuid'");

	$self->resume_vm_after_job_start($task, $vmid);

	my $stat = $query_backup_status_loop->($self, $vmid, $backup_job_uuid, $qemu_support);
	$task->{size} = $stat->{total};
    };
    my $err = $@;
    if ($err) {
	$self->logerr($err);
	$self->mon_backup_cancel($vmid);
	$self->resume_vm_after_job_start($task, $vmid);
    }
    $self->restore_vm_power_state($vmid);

    die $err if $err;
}

my $fork_compressor_pipe = sub {
    my ($self, $comp, $outfileno) = @_;

    my @pipefd = POSIX::pipe();
    my $cpid = fork();
    die "unable to fork worker - $!" if !defined($cpid) || $cpid < 0;
    if ($cpid == 0) {
	eval {
	    POSIX::close($pipefd[1]);
	    # redirect STDIN
	    my $fd = fileno(STDIN);
	    close STDIN;
	    POSIX::close(0) if $fd != 0;
	    die "unable to redirect STDIN - $!"
		if !open(STDIN, "<&", $pipefd[0]);

	    # redirect STDOUT
	    $fd = fileno(STDOUT);
	    close STDOUT;
	    POSIX::close (1) if $fd != 1;

	    die "unable to redirect STDOUT - $!"
		if !open(STDOUT, ">&", $outfileno);

	    exec($comp);
	    die "fork compressor '$comp' failed\n";
	};
	if (my $err = $@) {
	    $self->logerr($err);
	    POSIX::_exit(1);
	}
	POSIX::_exit(0);
	kill(-9, $$);
    } else {
	POSIX::close($pipefd[0]);
	$outfileno = $pipefd[1];
    }

    return ($cpid, $outfileno);
};

sub archive_vma {
    my ($self, $task, $vmid, $filename, $comp) = @_;

    my $conffile = "$task->{tmpdir}/qemu-server.conf";
    my $firewall = "$task->{tmpdir}/qemu-server.fw";

    my $opts = $self->{vzdump}->{opts};

    my $starttime = time();

    my $speed = 0;
    if ($opts->{bwlimit}) {
	$speed = $opts->{bwlimit}*1024;
    }

    my $is_template = PVE::QemuConfig->is_template($self->{vmlist}->{$vmid});

    my $diskcount = scalar(@{$task->{disks}});
    if ($is_template || !$diskcount) {
	my @pathlist;
	foreach my $di (@{$task->{disks}}) {
	    if ($di->{type} eq 'block' || $di->{type} eq 'file') {
		push @pathlist, "$di->{qmdevice}=$di->{path}";
	    } else {
		die "implement me";
	    }
	}

	if (!$diskcount) {
	    $self->loginfo("backup contains no disks");
	}

	my $outcmd;
	if ($comp) {
	    $outcmd = "exec:$comp";
	} else {
	    $outcmd = "exec:cat";
	}

	$outcmd .= " > $filename" if !$opts->{stdout};

	my $cmd = ['/usr/bin/vma', 'create', '-v', '-c', $conffile];
	push @$cmd, '-c', $firewall if -e $firewall;
	push @$cmd, $outcmd, @pathlist;

	$self->loginfo("starting template backup");
	$self->loginfo(join(' ', @$cmd));

	if ($opts->{stdout}) {
	    $self->cmd($cmd, output => ">&" . fileno($opts->{stdout}));
	} else {
	    $self->cmd($cmd);
	}

	return;
    }

    my $devlist = _get_task_devlist($task);

    $self->enforce_vm_running_for_backup($vmid);
    $self->{qmeventd_fh} = PVE::QemuServer::register_qmeventd_handle($vmid);

    my $cpid;
    my $backup_job_uuid;

    eval {
	$SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = $SIG{PIPE} = sub {
	    die "interrupted by signal\n";
	};

	# Currently, failing to determine Proxmox support is not critical here, because it's only
	# used for performance settings like 'max-workers'.
	my $qemu_support = eval { mon_cmd($vmid, "query-proxmox-support") };
	log_warn($@) if $@;

	$attach_tpmstate_drive->($self, $task, $vmid);

	$task->{'use-fleecing'} = check_and_prepare_fleecing(
	    $self, $vmid, $opts->{fleecing}, $task->{disks}, $is_template, $qemu_support);

	my $outfh;
	if ($opts->{stdout}) {
	    $outfh = $opts->{stdout};
	} else {
	    $outfh = IO::File->new($filename, "w") ||
		die "unable to open file '$filename' - $!\n";
	}
	my $outfileno = fileno($outfh);

	if ($comp) {
	    ($cpid, $outfileno) = $fork_compressor_pipe->($self, $comp, $outfileno);
	}

	my $qmpclient = PVE::QMPClient->new();
	my $backup_cb = sub {
	    my ($vmid, $resp) = @_;
	    $backup_job_uuid = $resp->{return}->{UUID};
	};
	my $add_fd_cb = sub {
	    my ($vmid, $resp) = @_;

	    my $params = {
		'backup-file' => "/dev/fdname/backup",
		speed => $speed,
		'config-file' => $conffile,
		devlist => $devlist
	    };
	    $params->{'firewall-file'} = $firewall if -e $firewall;
	    $params->{fleecing} = JSON::true if $task->{'use-fleecing'};
	    add_backup_performance_options($params, $opts->{performance}, $qemu_support);

	    $qmpclient->queue_cmd($vmid, $backup_cb, 'backup', %$params);
	};

	$qmpclient->queue_cmd($vmid, $add_fd_cb, 'getfd', fd => $outfileno, fdname => "backup");

	my $fs_frozen = $self->qga_fs_freeze($task, $vmid);

	eval { $qmpclient->queue_execute(30) };
	my $qmperr = $@;

	if ($fs_frozen) {
	    $self->qga_fs_thaw($vmid);
	}

	die $qmperr if $qmperr;
	die $qmpclient->{errors}->{$vmid} if $qmpclient->{errors}->{$vmid};

	if ($cpid) {
	    POSIX::close($outfileno) == 0 ||
		die "close output file handle failed\n";
	}

	die "got no uuid for backup task\n" if !defined($backup_job_uuid);

	$self->loginfo("started backup task '$backup_job_uuid'");

	$self->resume_vm_after_job_start($task, $vmid);

	$query_backup_status_loop->($self, $vmid, $backup_job_uuid);
    };
    my $err = $@;
    if ($err) {
	$self->logerr($err);
	$self->mon_backup_cancel($vmid);
	$self->resume_vm_after_job_start($task, $vmid);
    }

    $self->restore_vm_power_state($vmid);

    if ($err) {
	if ($cpid) {
	    kill(9, $cpid);
	    waitpid($cpid, 0);
	}
	die $err;
    }

    if ($cpid && (waitpid($cpid, 0) > 0)) {
	my $stat = $?;
	my $ec = $stat >> 8;
	my $signal = $stat & 127;
	if ($ec || $signal) {
	    die "$comp failed - wrong exit status $ec" .
		($signal ? " (signal $signal)\n" : "\n");
	}
    }
}

sub _get_task_devlist {
    my ($task) = @_;

    my $devlist = '';
    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block' || $di->{type} eq 'file') {
	    $devlist .= ',' if $devlist;
	    $devlist .= $di->{qmdevice};
	} else {
	    die "implement me (type '$di->{type}')";
	}
    }
    return $devlist;
}

sub qga_fs_freeze {
    my ($self, $task, $vmid) = @_;
    return if !$self->{vmlist}->{$vmid}->{agent} || $task->{mode} eq 'stop' || !$self->{vm_was_running} || $self->{vm_was_paused};

    if (!PVE::QemuServer::qga_check_running($vmid, 1)) {
	$self->loginfo("skipping guest-agent 'fs-freeze', agent configured but not running?");
	return;
    }

    my $freeze = PVE::QemuServer::get_qga_key($self->{vmlist}->{$vmid}, 'freeze-fs-on-backup') // 1;
    if (!$freeze) {
	$self->loginfo("skipping guest-agent 'fs-freeze', disabled in VM options");
	return;
    }

    $self->loginfo("issuing guest-agent 'fs-freeze' command");
    eval { mon_cmd($vmid, "guest-fsfreeze-freeze") };
    $self->logerr($@) if $@;

    return 1; # even on mon command error, ensure we always thaw again
}

# only call if fs_freeze return 1
sub qga_fs_thaw {
    my ($self, $vmid) = @_;

    $self->loginfo("issuing guest-agent 'fs-thaw' command");
    eval { mon_cmd($vmid, "guest-fsfreeze-thaw") };
    $self->logerr($@) if $@;
}

# we need a running QEMU/KVM process for backup, starts a paused (prelaunch)
# one if VM isn't already running
sub enforce_vm_running_for_backup {
    my ($self, $vmid) = @_;

    if (PVE::QemuServer::check_running($vmid)) {
	$self->{vm_was_running} = 1;
	return;
    }

    eval {
	$self->loginfo("starting kvm to execute backup task");
	# start with skiplock
	my $params = {
	    skiplock => 1,
	    skiptemplate => 1,
	    paused => 1,
	};
	PVE::QemuServer::vm_start($self->{storecfg}, $vmid, $params);
    };
    die $@ if $@;
}

# resume VM again once in a clear state (stop mode backup of running VM)
sub resume_vm_after_job_start {
    my ($self, $task, $vmid) = @_;

    return if !$self->{vm_was_running} || $self->{vm_was_paused};

    if (my $stoptime = $task->{vmstoptime}) {
	my $delay = time() - $task->{vmstoptime};
	$task->{vmstoptime} = undef; # avoid printing 'online after ..' twice
	$self->loginfo("resuming VM again after $delay seconds");
    } else {
	$self->loginfo("resuming VM again");
    }
    mon_cmd($vmid, 'cont', timeout => 45);
}

# stop again if VM was not running before
sub restore_vm_power_state {
    my ($self, $vmid) = @_;

    # we always let VMs keep running
    return if $self->{vm_was_running};

    eval {
	my $resp = mon_cmd($vmid, 'query-status');
	my $status = $resp && $resp->{status} ?  $resp->{status} : 'unknown';
	if ($status eq 'prelaunch') {
	    $self->loginfo("stopping kvm after backup task");
	    PVE::QemuServer::vm_stop($self->{storecfg}, $vmid, 1);
	} else {
	    $self->loginfo("kvm status changed after backup ('$status') - keep VM running");
	}
    };
    warn $@ if $@;
}

sub mon_backup_cancel {
    my ($self, $vmid) = @_;

    $self->loginfo("aborting backup job");
    eval { mon_cmd($vmid, 'backup-cancel') };
    $self->logerr($@) if $@;
}

sub snapshot {
    my ($self, $task, $vmid) = @_;

    # nothing to do
}

sub cleanup {
    my ($self, $task, $vmid) = @_;

    # If VM was started only for backup, it is already stopped now.
    if (PVE::QemuServer::Helpers::vm_running_locally($vmid)) {
	$detach_tpmstate_drive->($task, $vmid);
	detach_fleecing_images($task->{disks}, $vmid) if $task->{'use-fleecing'};
    }

    cleanup_fleecing_images($self, $task->{disks}) if $task->{'use-fleecing'};

    if ($self->{qmeventd_fh}) {
	close($self->{qmeventd_fh});
    }
}

1;
