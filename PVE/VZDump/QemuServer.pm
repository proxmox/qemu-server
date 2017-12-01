package PVE::VZDump::QemuServer;

use strict;
use warnings;
use File::Path;
use File::Basename;
use PVE::INotify;
use PVE::VZDump;
use PVE::IPCC;
use PVE::Cluster qw(cfs_read_file);
use PVE::Tools;
use PVE::Storage::Plugin;
use PVE::Storage;
use PVE::QemuServer;
use PVE::JSONSchema;
use IO::File;
use IPC::Open3;

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

    $task->{disks} = [];

    my $conf = $self->{vmlist}->{$vmid} = PVE::QemuConfig->load_config($vmid);

    $self->loginfo("VM Name: $conf->{name}")
	if defined($conf->{name});

    $self->{vm_was_running} = 1;
    if (!PVE::QemuServer::check_running($vmid)) {
	$self->{vm_was_running} = 0;
    }

    $task->{hostname} = $conf->{name};

    my $hostname = PVE::INotify::nodename();

    my $vollist = [];
    my $drivehash = {};
    PVE::QemuServer::foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	return if PVE::QemuServer::drive_is_cdrom($drive);

	my $volid = $drive->{file};

	if (defined($drive->{backup}) && !$drive->{backup}) {
	    $self->loginfo("exclude disk '$ds' '$volid' (backup=no)");
	    return;
	} elsif ($drive->{iothread}) {
	    die "disk '$ds' '$volid' (iothread=on) can't use backup feature currently. Please set backup=no for this drive";
	} else {
	    my $log = "include disk '$ds' '$volid'";
	   if (defined $drive->{size}) {
		my $readable_size = PVE::JSONSchema::format_size($drive->{size});
		$log .= " $readable_size";
	   }
	    $self->loginfo($log);
	}

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	push @$vollist, $volid if $storeid;
	$drivehash->{$ds} = $drive;
    });

    PVE::Storage::activate_volumes($self->{storecfg}, $vollist);

    foreach my $ds (sort keys %$drivehash) {
	my $drive = $drivehash->{$ds};

	my $volid = $drive->{file};

	my $path;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	if ($storeid) {
	    $path = PVE::Storage::path($self->{storecfg}, $volid);
	} else {
	    $path = $volid;
	}

	next if !$path;

	my $format = undef;
	my $size = undef;

	eval{
	    ($size, $format) = PVE::Storage::volume_size_info($self->{storecfg}, $volid, 5);
	};
	die "no such volume '$volid'\n" if $@;

	my $diskinfo = { path => $path , volid => $volid, storeid => $storeid,
			 format => $format, virtdev => $ds, qmdevice => "drive-$ds" };

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

    $self->cmd ("qm set $vmid --lock backup");
}

sub unlock_vm {
    my ($self, $vmid) = @_;

    $self->cmd ("qm unlock $vmid");
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

    $self->cmd ("qm suspend $vmid --skiplock");
}

sub resume_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("qm resume $vmid --skiplock");
}

sub assemble {
    my ($self, $task, $vmid) = @_;

    my $conffile = PVE::QemuConfig->config_file($vmid);

    my $outfile = "$task->{tmpdir}/qemu-server.conf";
    my $firewall_src = "/etc/pve/firewall/$vmid.fw";
    my $firewall_dest = "$task->{tmpdir}/qemu-server.fw";

    my $outfd = IO::File->new (">$outfile") ||
	die "unable to open '$outfile'";
    my $conffd = IO::File->new ($conffile, 'r') ||
	die "unable open '$conffile'";

    my $found_snapshot;
    my $found_pending;
    while (defined (my $line = <$conffd>)) {
	next if $line =~ m/^\#vzdump\#/; # just to be sure
	next if $line =~ m/^\#qmdump\#/; # just to be sure
	if ($line =~ m/^\[(.*)\]\s*$/) {
	    if ($1 =~ m/PENDING/i) {
		$found_pending = 1;
	    } else {
		$found_snapshot = 1;
	    }
	}

	next if $found_snapshot; # skip all snapshots data
	next if $found_pending; # skip all pending changes

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

    my $conffile = "$task->{tmpdir}/qemu-server.conf";
    my $firewall = "$task->{tmpdir}/qemu-server.fw";

    my $opts = $self->{vzdump}->{opts};

    my $starttime = time ();

    my $speed = 0;
    if ($opts->{bwlimit}) {
	$speed = $opts->{bwlimit}*1024;
    }

    my $diskcount = scalar(@{$task->{disks}});

    if (PVE::QemuConfig->is_template($self->{vmlist}->{$vmid}) || !$diskcount) {
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
	    $self->cmd($cmd, output => ">&=" . fileno($opts->{stdout}));
	} else {
	    $self->cmd($cmd);
	}

	return;
    }


    my $devlist = '';
    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block' || $di->{type} eq 'file') {
	    $devlist .= $devlist ? ",$di->{qmdevice}" : $di->{qmdevice};
	} else {
	    die "implement me";
	}
    }

    my $stop_after_backup;
    my $resume_on_backup;

    my $skiplock = 1;
    my $vm_is_running = PVE::QemuServer::check_running($vmid);
    if (!$vm_is_running) {
	eval {
	    $self->loginfo("starting kvm to execute backup task");
	    PVE::QemuServer::vm_start($self->{storecfg}, $vmid, undef,
				      $skiplock, undef, 1);
	    if ($self->{vm_was_running}) {
		$resume_on_backup = 1;
	    } else {
		$stop_after_backup = 1;
	    }
	};
	if (my $err = $@) {
	    die $err;
	}
    }

    my $cpid;
    my $interrupt_msg = "interrupted by signal\n";
    eval {
	$SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = $SIG{PIPE} = sub {
	    die $interrupt_msg;
	};

	my $qmpclient = PVE::QMPClient->new();

	my $uuid;

	my $backup_cb = sub {
	    my ($vmid, $resp) = @_;
	    $uuid = $resp->{return}->{UUID};
	};

	my $outfh;
	if ($opts->{stdout}) {
	    $outfh = $opts->{stdout};
	} else {
	    $outfh = IO::File->new($filename, "w") ||
		die "unable to open file '$filename' - $!\n";
	}

	my $outfileno;
	if ($comp) {
	    my @pipefd = POSIX::pipe();
	    $cpid = fork();
	    die "unable to fork worker - $!" if !defined($cpid);
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
			if !open(STDOUT, ">&", fileno($outfh));

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
	} else {
	    $outfileno = fileno($outfh);
	}

 	my $add_fd_cb = sub {
	    my ($vmid, $resp) = @_;

	    my $params = {
		'backup-file' => "/dev/fdname/backup",
		speed => $speed,
		'config-file' => $conffile,
		devlist => $devlist
	    };
	    
	    $params->{'firewall-file'} = $firewall if -e $firewall;
	    $qmpclient->queue_cmd($vmid, $backup_cb, 'backup', %$params);
	};

	$qmpclient->queue_cmd($vmid, $add_fd_cb, 'getfd',
			      fd => $outfileno, fdname => "backup");

	my $agent_running = 0;

	if ($self->{vmlist}->{$vmid}->{agent} && $vm_is_running) {
	    $agent_running = PVE::QemuServer::qga_check_running($vmid);
	}

	if ($agent_running){
	    eval { PVE::QemuServer::vm_mon_cmd($vmid, "guest-fsfreeze-freeze"); };
	    if (my $err = $@) {
		$self->logerr($err);
	    }
	}

	$qmpclient->queue_execute();

	if ($agent_running){
	    eval { PVE::QemuServer::vm_mon_cmd($vmid, "guest-fsfreeze-thaw"); };
	    if (my $err = $@) {
		$self->logerr($err);
	    }
	}
	die $qmpclient->{errors}->{$vmid} if $qmpclient->{errors}->{$vmid};

	if ($cpid) {
	    POSIX::close($outfileno) == 0 ||
		die "close output file handle failed\n";
	}

	die "got no uuid for backup task\n" if !$uuid;

	$self->loginfo("started backup task '$uuid'");

	if ($resume_on_backup) {
	    $self->loginfo("resume VM");
	    PVE::QemuServer::vm_mon_cmd($vmid, 'cont');
	}

	my $status;
	my $starttime = time ();
	my $last_per = -1;
	my $last_total = 0;
	my $last_zero = 0;
	my $last_transferred = 0;
	my $last_time = time();
	my $transferred;

	while(1) {
	    $status = PVE::QemuServer::vm_mon_cmd($vmid, 'query-backup');
	    my $total = $status->{total} || 0;
	    $transferred = $status->{transferred} || 0;
	    my $per = $total ? int(($transferred * 100)/$total) : 0;
	    my $zero = $status->{'zero-bytes'} || 0;
	    my $zero_per = $total ? int(($zero * 100)/$total) : 0;

	    die "got unexpected uuid\n" if !$status->{uuid} || ($status->{uuid} ne $uuid);

	    my $ctime = time();
	    my $duration = $ctime - $starttime;

	    my $rbytes = $transferred - $last_transferred;
	    my $wbytes = $rbytes - ($zero - $last_zero);

	    my $timediff = ($ctime - $last_time) || 1; # fixme
	    my $mbps_read = ($rbytes > 0) ?
		int(($rbytes/$timediff)/(1000*1000)) : 0;
	    my $mbps_write = ($wbytes > 0) ?
		int(($wbytes/$timediff)/(1000*1000)) : 0;

	    my $statusline = "status: $per% ($transferred/$total), " .
		"sparse ${zero_per}% ($zero), duration $duration, " .
		"read/write $mbps_read/$mbps_write MB/s";
	    my $res = $status->{status} || 'unknown';
	    if ($res ne 'active') {
		$self->loginfo($statusline);
		die(($status->{errmsg} || "unknown error") . "\n")
		    if $res eq 'error';
		die "got unexpected status '$res'\n"
		    if $res ne 'done';
		die "got wrong number of transfered bytes ($total != $transferred)\n"
		    if ($res eq 'done') && ($total != $transferred);

		last;
	    }
	    if ($per != $last_per && ($timediff > 2)) {
		$self->loginfo($statusline);
		$last_per = $per;
		$last_total = $total if $total;
		$last_zero = $zero if $zero;
		$last_transferred = $transferred if $transferred;
		$last_time = $ctime;
	    }
	    sleep(1);
	}

	my $duration = time() - $starttime;
	if ($transferred && $duration) {
	    my $mb = int($transferred/(1000*1000));
	    my $mbps = int(($transferred/$duration)/(1000*1000));
	    $self->loginfo("transferred $mb MB in $duration seconds ($mbps MB/s)");
	}
    };
    my $err = $@;

    if ($err) {
	$self->logerr($err);
	$self->loginfo("aborting backup job");
	eval { PVE::QemuServer::vm_mon_cmd($vmid, 'backup-cancel'); };
	if (my $err1 = $@) {
	    $self->logerr($err1);
	}
    }

    if ($stop_after_backup) {
	# stop if not running
	eval {
	    my $resp = PVE::QemuServer::vm_mon_cmd($vmid, 'query-status');
	    my $status = $resp && $resp->{status} ?  $resp->{status} : 'unknown';
	    if ($status eq 'prelaunch') {
		$self->loginfo("stopping kvm after backup task");
		PVE::QemuServer::vm_stop($self->{storecfg}, $vmid, $skiplock);
	    } else {
		$self->loginfo("kvm status changed after backup ('$status')" .
			       " - keep VM running");
	    }
	}
    }

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

sub snapshot {
    my ($self, $task, $vmid) = @_;

    # nothing to do
}

sub cleanup {
    my ($self, $task, $vmid) = @_;

    # nothing to do ?
}

1;
