package PVE::VZDump::QemuServer;

use strict;
use warnings;
use File::Path;
use File::Basename;
use PVE::INotify;
use PVE::VZDump;
use PVE::Cluster qw(cfs_read_file);
use PVE::Tools;
use PVE::Storage::Plugin;
use PVE::Storage;
use PVE::QemuServer;
use IO::File;

use base qw (PVE::VZDump::Plugin);

sub new {
    my ($class, $vzdump) = @_;
    
    PVE::VZDump::check_bin('qm');

    my $self = bless { vzdump => $vzdump };

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

    my $conf = $self->{vmlist}->{$vmid} = PVE::QemuServer::load_config($vmid);

    if (scalar(keys %{$conf->{snapshots}})) {
	die "VM contains snapshots - unable to backup\n";
    }

    $task->{hostname} = $conf->{name};

    my $lvmmap = PVE::VZDump::get_lvm_mapping();

    my $hostname = PVE::INotify::nodename(); 

    my $ind = {};
    my $mountinfo = {};
    my $mountind = 0;

    my $snapshot_count = 0;

    my $vollist = [];
    my $drivehash = {};
    PVE::QemuServer::foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	return if PVE::QemuServer::drive_is_cdrom($drive);

	if (defined($drive->{backup}) && $drive->{backup} eq "no") {
	    $self->loginfo("exclude disk '$ds' (backup=no)");
	    return;
	}	   

	my $volid = $drive->{file};

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	push @$vollist, $volid if $storeid;
	$drivehash->{$ds} = $drive;
    });

    PVE::Storage::activate_volumes($self->{storecfg}, $vollist);

    while (my ($ds, $drive) = each %$drivehash) {
 
	my $volid = $drive->{file};

	my $path;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	if ($storeid) {
	    $path = PVE::Storage::path($self->{storecfg}, $volid);
	} else {
	    $path = $volid;
	}

	next if !$path;

	die "no such volume '$volid'\n" if ! -e $path;

	my $diskinfo = { path => $path , volid => $volid, storeid => $storeid, 
			 snappath => $path, virtdev => $ds };

	if (-b $path) {

	    $diskinfo->{type} = 'block';

	    $diskinfo->{filename} = "vm-disk-$ds.raw";

	    if ($mode eq 'snapshot') {
		my ($lvmvg, $lvmlv) = @{$lvmmap->{$path}} if defined ($lvmmap->{$path});
		die ("mode failure - unable to detect lvm volume group\n") if !$lvmvg;

		$ind->{$lvmvg} = 0 if !defined $ind->{$lvmvg};
		$diskinfo->{snapname} = "vzsnap-$hostname-$ind->{$lvmvg}";
		$diskinfo->{snapdev} = "/dev/$lvmvg/$diskinfo->{snapname}";
		$diskinfo->{lvmvg} = $lvmvg;
		$diskinfo->{lvmlv} = $lvmlv;
		$diskinfo->{snappath} = $diskinfo->{snapdev};
		$ind->{$lvmvg}++;

		$snapshot_count++;
	    }

	} else {

	    $diskinfo->{type} = 'file';

	    my (undef, $dir, $ext) = fileparse ($path, qr/\.[^.]*/);

	    $diskinfo->{filename} = "vm-disk-$ds$ext";

	    if ($mode eq 'snapshot') {
	    
		my ($srcdev, $lvmpath, $lvmvg, $lvmlv, $fstype) =
		    PVE::VZDump::get_lvm_device ($dir, $lvmmap);

		my $targetdev = PVE::VZDump::get_lvm_device($task->{dumpdir}, $lvmmap);

		die ("mode failure - unable to detect lvm volume group\n") if !$lvmvg;
		die ("mode failure - wrong lvm mount point '$lvmpath'\n") if $dir !~ m|/?$lvmpath/?|;
		die ("mode failure - unable to dump into snapshot (use option --dumpdir)\n") 
		    if $targetdev eq $srcdev;
		
		$ind->{$lvmvg} = 0 if !defined $ind->{$lvmvg};
		    
		my $info = $mountinfo->{$lvmpath};
		if (!$info) {
		    my $snapname = "vzsnap-$hostname-$ind->{$lvmvg}";
		    my $snapdev = "/dev/$lvmvg/$snapname";
		    $mountinfo->{$lvmpath} = $info = {
			snapdev => $snapdev,
			snapname => $snapname,
			mountpoint => "/mnt/vzsnap$mountind",
		    };
		    $ind->{$lvmvg}++;
		    $mountind++;

		    $snapshot_count++;
		} 

		$diskinfo->{snapdev} = $info->{snapdev};
		$diskinfo->{snapname} = $info->{snapname};
		$diskinfo->{mountpoint} = $info->{mountpoint};
		
		$diskinfo->{lvmvg} = $lvmvg;
		$diskinfo->{lvmlv} = $lvmlv;
		
		$diskinfo->{fstype}  = $fstype;
		$diskinfo->{lvmpath} = $lvmpath;

		$diskinfo->{snappath} = $path;
		$diskinfo->{snappath} =~ s|/?$lvmpath/?|$diskinfo->{mountpoint}/|;
	    }
	}

	push @{$task->{disks}}, $diskinfo;
    }

    $task->{snapshot_count} = $snapshot_count;
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

sub snapshot_alloc {
    my ($self, $storeid, $name, $size, $srcdev) = @_;

    my $cmd = "lvcreate --size ${size}M --snapshot --name '$name' '$srcdev'";

    if ($storeid) {

	my $scfg = PVE::Storage::storage_config($self->{storecfg}, $storeid);

	# lock shared storage
	return PVE::Storage::Plugin->cluster_lock_storage($storeid, $scfg->{shared}, undef, sub {
		$self->cmd ($cmd);
	});
    } else {
	$self->cmd ($cmd);
    }
}

sub snapshot_free {
    my ($self, $storeid, $name, $snapdev, $noerr) = @_;

    my $cmd = ['lvremove', '-f', $snapdev];

    # loop, because we often get 'LV in use: not deactivating'
    # we use run_command() because we do not want to log errors here
    my $wait = 1;
    while(-b $snapdev) {
	eval {
	    if ($storeid) {
		my $scfg = PVE::Storage::storage_config($self->{storecfg}, $storeid);
		# lock shared storage
		return PVE::Storage::Plugin->cluster_lock_storage($storeid, $scfg->{shared}, undef, sub {
		    PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => sub {});
		});
	    } else {
		PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => sub {});
	    }
	};
	my $err = $@;
	last if !$err;
	if ($wait >= 64) {
	    $self->logerr($err);
	    die $@ if !$noerr;
	    last;
	}
	$self->loginfo("lvremove failed - trying again in $wait seconds") if $wait >= 8;
	sleep($wait);
	$wait = $wait*2;
    }
}

sub snapshot {
    my ($self, $task, $vmid) = @_;

    my $opts = $self->{vzdump}->{opts};

    my $mounts = {};

    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block') {

	    if (-b $di->{snapdev}) {
		$self->loginfo ("trying to remove stale snapshot '$di->{snapdev}'");
		$self->snapshot_free ($di->{storeid}, $di->{snapname}, $di->{snapdev}, 1); 
	    }

	    $di->{cleanup_lvm} = 1;
	    $self->snapshot_alloc ($di->{storeid}, $di->{snapname}, $opts->{size},
				   "/dev/$di->{lvmvg}/$di->{lvmlv}"); 

	} elsif ($di->{type} eq 'file') {

	    next if defined ($mounts->{$di->{mountpoint}}); # already mounted

	    if (-b $di->{snapdev}) {
		$self->loginfo ("trying to remove stale snapshot '$di->{snapdev}'");	    
	    
		$self->cmd_noerr ("umount $di->{mountpoint}");
		$self->snapshot_free ($di->{storeid}, $di->{snapname}, $di->{snapdev}, 1); 
	    }

	    mkpath $di->{mountpoint}; # create mount point for lvm snapshot

	    $di->{cleanup_lvm} = 1;

	    $self->snapshot_alloc ($di->{storeid}, $di->{snapname}, $opts->{size},
				   "/dev/$di->{lvmvg}/$di->{lvmlv}"); 
	    
	    my $mopts = $di->{fstype} eq 'xfs' ? "-o nouuid" : '';

	    $di->{snapshot_mount} = 1;

	    $self->cmd ("mount -n -t $di->{fstype} $mopts $di->{snapdev} $di->{mountpoint}");

	    $mounts->{$di->{mountpoint}} = 1;

	} else {
	    die "implement me";
	}
    }
}

sub get_size {
    my $path = shift;

    if (-f $path) {
	return -s $path;
    } elsif (-b $path) {
	my $fh = IO::File->new ($path, "r");
	die "unable to open '$path' to detect device size\n" if !$fh;
	my $size = sysseek $fh, 0, 2;
	$fh->close();
	die "unable to detect device size for '$path'\n" if !$size;
	return $size;
    }
}

sub assemble {
    my ($self, $task, $vmid) = @_;

    my $conffile = PVE::QemuServer::config_file ($vmid);

    my $outfile = "$task->{tmpdir}/qemu-server.conf";

    my $outfd;
    my $conffd;

    eval {

	$outfd = IO::File->new (">$outfile") ||
	    die "unable to open '$outfile'";
	$conffd = IO::File->new ($conffile, 'r') ||
	    die "unable open '$conffile'";

	while (defined (my $line = <$conffd>)) {
	    next if $line =~ m/^\#vzdump\#/; # just to be sure
	    print $outfd $line;
	}

	foreach my $di (@{$task->{disks}}) {
	    if ($di->{type} eq 'block' || $di->{type} eq 'file') {
		my $size = get_size ($di->{snappath});
		my $storeid = $di->{storeid} || '';
		print $outfd "#vzdump#map:$di->{virtdev}:$di->{filename}:$size:$storeid:\n";
	    } else {
		die "internal error";
	    }
	}
    };
    my $err = $@;

    close ($outfd) if $outfd;
    close ($conffd) if $conffd;
    
    die $err if $err;
}

sub archive {
    my ($self, $task, $vmid, $filename, $comp) = @_;

    my $conffile = "$task->{tmpdir}/qemu-server.conf";

    my $opts = $self->{vzdump}->{opts};

    my $starttime = time ();

    my $fh;

    my @filea = ($conffile, 'qemu-server.conf'); # always first file in tar
    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block' || $di->{type} eq 'file') {
	    push @filea, $di->{snappath}, $di->{filename};
	} else {
	    die "implement me";
	}
    }

    my $files = join (' ', map { "'$_'" } @filea);
    
    # no sparse file scan when we use compression
    my $sparse = $comp ? '' : '-s'; 

    my $cmd = "/usr/lib/qemu-server/vmtar $sparse $files";
    my $bwl = $opts->{bwlimit}*1024; # bandwidth limit for cstream
    $cmd .= "|cstream -t $bwl" if $opts->{bwlimit};
    $cmd .= "|$comp" if $comp;

    if ($opts->{stdout}) {
	$self->cmd ($cmd, output => ">&=" . fileno($opts->{stdout}));
    } else {
	$self->cmd ("$cmd >$filename");
    }
}

sub cleanup {
    my ($self, $task, $vmid) = @_;

   foreach my $di (@{$task->{disks}}) {
       
       if ($di->{snapshot_mount}) {
	   $self->cmd_noerr ("umount $di->{mountpoint}");
       }

       if ($di->{cleanup_lvm}) {
	   if (-b $di->{snapdev}) {
	       if ($di->{type} eq 'block') {
		   $self->snapshot_free ($di->{storeid}, $di->{snapname}, $di->{snapdev}, 1);
	       } elsif ($di->{type} eq 'file') {
		   $self->snapshot_free ($di->{storeid}, $di->{snapname}, $di->{snapdev}, 1);
	       }
	   }
       }
   }
}

1;
