package PVE::VZDump::QemuServer;

#    Copyright (C) 2007-2009 Proxmox Server Solutions GmbH
#
#    Copyright: vzdump is under GNU GPL, the GNU General Public License.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; version 2 dated June, 1991.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the
#    Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
#    MA 02110-1301, USA.
#
#    Author: Dietmar Maurer <dietmar@proxmox.com>

use strict;
use warnings;
use File::Path;
use File::Basename;
use PVE::VZDump;
use PVE::Cluster;
use PVE::Storage;
use PVE::QemuServer;
use Sys::Hostname;
use IO::File;

use base qw (PVE::VZDump::Plugin);

sub new {
    my ($class, $vzdump) = @_;
    
    PVE::VZDump::check_bin ('qm');

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

    my $conf = $self->{vmlist}->{$vmid} = PVE::QemuServer::load_config ($vmid);

    $task->{hostname} = $conf->{name};

    my $lvmmap = PVE::VZDump::get_lvm_mapping();

    my $hostname = hostname(); 

    my $ind = {};
    my $mountinfo = {};
    my $mountind = 0;

    my $snapshot_count = 0;

    PVE::QemuServer::foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	return if PVE::QemuServer::drive_is_cdrom ($drive);

	if (defined($drive->{backup}) && $drive->{backup} eq "no") {
	    $self->loginfo("exclude disk '$ds' (backup=no)");
	    return;
	}	   
 
	my $volid = $drive->{file};

	my $path;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id ($volid, 1);
	if ($storeid) {
	    PVE::Storage::activate_storage ($self->{storecfg}, $storeid);
	    $path = PVE::Storage::path ($self->{storecfg}, $volid);
	} else {
	    $path = $volid;
	}

	return if !$path;

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

		my $targetdev = PVE::VZDump::get_lvm_device ($task->{dumpdir}, $lvmmap);

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

    });

    $task->{snapshot_count} = $snapshot_count;
}

sub vm_status {
    my ($self, $vmid) = @_;

    my $status_text = $self->cmd ("qm status $vmid");
    chomp $status_text;

    my $running = $status_text =~ m/running/ ? 1 : 0;
   
    return wantarray ? ($running, $status_text) : $running; 
}

sub lock_vm {
    my ($self, $vmid) = @_;

    $self->cmd ("qm set $vmid --lock backup");
}

sub unlock_vm {
    my ($self, $vmid) = @_;

    $self->cmd ("qm --skiplock set $vmid --lock ''");
}

sub stop_vm {
    my ($self, $task, $vmid) = @_;

    my $opts = $self->{vzdump}->{opts};

    my $wait = $opts->{stopwait} * 60;
    # send shutdown and wait
    $self->cmd ("qm --skiplock shutdown $vmid && qm wait $vmid $wait");
}

sub start_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("qm --skiplock start $vmid");
}

sub suspend_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("qm --skiplock suspend $vmid");
}

sub resume_vm {
    my ($self, $task, $vmid) = @_;

    $self->cmd ("qm --skiplock resume $vmid");
}

sub snapshot_alloc {
    my ($self, $volid, $name, $size, $srcdev) = @_;

    my $cmd = "lvcreate --size ${size}M --snapshot --name '$name' '$srcdev'";

    my ($storeid, $volname) = PVE::Storage::parse_volume_id ($volid, 1);
    if ($storeid) {

	my $scfg = PVE::Storage::storage_config ($self->{storecfg}, $storeid);

	# lock shared storage
	return PVE::Storage::cluster_lock_storage ($storeid, $scfg->{shared}, undef, sub {

	    if ($scfg->{type} eq 'lvm') {
		my $vg = $scfg->{vgname};

		$self->cmd ($cmd);

	    } else {
		die "can't allocate snapshot on storage type '$scfg->{type}'\n";
	    }
	});
    } else {
	$self->cmd ($cmd);
    }
}

sub snapshot_free {
    my ($self, $volid, $name, $snapdev, $noerr) = @_;

    my $cmd = "lvremove -f '$snapdev'";

    eval {
	my ($storeid, $volname) = PVE::Storage::parse_volume_id ($volid, 1);
	if ($storeid) {

	    my $scfg = PVE::Storage::storage_config ($self->{storecfg}, $storeid);

	    # lock shared storage
	    return PVE::Storage::cluster_lock_storage ($storeid, $scfg->{shared}, undef, sub {

		if ($scfg->{type} eq 'lvm') {
		    my $vg = $scfg->{vgname};

		    $self->cmd ($cmd);

		} else {
		    die "can't allocate snapshot on storage type '$scfg->{type}'\n";
		}
	    });
	} else {
	    $self->cmd ($cmd);
	}
    };
    die $@ if !$noerr;
    $self->logerr ($@) if $@;
}

sub snapshot {
    my ($self, $task, $vmid) = @_;

    my $opts = $self->{vzdump}->{opts};

    my $mounts = {};

    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block') {

	    if (-b $di->{snapdev}) {
		$self->loginfo ("trying to remove stale snapshot '$di->{snapdev}'");
		$self->snapshot_free ($di->{volid}, $di->{snapname}, $di->{snapdev}, 1); 
	    }

	    $di->{cleanup_lvm} = 1;
	    $self->snapshot_alloc ($di->{volid}, $di->{snapname}, $opts->{size},
				   "/dev/$di->{lvmvg}/$di->{lvmlv}"); 

	} elsif ($di->{type} eq 'file') {

	    next if defined ($mounts->{$di->{mountpoint}}); # already mounted

	    # note: files are never on shared storage, so we use $di->{path} instead
	    # of $di->{volid} (avoid PVE:Storage calls because path start with /)

	    if (-b $di->{snapdev}) {
		$self->loginfo ("trying to remove stale snapshot '$di->{snapdev}'");	    
	    
		$self->cmd_noerr ("umount $di->{mountpoint}");

		$self->snapshot_free ($di->{path}, $di->{snapname}, $di->{snapdev}, 1); 
	    }

	    mkpath $di->{mountpoint}; # create mount point for lvm snapshot

	    $di->{cleanup_lvm} = 1;

	    $self->snapshot_alloc ($di->{path}, $di->{snapname}, $opts->{size},
				   "/dev/$di->{lvmvg}/$di->{lvmlv}"); 
	    
	    my $mopts = $di->{fstype} eq 'xfs' ? "-o nouuid" : '';

	    $di->{snapshot_mount} = 1;

	    $self->cmd ("mount -t $di->{fstype} $mopts $di->{snapdev} $di->{mountpoint}");

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
    my ($self, $task, $vmid, $filename) = @_;

    my $conffile = "$task->{tmpdir}/qemu-server.conf";

    my $opts = $self->{vzdump}->{opts};

    my $starttime = time ();

    my $fh;

    my $bwl = $opts->{bwlimit}*1024; # bandwidth limit for cstream

    my @filea = ($conffile, 'qemu-server.conf'); # always first file in tar
    foreach my $di (@{$task->{disks}}) {
	if ($di->{type} eq 'block' || $di->{type} eq 'file') {
	    push @filea, $di->{snappath}, $di->{filename};
	} else {
	    die "implement me";
	}
    }

    my $out = ">$filename";
    $out = "|cstream -t $bwl $out" if $opts->{bwlimit};
    $out = "|gzip $out" if $opts->{compress};

    my $files = join (' ', map { "'$_'" } @filea);
    
    $self->cmd("/usr/lib/qemu-server/vmtar $files $out");
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
		   $self->snapshot_free ($di->{volid}, $di->{snapname}, $di->{snapdev}, 1);
	       } elsif ($di->{type} eq 'file') {
		   $self->snapshot_free ($di->{path}, $di->{snapname}, $di->{snapdev}, 1);
	       }
	   }
       }
   }

}

1;
