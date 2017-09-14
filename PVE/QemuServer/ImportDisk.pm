package PVE::QemuServer::ImportDisk;

use strict;
use warnings;

use PVE::Storage;
use PVE::QemuServer;
use PVE::Tools qw(run_command extract_param);

# imports an external disk image to an existing VM
# and creates by default a drive entry unused[n] pointing to the created volume
# $optional->{drive_name} may be used to specify ide0, scsi1, etc ...
# $optional->{format} may be used to specify qcow2, raw, etc ...
sub do_import {
    my ($src_path, $vmid, $storage_id, $optional) = @_;

    my $drive_name = extract_param($optional, 'drive_name');
    my $format = extract_param($optional, 'format');
    my $debug = extract_param($optional, 'debug');
    if ($drive_name && !(PVE::QemuServer::is_valid_drivename($drive_name))) {
	die "invalid drive name: $drive_name\n";
    }

    # get the needed size from  source disk
    my $src_size = PVE::Storage::file_size_info($src_path);

    # get target format, target image's path, and whether it's possible to sparseinit
    my $storecfg = PVE::Storage::config();
    my $dst_format = PVE::QemuServer::resolve_dst_disk_format($storecfg,
	$storage_id, undef, $format);
    warn "format : $dst_format\n" if $debug;

    my $dst_volid = PVE::Storage::vdisk_alloc($storecfg, $storage_id, $vmid,
	$dst_format, undef, $src_size / 1024);
    my $dst_path = PVE::Storage::path($storecfg, $dst_volid);

    warn "args:  $src_path, $vmid, $storage_id, $optional\n",
	"\$dst_volid: $dst_volid\n", if $debug;

    # qemu-img convert does the hard job
    # we don't attempt to guess filetypes ourselves
    my $convert_command = ['qemu-img', 'convert', $src_path, '-p', '-n', '-O', $dst_format];
    if (PVE::Storage::volume_has_feature($storecfg, 'sparseinit', $dst_volid)) {
	push @$convert_command, "zeroinit:$dst_path";
    } else {
	push @$convert_command, $dst_path;
    }

    my $create_drive = sub {
	my $vm_conf = PVE::QemuConfig->load_config($vmid);
	PVE::QemuConfig->check_lock($vm_conf);

	if ($drive_name) {
		# should never happen as setting $drive_name is not exposed to public interface
		die "cowardly refusing to overwrite existing entry: $drive_name\n" if $vm_conf->{$drive_name};

		my $modified = {}; # record what $option we modify
		$modified->{$drive_name} = 1;
		$vm_conf->{pending}->{$drive_name} = $dst_volid;
		PVE::QemuConfig->write_config($vmid, $vm_conf);

		my $running = PVE::QemuServer::check_running($vmid);
		if ($running) {
		    my $errors = {};
		    PVE::QemuServer::vmconfig_hotplug_pending($vmid, $vm_conf, $storecfg, $modified, $errors);
		    if (scalar(keys %$errors)) {
			foreach my $k (keys %$errors) {
			    warn "$k: $errors->{$k}\n" if $debug;
			    warn "hotplugging imported disk failed\n";
			}
		    }
		} else {
		    PVE::QemuServer::vmconfig_apply_pending($vmid, $vm_conf, $storecfg);
		}

	} else {
	    PVE::QemuConfig->add_unused_volume($vm_conf, $dst_volid);
	    PVE::QemuConfig->write_config($vmid, $vm_conf);
	}

    };

    eval {
	# trap interrupts so we have a chance to clean up
	local $SIG{INT} =
	    local $SIG{TERM} =
	    local $SIG{QUIT} =
	    local $SIG{HUP} =
	    local $SIG{PIPE} = sub { die "interrupted by signal\n"; };
	PVE::Storage::activate_volumes($storecfg, [$dst_volid]);
	run_command($convert_command);
	PVE::Storage::deactivate_volumes($storecfg, [$dst_volid]);
	PVE::QemuConfig->lock_config($vmid, $create_drive);
    };

    my $err = $@;
    if ($err) {
	eval { # do not die before we returned $err
	    PVE::Storage::vdisk_free($storecfg, $dst_volid);
	};
	die $err;
    }
}

1;
