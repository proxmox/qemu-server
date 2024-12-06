package PVE::QemuServer::ImportDisk;

use strict;
use warnings;

use PVE::Storage;
use PVE::QemuServer;
use PVE::Tools qw(run_command extract_param);

# imports an external disk image to an existing VM
# and creates by default a drive entry unused[n] pointing to the created volume
# $params->{drive_name} may be used to specify ide0, scsi1, etc ...
# $params->{format} may be used to specify qcow2, raw, etc ...
# $params->{skiplock} may be used to skip checking for a lock in the VM config
# $params->{'skip-config-update'} may be used to import the disk without updating the VM config
sub do_import {
    my ($src_path, $src_size, $vmid, $storage_id, $params) = @_;

    my $drive_name = extract_param($params, 'drive_name');
    my $format = extract_param($params, 'format');
    if ($drive_name && !(PVE::QemuServer::is_valid_drivename($drive_name))) {
	die "invalid drive name: $drive_name\n";
    }

    # get target format, target image's path, and whether it's possible to sparseinit
    my $storecfg = PVE::Storage::config();
    my $dst_format = PVE::QemuServer::resolve_dst_disk_format($storecfg, $storage_id, undef, $format);
    warn "format '$format' is not supported by the target storage - using '$dst_format' instead\n"
	if $format && $format ne $dst_format;

    my $dst_volid = PVE::Storage::vdisk_alloc($storecfg, $storage_id, $vmid, $dst_format, undef, $src_size / 1024);

    my $zeroinit = PVE::Storage::volume_has_feature($storecfg, 'sparseinit', $dst_volid);

    my $create_drive = sub {
	my $vm_conf = PVE::QemuConfig->load_config($vmid);
	if (!$params->{skiplock}) {
	    PVE::QemuConfig->check_lock($vm_conf);
	}

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
		warn "hotplugging imported disk '$_' failed: $errors->{$_}\n" for keys %$errors;
	    } else {
		PVE::QemuServer::vmconfig_apply_pending($vmid, $vm_conf, $storecfg);
	    }
	} else {
	    $drive_name = PVE::QemuConfig->add_unused_volume($vm_conf, $dst_volid);
	    PVE::QemuConfig->write_config($vmid, $vm_conf);
	}
    };

    eval {
	# trap interrupts so we have a chance to clean up
	local $SIG{INT} =
	    local $SIG{TERM} =
	    local $SIG{QUIT} =
	    local $SIG{HUP} =
	    local $SIG{PIPE} = sub { die "interrupted by signal $!\n"; };

	PVE::Storage::activate_volumes($storecfg, [$dst_volid]);
	PVE::QemuServer::qemu_img_convert($src_path, $dst_volid, $src_size, undef, $zeroinit);
	PVE::Storage::deactivate_volumes($storecfg, [$dst_volid]);
	PVE::QemuConfig->lock_config($vmid, $create_drive) if !$params->{'skip-config-update'};
    };
    if (my $err = $@) {
	eval { PVE::Storage::vdisk_free($storecfg, $dst_volid) };
	warn "cleanup of $dst_volid failed: $@\n" if $@;
	die $err;
    }

    return ($drive_name, $dst_volid);
}

1;
