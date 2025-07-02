package PVE::QemuServer::Blockdev;

use strict;
use warnings;

use Digest::SHA;
use Fcntl qw(S_ISBLK S_ISCHR);
use File::stat;

use PVE::JSONSchema qw(json_bool);
use PVE::Storage;

use PVE::QemuServer::Drive qw(drive_is_cdrom);

my sub get_node_name {
    my ($type, $drive_id, $volid, $snap) = @_;

    my $info = "drive=$drive_id,";
    $info .= "snap=$snap," if defined($snap);
    $info .= "volid=$volid";

    my $hash = substr(Digest::SHA::sha256_hex($info), 0, 30);

    my $prefix = "";
    if ($type eq 'fmt') {
        $prefix = 'f';
    } elsif ($type eq 'file') {
        $prefix = 'e';
    } else {
        die "unknown node type '$type'";
    }
    # node-name must start with an alphabetical character
    return "${prefix}${hash}";
}

sub parse_top_node_name {
    my ($node_name) = @_;

    if ($node_name =~ m/^drive-(.+)$/) {
        my $drive_id = $1;
        return $drive_id if PVE::QemuServer::Drive::is_valid_drivename($drive_id);
    }

    return;
}

sub top_node_name {
    my ($drive_id) = @_;

    return "drive-$drive_id";
}

my sub read_only_json_option {
    my ($drive, $options) = @_;

    return json_bool($drive->{ro} || drive_is_cdrom($drive) || $options->{'read-only'});
}

my sub throttle_group_id {
    my ($drive_id) = @_;

    return "throttle-drive-$drive_id";
}

sub generate_throttle_group {
    my ($drive) = @_;

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    my $limits = {};

    for my $type (['', '-total'], [_rd => '-read'], [_wr => '-write']) {
        my ($dir, $qmpname) = @$type;
        if (my $v = $drive->{"mbps$dir"}) {
            $limits->{"bps$qmpname"} = int($v * 1024 * 1024);
        }
        if (my $v = $drive->{"mbps${dir}_max"}) {
            $limits->{"bps$qmpname-max"} = int($v * 1024 * 1024);
        }
        if (my $v = $drive->{"bps${dir}_max_length"}) {
            $limits->{"bps$qmpname-max-length"} = int($v);
        }
        if (my $v = $drive->{"iops${dir}"}) {
            $limits->{"iops$qmpname"} = int($v);
        }
        if (my $v = $drive->{"iops${dir}_max"}) {
            $limits->{"iops$qmpname-max"} = int($v);
        }
        if (my $v = $drive->{"iops${dir}_max_length"}) {
            $limits->{"iops$qmpname-max-length"} = int($v);
        }
    }

    return {
        id => throttle_group_id($drive_id),
        limits => $limits,
        'qom-type' => 'throttle-group',
    };
}

sub generate_blockdev_drive_cache {
    my ($drive, $scfg) = @_;

    my $cache_direct = PVE::QemuServer::Drive::drive_uses_cache_direct($drive, $scfg);
    return {
        direct => json_bool($cache_direct),
        'no-flush' => json_bool($drive->{cache} && $drive->{cache} eq 'unsafe'),
    };
}

sub generate_file_blockdev {
    my ($storecfg, $drive, $options) = @_;

    my $blockdev = {};
    my $scfg = undef;

    die "generate_file_blockdev called without volid/path\n" if !$drive->{file};
    die "generate_file_blockdev called with 'none'\n" if $drive->{file} eq 'none';
    # FIXME use overlay and new config option to define storage for temp write device
    die "'snapshot' option is not yet supported for '-blockdev'\n" if $drive->{snapshot};

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    if ($drive->{file} eq 'cdrom') {
        my $path = PVE::QemuServer::Drive::get_iso_path($storecfg, $drive->{file});
        $blockdev = { driver => 'host_cdrom', filename => "$path" };
    } elsif ($drive->{file} =~ m|^/|) {
        my $path = $drive->{file};
        # The 'file' driver only works for regular files. The check below is taken from
        # block/file-posix.c:hdev_probe_device() in QEMU. To detect CD-ROM host devices, QEMU issues
        # an ioctl, while the code here relies on the media=cdrom flag instead.
        my $st = File::stat::stat($path) or die "stat for '$path' failed - $!\n";
        my $driver = 'file';
        if (S_ISCHR($st->mode) || S_ISBLK($st->mode)) {
            $driver = drive_is_cdrom($drive) ? 'host_cdrom' : 'host_device';
        }
        $blockdev = { driver => "$driver", filename => "$path" };
    } else {
        my $volid = $drive->{file};
        my ($storeid) = PVE::Storage::parse_volume_id($volid);

        my $vtype = (PVE::Storage::parse_volname($storecfg, $drive->{file}))[0];
        die "$drive_id: explicit media parameter is required for iso images\n"
            if !defined($drive->{media}) && defined($vtype) && $vtype eq 'iso';

        my $storage_opts = { hints => {} };
        $storage_opts->{hints}->{'efi-disk'} = 1 if $drive->{interface} eq 'efidisk';
        $storage_opts->{'snapshot-name'} = $options->{'snapshot-name'}
            if defined($options->{'snapshot-name'});
        $blockdev = PVE::Storage::qemu_blockdev_options($storecfg, $volid, $storage_opts);
        $scfg = PVE::Storage::storage_config($storecfg, $storeid);
    }

    # SPI flash does lots of read-modify-write OPs, without writeback this gets really slow #3329
    # It also needs the rbd_cache_policy set to 'writeback' on the RBD side, which is done by the
    # storage layer.
    if ($blockdev->{driver} eq 'rbd' && $drive->{interface} eq 'efidisk') {
        $blockdev->{cache} = { direct => JSON::false, 'no-flush' => JSON::false };
    } else {
        $blockdev->{cache} = generate_blockdev_drive_cache($drive, $scfg);
    }

    my $driver = $blockdev->{driver};
    # only certain drivers have the aio setting
    if ($driver eq 'file' || $driver eq 'host_cdrom' || $driver eq 'host_device') {
        $blockdev->{aio} =
            PVE::QemuServer::Drive::aio_cmdline_option($scfg, $drive, $blockdev->{cache}->{direct});
    }

    if (!drive_is_cdrom($drive)) {
        $blockdev->{discard} = $drive->{discard} && $drive->{discard} eq 'on' ? 'unmap' : 'ignore';
        $blockdev->{'detect-zeroes'} = PVE::QemuServer::Drive::detect_zeroes_cmdline_option($drive);
    }

    $blockdev->{'node-name'} =
        get_node_name('file', $drive_id, $drive->{file}, $options->{'snapshot-name'});

    $blockdev->{'read-only'} = read_only_json_option($drive, $options);

    return $blockdev;
}

sub generate_format_blockdev {
    my ($storecfg, $drive, $child, $options) = @_;

    die "generate_format_blockdev called without volid/path\n" if !$drive->{file};
    die "generate_format_blockdev called with 'none'\n" if $drive->{file} eq 'none';

    my $scfg;
    my $format;
    my $volid = $drive->{file};
    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);
    my ($storeid) = PVE::Storage::parse_volume_id($volid, 1);

    # For PVE-managed volumes, use the format from the storage layer and prevent overrides via the
    # drive's 'format' option. For unmanaged volumes, fallback to 'raw' to avoid auto-detection by
    # QEMU.
    if ($storeid) {
        $scfg = PVE::Storage::storage_config($storecfg, $storeid);
        $format = PVE::QemuServer::Drive::checked_volume_format($storecfg, $volid);
        if ($drive->{format} && $drive->{format} ne $format) {
            die "drive '$drive->{interface}$drive->{index}' - volume '$volid'"
                . " - 'format=$drive->{format}' option different from storage format '$format'\n";
        }
    } else {
        $format = $drive->{format} // 'raw';
    }

    my $node_name = get_node_name('fmt', $drive_id, $drive->{file}, $options->{'snapshot-name'});

    my $blockdev = {
        'node-name' => "$node_name",
        driver => "$format",
        file => $child,
        cache => $child->{cache}, # define cache option on both format && file node like libvirt
        'read-only' => read_only_json_option($drive, $options),
    };

    if (defined($options->{size})) {
        die "blockdev: 'size' is only supported for 'raw' format" if $format ne 'raw';
        $blockdev->{size} = int($options->{size});
    }

    return $blockdev;
}

sub generate_drive_blockdev {
    my ($storecfg, $drive, $options) = @_;

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    die "generate_drive_blockdev called without volid/path\n" if !$drive->{file};
    die "generate_drive_blockdev called with 'none'\n" if $drive->{file} eq 'none';

    my $child = generate_file_blockdev($storecfg, $drive, $options);
    $child = generate_format_blockdev($storecfg, $drive, $child, $options);

    # this is the top filter entry point, use $drive-drive_id as nodename
    return {
        driver => "throttle",
        'node-name' => top_node_name($drive_id),
        'throttle-group' => throttle_group_id($drive_id),
        file => $child,
    };
}

1;
