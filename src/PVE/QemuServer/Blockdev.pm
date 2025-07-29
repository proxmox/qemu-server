package PVE::QemuServer::Blockdev;

use strict;
use warnings;

use Digest::SHA;
use Fcntl qw(S_ISBLK S_ISCHR);
use File::Basename qw(basename dirname);
use File::stat;
use JSON;

use PVE::JSONSchema qw(json_bool);
use PVE::Storage;

use PVE::QemuServer::BlockJob;
use PVE::QemuServer::Drive qw(drive_is_cdrom);
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Machine;
use PVE::QemuServer::Monitor qw(mon_cmd);

# gives ($host, $port, $export)
my $NBD_TCP_PATH_RE_3 = qr/nbd:(\S+):(\d+):exportname=(\S+)/;
my $NBD_UNIX_PATH_RE_2 = qr/nbd:unix:(\S+):exportname=(\S+)/;

sub is_nbd {
    my ($drive) = @_;

    return 1 if $drive->{file} =~ $NBD_TCP_PATH_RE_3;
    return 1 if $drive->{file} =~ $NBD_UNIX_PATH_RE_2;
    return 0;
}

my sub tpm_backup_node_name {
    my ($type, $drive_id) = @_;

    if ($type eq 'fmt') {
        return "drive-$drive_id-backup"; # this is the top node
    } elsif ($type eq 'file') {
        return "$drive_id-backup-file"; # drop the "drive-" prefix to be sure, max length is 31
    }

    die "unknown node type '$type' for TPM backup node";
}

my sub fleecing_node_name {
    my ($type, $drive_id) = @_;

    if ($type eq 'fmt') {
        return "drive-$drive_id-fleecing"; # this is the top node for fleecing
    } elsif ($type eq 'file') {
        return "$drive_id-fleecing-file"; # drop the "drive-" prefix to be sure, max length is 31
    }

    die "unknown node type '$type' for fleecing";
}

my sub is_fleecing_top_node {
    my ($node_name) = @_;

    return $node_name =~ m/-fleecing$/ ? 1 : 0;
}

sub qdev_id_to_drive_id {
    my ($qdev_id) = @_;

    if ($qdev_id =~ m|^/machine/peripheral/(virtio(\d+))/virtio-backend$|) {
        return $1;
    } elsif ($qdev_id =~ m|^/machine/system\.flash0$|) {
        return 'pflash0';
    } elsif ($qdev_id =~ m|^/machine/system\.flash1$|) {
        return 'efidisk0';
    }

    return $qdev_id; # for SCSI/SATA/IDE it's the same
}

=pod

=head3 get_block_info

    my $block_info = get_block_info($vmid);
    my $inserted = $block_info->{$drive_key}->{inserted};
    my $node_name = $inserted->{'node-name'};
    my $block_node_size = $inserted->{image}->{'virtual-size'};

Returns a hash reference with the information from the C<query-block> QMP command indexed by
configuration drive keys like C<scsi2>. See the QMP documentation for details.

Parameters:

=over

=item C<$vmid>: The ID of the virtual machine to query.

=back

=cut

sub get_block_info {
    my ($vmid) = @_;

    my $block_info = {};

    my $qmp_block_info = mon_cmd($vmid, "query-block");
    for my $info ($qmp_block_info->@*) {
        my $qdev_id = $info->{qdev} or next;
        my $drive_id = qdev_id_to_drive_id($qdev_id);
        $block_info->{$drive_id} = $info;
    }

    return $block_info;
}

my sub get_node_name {
    my ($type, $drive_id, $volid, $options) = @_;

    return fleecing_node_name($type, $drive_id) if $options->{fleecing};
    return tpm_backup_node_name($type, $drive_id) if $options->{'tpm-backup'};

    my $snap = $options->{'snapshot-name'};

    my $info = "drive=$drive_id,";
    $info .= "snap=$snap," if defined($snap);
    $info .= "volid=$volid";

    my $hash = substr(Digest::SHA::sha256_hex($info), 0, 30);

    my $prefix = "";
    if ($type eq 'alloc-track') {
        $prefix = 'a';
    } elsif ($type eq 'file') {
        $prefix = 'e';
    } elsif ($type eq 'fmt') {
        $prefix = 'f';
    } elsif ($type eq 'zeroinit') {
        $prefix = 'z';
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

sub get_node_name_below_throttle {
    my ($vmid, $device_id, $assert_top_is_throttle) = @_;

    my $block_info = get_block_info($vmid);
    my $drive_id = $device_id =~ s/^drive-//r;
    my $inserted = $block_info->{$drive_id}->{inserted}
        or die "no block node inserted for drive '$drive_id'\n";

    if ($inserted->{drv} ne 'throttle') {
        die "$device_id: unexpected top node $inserted->{'node-name'} ($inserted->{drv})\n"
            if $assert_top_is_throttle;
        # before the switch to -blockdev, the top node was not throttle
        return $inserted->{'node-name'};
    }

    my $children = { map { $_->{child} => $_ } $inserted->{children}->@* };

    if (my $node_name = $children->{file}->{'node-name'}) {
        return $node_name;
    }

    die "$device_id: throttle node without file child node name!\n";
}

my sub read_only_json_option {
    my ($drive, $options) = @_;

    return json_bool($drive->{ro} || drive_is_cdrom($drive) || $options->{'read-only'});
}

# Common blockdev options that need to be set across the whole throttle->fmt->file chain.
my sub add_common_options {
    my ($blockdev, $drive, $options) = @_;

    if (!drive_is_cdrom($drive)) {
        $blockdev->{discard} = $drive->{discard} && $drive->{discard} eq 'on' ? 'unmap' : 'ignore';
        $blockdev->{'detect-zeroes'} = PVE::QemuServer::Drive::detect_zeroes_cmdline_option($drive);
    }

    $blockdev->{'read-only'} = read_only_json_option($drive, $options);
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

my sub generate_blockdev_drive_cache {
    my ($drive, $scfg) = @_;

    my $cache_direct = PVE::QemuServer::Drive::drive_uses_cache_direct($drive, $scfg);
    return {
        direct => json_bool($cache_direct),
        'no-flush' => json_bool($drive->{cache} && $drive->{cache} eq 'unsafe'),
    };
}

my sub generate_file_blockdev {
    my ($storecfg, $drive, $machine_version, $options) = @_;

    my $blockdev = {};
    my $scfg = undef;

    delete $options->{'snapshot-name'}
        if $options->{'snapshot-name'} && $options->{'snapshot-name'} eq 'current';

    die "generate_file_blockdev called without volid/path\n" if !$drive->{file};
    die "generate_file_blockdev called with 'none'\n" if $drive->{file} eq 'none';
    # FIXME use overlay and new config option to define storage for temp write device
    die "'snapshot' option is not yet supported for '-blockdev'\n" if $drive->{snapshot};

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    if ($drive->{file} =~ m/^$NBD_UNIX_PATH_RE_2$/) {
        my $server = { type => 'unix', path => "$1" };
        $blockdev = { driver => 'nbd', server => $server, export => "$2" };
    } elsif ($drive->{file} =~ m/^$NBD_TCP_PATH_RE_3$/) {
        my $server = { type => 'inet', host => "$1", port => "$2" }; # port is also a string in QAPI
        $blockdev = { driver => 'nbd', server => $server, export => "$3" };
    } elsif ($drive->{file} eq 'cdrom') {
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
        $blockdev =
            PVE::Storage::qemu_blockdev_options($storecfg, $volid, $machine_version, $storage_opts);
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

    $blockdev->{'node-name'} = get_node_name('file', $drive_id, $drive->{file}, $options);

    add_common_options($blockdev, $drive, $options);

    return $blockdev;
}

my sub generate_format_blockdev {
    my ($storecfg, $drive, $child, $options) = @_;

    die "generate_format_blockdev called without volid/path\n" if !$drive->{file};
    die "generate_format_blockdev called with 'none'\n" if $drive->{file} eq 'none';
    die "generate_format_blockdev called with NBD path\n" if is_nbd($drive);

    delete($options->{'snapshot-name'})
        if $options->{'snapshot-name'} && $options->{'snapshot-name'} eq 'current';

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

    my $node_name = get_node_name('fmt', $drive_id, $drive->{file}, $options);

    my $blockdev = {
        'node-name' => "$node_name",
        driver => "$format",
        file => $child,
        cache => $child->{cache}, # define cache option on both format && file node like libvirt
    };

    add_common_options($blockdev, $drive, $options);

    if (defined($options->{size})) {
        die "blockdev: 'size' is only supported for 'raw' format" if $format ne 'raw';
        $blockdev->{size} = int($options->{size});
    }

    # see bug #6543: without this option, fragmentation can lead to the qcow2 file growing larger
    # than what qemu-img measure reports, which is problematic for qcow2-on-top-of-LVM
    # TODO test and consider enabling this in general
    if ($scfg && $scfg->{'snapshot-as-volume-chain'}) {
        $blockdev->{'discard-no-unref'} = JSON::true if $format eq 'qcow2';
    }

    return $blockdev;
}

my sub generate_backing_blockdev {
    use feature 'current_sub';
    my ($storecfg, $snapshots, $deviceid, $drive, $machine_version, $options) = @_;

    my $snap_id = $options->{'snapshot-name'};
    my $snapshot = $snapshots->{$snap_id};
    my $parentid = $snapshot->{parent};

    my $volid = $drive->{file};

    my $snap_file_blockdev = generate_file_blockdev($storecfg, $drive, $machine_version, $options);
    $snap_file_blockdev->{filename} = $snapshot->{file};

    my $snap_fmt_blockdev =
        generate_format_blockdev($storecfg, $drive, $snap_file_blockdev, $options);

    if ($parentid) {
        my $options = { 'snapshot-name' => $parentid };
        $snap_fmt_blockdev->{backing} = __SUB__->(
            $storecfg, $snapshots, $deviceid, $drive, $machine_version, $options,
        );
    }
    return $snap_fmt_blockdev;
}

my sub generate_backing_chain_blockdev {
    my ($storecfg, $deviceid, $drive, $machine_version) = @_;

    my $volid = $drive->{file};

    my $snapshots = PVE::Storage::volume_snapshot_info($storecfg, $volid);
    my $parentid = $snapshots->{'current'}->{parent};
    return undef if !$parentid;
    my $options = { 'snapshot-name' => $parentid };
    return generate_backing_blockdev(
        $storecfg, $snapshots, $deviceid, $drive, $machine_version, $options,
    );
}

sub generate_throttle_blockdev {
    my ($drive, $child, $options) = @_;

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    my $blockdev = {
        driver => "throttle",
        'node-name' => top_node_name($drive_id),
        'throttle-group' => throttle_group_id($drive_id),
        file => $child,
    };

    add_common_options($blockdev, $drive, $options);

    return $blockdev;
}

sub generate_drive_blockdev {
    my ($storecfg, $drive, $machine_version, $options) = @_;

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    die "generate_drive_blockdev called without volid/path\n" if !$drive->{file};
    die "generate_drive_blockdev called with 'none'\n" if $drive->{file} eq 'none';

    my $child = generate_file_blockdev($storecfg, $drive, $machine_version, $options);
    if (!is_nbd($drive)) {
        $child = generate_format_blockdev($storecfg, $drive, $child, $options);

        my $support_qemu_snapshots =
            PVE::Storage::volume_qemu_snapshot_method($storecfg, $drive->{file});
        if ($support_qemu_snapshots && $support_qemu_snapshots eq 'mixed') {
            my $backing_chain = generate_backing_chain_blockdev(
                $storecfg, "drive-$drive_id", $drive, $machine_version,
            );
            $child->{backing} = $backing_chain if $backing_chain;
        }
    }

    if ($options->{'zero-initialized'}) {
        my $node_name = get_node_name('zeroinit', $drive_id, $drive->{file}, $options);
        $child = { driver => 'zeroinit', file => $child, 'node-name' => "$node_name" };
    }

    if (my $live_restore = $options->{'live-restore'}) {
        my $node_name = get_node_name('alloc-track', $drive_id, $drive->{file}, $options);
        $child = {
            driver => 'alloc-track',
            'auto-remove' => JSON::true,
            backing => $live_restore->{blockdev},
            file => $child,
            'node-name' => "$node_name",
        };
    }

    # for fleecing and TPM backup, this is already the top node
    return $child if $options->{fleecing} || $options->{'tpm-backup'} || $options->{'no-throttle'};

    # this is the top filter entry point, use $drive-drive_id as nodename
    return generate_throttle_blockdev($drive, $child, $options);
}

sub generate_pbs_blockdev {
    my ($pbs_conf, $pbs_name) = @_;

    my $blockdev = {
        driver => 'pbs',
        'node-name' => "$pbs_name",
        'read-only' => JSON::true,
        archive => "$pbs_conf->{archive}",
        repository => "$pbs_conf->{repository}",
        snapshot => "$pbs_conf->{snapshot}",
    };
    $blockdev->{namespace} = "$pbs_conf->{namespace}" if $pbs_conf->{namespace};
    $blockdev->{keyfile} = "$pbs_conf->{keyfile}" if $pbs_conf->{keyfile};

    return $blockdev;
}

my sub blockdev_add {
    my ($vmid, $blockdev) = @_;

    eval { mon_cmd($vmid, 'blockdev-add', $blockdev->%*); };
    if (my $err = $@) {
        my $node_name = $blockdev->{'node-name'} // 'undefined';
        die "adding blockdev '$node_name' failed : $err\n" if $@;
    }

    return;
}

=pod

=head3 attach

    my $node_name = attach($storecfg, $vmid, $drive, $options);

Attach the drive C<$drive> to the VM C<$vmid> considering the additional options C<$options>.
Returns the node name of the (topmost) attached block device node.

Parameters:

=over

=item C<$storecfg>: The storage configuration.

=item C<$vmid>: The ID of the virtual machine.

=item C<$drive>: The drive as parsed from a virtual machine configuration.

=item C<$options>: A hash reference with additional options.

=over

=item C<< $options->{fleecing} >>: Generate and attach a block device for backup fleecing.

=item C<< $options->{'no-throttle'} >>: Do not insert a throttle node as the top node.

=item C<< $options->{'read-only'} >>: Attach the image as read-only irrespective of the
configuration in C<$drive>.

=item C<< $options->{size} >>: Attach the image with this virtual size. Must be smaller than the
actual size of the image. The image format must be C<raw>.

=item C<< $options->{'snapshot-name'} >>: Attach this snapshot of the volume C<< $drive->{file} >>,
rather than the volume itself.

=item C<< $options->{'tpm-backup'} >>: Generate and attach a block device for backing up the TPM
state image.

=back

=back

=cut

sub attach {
    my ($storecfg, $vmid, $drive, $options) = @_;

    my $machine_version = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);

    my $blockdev = generate_drive_blockdev($storecfg, $drive, $machine_version, $options);

    my $throttle_group_id;
    if (parse_top_node_name($blockdev->{'node-name'})) { # device top nodes need a throttle group
        my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);
        $throttle_group_id = throttle_group_id($drive_id);
    }

    eval {
        if ($throttle_group_id) {
            # Try to remove potential left-over.
            eval { mon_cmd($vmid, 'object-del', id => $throttle_group_id); };

            my $throttle_group = generate_throttle_group($drive);
            mon_cmd($vmid, 'object-add', $throttle_group->%*);
        }

        blockdev_add($vmid, $blockdev);
    };
    if (my $err = $@) {
        if ($throttle_group_id) {
            eval { mon_cmd($vmid, 'object-del', id => $throttle_group_id); };
        }
        die $err;
    }

    return $blockdev->{'node-name'};
}

=pod

=head3 detach

    detach($vmid, $node_name);

Detach the block device C<$node_name> from the VM C<$vmid>. Also removes associated child block
nodes.

Parameters:

=over

=item C<$vmid>: The ID of the virtual machine.

=item C<$node_name>: The node name identifying the block node in QEMU.

=back

=cut

sub detach {
    my ($vmid, $node_name) = @_;

    die "Blockdev::detach - no node name\n" if !$node_name;

    my $block_info = mon_cmd($vmid, "query-named-block-nodes");
    $block_info = { map { $_->{'node-name'} => $_ } $block_info->@* };

    my $remove_throttle_group_id;
    if ((my $drive_id = parse_top_node_name($node_name)) && $block_info->{$node_name}) {
        $remove_throttle_group_id = throttle_group_id($drive_id);
    }

    while ($node_name) {
        last if !$block_info->{$node_name}; # already gone

        eval { mon_cmd($vmid, 'blockdev-del', 'node-name' => "$node_name"); };
        if (my $err = $@) {
            last if $err =~ m/Failed to find node with node-name/; # already gone
            die "deleting blockdev '$node_name' failed : $err\n";
        }

        my $children = { map { $_->{child} => $_ } $block_info->{$node_name}->{children}->@* };
        # Recursively remove 'file' child nodes. QEMU will auto-remove implicitly added child nodes,
        # but e.g. the child of the top throttle node might have been explicitly added as a mirror
        # target, and needs to be removed manually.
        $node_name = $children->{file}->{'node-name'};
    }

    if ($remove_throttle_group_id) {
        eval { mon_cmd($vmid, 'object-del', id => $remove_throttle_group_id); };
        die "removing throttle group failed - $@\n" if $@;
    }

    return;
}

sub detach_tpm_backup_node {
    my ($vmid) = @_;

    detach($vmid, "drive-tpmstate0-backup");
}

sub detach_fleecing_block_nodes {
    my ($vmid, $log_func) = @_;

    my $block_info = mon_cmd($vmid, "query-named-block-nodes");
    for my $info ($block_info->@*) {
        my $node_name = $info->{'node-name'};
        next if !is_fleecing_top_node($node_name);

        $log_func->('info', "detaching (old) fleecing image '$node_name'");
        eval { detach($vmid, $node_name) };
        $log_func->('warn', "error detaching (old) fleecing image '$node_name' - $@") if $@;
    }
}

sub resize {
    my ($vmid, $deviceid, $storecfg, $volid, $size) = @_;

    my $running = PVE::QemuServer::Helpers::vm_running_locally($vmid);

    PVE::Storage::volume_resize($storecfg, $volid, $size, $running);

    return if !$running;

    my $block_info = get_block_info($vmid);
    my $drive_id = $deviceid =~ s/^drive-//r;
    my $inserted = $block_info->{$drive_id}->{inserted}
        or die "no block node inserted for drive '$drive_id'\n";

    my $padding = (1024 - $size % 1024) % 1024;
    $size = $size + $padding;

    mon_cmd(
        $vmid,
        "block_resize",
        # Need to use the top throttle node, not the node below, because QEMU won't update the size
        # of the top node otherwise, even though it's a filter node (as of QEMU 10.0). For legacy
        # -drive, there is no top throttle node, so this also is the correct node.
        'node-name' => "$inserted->{'node-name'}",
        size => int($size),
        timeout => 60,
    );
}

my sub blockdev_change_medium {
    my ($storecfg, $vmid, $qdev_id, $drive) = @_;

    # force eject if locked
    mon_cmd($vmid, "blockdev-open-tray", force => JSON::true, id => "$qdev_id");
    mon_cmd($vmid, "blockdev-remove-medium", id => "$qdev_id");
    detach($vmid, "drive-$qdev_id");

    return if $drive->{file} eq 'none';

    attach($storecfg, $vmid, $drive, {});
    mon_cmd($vmid, "blockdev-insert-medium", id => "$qdev_id", 'node-name' => "drive-$qdev_id");
    mon_cmd($vmid, "blockdev-close-tray", id => "$qdev_id");
}

sub change_medium {
    my ($storecfg, $vmid, $qdev_id, $drive) = @_;

    my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
    # for the switch to -blockdev
    if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 10, 0)) {
        blockdev_change_medium($storecfg, $vmid, $qdev_id, $drive);
    } else {
        # force eject if locked
        mon_cmd($vmid, "eject", force => JSON::true, id => "$qdev_id");

        my ($path, $format) = PVE::QemuServer::Drive::get_path_and_format($storecfg, $drive);

        if ($path) { # no path for 'none'
            mon_cmd(
                $vmid, "blockdev-change-medium",
                id => "$qdev_id",
                filename => "$path",
                format => "$format",
            );
        }
    }
}

sub set_io_throttle {
    my (
        $vmid,
        $deviceid,
        $bps,
        $bps_rd,
        $bps_wr,
        $iops,
        $iops_rd,
        $iops_wr,
        $bps_max,
        $bps_rd_max,
        $bps_wr_max,
        $iops_max,
        $iops_rd_max,
        $iops_wr_max,
        $bps_max_length,
        $bps_rd_max_length,
        $bps_wr_max_length,
        $iops_max_length,
        $iops_rd_max_length,
        $iops_wr_max_length,
    ) = @_;

    return if !PVE::QemuServer::Helpers::vm_running_locally($vmid);

    my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
    # for the switch to -blockdev
    if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 10, 0)) {
        mon_cmd(
            $vmid,
            'qom-set',
            path => "throttle-$deviceid",
            property => "limits",
            value => {
                'bps-total' => int($bps),
                'bps-read' => int($bps_rd),
                'bps-write' => int($bps_wr),
                'iops-total' => int($iops),
                'iops-read' => int($iops_rd),
                'iops-write' => int($iops_wr),
                'bps-total-max' => int($bps_max),
                'bps-read-max' => int($bps_rd_max),
                'bps-write-max' => int($bps_wr_max),
                'iops-total-max' => int($iops_max),
                'iops-read-max' => int($iops_rd_max),
                'iops-write-max' => int($iops_wr_max),
                'bps-total-max-length' => int($bps_max_length),
                'bps-read-max-length' => int($bps_rd_max_length),
                'bps-write-max-length' => int($bps_wr_max_length),
                'iops-total-max-length' => int($iops_max_length),
                'iops-read-max-length' => int($iops_rd_max_length),
                'iops-write-max-length' => int($iops_wr_max_length),
            },
        );
    } else {
        mon_cmd(
            $vmid, "block_set_io_throttle",
            device => $deviceid,
            bps => int($bps),
            bps_rd => int($bps_rd),
            bps_wr => int($bps_wr),
            iops => int($iops),
            iops_rd => int($iops_rd),
            iops_wr => int($iops_wr),
            bps_max => int($bps_max),
            bps_rd_max => int($bps_rd_max),
            bps_wr_max => int($bps_wr_max),
            iops_max => int($iops_max),
            iops_rd_max => int($iops_rd_max),
            iops_wr_max => int($iops_wr_max),
            bps_max_length => int($bps_max_length),
            bps_rd_max_length => int($bps_rd_max_length),
            bps_wr_max_length => int($bps_wr_max_length),
            iops_max_length => int($iops_max_length),
            iops_rd_max_length => int($iops_rd_max_length),
            iops_wr_max_length => int($iops_wr_max_length),
        );
    }
}

sub blockdev_external_snapshot {
    my ($storecfg, $vmid, $machine_version, $deviceid, $drive, $snap, $parent_snap) = @_;

    print "Creating a new current volume with $snap as backing snap\n";

    my $volid = $drive->{file};

    #rename current to snap && preallocate add a new current file with reference to snap1 backing-file
    PVE::Storage::volume_snapshot($storecfg, $volid, $snap);

    #reopen current to snap
    blockdev_replace(
        $storecfg,
        $vmid,
        $machine_version,
        $deviceid,
        $drive,
        'current',
        $snap,
        $parent_snap,
    );

    #be sure to add drive in write mode
    delete($drive->{ro});

    my $new_file_blockdev = generate_file_blockdev($storecfg, $drive);
    my $new_fmt_blockdev = generate_format_blockdev($storecfg, $drive, $new_file_blockdev);

    my $snap_file_blockdev =
        generate_file_blockdev($storecfg, $drive, $machine_version, { 'snapshot-name' => $snap });
    my $snap_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $snap_file_blockdev,
        { 'snapshot-name' => $snap },
    );

    #backing need to be forced to undef in blockdev, to avoid reopen of backing-file on blockdev-add
    $new_fmt_blockdev->{backing} = undef;

    mon_cmd($vmid, 'blockdev-add', %$new_fmt_blockdev);

    print "blockdev-snapshot: reopen current with $snap backing image\n";
    mon_cmd(
        $vmid, 'blockdev-snapshot',
        node => $snap_fmt_blockdev->{'node-name'},
        overlay => $new_fmt_blockdev->{'node-name'},
    );
}

sub blockdev_delete {
    my ($storecfg, $vmid, $drive, $file_blockdev, $fmt_blockdev, $snap) = @_;

    #add eval as reopen is auto removing the old nodename automatically only if it was created at vm start in command line argument
    eval { mon_cmd($vmid, 'blockdev-del', 'node-name' => $file_blockdev->{'node-name'}) };
    eval { mon_cmd($vmid, 'blockdev-del', 'node-name' => $fmt_blockdev->{'node-name'}) };

    #delete the file (don't use vdisk_free as we don't want to delete all snapshot chain)
    print "delete old $file_blockdev->{filename}\n";

    my $storage_name = PVE::Storage::parse_volume_id($drive->{file});

    my $volid = $drive->{file};
    PVE::Storage::volume_snapshot_delete($storecfg, $volid, $snap, 1);
}

my sub blockdev_relative_backing_file {
    my ($backing, $backed) = @_;

    my $backing_file = $backing->{filename};
    my $backed_file = $backed->{filename};

    if (dirname($backing_file) eq dirname($backed_file)) {
        # make backing file relative if in same directory
        return basename($backing_file);
    }

    return $backing_file;
}

sub blockdev_replace {
    my (
        $storecfg,
        $vmid,
        $machine_version,
        $deviceid,
        $drive,
        $src_snap,
        $target_snap,
        $parent_snap,
    ) = @_;

    print "blockdev replace $src_snap by $target_snap\n";

    my $volid = $drive->{file};
    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    my $src_name_options = $src_snap eq 'current' ? {} : { 'snapshot-name' => $src_snap };
    my $src_file_blockdev_name = get_node_name('file', $drive_id, $volid, $src_name_options);
    my $src_fmt_blockdev_name = get_node_name('fmt', $drive_id, $volid, $src_name_options);

    my $target_file_blockdev = generate_file_blockdev(
        $storecfg,
        $drive,
        $machine_version,
        { 'snapshot-name' => $target_snap },
    );
    my $target_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $target_file_blockdev,
        { 'snapshot-name' => $target_snap },
    );

    if ($target_snap eq 'current' || $src_snap eq 'current') {
        #rename from|to current

        #add backing to target
        if ($parent_snap) {
            my $parent_fmt_nodename =
                get_node_name('fmt', $drive_id, $volid, { 'snapshot-name' => $parent_snap });
            $target_fmt_blockdev->{backing} = $parent_fmt_nodename;
        }
        mon_cmd($vmid, 'blockdev-add', %$target_fmt_blockdev);

        #reopen the current throttlefilter nodename with the target fmt nodename
        my $throttle_blockdev =
            generate_throttle_blockdev($drive, $target_fmt_blockdev->{'node-name'}, {});
        mon_cmd($vmid, 'blockdev-reopen', options => [$throttle_blockdev]);
    } else {
        #intermediate snapshot
        mon_cmd($vmid, 'blockdev-add', %$target_fmt_blockdev);

        #reopen the parent node with the new target fmt backing node
        my $parent_file_blockdev = generate_file_blockdev(
            $storecfg,
            $drive,
            $machine_version,
            { 'snapshot-name' => $parent_snap },
        );
        my $parent_fmt_blockdev = generate_format_blockdev(
            $storecfg,
            $drive,
            $parent_file_blockdev,
            { 'snapshot-name' => $parent_snap },
        );
        $parent_fmt_blockdev->{backing} = $target_fmt_blockdev->{'node-name'};
        mon_cmd($vmid, 'blockdev-reopen', options => [$parent_fmt_blockdev]);

        my $backing_file =
            blockdev_relative_backing_file($target_file_blockdev, $parent_file_blockdev);

        #change backing-file in qcow2 metadatas
        mon_cmd(
            $vmid, 'change-backing-file',
            device => $deviceid,
            'image-node-name' => $parent_fmt_blockdev->{'node-name'},
            'backing-file' => $backing_file,
        );
    }

    # delete old file|fmt nodes
    # add eval as reopen is auto removing the old nodename automatically only if it was created at vm start in command line argument
    eval { mon_cmd($vmid, 'blockdev-del', 'node-name' => $src_fmt_blockdev_name) };
    eval { mon_cmd($vmid, 'blockdev-del', 'node-name' => $src_file_blockdev_name) };
}

sub blockdev_commit {
    my ($storecfg, $vmid, $machine_version, $deviceid, $drive, $src_snap, $target_snap) = @_;

    my $volid = $drive->{file};

    print "block-commit $src_snap to base:$target_snap\n";

    my $target_file_blockdev = generate_file_blockdev(
        $storecfg,
        $drive,
        $machine_version,
        { 'snapshot-name' => $target_snap },
    );
    my $target_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $target_file_blockdev,
        { 'snapshot-name' => $target_snap },
    );

    my $src_file_blockdev = generate_file_blockdev(
        $storecfg,
        $drive,
        $machine_version,
        { 'snapshot-name' => $src_snap },
    );
    my $src_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $src_file_blockdev,
        { 'snapshot-name' => $src_snap },
    );

    my $job_id = "commit-$deviceid";
    my $jobs = {};
    my $opts = { 'job-id' => $job_id, device => $deviceid };

    $opts->{'base-node'} = $target_fmt_blockdev->{'node-name'};
    $opts->{'top-node'} = $src_fmt_blockdev->{'node-name'};

    mon_cmd($vmid, "block-commit", %$opts);
    $jobs->{$job_id} = {};

    # if we commit the current, the blockjob need to be in 'complete' mode
    my $complete = $src_snap && $src_snap ne 'current' ? 'auto' : 'complete';

    eval {
        PVE::QemuServer::BlockJob::qemu_drive_mirror_monitor(
            $vmid, undef, $jobs, $complete, 0, 'commit',
        );
    };
    if ($@) {
        die "Failed to complete block commit: $@\n";
    }

    blockdev_delete($storecfg, $vmid, $drive, $src_file_blockdev, $src_fmt_blockdev, $src_snap);
}

sub blockdev_stream {
    my ($storecfg, $vmid, $machine_version, $deviceid, $drive, $snap, $parent_snap, $target_snap) =
        @_;

    my $volid = $drive->{file};
    $target_snap = undef if $target_snap eq 'current';

    my $parent_file_blockdev = generate_file_blockdev(
        $storecfg,
        $drive,
        $machine_version,
        { 'snapshot-name' => $parent_snap },
    );
    my $parent_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $parent_file_blockdev,
        { 'snapshot-name' => $parent_snap },
    );

    my $target_file_blockdev = generate_file_blockdev(
        $storecfg,
        $drive,
        $machine_version,
        { 'snapshot-name' => $target_snap },
    );
    my $target_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $target_file_blockdev,
        { 'snapshot-name' => $target_snap },
    );

    my $snap_file_blockdev =
        generate_file_blockdev($storecfg, $drive, $machine_version, { 'snapshot-name' => $snap });
    my $snap_fmt_blockdev = generate_format_blockdev(
        $storecfg,
        $drive,
        $snap_file_blockdev,
        { 'snapshot-name' => $snap },
    );

    my $backing_file = blockdev_relative_backing_file($parent_file_blockdev, $target_file_blockdev);

    my $job_id = "stream-$deviceid";
    my $jobs = {};
    my $options = { 'job-id' => $job_id, device => $target_fmt_blockdev->{'node-name'} };
    $options->{'base-node'} = $parent_fmt_blockdev->{'node-name'};
    $options->{'backing-file'} = $backing_file;

    mon_cmd($vmid, 'block-stream', %$options);
    $jobs->{$job_id} = {};

    eval {
        PVE::QemuServer::BlockJob::qemu_drive_mirror_monitor(
            $vmid, undef, $jobs, 'auto', 0, 'stream',
        );
    };
    if ($@) {
        die "Failed to complete block stream: $@\n";
    }

    blockdev_delete($storecfg, $vmid, $drive, $snap_file_blockdev, $snap_fmt_blockdev, $snap);
}

1;
