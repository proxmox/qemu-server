package PVE::QemuServer::QemuImage;

use strict;
use warnings;

use Fcntl qw(S_ISBLK);
use File::stat;
use JSON;

use PVE::Format qw(render_bytes);
use PVE::Storage;
use PVE::Tools;

use PVE::QemuServer::Blockdev;
use PVE::QemuServer::Drive qw(checked_volume_format);
use PVE::QemuServer::Helpers;

sub convert_iscsi_path {
    my ($path) = @_;

    if ($path =~ m|^iscsi://([^/]+)/([^/]+)/(.+)$|) {
        my $portal = $1;
        my $target = $2;
        my $lun = $3;

        my $initiator_name = PVE::QemuServer::Helpers::get_iscsi_initiator_name();

        return "file.driver=iscsi,file.transport=tcp,file.initiator-name=$initiator_name,"
            . "file.portal=$portal,file.target=$target,file.lun=$lun,driver=raw";
    }

    die "cannot convert iscsi path '$path', unknown format\n";
}

my sub qcow2_target_image_opts {
    my ($storecfg, $drive, $qcow2_opts, $zeroinit) = @_;

    # There is no machine version, the qemu-img binary version is what's important.
    my $version = PVE::QemuServer::Helpers::kvm_user_version();

    my $blockdev_opts = { 'no-throttle' => 1 };
    $blockdev_opts->{'zero-initialized'} = 1 if $zeroinit;

    my $blockdev = PVE::QemuServer::Blockdev::generate_drive_blockdev(
        $storecfg, $drive, $version, $blockdev_opts,
    );

    my $opts = [];
    my $opt_prefix = '';
    my $next_child = $blockdev;
    while ($next_child) {
        my $current = $next_child;
        $next_child = delete($current->{file});

        # TODO should cache settings be configured here (via appropriate drive configuration) rather
        # than via dedicated qemu-img options?
        delete($current->{cache});
        # TODO e.g. can't use aio 'native' without cache.direct, just use QEMU default like for
        # other targets for now
        delete($current->{aio});

        # no need for node names
        delete($current->{'node-name'});

        # it's the write target, while the flag should be 'false' anyways, remove to be sure
        delete($current->{'read-only'});

        # TODO should those be set (via appropriate drive configuration)?
        delete($current->{'detect-zeroes'});
        delete($current->{'discard'});

        for my $key (sort keys $current->%*) {
            my $value;
            if (ref($current->{$key})) {
                if ($current->{$key} eq JSON::false) {
                    $value = 'false';
                } elsif ($current->{$key} eq JSON::true) {
                    $value = 'true';
                } else {
                    die "target image options: unhandled structured key: $key\n";
                }
            } else {
                $value = $current->{$key};
            }
            push $opts->@*, "$opt_prefix$key=$value";
        }

        $opt_prefix .= 'file.';
    }

    return join(',', $opts->@*);
}

# The possible options are:
# bwlimit - The bandwidth limit in KiB/s.
# is-zero-initialized - If the destination image is zero-initialized.
# snapname - Use this snapshot of the source image.
# source-path-format - Indicate the format of the source when the source is a path. For PVE-managed
# volumes, the format from the storage layer is always used.
sub convert {
    my ($src_volid, $dst_volid, $size, $opts) = @_;

    my ($bwlimit, $snapname) = $opts->@{qw(bwlimit snapname)};

    my $storecfg = PVE::Storage::config();
    my ($src_storeid) = PVE::Storage::parse_volume_id($src_volid, 1);
    my ($dst_storeid) = PVE::Storage::parse_volume_id($dst_volid, 1);

    die "destination '$dst_volid' is not a valid volid form qemu-img convert\n" if !$dst_storeid;

    my $cachemode;
    my $src_path;
    my $src_is_iscsi = 0;
    my $src_format;

    if ($src_storeid) {
        PVE::Storage::activate_volumes($storecfg, [$src_volid], $snapname);
        my $src_scfg = PVE::Storage::storage_config($storecfg, $src_storeid);
        $src_format = checked_volume_format($storecfg, $src_volid);
        $src_path = PVE::Storage::path($storecfg, $src_volid, $snapname);
        $src_is_iscsi = ($src_path =~ m|^iscsi://|);
        $cachemode = 'none' if $src_scfg->{type} eq 'zfspool';
    } elsif (-f $src_volid || -b $src_volid) {
        $src_path = $src_volid;
        if ($opts->{'source-path-format'}) {
            $src_format = $opts->{'source-path-format'};
        } elsif ($src_path =~ m/\.($PVE::QemuServer::Drive::QEMU_FORMAT_RE)$/) {
            $src_format = $1;
        }
    }

    die "source '$src_volid' is not a valid volid nor path for qemu-img convert\n" if !$src_path;

    my $dst_scfg = PVE::Storage::storage_config($storecfg, $dst_storeid);
    my $dst_format = checked_volume_format($storecfg, $dst_volid);
    my $dst_path = PVE::Storage::path($storecfg, $dst_volid);
    my $dst_is_iscsi = ($dst_path =~ m|^iscsi://|);
    my $dst_needs_discard_no_unref =
        $dst_scfg->{'snapshot-as-volume-chain'} && $dst_format eq 'qcow2';
    my $support_qemu_snapshots = PVE::Storage::volume_qemu_snapshot_method($storecfg, $src_volid);

    my $cmd = [];
    push @$cmd, '/usr/bin/qemu-img', 'convert', '-p', '-n';
    push @$cmd, '-l', "snapshot.name=$snapname"
        if $snapname
        && $src_format eq 'qcow2'
        && $support_qemu_snapshots
        && $support_qemu_snapshots eq 'qemu';
    push @$cmd, '-t', 'none' if $dst_scfg->{type} eq 'zfspool';
    push @$cmd, '-T', $cachemode if defined($cachemode);
    push @$cmd, '-r', "${bwlimit}K" if defined($bwlimit);

    if ($src_is_iscsi) {
        push @$cmd, '--image-opts';
        $src_path = convert_iscsi_path($src_path);
    } elsif ($src_format) {
        push @$cmd, '-f', $src_format;
    }

    my $dst_uses_target_image_opts = $dst_is_iscsi || $dst_needs_discard_no_unref;
    push @$cmd, '--target-image-opts' if $dst_uses_target_image_opts;

    if ($dst_is_iscsi) {
        $dst_path = convert_iscsi_path($dst_path);
    } elsif ($dst_needs_discard_no_unref) {
        # don't use any other drive options, those are intended for use with a running VM and just
        # use scsi0 as a dummy interface+index for now
        my $dst_drive = { file => $dst_volid, interface => 'scsi', index => 0 };
        $dst_path = qcow2_target_image_opts(
            $storecfg,
            $dst_drive,
            ['discard-no-unref=true'],
            $opts->{'is-zero-initialized'},
        );
    } else {
        push @$cmd, '-O', $dst_format;
    }

    push @$cmd, $src_path;

    if (!$dst_uses_target_image_opts && $opts->{'is-zero-initialized'}) {
        push @$cmd, "zeroinit:$dst_path";
    } else {
        push @$cmd, $dst_path;
    }

    my $parser = sub {
        my $line = shift;
        if ($line =~ m/\((\S+)\/100\%\)/) {
            my $percent = $1;
            my $transferred = int($size * $percent / 100);
            my $total_h = render_bytes($size, 1);
            my $transferred_h = render_bytes($transferred, 1);

            print "transferred $transferred_h of $total_h ($percent%)\n";
        }

    };

    eval { PVE::Tools::run_command($cmd, timeout => undef, outfunc => $parser); };
    my $err = $@;
    die "copy failed: $err" if $err;
}

1;
