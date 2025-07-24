package PVE::QemuServer::QemuImage;

use strict;
use warnings;

use Fcntl qw(S_ISBLK);
use File::stat;

use PVE::Format qw(render_bytes);
use PVE::Storage;
use PVE::Tools;

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
    my ($path, @qcow2_opts) = @_;

    my $st = File::stat::stat($path) or die "stat for '$path' failed - $!\n";

    my $driver = S_ISBLK($st->mode) ? 'host_device' : 'file';

    my $qcow2_opts_str = ',' . join(',', @qcow2_opts);

    return "driver=qcow2$qcow2_opts_str,file.driver=$driver,file.filename=$path";
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

    if ($dst_is_iscsi) {
        push @$cmd, '--target-image-opts';
        $dst_path = convert_iscsi_path($dst_path);
    } elsif ($dst_needs_discard_no_unref) {
        push @$cmd, '--target-image-opts';
        $dst_path = qcow2_target_image_opts($dst_path, 'discard-no-unref=true');
    } else {
        push @$cmd, '-O', $dst_format;
    }

    push @$cmd, $src_path;

    if (!$dst_is_iscsi && $opts->{'is-zero-initialized'}) {
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
