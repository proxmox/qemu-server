package PVE::QemuServer::VolumeChain;

use strict;
use warnings;

use File::Basename qw(basename dirname);
use JSON;

use PVE::Storage;

use PVE::QemuServer::Blockdev qw(generate_file_blockdev generate_format_blockdev);
use PVE::QemuServer::BlockJob;
use PVE::QemuServer::Drive;
use PVE::QemuServer::Monitor qw(qmp_cmd);

sub blockdev_external_snapshot {
    my ($storecfg, $qmp_peer, $machine_version, $deviceid, $drive, $snap, $parent_snap) = @_;

    print "Creating a new current volume with $snap as backing snap\n";

    my $volid = $drive->{file};

    #rename current to snap && preallocate add a new current file with reference to snap1 backing-file
    PVE::Storage::volume_snapshot($storecfg, $volid, $snap);

    #reopen current to snap
    blockdev_replace(
        $storecfg,
        $qmp_peer,
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

    qmp_cmd($qmp_peer, 'blockdev-add', %$new_fmt_blockdev);

    print "blockdev-snapshot: reopen current with $snap backing image\n";
    qmp_cmd(
        $qmp_peer, 'blockdev-snapshot',
        node => $snap_fmt_blockdev->{'node-name'},
        overlay => $new_fmt_blockdev->{'node-name'},
    );
}

my sub blockdev_delete {
    my ($storecfg, $qmp_peer, $volid, $file_blockdev, $fmt_blockdev, $snap) = @_;

    eval { PVE::QemuServer::Blockdev::detach($qmp_peer, $fmt_blockdev->{'node-name'}); };
    warn "detaching block node for $file_blockdev->{filename} failed - $@" if $@;

    #delete the file (don't use vdisk_free as we don't want to delete all snapshot chain)
    print "delete old $file_blockdev->{filename}\n";

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
        $qmp_peer,
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

    my $src_name_options = {};
    my $src_blockdev_name;
    if ($src_snap eq 'current') {
        # there might be other nodes on top like zeroinit, look up the current node below throttle
        $src_blockdev_name =
            PVE::QemuServer::Blockdev::get_node_name_below_throttle($qmp_peer, $deviceid, 1);
    } else {
        $src_name_options = { 'snapshot-name' => $src_snap };
        $src_blockdev_name =
            PVE::QemuServer::Blockdev::get_node_name('fmt', $drive_id, $volid, $src_name_options);
    }

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
            my $parent_fmt_nodename = PVE::QemuServer::Blockdev::get_node_name(
                'fmt',
                $drive_id,
                $volid,
                { 'snapshot-name' => $parent_snap },
            );
            $target_fmt_blockdev->{backing} = $parent_fmt_nodename;
        }
        qmp_cmd($qmp_peer, 'blockdev-add', %$target_fmt_blockdev);

        #reopen the current throttlefilter nodename with the target fmt nodename
        my $throttle_blockdev = PVE::QemuServer::Blockdev::generate_throttle_blockdev(
            $drive, $target_fmt_blockdev->{'node-name'}, {},
        );
        qmp_cmd($qmp_peer, 'blockdev-reopen', options => [$throttle_blockdev]);
    } else {
        #intermediate snapshot
        qmp_cmd($qmp_peer, 'blockdev-add', %$target_fmt_blockdev);

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
        qmp_cmd($qmp_peer, 'blockdev-reopen', options => [$parent_fmt_blockdev]);

        my $backing_file =
            blockdev_relative_backing_file($target_file_blockdev, $parent_file_blockdev);

        #change backing-file in qcow2 metadatas
        qmp_cmd(
            $qmp_peer, 'change-backing-file',
            device => $deviceid,
            'image-node-name' => $parent_fmt_blockdev->{'node-name'},
            'backing-file' => $backing_file,
        );
    }

    # delete old file|fmt nodes
    eval { PVE::QemuServer::Blockdev::detach($qmp_peer, $src_blockdev_name); };
    warn "detaching block node for $src_snap failed - $@" if $@;
}

sub blockdev_commit {
    my ($storecfg, $qmp_peer, $machine_version, $deviceid, $drive, $src_snap, $target_snap) = @_;

    my $target_was_read_only;

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

    if ($target_was_read_only = $target_fmt_blockdev->{'read-only'}) {
        print "reopening internal read-only block node for '$target_snap' as writable\n";
        $target_fmt_blockdev->{'read-only'} = JSON::false;
        $target_file_blockdev->{'read-only'} = JSON::false;
        qmp_cmd($qmp_peer, 'blockdev-reopen', options => [$target_fmt_blockdev]);
        # For the guest, the drive is still read-only, because the top throttle node is.
    }

    eval {
        my $job_id = "commit-$deviceid";
        my $jobs = {};
        my $opts = { 'job-id' => $job_id, device => $deviceid };

        $opts->{'base-node'} = $target_fmt_blockdev->{'node-name'};
        $opts->{'top-node'} = $src_fmt_blockdev->{'node-name'};

        qmp_cmd($qmp_peer, "block-commit", %$opts);
        $jobs->{$job_id} = {};

        # If the 'current' state is committed to its backing snapshot, the job will not complete
        # automatically, because there is a writer, i.e. the guest. It is necessary to use the
        # 'complete' completion mode, so that the 'current' block node is replaced with the backing
        # node upon completion. Like that, IO after the commit operation will already land in the
        # backing node, which will be renamed since it will be the new top of the chain (done by the
        # caller).
        #
        # For other snapshots in the chain, it can be assumed that they have no writer, so
        # 'block-commit' will complete automatically.
        my $complete = $src_snap && $src_snap ne 'current' ? 'auto' : 'complete';

        PVE::QemuServer::BlockJob::monitor($qmp_peer, undef, $jobs, $complete, 0, 'commit');

        blockdev_delete(
            $storecfg,
            $qmp_peer,
            $drive->{file},
            $src_file_blockdev,
            $src_fmt_blockdev,
            $src_snap,
        );
    };
    my $err = $@;

    if ($target_was_read_only) {
        # Even when restoring the read-only flag on the format and file nodes fails, the top
        # throttle node still has it, ensuring it is read-only for the guest.
        print "re-applying read-only flag for internal block node for '$target_snap'\n";
        $target_fmt_blockdev->{'read-only'} = JSON::true;
        $target_file_blockdev->{'read-only'} = JSON::true;
        eval { qmp_cmd($qmp_peer, 'blockdev-reopen', options => [$target_fmt_blockdev]); };
        print "failed to re-apply read-only flag - $@\n" if $@;
    }

    die $err if $err;
}

sub blockdev_stream {
    my (
        $storecfg,
        $qmp_peer,
        $machine_version,
        $deviceid,
        $drive,
        $snap,
        $parent_snap,
        $target_snap,
    ) = @_;

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

    qmp_cmd($qmp_peer, 'block-stream', %$options);
    $jobs->{$job_id} = {};

    PVE::QemuServer::BlockJob::monitor($qmp_peer, undef, $jobs, 'auto', 0, 'stream');

    blockdev_delete(
        $storecfg, $qmp_peer, $drive->{file}, $snap_file_blockdev, $snap_fmt_blockdev, $snap,
    );
}

1;
