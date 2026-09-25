package PVE::QemuServer::Snapshot;

use strict;
use warnings;

use PVE::Storage;

use PVE::QemuServer::Drive;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Machine;
use PVE::QemuServer::Monitor qw(qmp_cmd);
use PVE::QemuServer::VolumeChain;

sub do_snapshots_type {
    my ($storecfg, $drive, $deviceid, $running) = @_;

    #we use storage snapshot if vm is not running or if disk is unused;
    return 'storage' if !$running || !$deviceid;

    if (
        $deviceid eq 'drive-tpmstate0'
        && !PVE::QemuServer::Drive::drive_uses_qsd_fuse($storecfg, $drive)
    ) {
        return 'storage';
    }

    if (my $method = PVE::Storage::volume_qemu_snapshot_method($storecfg, $drive->{file})) {
        return 'internal' if $method eq 'qemu';
        return 'external' if $method eq 'mixed';
    }
    return 'storage';
}

sub qemu_volume_snapshot {
    my ($vmid, $deviceid, $storecfg, $drive, $snap) = @_;

    my $volid = $drive->{file};
    my $running = PVE::QemuServer::Helpers::vm_running_locally($vmid);

    my $do_snapshots_type = do_snapshots_type($storecfg, $drive, $deviceid, $running);

    if ($do_snapshots_type eq 'internal') {
        print "internal qemu snapshot\n";
        my $qmp_peer = PVE::QemuServer::Drive::drive_qmp_peer($storecfg, $vmid, $drive);
        qmp_cmd($qmp_peer, 'blockdev-snapshot-internal-sync', device => $deviceid, name => $snap);
    } elsif ($do_snapshots_type eq 'external') {
        my $machine_version = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
        if (!PVE::QemuServer::Machine::is_machine_version_at_least($machine_version, 10, 0)) {
            die "storage for '$volid' is configured for snapshots as a volume chain - this requires"
                . " QEMU machine version >= 10.0. See"
                . " https://pve.proxmox.com/wiki/QEMU_Machine_Version_Upgrade\n";
        }
        my $storeid = (PVE::Storage::parse_volume_id($volid))[0];
        my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
        print "external qemu snapshot\n";
        my $snapshots = PVE::Storage::volume_snapshot_info($storecfg, $volid);
        my $parent_snap = $snapshots->{'current'}->{parent};
        my $qmp_peer = PVE::QemuServer::Drive::drive_qmp_peer($storecfg, $vmid, $drive);
        PVE::QemuServer::VolumeChain::blockdev_external_snapshot(
            $storecfg, $qmp_peer, $machine_version, $deviceid, $drive, $snap, $parent_snap,
        );
    } elsif ($do_snapshots_type eq 'storage') {
        PVE::Storage::volume_snapshot($storecfg, $volid, $snap);
    }
}

sub qemu_volume_snapshot_delete {
    my ($vmid, $storecfg, $drive, $snap, $attached_deviceid, $running) = @_;

    my $volid = $drive->{file};

    my $do_snapshots_type = do_snapshots_type($storecfg, $drive, $attached_deviceid, $running);

    if ($do_snapshots_type eq 'internal') {
        my $qmp_peer = PVE::QemuServer::Drive::drive_qmp_peer($storecfg, $vmid, $drive);
        qmp_cmd(
            $qmp_peer,
            'blockdev-snapshot-delete-internal-sync',
            device => $attached_deviceid,
            name => $snap,
        );
    } elsif ($do_snapshots_type eq 'external') {
        my $machine_version = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
        if (!PVE::QemuServer::Machine::is_machine_version_at_least($machine_version, 10, 0)) {
            die "storage for '$volid' is configured for snapshots as a volume chain - this requires"
                . " QEMU machine version >= 10.0. See"
                . " https://pve.proxmox.com/wiki/QEMU_Machine_Version_Upgrade\n";
        }

        print "delete qemu external snapshot\n";

        my $path = PVE::Storage::path($storecfg, $volid);
        my $snapshots = PVE::Storage::volume_snapshot_info($storecfg, $volid);

        die "could not find snapshot '$snap' for volume '$volid'\n"
            if !defined($snapshots->{$snap});

        my $parentsnap = $snapshots->{$snap}->{parent};
        my $childsnap = $snapshots->{$snap}->{child};

        my $qmp_peer = PVE::QemuServer::Drive::drive_qmp_peer($storecfg, $vmid, $drive);

        # if we delete the first snasphot, we commit because the first snapshot original base image, it should be big.
        # improve-me: if firstsnap > child : commit, if firstsnap < child do a stream.
        if (!$parentsnap) {
            print "delete first snapshot $snap\n";

            my $snap_size = $snapshots->{$snap}->{'virtual-size'};
            my $child_size = $snapshots->{$childsnap}->{'virtual-size'};
            if (defined($child_size) && defined($snap_size) && $child_size > $snap_size) {
                print
                    "resize '$snap' ($snap_size bytes) to match '$childsnap' ($child_size bytes)\n";
                PVE::Storage::volume_resize($storecfg, $volid, $child_size, $running, $snap);
            }

            PVE::QemuServer::VolumeChain::blockdev_commit(
                $storecfg,
                $qmp_peer,
                $machine_version,
                $attached_deviceid,
                $drive,
                $childsnap,
                $snap,
            );

            PVE::Storage::rename_snapshot($storecfg, $volid, $snap, $childsnap);

            PVE::QemuServer::VolumeChain::blockdev_replace(
                $storecfg,
                $qmp_peer,
                $machine_version,
                $attached_deviceid,
                $drive,
                $snap,
                $childsnap,
                $snapshots->{$childsnap}->{child},
            );
        } else {
            #intermediate snapshot, we always stream the snapshot to child snapshot
            print "stream intermediate snapshot $snap to $childsnap\n";
            PVE::QemuServer::VolumeChain::blockdev_stream(
                $storecfg,
                $qmp_peer,
                $machine_version,
                $attached_deviceid,
                $drive,
                $snap,
                $parentsnap,
                $childsnap,
            );
        }
    } elsif ($do_snapshots_type eq 'storage') {
        PVE::Storage::volume_snapshot_delete(
            $storecfg,
            $volid,
            $snap,
            $attached_deviceid ? 1 : undef,
        );
    }
}

1;
