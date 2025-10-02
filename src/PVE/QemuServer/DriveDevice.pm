package PVE::QemuServer::DriveDevice;

use strict;
use warnings;

use URI::Escape;

use PVE::QemuServer::Drive qw (drive_is_cdrom);
use PVE::QemuServer::Helpers qw(kvm_user_version min_version);
use PVE::QemuServer::Machine;
use PVE::QemuServer::PCI qw(print_pci_addr);

use base qw(Exporter);

our @EXPORT_OK = qw(
    print_drivedevice_full
    scsihw_infos
);

sub scsihw_infos {
    my ($scsihw, $drive_index) = @_;

    my $maxdev = 0;

    if (!$scsihw || ($scsihw =~ m/^lsi/)) {
        $maxdev = 7;
    } elsif ($scsihw && ($scsihw eq 'virtio-scsi-single')) {
        $maxdev = 1;
    } else {
        $maxdev = 256;
    }

    my $controller = int($drive_index / $maxdev);
    my $controller_prefix =
        ($scsihw && $scsihw eq 'virtio-scsi-single')
        ? "virtioscsi"
        : "scsihw";

    return ($maxdev, $controller, $controller_prefix);
}

sub print_drivedevice_full {
    my ($storecfg, $conf, $vmid, $drive, $bridges, $arch, $machine_type) = @_;

    my $device = '';
    my $maxdev = 0;

    my $machine_version =
        PVE::QemuServer::Machine::extract_version($machine_type, kvm_user_version());
    my $has_write_cache = 1; # whether the device has a 'write-cache' option

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);
    if ($drive->{interface} eq 'virtio') {
        my $pciaddr = print_pci_addr("$drive_id", $bridges, $arch);
        $device = 'virtio-blk-pci';
        # for the switch to -blockdev, there is no blockdev for 'none'
        if (!min_version($machine_version, 10, 0) || $drive->{file} ne 'none') {
            $device .= ",drive=drive-$drive_id";
        }
        $device .= ",id=${drive_id}${pciaddr}";
        $device .= ",iothread=iothread-$drive_id" if $drive->{iothread};
    } elsif ($drive->{interface} eq 'scsi') {

        my ($maxdev, $controller, $controller_prefix) =
            scsihw_infos($conf->{scsihw}, $drive->{index});
        my $unit = $drive->{index} % $maxdev;

        my $device_type =
            PVE::QemuServer::Drive::get_scsi_device_type($drive, $storecfg, $machine_version);

        if (!$conf->{scsihw} || $conf->{scsihw} =~ m/^lsi/ || $conf->{scsihw} eq 'pvscsi') {
            $device = "scsi-$device_type,bus=$controller_prefix$controller.0,scsi-id=$unit";
        } else {
            $device = "scsi-$device_type,bus=$controller_prefix$controller.0,channel=0,scsi-id=0"
                . ",lun=$drive->{index}";
        }
        # for the switch to -blockdev, there is no blockdev for 'none'
        if (!min_version($machine_version, 10, 0) || $drive->{file} ne 'none') {
            $device .= ",drive=drive-$drive_id";
        }
        $device .= ",id=$drive_id";

        # For the switch to -blockdev, the SCSI device ID needs to be explicitly specified. Note
        # that only ide-cd and ide-hd have a 'device_id' option.
        if (
            min_version($machine_version, 10, 0) && ($device_type eq 'cd' || $device_type eq 'hd')
        ) {
            $device .= ",device_id=drive-${drive_id}";
        }

        if ($drive->{ssd} && ($device_type eq 'block' || $device_type eq 'hd')) {
            $device .= ",rotation_rate=1";
        }
        $device .= ",wwn=$drive->{wwn}" if $drive->{wwn};

        # only scsi-hd and scsi-cd support passing vendor and product information and have a
        # 'write-cache' option
        if ($device_type eq 'hd' || $device_type eq 'cd') {
            if (my $vendor = $drive->{vendor}) {
                $device .= ",vendor=$vendor";
            }
            if (my $product = $drive->{product}) {
                $device .= ",product=$product";
            }

            $has_write_cache = 1;
        } else {
            $has_write_cache = 0;
        }

    } elsif ($drive->{interface} eq 'ide' || $drive->{interface} eq 'sata') {
        my $maxdev = ($drive->{interface} eq 'sata') ? $PVE::QemuServer::Drive::MAX_SATA_DISKS : 2;
        my $controller = int($drive->{index} / $maxdev);
        my $unit = $drive->{index} % $maxdev;

        # machine type q35 only supports unit=0 for IDE rather than 2 units. This wasn't handled
        # correctly before, so e.g. index=2 was mapped to controller=1,unit=0 rather than
        # controller=2,unit=0. Note that odd indices never worked, as they would be mapped to
        # unit=1, so to keep backwards compat for migration, it suffices to keep even ones as they
        # were before. Move odd ones up by 2 where they don't clash.
        if (PVE::QemuServer::Machine::machine_type_is_q35($conf) && $drive->{interface} eq 'ide') {
            $controller += 2 * ($unit % 2);
            $unit = 0;
        }

        my $device_type = ($drive->{media} && $drive->{media} eq 'cdrom') ? "cd" : "hd";

        # With ide-hd, the inserted block node needs to be marked as writable too, but -blockdev
        # will complain if it's marked as writable but the actual backing device is read-only (e.g.
        # read-only base LV). IDE/SATA do not support being configured as read-only, the most
        # similar is using ide-cd instead of ide-hd, with most of the code and configuration shared
        # in QEMU. Since a template is never actually started, the front-end device is never
        # accessed. The backup only accesses the inserted block node, so it does not matter for the
        # backup if the type is 'ide-cd' instead.
        $device_type = 'cd' if $conf->{template};

        $device = "ide-$device_type";
        if ($drive->{interface} eq 'ide') {
            $device .= ",bus=ide.$controller,unit=$unit";
        } else {
            $device .= ",bus=ahci$controller.$unit";
        }
        if (!min_version($machine_version, 10, 0) || $drive->{file} ne 'none') {
            $device .= ",drive=drive-$drive_id";
        }
        $device .= ",id=$drive_id";

        if ($device_type eq 'hd') {
            if (my $model = $drive->{model}) {
                $model = URI::Escape::uri_unescape($model);
                $device .= ",model=$model";
            }
            if ($drive->{ssd}) {
                $device .= ",rotation_rate=1";
            }
        }
        $device .= ",wwn=$drive->{wwn}" if $drive->{wwn};
    } elsif ($drive->{interface} eq 'usb') {
        die "implement me";
        #  -device ide-drive,bus=ide.1,unit=0,drive=drive-ide0-1-0,id=ide0-1-0
    } else {
        die "unsupported interface type";
    }

    $device .= ",bootindex=$drive->{bootindex}" if $drive->{bootindex};

    if (my $serial = $drive->{serial}) {
        $serial = URI::Escape::uri_unescape($serial);
        $device .= ",serial=$serial";
    }

    if (min_version($machine_version, 10, 0)) { # for the switch to -blockdev
        if (!drive_is_cdrom($drive) && $has_write_cache) {
            my $write_cache = 'on';
            if (my $cache = $drive->{cache}) {
                $write_cache = 'off' if $cache eq 'writethrough' || $cache eq 'directsync';
            }
            $device .= ",write-cache=$write_cache";
        }
        for my $o (qw(rerror werror)) {
            $device .= ",$o=$drive->{$o}" if defined($drive->{$o});
        }
    }

    return $device;
}

1;
