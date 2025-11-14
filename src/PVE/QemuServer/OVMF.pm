package PVE::QemuServer::OVMF;

use strict;
use warnings;

use JSON qw(to_json);

use PVE::RESTEnvironment qw(log_warn);
use PVE::Storage;
use PVE::Tools;

use PVE::QemuServer::Blockdev;
use PVE::QemuServer::Drive qw(checked_volume_format parse_drive print_drive);
use PVE::QemuServer::Helpers;
use PVE::QemuServer::QemuImage;
use PVE::QemuServer::QSD;

my $EDK2_FW_BASE = '/usr/share/pve-edk2-firmware/';
my $OVMF = {
    x86_64 => {
        '4m-no-smm' => [
            "$EDK2_FW_BASE/OVMF_CODE_4M.fd", "$EDK2_FW_BASE/OVMF_VARS_4M.fd",
        ],
        '4m-no-smm-ms' => [
            "$EDK2_FW_BASE/OVMF_CODE_4M.fd", "$EDK2_FW_BASE/OVMF_VARS_4M.ms.fd",
        ],
        '4m' => [
            "$EDK2_FW_BASE/OVMF_CODE_4M.secboot.fd", "$EDK2_FW_BASE/OVMF_VARS_4M.fd",
        ],
        '4m-ms' => [
            "$EDK2_FW_BASE/OVMF_CODE_4M.secboot.fd", "$EDK2_FW_BASE/OVMF_VARS_4M.ms.fd",
        ],
        '4m-sev' => [
            "$EDK2_FW_BASE/OVMF_SEV_CODE_4M.fd", "$EDK2_FW_BASE/OVMF_SEV_VARS_4M.fd",
        ],
        '4m-snp' => [
            "$EDK2_FW_BASE/OVMF_SEV_4M.fd",
        ],
        '4m-tdx' => [
            "$EDK2_FW_BASE/OVMF_TDX_4M.ms.fd",
        ],
        # FIXME: These are legacy 2MB-sized images that modern OVMF doesn't supports to build
        # anymore. how can we deperacate this sanely without breaking existing instances, or using
        # older backups and snapshot?
        default => [
            "$EDK2_FW_BASE/OVMF_CODE.fd", "$EDK2_FW_BASE/OVMF_VARS.fd",
        ],
    },
    aarch64 => {
        default => [
            "$EDK2_FW_BASE/AAVMF_CODE.fd", "$EDK2_FW_BASE/AAVMF_VARS.fd",
        ],
    },
};

my sub get_ovmf_files($$$$) {
    my ($arch, $efidisk, $smm, $cvm_type) = @_;

    my $types = $OVMF->{$arch}
        or die "no OVMF images known for architecture '$arch'\n";

    my $type = 'default';
    if ($arch eq 'x86_64') {
        if ($cvm_type && $cvm_type eq 'snp') {
            $type = "4m-snp";
            my ($ovmf) = $types->{$type}->@*;
            die "EFI base image '$ovmf' not found\n" if !-f $ovmf;
            return ($ovmf);
        } elsif ($cvm_type && ($cvm_type eq 'std' || $cvm_type eq 'es')) {
            $type = "4m-sev";
        } elsif ($cvm_type && $cvm_type eq 'tdx') {
            $type = "4m-tdx";
            my ($ovmf) = $types->{$type}->@*;
            die "EFI base image '$ovmf' not found\n" if !-f $ovmf;
            return ($ovmf);
        } elsif (defined($efidisk->{efitype}) && $efidisk->{efitype} eq '4m') {
            $type = $smm ? "4m" : "4m-no-smm";
            $type .= '-ms' if $efidisk->{'pre-enrolled-keys'};
        } else {
            # TODO: log_warn about use of legacy images for x86_64 with Promxox VE 9
        }
    }

    my ($ovmf_code, $ovmf_vars) = $types->{$type}->@*;
    die "EFI base image '$ovmf_code' not found\n" if !-f $ovmf_code;
    die "EFI vars image '$ovmf_vars' not found\n" if !-f $ovmf_vars;

    return ($ovmf_code, $ovmf_vars);
}

my sub print_ovmf_drive_commandlines {
    my ($conf, $storecfg, $vmid, $hw_info, $version_guard, $readonly) = @_;

    my ($cvm_type, $arch, $q35) = $hw_info->@{qw(cvm-type arch q35)};

    my $d = $conf->{efidisk0} ? parse_drive('efidisk0', $conf->{efidisk0}) : undef;

    die "Attempting to configure SEV-SNP with pflash devices instead of using `-bios`\n"
        if $cvm_type && $cvm_type eq 'snp';

    die "Attempting to configure TDX with pflash devices instead of using `-bios`\n"
        if $cvm_type && $cvm_type eq 'tdx';

    my ($ovmf_code, $ovmf_vars) = get_ovmf_files($arch, $d, $q35, $cvm_type);

    my $var_drive_str = "if=pflash,unit=1,id=drive-efidisk0";
    if ($d) {
        my ($storeid, $volname) = PVE::Storage::parse_volume_id($d->{file}, 1);
        my ($path, $format) = $d->@{ 'file', 'format' };
        if ($storeid) {
            $path = PVE::Storage::path($storecfg, $d->{file});
            $format //= checked_volume_format($storecfg, $d->{file});
        } elsif (!defined($format)) {
            die "efidisk format must be specified\n";
        }
        # SPI flash does lots of read-modify-write OPs, without writeback this gets really slow #3329
        if ($path =~ m/^rbd:/) {
            $var_drive_str .= ',cache=writeback';
            $path .= ':rbd_cache_policy=writeback'; # avoid write-around, we *need* to cache writes too
        }
        $var_drive_str .= ",format=$format,file=$path";

        $var_drive_str .= ",size=" . (-s $ovmf_vars)
            if $format eq 'raw' && $version_guard->(4, 1, 2);
        $var_drive_str .= ',readonly=on' if $readonly;
    } else {
        log_warn("no efidisk configured! Using temporary efivars disk.");
        my $path = "/tmp/$vmid-ovmf.fd";
        PVE::Tools::file_copy($ovmf_vars, $path, -s $ovmf_vars);
        $var_drive_str .= ",format=raw,file=$path";
        $var_drive_str .= ",size=" . (-s $ovmf_vars) if $version_guard->(4, 1, 2);
    }

    return ("if=pflash,unit=0,format=raw,readonly=on,file=$ovmf_code", $var_drive_str);
}

sub get_efivars_size {
    my ($arch, $efidisk, $smm, $cvm_type) = @_;

    my (undef, $ovmf_vars) = get_ovmf_files($arch, $efidisk, $smm, $cvm_type);
    return -s $ovmf_vars;
}

my sub is_ms_2023_cert_enrolled {
    my ($path) = @_;

    my $inside_db_section;
    my $found_ms_2023_cert;

    my $detect_ms_2023_cert = sub {
        my ($line) = @_;
        return if $found_ms_2023_cert;
        $inside_db_section = undef if !$line;
        $found_ms_2023_cert = 1
            if $inside_db_section && $line =~ m/CN=Microsoft UEFI CA 2023/;
        $inside_db_section = 1 if $line =~ m/^name=db guid=guid:EfiImageSecurityDatabase/;
        return;
    };

    PVE::Tools::run_command(
        ['virt-fw-vars', '--input', $path, '--print', '--verbose'],
        outfunc => $detect_ms_2023_cert,
    );

    return $found_ms_2023_cert;
}

sub create_efidisk($$$$$$$$) {
    my ($storecfg, $storeid, $vmid, $fmt, $arch, $efidisk, $smm, $cvm_type) = @_;

    my (undef, $ovmf_vars) = get_ovmf_files($arch, $efidisk, $smm, $cvm_type);

    my $vars_size_b = -s $ovmf_vars;
    my $vars_size = PVE::Tools::convert_size($vars_size_b, 'b' => 'kb');
    my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $fmt, undef, $vars_size);
    PVE::Storage::activate_volumes($storecfg, [$volid]);

    PVE::QemuServer::QemuImage::convert($ovmf_vars, $volid, $vars_size_b);
    my $size = PVE::Storage::volume_size_info($storecfg, $volid, 3);

    if ($efidisk->{'pre-enrolled-keys'} && is_ms_2023_cert_enrolled($ovmf_vars)) {
        $efidisk->{'ms-cert'} = '2023';
    }

    return ($volid, $size / 1024);
}

my sub generate_ovmf_blockdev {
    my ($conf, $storecfg, $vmid, $hw_info, $readonly) = @_;

    my ($cvm_type, $arch, $machine_version, $q35) =
        $hw_info->@{qw(cvm-type arch machine-version q35)};

    my $drive = $conf->{efidisk0} ? parse_drive('efidisk0', $conf->{efidisk0}) : undef;

    die "Attempting to configure SEV-SNP with pflash devices instead of using `-bios`\n"
        if $cvm_type && $cvm_type eq 'snp';

    my ($ovmf_code, $ovmf_vars) = get_ovmf_files($arch, $drive, $q35, $cvm_type);

    my $ovmf_code_blockdev = {
        driver => 'raw',
        file => { driver => 'file', filename => "$ovmf_code" },
        'node-name' => 'pflash0',
        'read-only' => JSON::true,
    };

    my $format;

    if ($drive) {
        my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);
        $format = $drive->{format};
        if ($storeid) {
            $format //= checked_volume_format($storecfg, $drive->{file});
        } elsif (!defined($format)) {
            die "efidisk format must be specified\n";
        }
    } else {
        log_warn("no efidisk configured! Using temporary efivars disk.");
        my $path = "/tmp/$vmid-ovmf.fd";
        PVE::Tools::file_copy($ovmf_vars, $path, -s $ovmf_vars);
        $drive = { file => $path, interface => 'efidisk', index => 0 };
        $format = 'raw';
    }

    # Prior to -blockdev, QEMU's default 'writeback' cache mode was used for EFI disks, rather than
    # the Proxmox VE default 'none'. Use that for -blockdev too, to avoid bug #3329.
    $drive->{cache} = 'writeback' if !$drive->{cache};

    my $extra_blockdev_options = {};
    $extra_blockdev_options->{'read-only'} = 1 if $readonly;

    $extra_blockdev_options->{size} = -s $ovmf_vars if $format eq 'raw';

    my $throttle_group = PVE::QemuServer::Blockdev::generate_throttle_group($drive);

    my $ovmf_vars_blockdev = PVE::QemuServer::Blockdev::generate_drive_blockdev(
        $storecfg, $drive, $machine_version, $extra_blockdev_options,
    );

    return ($ovmf_code_blockdev, $ovmf_vars_blockdev, $throttle_group);
}

sub print_ovmf_commandline {
    my ($conf, $storecfg, $vmid, $hw_info, $version_guard, $readonly) = @_;

    my $cvm_type = $hw_info->{'cvm-type'};

    my $cmd = [];
    my $machine_flags = [];

    if ($cvm_type && ($cvm_type eq 'snp' || $cvm_type eq 'tdx')) {
        if (defined($conf->{efidisk0})) {
            log_warn(
                "EFI disks are not supported with Confidential Virtual Machines and will be ignored"
            );
        }
        push $cmd->@*, '-bios', get_ovmf_files($hw_info->{arch}, undef, undef, $cvm_type);
    } else {
        if ($version_guard->(10, 0, 0)) { # for the switch to -blockdev
            my ($code_blockdev, $vars_blockdev, $throttle_group) =
                generate_ovmf_blockdev($conf, $storecfg, $vmid, $hw_info, $readonly);

            push $cmd->@*, '-object', to_json($throttle_group, { canonical => 1 });
            push $cmd->@*, '-blockdev', to_json($code_blockdev, { canonical => 1 });
            push $cmd->@*, '-blockdev', to_json($vars_blockdev, { canonical => 1 });
            push $machine_flags->@*, "pflash0=$code_blockdev->{'node-name'}",
                "pflash1=$vars_blockdev->{'node-name'}";
        } else {
            my ($code_drive_str, $var_drive_str) = print_ovmf_drive_commandlines(
                $conf, $storecfg, $vmid, $hw_info, $version_guard, $readonly,
            );
            push $cmd->@*, '-drive', $code_drive_str;
            push $cmd->@*, '-drive', $var_drive_str;
        }
    }

    return ($cmd, $machine_flags);
}

# May only be called as part of VM start right now, because it uses the main QSD associated to the
# VM. If required for another scenario, change the QSD ID to something else.
sub ensure_ms_2023_cert_enrolled {
    my ($storecfg, $vmid, $efidisk_str) = @_;

    my $efidisk = parse_drive('efidisk0', $efidisk_str);
    return if !$efidisk->{'pre-enrolled-keys'};
    return if $efidisk->{'ms-cert'} && $efidisk->{'ms-cert'} eq '2023';

    print "efidisk0: enrolling Microsoft UEFI CA 2023\n";

    my $new_qsd = !PVE::QemuServer::Helpers::qsd_running_locally($vmid);
    PVE::QemuServer::QSD::start($vmid) if $new_qsd;

    eval {
        my $efi_vars_path =
            PVE::QemuServer::QSD::add_fuse_export($vmid, $efidisk, 'efidisk0-enroll');
        PVE::Tools::run_command(
            ['virt-fw-vars', '--inplace', $efi_vars_path, '--distro-keys', 'ms-uefi']);
        PVE::QemuServer::QSD::remove_fuse_export($vmid, 'efidisk0-enroll');
    };
    my $err = $@;

    PVE::QemuServer::QSD::quit($vmid) if $new_qsd;

    die "efidisk0: enrolling Microsoft UEFI CA 2023 failed - $err" if $err;

    $efidisk->{'ms-cert'} = '2023';
    return print_drive($efidisk);
}

1;
