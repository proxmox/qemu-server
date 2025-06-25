package PVE::QemuServer::OVMF;

use strict;
use warnings;

use JSON;

use PVE::RESTEnvironment qw(log_warn);
use PVE::Storage;
use PVE::Tools;

use PVE::QemuServer::Blockdev;
use PVE::QemuServer::Drive qw(checked_volume_format drive_is_read_only parse_drive print_drive);
use PVE::QemuServer::QemuImage;

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
            "$EDK2_FW_BASE/OVMF_CVM_CODE_4M.fd", "$EDK2_FW_BASE/OVMF_CVM_VARS_4M.fd",
        ],
        '4m-snp' => [
            "$EDK2_FW_BASE/OVMF_CVM_4M.fd",
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
    my ($arch, $efidisk, $smm, $amd_sev_type) = @_;

    my $types = $OVMF->{$arch}
        or die "no OVMF images known for architecture '$arch'\n";

    my $type = 'default';
    if ($arch eq 'x86_64') {
        if ($amd_sev_type && $amd_sev_type eq 'snp') {
            $type = "4m-snp";
            my ($ovmf) = $types->{$type}->@*;
            die "EFI base image '$ovmf' not found\n" if !-f $ovmf;
            return ($ovmf);
        } elsif ($amd_sev_type) {
            $type = "4m-sev";
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
    my ($conf, $storecfg, $vmid, $hw_info, $version_guard) = @_;

    my ($amd_sev_type, $arch, $q35) = $hw_info->@{qw(amd-sev-type arch q35)};

    my $d = $conf->{efidisk0} ? parse_drive('efidisk0', $conf->{efidisk0}) : undef;

    die "Attempting to configure SEV-SNP with pflash devices instead of using `-bios`\n"
        if $amd_sev_type && $amd_sev_type eq 'snp';

    my ($ovmf_code, $ovmf_vars) = get_ovmf_files($arch, $d, $q35, $amd_sev_type);

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
        $var_drive_str .= ',readonly=on' if drive_is_read_only($conf, $d);
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
    my ($arch, $efidisk, $smm, $amd_sev_type) = @_;

    my (undef, $ovmf_vars) = get_ovmf_files($arch, $efidisk, $smm, $amd_sev_type);
    return -s $ovmf_vars;
}

sub create_efidisk($$$$$$$$) {
    my ($storecfg, $storeid, $vmid, $fmt, $arch, $efidisk, $smm, $amd_sev_type) = @_;

    my (undef, $ovmf_vars) = get_ovmf_files($arch, $efidisk, $smm, $amd_sev_type);

    my $vars_size_b = -s $ovmf_vars;
    my $vars_size = PVE::Tools::convert_size($vars_size_b, 'b' => 'kb');
    my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $fmt, undef, $vars_size);
    PVE::Storage::activate_volumes($storecfg, [$volid]);

    PVE::QemuServer::QemuImage::convert($ovmf_vars, $volid, $vars_size_b);
    my $size = PVE::Storage::volume_size_info($storecfg, $volid, 3);

    return ($volid, $size / 1024);
}

my sub generate_ovmf_blockdev {
    my ($conf, $storecfg, $vmid, $hw_info) = @_;

    my ($amd_sev_type, $arch, $q35) = $hw_info->@{qw(amd-sev-type arch q35)};

    my $drive = $conf->{efidisk0} ? parse_drive('efidisk0', $conf->{efidisk0}) : undef;

    die "Attempting to configure SEV-SNP with pflash devices instead of using `-bios`\n"
        if $amd_sev_type && $amd_sev_type eq 'snp';

    my ($ovmf_code, $ovmf_vars) = get_ovmf_files($arch, $drive, $q35, $amd_sev_type);

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
        $drive = { file => $path };
        $format = 'raw';
    }

    my $extra_blockdev_options = {};
    # extra protection for templates, but SATA and IDE don't support it..
    $extra_blockdev_options->{'read-only'} = 1 if drive_is_read_only($conf, $drive);

    $extra_blockdev_options->{size} = -s $ovmf_vars if $format eq 'raw';

    my $throttle_group = PVE::QemuServer::Blockdev::generate_throttle_group($drive);

    my $ovmf_vars_blockdev = PVE::QemuServer::Blockdev::generate_drive_blockdev(
        $storecfg, $drive, $extra_blockdev_options,
    );

    return ($ovmf_code_blockdev, $ovmf_vars_blockdev, $throttle_group);
}

sub print_ovmf_commandline {
    my ($conf, $storecfg, $vmid, $hw_info, $version_guard) = @_;

    my $amd_sev_type = $hw_info->{'amd-sev-type'};

    my $cmd = [];
    my $machine_flags = [];

    if ($amd_sev_type && $amd_sev_type eq 'snp') {
        if (defined($conf->{efidisk0})) {
            log_warn("EFI disks are not supported with SEV-SNP and will be ignored");
        }
        push $cmd->@*, '-bios', get_ovmf_files($hw_info->{arch}, undef, undef, $amd_sev_type);
    } else {
        my ($code_drive_str, $var_drive_str) =
            print_ovmf_drive_commandlines($conf, $storecfg, $vmid, $hw_info, $version_guard);
        push $cmd->@*, '-drive', $code_drive_str;
        push $cmd->@*, '-drive', $var_drive_str;
    }

    return ($cmd, $machine_flags);
}

1;
