package PVE::QemuServer::OVMF;

use strict;
use warnings;

use PVE::Tools;

use PVE::QemuServer::Drive qw(parse_drive print_drive);

sub is_ms_2023_cert_enrolled {
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

sub should_enroll_ms_2023_cert {
    my ($efidisk_str) = @_;

    my $efidisk = parse_drive('efidisk0', $efidisk_str);
    return if !$efidisk->{'pre-enrolled-keys'};
    return if $efidisk->{'ms-cert'} && $efidisk->{'ms-cert'} eq '2023';

    return 1;
}

sub ensure_ms_2023_cert_enrolled {
    my ($storecfg, $vmid, $efidisk_str) = @_;

    return if !should_enroll_ms_2023_cert($efidisk_str);

    my $efidisk = parse_drive('efidisk0', $efidisk_str);

    print "efidisk0: enrolling Microsoft UEFI CA 2023\n";

    PVE::Storage::activate_volumes($storecfg, [$efidisk->{file}]);

    my ($path) = PVE::QemuServer::Drive::get_path_and_format($storecfg, $vmid, $efidisk);

    eval {
        PVE::Tools::run_command([
            'virt-fw-vars', '--inplace', $path, '--distro-keys', 'ms-uefi',
        ]);
    };
    die "efidisk0: enrolling Microsoft UEFI CA 2023 failed - $@" if $@;

    $efidisk->{'ms-cert'} = '2023';
    return print_drive($efidisk);
}

1;
