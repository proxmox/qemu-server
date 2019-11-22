package PVE::QemuServer::Machine;

use strict;
use warnings;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;

sub machine_type_is_q35 {
    my ($conf) = @_;

    return $conf->{machine} && ($conf->{machine} =~ m/q35/) ? 1 : 0;
}

# this only works if VM is running
sub get_current_qemu_machine {
    my ($vmid) = @_;

    my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, 'query-machines');

    my ($current, $default);
    foreach my $e (@$res) {
	$default = $e->{name} if $e->{'is-default'};
	$current = $e->{name} if $e->{'is-current'};
    }

    # fallback to the default machine if current is not supported by qemu
    return $current || $default || 'pc';
}

sub extract_version {
    my ($machine_type) = @_;

    if ($machine_type && $machine_type =~ m/^((?:pc(-i440fx|-q35)?|virt)-(\d+)\.(\d+))/) {
	return "$3.$4";
    }

    return undef;
}

sub machine_version {
    my ($machine_type, $version_major, $version_minor) = @_;

    return PVE::QemuServer::Helpers::min_version(
	extract_version($machine_type), $version_major, $version_minor);
}

# dies if a) VM not running or not exisiting b) Version query failed
# So, any defined return value is valid, any invalid state can be caught by eval
sub runs_at_least_qemu_version {
    my ($vmid, $major, $minor, $extra) = @_;

    my $v = PVE::QemuServer::Monitor::mon_cmd($vmid, 'query-version');
    die "could not query currently running version for VM $vmid\n" if !defined($v);
    $v = $v->{qemu};

    return PVE::QemuServer::Helpers::version_cmp($v->{major}, $major, $v->{minor}, $minor, $v->{micro}, $extra) >= 0;
}

sub qemu_machine_pxe {
    my ($vmid, $conf) = @_;

    my $machine =  get_current_qemu_machine($vmid);

    if ($conf->{machine} && $conf->{machine} =~ m/\.pxe$/) {
	$machine .= '.pxe';
    }

    return $machine;
}

1;
