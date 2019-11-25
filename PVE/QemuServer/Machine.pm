package PVE::QemuServer::Machine;

use strict;
use warnings;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;

# Bump this for VM HW layout changes during a release (where the QEMU machine
# version stays the same)
our $PVE_MACHINE_VERSION = 1;

sub machine_type_is_q35 {
    my ($conf) = @_;

    return $conf->{machine} && ($conf->{machine} =~ m/q35/) ? 1 : 0;
}

# this only works if VM is running
sub get_current_qemu_machine {
    my ($vmid) = @_;

    my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, 'query-machines');

    my ($current, $pve_version, $default);
    foreach my $e (@$res) {
	$default = $e->{name} if $e->{'is-default'};
	$current = $e->{name} if $e->{'is-current'};
	$pve_version = $e->{'pve-version'} if $e->{'pve-version'};
    }

    $current .= "+$pve_version" if $current && $pve_version;

    # fallback to the default machine if current is not supported by qemu
    return $current || $default || 'pc';
}

# returns a string with major.minor+pve<VERSION>, patch version-part is ignored
# as it's seldom ressembling a real QEMU machine type, so it would be '0' 99% of
# the time anyway.. This explicitly separates pveversion from the machine.
sub extract_version {
    my ($machine_type, $kvmversion) = @_;

    if (defined($machine_type) && $machine_type =~ m/^(?:pc(?:-i440fx|-q35)?|virt)-(\d+)\.(\d+)(?:\.(\d+))?(\+pve\d+)?/) {
	my $versionstr = "$1.$2";
	$versionstr .= $4 if $4;
	return $versionstr;
    } elsif (defined($kvmversion)) {
	if ($kvmversion =~ m/^(\d+)\.(\d+)/) {
	    return "$1.$2+pve$PVE_MACHINE_VERSION";
	}
    }

    return undef;
}

sub machine_version {
    my ($machine_type, $major, $minor, $pve) = @_;

    return PVE::QemuServer::Helpers::min_version(
	extract_version($machine_type), $major, $minor, $pve);
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
