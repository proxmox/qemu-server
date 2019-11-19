package PVE::QemuServer::Machine;

use strict;
use warnings;

use PVE::QemuServer::Monitor;

use base 'Exporter';
our @EXPORT_OK = qw(
qemu_machine_feature_enabled
);

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

sub qemu_machine_feature_enabled {
    my ($machine, $kvmver, $version_major, $version_minor) = @_;

    my $current_major;
    my $current_minor;

    if ($machine && $machine =~ m/^((?:pc(-i440fx|-q35)?|virt)-(\d+)\.(\d+))/) {

	$current_major = $3;
	$current_minor = $4;

    } elsif ($kvmver =~ m/^(\d+)\.(\d+)/) {

	$current_major = $1;
	$current_minor = $2;
    }

    return 1 if version_cmp($current_major, $version_major, $current_minor, $version_minor) >= 0;
}

# gets in pairs the versions you want to compares, i.e.:
# ($a-major, $b-major, $a-minor, $b-minor, $a-extra, $b-extra, ...)
# returns 0 if same, -1 if $a is older than $b, +1 if $a is newer than $b
sub version_cmp {
    my @versions = @_;

    my $size = scalar(@versions);

    return 0 if $size == 0;
    die "cannot compare odd count of versions" if $size & 1;

    for (my $i = 0; $i < $size; $i += 2) {
	my ($a, $b) = splice(@versions, 0, 2);
	$a //= 0;
	$b //= 0;

	return 1 if $a > $b;
	return -1 if $a < $b;
    }
    return 0;
}

# dies if a) VM not running or not exisiting b) Version query failed
# So, any defined return value is valid, any invalid state can be caught by eval
sub runs_at_least_qemu_version {
    my ($vmid, $major, $minor, $extra) = @_;

    my $v = PVE::QemuServer::Monitor::mon_cmd($vmid, 'query-version');
    die "could not query currently running version for VM $vmid\n" if !defined($v);
    $v = $v->{qemu};

    return version_cmp($v->{major}, $major, $v->{minor}, $minor, $v->{micro}, $extra) >= 0;
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
