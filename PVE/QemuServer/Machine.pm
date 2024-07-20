package PVE::QemuServer::Machine;

use strict;
use warnings;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;
use PVE::JSONSchema qw(get_standard_option parse_property_string print_property_string);

# Bump this for VM HW layout changes during a release (where the QEMU machine
# version stays the same)
our $PVE_MACHINE_VERSION = {
    '4.1' => 2,
};

my $machine_fmt = {
    type => {
	default_key => 1,
	description => "Specifies the QEMU machine type.",
	type => 'string',
	pattern => '(pc|pc(-i440fx)?-\d+(\.\d+)+(\+pve\d+)?(\.pxe)?|q35|pc-q35-\d+(\.\d+)+(\+pve\d+)?(\.pxe)?|virt(?:-\d+(\.\d+)+)?(\+pve\d+)?|sun4[a-z]{1}|SS-\d{1,2})',
	maxLength => 40,
	format_description => 'machine type',
	optional => 1,
    },
    viommu => {
	type => 'string',
	description => "Enable and set guest vIOMMU variant (Intel vIOMMU needs q35 to be set as"
	    ." machine type).",
	enum => ['intel', 'virtio'],
	optional => 1,
    },
};

PVE::JSONSchema::register_format('pve-qemu-machine-fmt', $machine_fmt);

PVE::JSONSchema::register_standard_option('pve-qemu-machine', {
    description => "Specify the QEMU machine.",
    type => 'string',
    optional => 1,
    format => PVE::JSONSchema::get_format('pve-qemu-machine-fmt'),
});

sub parse_machine {
    my ($value) = @_;

    return if !$value;

    my $res = parse_property_string($machine_fmt, $value);
    return $res;
}

sub print_machine {
    my ($machine_conf) = @_;
    return print_property_string($machine_conf, $machine_fmt);
}

sub assert_valid_machine_property {
    my ($conf, $machine_conf) = @_;
    my $q35 = $machine_conf->{type} && ($machine_conf->{type} =~ m/q35/) ? 1 : 0;
    if ($machine_conf->{viommu} && $machine_conf->{viommu} eq "intel" && !$q35) {
	die "to use Intel vIOMMU please set the machine type to q35\n";
    }
}

sub machine_type_is_q35 {
    my ($conf) = @_;

    my $machine_conf = parse_machine($conf->{machine});
    return $machine_conf->{type} && ($machine_conf->{type} =~ m/q35/) ? 1 : 0;
}

# In list context, also returns whether the current machine is deprecated or not.
sub current_from_query_machines {
    my ($machines) = @_;

    my ($current, $default);
    for my $machine ($machines->@*) {
	$default = $machine->{name} if $machine->{'is-default'};

	if ($machine->{'is-current'}) {
	    $current = $machine->{name};
	    # pve-version only exists for the current machine
	    $current .= "+$machine->{'pve-version'}" if $machine->{'pve-version'};
	    return wantarray ? ($current, $machine->{deprecated} ? 1 : 0) : $current;
	}
    }

    # fallback to the default machine if current is not supported by qemu - assume never deprecated
    my $fallback = $default || 'pc';
    return wantarray ? ($fallback, 0) : $fallback;
}

# This only works if VM is running.
# In list context, also returns whether the current machine is deprecated or not.
sub get_current_qemu_machine {
    my ($vmid) = @_;

    my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, 'query-machines');

    return current_from_query_machines($res);
}

# returns a string with major.minor+pve<VERSION>, patch version-part is ignored
# as it's seldom ressembling a real QEMU machine type, so it would be '0' 99% of
# the time anyway.. This explicitly separates pveversion from the machine.
sub extract_version {
    my ($machine_type, $kvmversion) = @_;

    if (defined($machine_type) && $machine_type =~
	m/^(?:pc(?:-i440fx|-q35)?|virt)-(\d+)\.(\d+)(?:\.(\d+))?(\+pve\d+)?(?:\.pxe)?/)
    {
	my $versionstr = "$1.$2";
	$versionstr .= $4 if $4;
	return $versionstr;
    } elsif (defined($kvmversion)) {
	if ($kvmversion =~ m/^(\d+)\.(\d+)/) {
	    my $pvever = get_pve_version($kvmversion);
	    return "$1.$2+pve$pvever";
	}
    }

    return;
}

sub machine_version {
    my ($machine_type, $major, $minor, $pve) = @_;

    return PVE::QemuServer::Helpers::min_version(
	extract_version($machine_type), $major, $minor, $pve);
}

sub get_pve_version {
    my ($verstr) = @_;

    if ($verstr =~ m/^(\d+\.\d+)/) {
	return $PVE_MACHINE_VERSION->{$1} // 0;
    }

    die "internal error: cannot get pve version for invalid string '$verstr'";
}

sub can_run_pve_machine_version {
    my ($machine_version, $kvmversion) = @_;

    $machine_version =~ m/^(\d+)\.(\d+)(?:\+pve(\d+))?(?:\.pxe)?$/;
    my $major = $1;
    my $minor = $2;
    my $pvever = $3;

    $kvmversion =~ m/(\d+)\.(\d+)/;
    return 0 if PVE::QemuServer::Helpers::version_cmp($1, $major, $2, $minor) < 0;

    # if $pvever is missing or 0, we definitely support it as long as we didn't
    # fail the QEMU version check above
    return 1 if !$pvever;

    my $max_supported = get_pve_version("$major.$minor");
    return 1 if $max_supported >= $pvever;

    return 0;
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

    my $machine_conf = parse_machine($conf->{machine});
    if ($machine_conf->{type} && $machine_conf->{type} =~ m/\.pxe$/) {
	$machine .= '.pxe';
    }

    return $machine;
}

1;
