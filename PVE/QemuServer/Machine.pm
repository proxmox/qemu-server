package PVE::QemuServer::Machine;

use strict;
use warnings;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::MetaInfo;
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
	pattern => '(pc|pc(-i440fx)?-\d+(\.\d+)+(\+pve\d+)?(\.pxe)?|q35|pc-q35-\d+(\.\d+)+(\+pve\d+)?(\.pxe)?|virt(?:-\d+(\.\d+)+)?(\+pve\d+)?)',
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

my $default_machines = {
    x86_64 => 'pc',
    aarch64 => 'virt',
};

sub default_machine_for_arch {
    my ($arch) = @_;

    my $machine = $default_machines->{$arch} or die "unsupported architecture '$arch'\n";
    return $machine;
}

sub assert_valid_machine_property {
    my ($machine_conf) = @_;
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
# as it's seldom resembling a real QEMU machine type, so it would be '0' 99% of
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

sub is_machine_version_at_least {
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

sub qemu_machine_pxe {
    my ($vmid, $conf) = @_;

    my $machine =  get_current_qemu_machine($vmid);

    my $machine_conf = parse_machine($conf->{machine});
    if ($machine_conf->{type} && $machine_conf->{type} =~ m/\.pxe$/) {
	$machine .= '.pxe';
    }

    return $machine;
}

sub get_installed_machine_version {
    my ($kvmversion) = @_;
    $kvmversion = PVE::QemuServer::Helpers::kvm_user_version() if !defined($kvmversion);
    $kvmversion =~ m/^(\d+\.\d+)/;
    return $1;
}

sub windows_get_pinned_machine_version {
    my ($machine, $base_version, $kvmversion) = @_;

    my $pin_version = $base_version;
    if (!defined($base_version) || !can_run_pve_machine_version($base_version, $kvmversion)) {
	$pin_version = get_installed_machine_version($kvmversion);
    }
    if (!$machine || $machine eq 'pc') {
	$machine = "pc-i440fx-$pin_version";
    } elsif ($machine eq 'q35') {
	$machine = "pc-q35-$pin_version";
    } elsif ($machine eq 'virt') {
	$machine = "virt-$pin_version";
    } else {
	warn "unknown machine type '$machine', not touching that!\n";
    }

    return $machine;
}

sub get_vm_machine {
    my ($conf, $forcemachine, $arch) = @_;

    my $machine_conf = parse_machine($conf->{machine});
    my $machine = $forcemachine || $machine_conf->{type};

    if (!$machine || $machine =~ m/^(?:pc|q35|virt)$/) {
	my $kvmversion = PVE::QemuServer::Helpers::kvm_user_version();
	# we must pin Windows VMs without a specific version and no meta info about creation QEMU to
	# 5.1, as 5.2 fixed a bug in ACPI layout which confuses windows quite a bit and may result
	# in various regressions..
	# see: https://lists.gnu.org/archive/html/qemu-devel/2021-02/msg08484.html
	# Starting from QEMU 9.1, pin to the creation version instead. Support for 5.1 is expected
	# to drop with QEMU 11.1 and it would still be good to handle Windows VMs that do not have
	# an explicit machine version for whatever reason.
	if (PVE::QemuServer::Helpers::windows_version($conf->{ostype})) {
	    my $base_version = '5.1';
	    # TODO PVE 10 - die early if there is a Windows VM both without explicit machine version
	    # and without meta info.
	    if (my $meta = PVE::QemuServer::MetaInfo::parse_meta_info($conf->{meta})) {
		if (PVE::QemuServer::Helpers::min_version($meta->{'creation-qemu'}, 9, 1)) {
		    # need only major.minor
		    ($base_version) = ($meta->{'creation-qemu'} =~ m/^(\d+.\d+)/);
		}
	    }
	    $machine = windows_get_pinned_machine_version($machine, $base_version, $kvmversion);
	} else {
	    $arch //= 'x86_64';
	    $machine ||= default_machine_for_arch($arch);
	    my $pvever = get_pve_version($kvmversion);
	    $machine .= "+pve$pvever";
	}
    }

    if ($machine !~ m/\+pve\d+?(?:\.pxe)?$/) {
	my $is_pxe = $machine =~ m/^(.*?)\.pxe$/;
	$machine = $1 if $is_pxe;

	# for version-pinned machines that do not include a pve-version (e.g.
	# pc-q35-4.1), we assume 0 to keep them stable in case we bump
	$machine .= '+pve0';

	$machine .= '.pxe' if $is_pxe;
    }

    return $machine;
}

sub check_and_pin_machine_string {
    my ($machine_string, $ostype) = @_;

    my $machine_conf = parse_machine($machine_string);
    my $machine = $machine_conf->{type};
    if (!$machine || $machine =~ m/^(?:pc|q35|virt)$/) {
	# always pin Windows' machine version on create, they get confused too easily
	if (PVE::QemuServer::Helpers::windows_version($ostype)) {
	    $machine_conf->{type} = windows_get_pinned_machine_version($machine);
	    print "pinning machine type to '$machine_conf->{type}' for Windows guest OS\n";
	}
    }

    assert_valid_machine_property($machine_conf);
    return print_machine($machine_conf);
}

1;
