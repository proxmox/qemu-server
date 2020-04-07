package PVE::QemuServer::CPUConfig;

use strict;
use warnings;

use PVE::JSONSchema;
use PVE::Cluster qw(cfs_register_file cfs_read_file);
use PVE::QemuServer::Helpers qw(min_version);

use base qw(PVE::SectionConfig Exporter);

our @EXPORT_OK = qw(
print_cpu_device
get_cpu_options
);

# under certain race-conditions, this module might be loaded before pve-cluster
# has started completely, so ensure we don't prevent the FUSE mount with our dir
if (PVE::Cluster::check_cfs_is_mounted(1)) {
    mkdir "/etc/pve/virtual-guest";
}

my $default_filename = "virtual-guest/cpu-models.conf";
cfs_register_file($default_filename,
		  sub { PVE::QemuServer::CPUConfig->parse_config(@_); },
		  sub { PVE::QemuServer::CPUConfig->write_config(@_); });

sub load_custom_model_conf {
    return cfs_read_file($default_filename);
}

my $cpu_vendor_list = {
    # Intel CPUs
    486 => 'GenuineIntel',
    pentium => 'GenuineIntel',
    pentium2 => 'GenuineIntel',
    pentium3 => 'GenuineIntel',
    coreduo => 'GenuineIntel',
    core2duo => 'GenuineIntel',
    Conroe => 'GenuineIntel',
    Penryn => 'GenuineIntel',
    Nehalem => 'GenuineIntel',
    'Nehalem-IBRS' => 'GenuineIntel',
    Westmere => 'GenuineIntel',
    'Westmere-IBRS' => 'GenuineIntel',
    SandyBridge => 'GenuineIntel',
    'SandyBridge-IBRS' => 'GenuineIntel',
    IvyBridge => 'GenuineIntel',
    'IvyBridge-IBRS' => 'GenuineIntel',
    Haswell => 'GenuineIntel',
    'Haswell-IBRS' => 'GenuineIntel',
    'Haswell-noTSX' => 'GenuineIntel',
    'Haswell-noTSX-IBRS' => 'GenuineIntel',
    Broadwell => 'GenuineIntel',
    'Broadwell-IBRS' => 'GenuineIntel',
    'Broadwell-noTSX' => 'GenuineIntel',
    'Broadwell-noTSX-IBRS' => 'GenuineIntel',
    'Skylake-Client' => 'GenuineIntel',
    'Skylake-Client-IBRS' => 'GenuineIntel',
    'Skylake-Client-noTSX-IBRS' => 'GenuineIntel',
    'Skylake-Server' => 'GenuineIntel',
    'Skylake-Server-IBRS' => 'GenuineIntel',
    'Skylake-Server-noTSX-IBRS' => 'GenuineIntel',
    'Cascadelake-Server' => 'GenuineIntel',
    'Cascadelake-Server-noTSX' => 'GenuineIntel',
    KnightsMill => 'GenuineIntel',
    'Icelake-Client' => 'GenuineIntel',
    'Icelake-Client-noTSX' => 'GenuineIntel',
    'Icelake-Server' => 'GenuineIntel',
    'Icelake-Server-noTSX' => 'GenuineIntel',

    # AMD CPUs
    athlon => 'AuthenticAMD',
    phenom => 'AuthenticAMD',
    Opteron_G1 => 'AuthenticAMD',
    Opteron_G2 => 'AuthenticAMD',
    Opteron_G3 => 'AuthenticAMD',
    Opteron_G4 => 'AuthenticAMD',
    Opteron_G5 => 'AuthenticAMD',
    EPYC => 'AuthenticAMD',
    'EPYC-IBPB' => 'AuthenticAMD',

    # generic types, use vendor from host node
    host => 'default',
    kvm32 => 'default',
    kvm64 => 'default',
    qemu32 => 'default',
    qemu64 => 'default',
    max => 'default',
};

my @supported_cpu_flags = (
    'pcid',
    'spec-ctrl',
    'ibpb',
    'ssbd',
    'virt-ssbd',
    'amd-ssbd',
    'amd-no-ssb',
    'pdpe1gb',
    'md-clear',
    'hv-tlbflush',
    'hv-evmcs',
    'aes'
);
my $cpu_flag_supported_re = qr/([+-])(@{[join('|', @supported_cpu_flags)]})/;
my $cpu_flag_any_re = qr/([+-])([a-zA-Z0-9\-_\.]+)/;

our $qemu_cmdline_cpu_re = qr/^((?>[+-]?[\w\-_=]+,?)+)$/;

my $cpu_fmt = {
    cputype => {
	description => "Emulated CPU type. Can be default or custom name (custom model names must be prefixed with 'custom-').",
	type => 'string',
	format_description => 'string',
	default => 'kvm64',
	default_key => 1,
	optional => 1,
    },
    'reported-model' => {
	description => "CPU model and vendor to report to the guest. Must be a QEMU/KVM supported model."
		     . " Only valid for custom CPU model definitions, default models will always report themselves to the guest OS.",
	type => 'string',
	enum => [ sort { lc("$a") cmp lc("$b") } keys %$cpu_vendor_list ],
	default => 'kvm64',
	optional => 1,
    },
    hidden => {
	description => "Do not identify as a KVM virtual machine.",
	type => 'boolean',
	optional => 1,
	default => 0
    },
    'hv-vendor-id' => {
	type => 'string',
	pattern => qr/[a-zA-Z0-9]{1,12}/,
	format_description => 'vendor-id',
	description => 'The Hyper-V vendor ID. Some drivers or programs inside Windows guests need a specific ID.',
	optional => 1,
    },
    flags => {
	description => "List of additional CPU flags separated by ';'."
		     . " Use '+FLAG' to enable, '-FLAG' to disable a flag."
		     . " Custom CPU models can specify any flag supported by"
		     . " QEMU/KVM, VM-specific flags must be from the following"
		     . " set for security reasons: @{[join(', ', @supported_cpu_flags)]}.",
	format_description => '+FLAG[;-FLAG...]',
	type => 'string',
	pattern => qr/$cpu_flag_any_re(;$cpu_flag_any_re)*/,
	optional => 1,
    },
};

# $cpu_fmt describes both the CPU config passed as part of a VM config, as well
# as the definition of a custom CPU model. There are some slight differences
# though, which we catch in the custom verification function below.
PVE::JSONSchema::register_format('pve-cpu-conf', \&parse_cpu_conf_basic);
sub parse_cpu_conf_basic {
    my ($cpu_str, $noerr) = @_;

    my $cpu = eval { PVE::JSONSchema::parse_property_string($cpu_fmt, $cpu_str) };
    if ($@) {
        die $@ if !$noerr;
        return undef;
    }

    # required, but can't be forced in schema since it's encoded in section
    # header for custom models
    if (!$cpu->{cputype}) {
	die "CPU is missing cputype\n" if !$noerr;
	return undef;
    }

    return $cpu;
}

PVE::JSONSchema::register_format('pve-vm-cpu-conf', \&parse_vm_cpu_conf);
sub parse_vm_cpu_conf {
    my ($cpu_str, $noerr) = @_;

    my $cpu = parse_cpu_conf_basic($cpu_str, $noerr);
    return undef if !$cpu;

    my $cputype = $cpu->{cputype};

    # a VM-specific config is only valid if the cputype exists
    if (is_custom_model($cputype)) {
	eval { get_custom_model($cputype); };
	if ($@) {
	    die $@ if !$noerr;
	    return undef;
	}
    } else {
	if (!defined($cpu_vendor_list->{$cputype})) {
	    die "Built-in cputype '$cputype' is not defined (missing 'custom-' prefix?)\n" if !$noerr;
	    return undef;
	}
    }

    # in a VM-specific config, certain properties are limited/forbidden

    if ($cpu->{flags} && $cpu->{flags} !~ m/$cpu_flag_supported_re(;$cpu_flag_supported_re)*/) {
	die "VM-specific CPU flags must be a subset of: @{[join(', ', @supported_cpu_flags)]}\n"
	    if !$noerr;
	return undef;
    }

    die "Property 'reported-model' not allowed in VM-specific CPU config.\n"
	if defined($cpu->{'reported-model'});

    return $cpu;
}

# Section config settings
my $defaultData = {
    # shallow copy, since SectionConfig modifies propertyList internally
    propertyList => { %$cpu_fmt },
};

sub private {
    return $defaultData;
}

sub options {
    return { %$cpu_fmt };
}

sub type {
    return 'cpu-model';
}

sub parse_section_header {
    my ($class, $line) = @_;

    my ($type, $sectionId, $errmsg, $config) =
	$class->SUPER::parse_section_header($line);

    return undef if !$type;
    return ($type, $sectionId, $errmsg, {
	# name is given by section header, and we can always prepend 'custom-'
	# since we're reading the custom CPU file
	cputype => "custom-$sectionId",
    });
}

sub write_config {
    my ($class, $filename, $cfg) = @_;

    mkdir "/etc/pve/virtual-guest";

    for my $model (keys %{$cfg->{ids}}) {
	my $model_conf = $cfg->{ids}->{$model};

	die "internal error: tried saving built-in CPU model (or missing prefix): $model_conf->{cputype}\n"
	    if !is_custom_model($model_conf->{cputype});

	die "internal error: tried saving custom cpumodel with cputype (ignoring prefix: $model_conf->{cputype}) not equal to \$cfg->ids entry ($model)\n"
	    if "custom-$model" ne $model_conf->{cputype};

	# saved in section header
	delete $model_conf->{cputype};
    }

    $class->SUPER::write_config($filename, $cfg);
}

sub is_custom_model {
    my ($cputype) = @_;
    return $cputype =~ m/^custom-/;
}

# Use this to get a single model in the format described by $cpu_fmt.
# Allows names with and without custom- prefix.
sub get_custom_model {
    my ($name, $noerr) = @_;

    $name =~ s/^custom-//;
    my $conf = load_custom_model_conf();

    my $entry = $conf->{ids}->{$name};
    if (!defined($entry)) {
	die "Custom cputype '$name' not found\n" if !$noerr;
	return undef;
    }

    my $model = {};
    for my $property (keys %$cpu_fmt) {
	if (my $value = $entry->{$property}) {
	    $model->{$property} = $value;
	}
    }

    return $model;
}

# Print a QEMU device node for a given VM configuration for hotplugging CPUs
sub print_cpu_device {
    my ($conf, $id) = @_;

    my $kvm = $conf->{kvm} // 1;
    my $cpu = $kvm ? "kvm64" : "qemu64";
    if (my $cputype = $conf->{cpu}) {
	my $cpuconf = parse_cpu_conf_basic($cputype)
	    or die "Cannot parse cpu description: $cputype\n";
	$cpu = $cpuconf->{cputype};

	if (is_custom_model($cpu)) {
	    my $custom_cpu = get_custom_model($cpu);

	    $cpu = $custom_cpu->{'reported-model'} //
		$cpu_fmt->{'reported-model'}->{default};
	}
    }

    my $cores = $conf->{cores} || 1;

    my $current_core = ($id - 1) % $cores;
    my $current_socket = int(($id - 1 - $current_core)/$cores);

    return "$cpu-x86_64-cpu,id=cpu$id,socket-id=$current_socket,core-id=$current_core,thread-id=0";
}

# Calculate QEMU's '-cpu' argument from a given VM configuration
sub get_cpu_options {
    my ($conf, $arch, $kvm, $kvm_off, $machine_version, $winversion, $gpu_passthrough) = @_;

    my $cpuFlags = [];
    my $ostype = $conf->{ostype};

    my $cpu = $kvm ? "kvm64" : "qemu64";
    if ($arch eq 'aarch64') {
	$cpu = 'cortex-a57';
    }
    my $hv_vendor_id;
    if (my $cputype = $conf->{cpu}) {
	my $cpuconf = PVE::JSONSchema::parse_property_string($cpu_fmt, $cputype)
	    or die "Cannot parse cpu description: $cputype\n";
	$cpu = $cpuconf->{cputype};
	$kvm_off = 1 if $cpuconf->{hidden};
	$hv_vendor_id = $cpuconf->{'hv-vendor-id'};

	if (defined(my $flags = $cpuconf->{flags})) {
	    push @$cpuFlags, split(";", $flags);
	}
    }

    push @$cpuFlags , '+lahf_lm' if $cpu eq 'kvm64' && $arch eq 'x86_64';

    push @$cpuFlags , '-x2apic' if $ostype && $ostype eq 'solaris';

    push @$cpuFlags, '+sep' if $cpu eq 'kvm64' || $cpu eq 'kvm32';

    push @$cpuFlags, '-rdtscp' if $cpu =~ m/^Opteron/;

    if (min_version($machine_version, 2, 3) && $arch eq 'x86_64') {

	push @$cpuFlags , '+kvm_pv_unhalt' if $kvm;
	push @$cpuFlags , '+kvm_pv_eoi' if $kvm;
    }

    add_hyperv_enlightenments($cpuFlags, $winversion, $machine_version, $conf->{bios}, $gpu_passthrough, $hv_vendor_id) if $kvm;

    push @$cpuFlags, 'enforce' if $cpu ne 'host' && $kvm && $arch eq 'x86_64';

    push @$cpuFlags, 'kvm=off' if $kvm_off;

    if (my $cpu_vendor = $cpu_vendor_list->{$cpu}) {
	push @$cpuFlags, "vendor=${cpu_vendor}"
	    if $cpu_vendor ne 'default';
    } elsif ($arch ne 'aarch64') {
	die "internal error"; # should not happen
    }

    $cpu .= "," . join(',', @$cpuFlags) if scalar(@$cpuFlags);

    return ('-cpu', $cpu);
}

sub add_hyperv_enlightenments {
    my ($cpuFlags, $winversion, $machine_version, $bios, $gpu_passthrough, $hv_vendor_id) = @_;

    return if $winversion < 6;
    return if $bios && $bios eq 'ovmf' && $winversion < 8;

    if ($gpu_passthrough || defined($hv_vendor_id)) {
	$hv_vendor_id //= 'proxmox';
	push @$cpuFlags , "hv_vendor_id=$hv_vendor_id";
    }

    if (min_version($machine_version, 2, 3)) {
	push @$cpuFlags , 'hv_spinlocks=0x1fff';
	push @$cpuFlags , 'hv_vapic';
	push @$cpuFlags , 'hv_time';
    } else {
	push @$cpuFlags , 'hv_spinlocks=0xffff';
    }

    if (min_version($machine_version, 2, 6)) {
	push @$cpuFlags , 'hv_reset';
	push @$cpuFlags , 'hv_vpindex';
	push @$cpuFlags , 'hv_runtime';
    }

    if ($winversion >= 7) {
	push @$cpuFlags , 'hv_relaxed';

	if (min_version($machine_version, 2, 12)) {
	    push @$cpuFlags , 'hv_synic';
	    push @$cpuFlags , 'hv_stimer';
	}

	if (min_version($machine_version, 3, 1)) {
	    push @$cpuFlags , 'hv_ipi';
	}
    }
}

sub get_cpu_from_running_vm {
    my ($pid) = @_;

    my $cmdline = PVE::QemuServer::Helpers::parse_cmdline($pid);
    die "could not read commandline of running machine\n"
	if !$cmdline->{cpu}->{value};

    # sanitize and untaint value
    $cmdline->{cpu}->{value} =~ $qemu_cmdline_cpu_re;
    return $1;
}

__PACKAGE__->register();
__PACKAGE__->init();

1;
