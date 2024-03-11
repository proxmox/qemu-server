package PVE::QemuServer::CPUConfig;

use strict;
use warnings;

use PVE::JSONSchema;
use PVE::Cluster qw(cfs_register_file cfs_read_file);
use PVE::Tools qw(get_host_arch);
use PVE::QemuServer::Helpers qw(min_version);

use base qw(PVE::SectionConfig Exporter);

our @EXPORT_OK = qw(
print_cpu_device
get_cpu_options
get_cpu_bitness
is_native_arch
);

# under certain race-conditions, this module might be loaded before pve-cluster
# has started completely, so ensure we don't prevent the FUSE mount with our dir
if (PVE::Cluster::check_cfs_is_mounted(1)) {
    mkdir "/etc/pve/virtual-guest";
}

my $default_filename = "virtual-guest/cpu-models.conf";
cfs_register_file(
    $default_filename,
    sub { PVE::QemuServer::CPUConfig->parse_config(@_); },
    sub { PVE::QemuServer::CPUConfig->write_config(@_); },
);

sub load_custom_model_conf {
    return cfs_read_file($default_filename);
}

#builtin models : reported-model is mandatory
my $builtin_models = {
    'x86-64-v2' => {
	'reported-model' => 'qemu64',
	flags => "+popcnt;+pni;+sse4.1;+sse4.2;+ssse3",
    },
    'x86-64-v2-AES' => {
	'reported-model' => 'qemu64',
	flags => "+aes;+popcnt;+pni;+sse4.1;+sse4.2;+ssse3",
    },
    'x86-64-v3' => {
	'reported-model' => 'qemu64',
	flags => "+aes;+popcnt;+pni;+sse4.1;+sse4.2;+ssse3;+avx;+avx2;+bmi1;+bmi2;+f16c;+fma;+abm;+movbe;+xsave",
    },
    'x86-64-v4' => {
	'reported-model' => 'qemu64',
	flags => "+aes;+popcnt;+pni;+sse4.1;+sse4.2;+ssse3;+avx;+avx2;+bmi1;+bmi2;+f16c;+fma;+abm;+movbe;+xsave;+avx512f;+avx512bw;+avx512cd;+avx512dq;+avx512vl",
    },
};

my $depreacated_cpu_map = {
    # there never was such a client CPU, so map it to the server one for backward compat
    'Icelake-Client' => 'Icelake-Server',
    'Icelake-Client-noTSX' => 'Icelake-Server-noTSX',
};

my $cputypes_32bit = {
    '486' => 1,
    'pentium' => 1,
    'pentium2' => 1,
    'pentium3' => 1,
    'coreduo' => 1,
    'athlon' => 1,
    'kvm32' => 1,
    'qemu32' => 1,
};

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
    'Skylake-Client-v4' => 'GenuineIntel',
    'Skylake-Server' => 'GenuineIntel',
    'Skylake-Server-IBRS' => 'GenuineIntel',
    'Skylake-Server-noTSX-IBRS' => 'GenuineIntel',
    'Skylake-Server-v4' => 'GenuineIntel',
    'Skylake-Server-v5' => 'GenuineIntel',
    'Cascadelake-Server' => 'GenuineIntel',
    'Cascadelake-Server-v2' => 'GenuineIntel',
    'Cascadelake-Server-noTSX' => 'GenuineIntel',
    'Cascadelake-Server-v4' => 'GenuineIntel',
    'Cascadelake-Server-v5' => 'GenuineIntel',
    'Cooperlake' => 'GenuineIntel',
    'Cooperlake-v2' => 'GenuineIntel',
    KnightsMill => 'GenuineIntel',
    'Icelake-Client' => 'GenuineIntel', # depreacated, removed with QEMU 7.1
    'Icelake-Client-noTSX' => 'GenuineIntel', # depreacated, removed with QEMU 7.1
    'Icelake-Server' => 'GenuineIntel',
    'Icelake-Server-noTSX' => 'GenuineIntel',
    'Icelake-Server-v3' => 'GenuineIntel',
    'Icelake-Server-v4' => 'GenuineIntel',
    'Icelake-Server-v5' => 'GenuineIntel',
    'Icelake-Server-v6' => 'GenuineIntel',
    'SapphireRapids' => 'GenuineIntel',
    'SapphireRapids-v2' => 'GenuineIntel',
    'GraniteRapids' => 'GenuineIntel',

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
    'EPYC-v3' => 'AuthenticAMD',
    'EPYC-v4' => 'AuthenticAMD',
    'EPYC-Rome' => 'AuthenticAMD',
    'EPYC-Rome-v2' => 'AuthenticAMD',
    'EPYC-Rome-v3' => 'AuthenticAMD',
    'EPYC-Rome-v4' => 'AuthenticAMD',
    'EPYC-Milan' => 'AuthenticAMD',
    'EPYC-Milan-v2' => 'AuthenticAMD',
    'EPYC-Genoa' => 'AuthenticAMD',

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

our $qemu_cmdline_cpu_re = qr/^((?>[+-]?[\w\-\._=]+,?)+)$/;

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
	    ." Only valid for custom CPU model definitions, default models will always report themselves to the guest OS.",
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
	description => "List of additional CPU flags separated by ';'. Use '+FLAG' to enable,"
	    ." '-FLAG' to disable a flag. Custom CPU models can specify any flag supported by"
	    ." QEMU/KVM, VM-specific flags must be from the following set for security reasons: "
	    . join(', ', @supported_cpu_flags),
	format_description => '+FLAG[;-FLAG...]',
	type => 'string',
	pattern => qr/$cpu_flag_any_re(;$cpu_flag_any_re)*/,
	optional => 1,
    },
    'phys-bits' => {
	type => 'string',
	format => 'pve-phys-bits',
	format_description => '8-64|host',
	description => "The physical memory address bits that are reported to the guest OS. Should"
	    ." be smaller or equal to the host's. Set to 'host' to use value from host CPU, but"
	    ." note that doing so will break live migration to CPUs with other values.",
	optional => 1,
    },
};

PVE::JSONSchema::register_format('pve-phys-bits', \&parse_phys_bits);
sub parse_phys_bits {
    my ($str, $noerr) = @_;

    my $err_msg = "value must be an integer between 8 and 64 or 'host'\n";

    if ($str !~ m/^(host|\d{1,2})$/) {
	die $err_msg if !$noerr;
	return;
    }

    if ($str =~ m/^\d+$/ && (int($str) < 8 || int($str) > 64)) {
	die $err_msg if !$noerr;
	return;
    }

    return $str;
}

# $cpu_fmt describes both the CPU config passed as part of a VM config, as well
# as the definition of a custom CPU model. There are some slight differences
# though, which we catch in the custom validation functions below.
PVE::JSONSchema::register_format('pve-cpu-conf', $cpu_fmt, \&validate_cpu_conf);
sub validate_cpu_conf {
    my ($cpu) = @_;
    # required, but can't be forced in schema since it's encoded in section header for custom models
    die "CPU is missing cputype\n" if !$cpu->{cputype};
    return $cpu;
}
PVE::JSONSchema::register_format('pve-vm-cpu-conf', $cpu_fmt, \&validate_vm_cpu_conf);
sub validate_vm_cpu_conf {
    my ($cpu) = @_;

    validate_cpu_conf($cpu);

    my $cputype = $cpu->{cputype};

    # a VM-specific config is only valid if the cputype exists
    if (is_custom_model($cputype)) {
	# dies on unknown model
	get_custom_model($cputype);
    } else {
	die "Built-in cputype '$cputype' is not defined (missing 'custom-' prefix?)\n"
	    if !defined($cpu_vendor_list->{$cputype}) && !defined($builtin_models->{$cputype});
    }

    # in a VM-specific config, certain properties are limited/forbidden

    die "VM-specific CPU flags must be a subset of: @{[join(', ', @supported_cpu_flags)]}\n"
	if ($cpu->{flags} && $cpu->{flags} !~ m/^$cpu_flag_supported_re(;$cpu_flag_supported_re)*$/);

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

    return if !$type;
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

sub add_cpu_json_properties {
    my ($prop) = @_;

    foreach my $opt (keys %$cpu_fmt) {
	$prop->{$opt} = $cpu_fmt->{$opt};
    }

    return $prop;
}

sub get_cpu_models {
    my ($include_custom) = @_;

    my $models = [];

    for my $default_model (keys %{$cpu_vendor_list}) {
	push @$models, {
	    name => $default_model,
	    custom => 0,
	    vendor => $cpu_vendor_list->{$default_model},
	};
    }

    for my $model (keys %{$builtin_models}) {
	my $reported_model = $builtin_models->{$model}->{'reported-model'};
	my $vendor = $cpu_vendor_list->{$reported_model};
	push @$models, {
	    name => $model,
	    custom => 0,
	    vendor => $vendor,
	};
    }

    return $models if !$include_custom;

    my $conf = load_custom_model_conf();
    for my $custom_model (keys %{$conf->{ids}}) {
	my $reported_model = $conf->{ids}->{$custom_model}->{'reported-model'};
	$reported_model //= $cpu_fmt->{'reported-model'}->{default};
	my $vendor = $cpu_vendor_list->{$reported_model};
	push @$models, {
	    name => "custom-$custom_model",
	    custom => 1,
	    vendor => $vendor,
	};
    }

    return $models;
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
	return;
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
    my ($conf, $arch, $id) = @_;

    # FIXME: hot plugging other architectures like our unofficial aarch64 support?
    die "Hotplug of non x86_64 CPU not yet supported" if $arch ne 'x86_64';

    my $kvm = $conf->{kvm} // is_native_arch($arch);
    my $cpu = get_default_cpu_type('x86_64', $kvm);
    if (my $cputype = $conf->{cpu}) {
	my $cpuconf = PVE::JSONSchema::parse_property_string('pve-vm-cpu-conf', $cputype)
	    or die "Cannot parse cpu description: $cputype\n";
	$cpu = $cpuconf->{cputype};

	if (my $model = $builtin_models->{$cpu}) {
	    $cpu = $model->{'reported-model'};
	} elsif (is_custom_model($cputype)) {
	    my $custom_cpu = get_custom_model($cpu);

	    $cpu = $custom_cpu->{'reported-model'} // $cpu_fmt->{'reported-model'}->{default};
	}
	if (my $replacement_type = $depreacated_cpu_map->{$cpu}) {
	    $cpu = $replacement_type;
	}
    }

    my $cores = $conf->{cores} || 1;

    my $current_core = ($id - 1) % $cores;
    my $current_socket = int(($id - 1 - $current_core)/$cores);

    return "$cpu-x86_64-cpu,id=cpu$id,socket-id=$current_socket,core-id=$current_core,thread-id=0";
}

# Resolves multiple arrays of hashes representing CPU flags with metadata to a
# single string in QEMU "-cpu" compatible format. Later arrays have higher
# priority.
#
# Hashes take the following format:
# {
#     aes => {
#         op => "+", # defaults to "" if undefined
#         reason => "to support AES acceleration", # for override warnings
#         value => "" # needed for kvm=off (value: off) etc...
#     },
#     ...
# }
sub resolve_cpu_flags {
    my $flags = {};

    for my $hash (@_) {
	for my $flag_name (keys %$hash) {
	    my $flag = $hash->{$flag_name};
	    my $old_flag = $flags->{$flag_name};

	    $flag->{op} //= "";
	    $flag->{reason} //= "unknown origin";

	    if ($old_flag) {
		my $value_changed = (defined($flag->{value}) != defined($old_flag->{value})) ||
				    (defined($flag->{value}) && $flag->{value} ne $old_flag->{value});

		if ($old_flag->{op} eq $flag->{op} && !$value_changed) {
		    $flags->{$flag_name}->{reason} .= " & $flag->{reason}";
		    next;
		}

		my $old = print_cpuflag_hash($flag_name, $flags->{$flag_name});
		my $new = print_cpuflag_hash($flag_name, $flag);
		warn "warning: CPU flag/setting $new overwrites $old\n";
	    }

	    $flags->{$flag_name} = $flag;
	}
    }

    my $flag_str = '';
    # sort for command line stability
    for my $flag_name (sort keys %$flags) {
	$flag_str .= ',';
	$flag_str .= $flags->{$flag_name}->{op};
	$flag_str .= $flag_name;
	$flag_str .= "=$flags->{$flag_name}->{value}"
	    if $flags->{$flag_name}->{value};
    }

    return $flag_str;
}

sub print_cpuflag_hash {
    my ($flag_name, $flag) = @_;
    my $formatted = "'$flag->{op}$flag_name";
    $formatted .= "=$flag->{value}" if defined($flag->{value});
    $formatted .= "'";
    $formatted .= " ($flag->{reason})" if defined($flag->{reason});
    return $formatted;
}

sub parse_cpuflag_list {
    my ($re, $reason, $flaglist) = @_;

    my $res = {};
    return $res if !$flaglist;

    foreach my $flag (split(";", $flaglist)) {
	if ($flag =~ m/^$re$/) {
	    $res->{$2} = { op => $1, reason => $reason };
	}
    }

    return $res;
}

# Calculate QEMU's '-cpu' argument from a given VM configuration
sub get_cpu_options {
    my ($conf, $arch, $kvm, $kvm_off, $machine_version, $winversion, $gpu_passthrough) = @_;

    my $cputype = get_default_cpu_type($arch, $kvm);

    my $cpu = {};
    my $custom_cpu;
    my $builtin_cpu;
    my $hv_vendor_id;
    if (my $cpu_prop_str = $conf->{cpu}) {
	$cpu = PVE::JSONSchema::parse_property_string('pve-vm-cpu-conf', $cpu_prop_str)
	    or die "Cannot parse cpu description: $cpu_prop_str\n";

	$cputype = $cpu->{cputype};
	if (my $model = $builtin_models->{$cputype}) {
	    $cputype = $model->{'reported-model'};
	    $builtin_cpu->{flags} = $model->{'flags'};
	} elsif (is_custom_model($cputype)) {
	    $custom_cpu = get_custom_model($cputype);

	    $cputype = $custom_cpu->{'reported-model'} // $cpu_fmt->{'reported-model'}->{default};
	    $kvm_off = $custom_cpu->{hidden} if defined($custom_cpu->{hidden});
	    $hv_vendor_id = $custom_cpu->{'hv-vendor-id'};
	}

	if (my $replacement_type = $depreacated_cpu_map->{$cputype}) {
	    $cputype = $replacement_type;
	}

	# VM-specific settings override custom CPU config
	$kvm_off = $cpu->{hidden} if defined($cpu->{hidden});
	$hv_vendor_id = $cpu->{'hv-vendor-id'} if defined($cpu->{'hv-vendor-id'});
    }

    my $pve_flags = get_pve_cpu_flags($conf, $kvm, $cputype, $arch, $machine_version);

    my $hv_flags = $kvm
	? get_hyperv_enlightenments(
	    $winversion,
	    $machine_version,
	    $conf->{bios},
	    $gpu_passthrough,
	    $hv_vendor_id,
	)
	: undef;

    my $builtin_cputype_flags = parse_cpuflag_list(
	$cpu_flag_any_re, "set by builtin CPU model", $builtin_cpu->{flags});

    my $custom_cputype_flags = parse_cpuflag_list(
	$cpu_flag_any_re, "set by custom CPU model", $custom_cpu->{flags});

    my $vm_flags = parse_cpuflag_list(
	$cpu_flag_supported_re, "manually set for VM", $cpu->{flags});

    my $pve_forced_flags = {};
    $pve_forced_flags->{'enforce'} = {
	reason => "error if requested CPU settings not available",
    } if $cputype ne 'host' && $kvm && $arch eq 'x86_64';
    $pve_forced_flags->{'kvm'} = {
	value => "off",
	reason => "hide KVM virtualization from guest",
    } if $kvm_off;

    # $cputype is the "reported-model" for custom types, so we can just look up
    # the vendor in the default list
    my $cpu_vendor = $cpu_vendor_list->{$cputype};
    if ($cpu_vendor) {
	$pve_forced_flags->{'vendor'} = {
	    value => $cpu_vendor,
	} if $cpu_vendor ne 'default';
    } elsif ($arch ne 'aarch64') {
	die "internal error"; # should not happen
    }

    my $cpu_str = $cputype;

    # will be resolved in parameter order
    $cpu_str .= resolve_cpu_flags(
	$pve_flags, $hv_flags, $builtin_cputype_flags, $custom_cputype_flags, $vm_flags, $pve_forced_flags);

    my $phys_bits = '';
    foreach my $conf ($custom_cpu, $cpu) {
	next if !defined($conf);
	my $conf_val = $conf->{'phys-bits'};
	next if !$conf_val;
	if ($conf_val eq 'host') {
	    $phys_bits = ",host-phys-bits=true";
	} else {
	    $phys_bits = ",phys-bits=$conf_val";
	}
    }
    $cpu_str .= $phys_bits;

    return ('-cpu', $cpu_str);
}

# Some hardcoded flags required by certain configurations
sub get_pve_cpu_flags {
    my ($conf, $kvm, $cputype, $arch, $machine_version) = @_;

    my $pve_flags = {};
    my $pve_msg = "set by PVE;";

    $pve_flags->{'lahf_lm'} = {
	op => '+',
	reason => "$pve_msg to support Windows 8.1+",
    } if $cputype eq 'kvm64' && $arch eq 'x86_64';

    $pve_flags->{'x2apic'} = {
	op => '-',
	reason => "$pve_msg incompatible with Solaris",
    } if $conf->{ostype} && $conf->{ostype} eq 'solaris';

    $pve_flags->{'sep'} = {
	op => '+',
	reason => "$pve_msg to support Windows 8+ and improve Windows XP+",
    } if $cputype eq 'kvm64' || $cputype eq 'kvm32';

    $pve_flags->{'rdtscp'} = {
	op => '-',
	reason => "$pve_msg broken on AMD Opteron",
    } if $cputype =~ m/^Opteron/;

    if (min_version($machine_version, 2, 3) && $kvm && $arch eq 'x86_64') {
	$pve_flags->{'kvm_pv_unhalt'} = {
	    op => '+',
	    reason => "$pve_msg to improve Linux guest spinlock performance",
	};
	$pve_flags->{'kvm_pv_eoi'} = {
	    op => '+',
	    reason => "$pve_msg to improve Linux guest interrupt performance",
	};
    }

    return $pve_flags;
}

sub get_hyperv_enlightenments {
    my ($winversion, $machine_version, $bios, $gpu_passthrough, $hv_vendor_id) = @_;

    return if $winversion < 6;
    return if $bios && $bios eq 'ovmf' && $winversion < 8;

    my $flags = {};
    my $default_reason = "automatic Hyper-V enlightenment for Windows";
    my $flagfn = sub {
	my ($flag, $value, $reason) = @_;
	$flags->{$flag} = {
	    reason => $reason // $default_reason,
	    value => $value,
	}
    };

    my $hv_vendor_set = defined($hv_vendor_id);
    if ($gpu_passthrough || $hv_vendor_set) {
	$hv_vendor_id //= 'proxmox';
	$flagfn->('hv_vendor_id', $hv_vendor_id, $hv_vendor_set ?
	    "custom hv_vendor_id set" : "NVIDIA workaround for GPU passthrough");
    }

    if (min_version($machine_version, 2, 3)) {
	$flagfn->('hv_spinlocks', '0x1fff');
	$flagfn->('hv_vapic');
	$flagfn->('hv_time');
    } else {
	$flagfn->('hv_spinlocks', '0xffff');
    }

    if (min_version($machine_version, 2, 6)) {
	$flagfn->('hv_reset');
	$flagfn->('hv_vpindex');
	$flagfn->('hv_runtime');
    }

    if ($winversion >= 7) {
	my $win7_reason = $default_reason . " 7 and higher";
	$flagfn->('hv_relaxed', undef, $win7_reason);

	if (min_version($machine_version, 2, 12)) {
	    $flagfn->('hv_synic', undef, $win7_reason);
	    $flagfn->('hv_stimer', undef, $win7_reason);
	}

	if (min_version($machine_version, 3, 1)) {
	    $flagfn->('hv_ipi', undef, $win7_reason);
	}
    }

    return $flags;
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

sub get_default_cpu_type {
    my ($arch, $kvm) = @_;

    my $cputype = $kvm ? 'kvm64' : 'qemu64';
    $cputype = 'cortex-a57' if $arch eq 'aarch64';

    return $cputype;
}

sub is_native_arch($) {
    my ($arch) = @_;
    return get_host_arch() eq $arch;
}

sub get_cpu_bitness {
    my ($cpu_prop_str, $arch) = @_;

    $arch //= get_host_arch();

    my $cputype = get_default_cpu_type($arch, 0);

    if ($cpu_prop_str) {
	my $cpu = PVE::JSONSchema::parse_property_string('pve-vm-cpu-conf', $cpu_prop_str)
	    or die "Cannot parse cpu description: $cpu_prop_str\n";

	my $cputype = $cpu->{cputype};

	if (my $model = $builtin_models->{$cputype}) {
	    $cputype = $model->{'reported-model'};
	} elsif (is_custom_model($cputype)) {
	    my $custom_cpu = get_custom_model($cputype);
	    $cputype = $custom_cpu->{'reported-model'} // $cpu_fmt->{'reported-model'}->{default};
	}
    }

    return $cputypes_32bit->{$cputype} ? 32 : 64 if $arch eq 'x86_64';
    return 64 if $arch eq 'aarch64';

    die "unsupported architecture '$arch'\n";
}

__PACKAGE__->register();
__PACKAGE__->init();

1;
