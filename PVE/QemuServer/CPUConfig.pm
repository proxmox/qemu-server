package PVE::QemuServer::CPUConfig;

use strict;
use warnings;

use PVE::JSONSchema;
use PVE::QemuServer::Helpers qw(min_version);

use base qw(Exporter);

our @EXPORT_OK = qw(
print_cpu_device
get_cpu_options
);

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
my $cpu_flag = qr/[+-](@{[join('|', @supported_cpu_flags)]})/;

our $cpu_fmt = {
    cputype => {
	description => "Emulated CPU type.",
	type => 'string',
	enum => [ sort { "\L$a" cmp "\L$b" } keys %$cpu_vendor_list ],
	default => 'kvm64',
	default_key => 1,
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
		     . " Currently supported flags: @{[join(', ', @supported_cpu_flags)]}.",
	format_description => '+FLAG[;-FLAG...]',
	type => 'string',
	pattern => qr/$cpu_flag(;$cpu_flag)*/,
	optional => 1,
    },
};

# Print a QEMU device node for a given VM configuration for hotplugging CPUs
sub print_cpu_device {
    my ($conf, $id) = @_;

    my $kvm = $conf->{kvm} // 1;
    my $cpu = $kvm ? "kvm64" : "qemu64";
    if (my $cputype = $conf->{cpu}) {
	my $cpuconf = PVE::JSONSchema::parse_property_string($cpu_fmt, $cputype)
	    or die "Cannot parse cpu description: $cputype\n";
	$cpu = $cpuconf->{cputype};
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

1;
