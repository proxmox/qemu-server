package PVE::QemuServer::CPUFlags;

use v5.36;

use Exporter qw(import);

use PVE::Cluster;
use PVE::File;
use PVE::QemuServer::Helpers qw(get_host_arch);

our @EXPORT_OK = qw(
    cpu_flag_supported_re
    cpu_flag_any_re
    supported_cpu_flags_names
    get_supported_cpu_flags
    query_understood_cpu_flags
);

my $supported_vm_specific_cpu_flags_by_arch = {
    x86_64 => [
        {
            name => 'nested-virt',
            description =>
                "Controls nested virtualization, namely 'svm' for AMD CPUs and 'vmx' for"
                . " Intel CPUs. Live migration still only works if it's the same flag on both sides."
                . " Use a CPU model similar to the host, with the same vendor, not x86-64-vX!",
        },
        {
            name => 'md-clear',
            description => "Required to let the guest OS know if MDS is mitigated correctly.",
        },
        {
            name => 'pcid',
            description =>
                "Meltdown fix cost reduction on Westmere, Sandy-, and IvyBridge Intel CPUs.",
        },
        {
            name => 'spec-ctrl',
            description => "Allows improved Spectre mitigation with Intel CPUs.",
        },
        {
            name => 'ssbd',
            description => "Protection for 'Speculative Store Bypass' for Intel models.",
        },
        {
            name => 'ibpb',
            description => "Allows improved Spectre mitigation with AMD CPUs.",
        },
        {
            name => 'virt-ssbd',
            description => "Basis for 'Speculative Store Bypass' protection for AMD models.",
        },
        {
            name => 'amd-ssbd',
            description =>
                "Improves Spectre mitigation performance with AMD CPUs, best used with"
                . " 'virt-ssbd'.",
        },
        {
            name => 'amd-no-ssb',
            description =>
                "Notifies guest OS that host is not vulnerable for Spectre on AMD CPUs.",
        },
        {
            name => 'pdpe1gb',
            description => "Allow guest OS to use 1GB size pages, if host HW supports it.",
        },
        {
            name => 'hv-tlbflush',
            description =>
                "Improve performance in overcommitted Windows guests. May lead to guest"
                . " bluescreens on old CPUs.",
        },
        {
            name => 'hv-evmcs',
            description =>
                "Improve performance for nested virtualization. Only supported on Intel" . " CPUs.",
        },
        {
            name => 'aes',
            description => "Activate AES instruction set for HW acceleration.",
        },
    ],
    aarch64 => [],
};

my $all_supported_vm_specific_cpu_flags = {};
for my $arch (keys $supported_vm_specific_cpu_flags_by_arch->%*) {
    for my $flag ($supported_vm_specific_cpu_flags_by_arch->{$arch}->@*) {
        $all_supported_vm_specific_cpu_flags->{ $flag->{name} } = 1;
    }
}

my @supported_cpu_flags_name_sorted = sort keys $all_supported_vm_specific_cpu_flags->%*;

# Understood CPU flags are written to a file at 'pve-qemu' compile time and
# shipped below this directory by the pve-qemu-kvm package.
my $understood_cpu_flag_dir = "/usr/share/kvm";

sub supported_cpu_flags_names() {
    return @supported_cpu_flags_name_sorted;
}

sub cpu_flag_supported_re() {
    return qr/([+-])(@{[join('|', supported_cpu_flags_names())]})/;
}

sub cpu_flag_any_re() {
    return qr/([+-])([a-zA-Z0-9\-_\.]+)/;
}

=head3 get_supported_cpu_flags($arch)

Return supported VM-specific CPU flags for $arch. $arch defaults to the host architecture
if C<undef>.

=cut

sub get_supported_cpu_flags($arch) {
    $arch = get_host_arch() if !defined($arch);
    return $supported_vm_specific_cpu_flags_by_arch->{$arch};
}

sub query_understood_cpu_flags($arch) {
    my $filepath = "$understood_cpu_flag_dir/recognized-CPUID-flags-$arch";

    die "Cannot query understood QEMU CPU flags for architecture: $arch (file not found)\n"
        if !-e $filepath;

    my $raw = PVE::File::file_get_contents($filepath);
    $raw =~ s/^\s+|\s+$//g;
    my @flags = split(/\s+/, $raw);

    return \@flags;
}

1;
