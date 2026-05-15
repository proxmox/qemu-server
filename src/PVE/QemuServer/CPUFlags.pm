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
    normalize_cpu_flag
    query_available_cpu_flags
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

# qemu/target/i386/cpu.c, x86_cpu_initfn()
my $qemu_cpu_flag_alias_map = {
    sse3 => 'pni',
    pclmuldq => 'pclmulqdq',
    'sse4-1' => 'sse4.1',
    'sse4-2' => 'sse4.2',
    xd => 'nx',
    ffxsr => 'fxsr-opt',
    i64 => 'lm',
    ds_cpl => 'ds-cpl',
    tsc_adjust => 'tsc-adjust',
    fxsr_opt => 'fxsr-opt',
    lahf_lm => 'lahf-lm',
    cmp_legacy => 'cmp-legacy',
    nodeid_msr => 'nodeid-msr',
    perfctr_core => 'perfctr-core',
    perfctr_nb => 'perfctr-nb',
    kvm_nopiodelay => 'kvm-nopiodelay',
    kvm_mmu => 'kvm-mmu',
    kvm_asyncpf => 'kvm-asyncpf',
    kvm_asyncpf_int => 'kvm-asyncpf-int',
    kvm_steal_time => 'kvm-steal-time',
    kvm_pv_eoi => 'kvm-pv-eoi',
    kvm_pv_unhalt => 'kvm-pv-unhalt',
    kvm_poll_control => 'kvm-poll-control',
    svm_lock => 'svm-lock',
    nrip_save => 'nrip-save',
    tsc_scale => 'tsc-scale',
    vmcb_clean => 'vmcb-clean',
    pause_filter => 'pause-filter',
    sse4_1 => 'sse4.1',
    sse4_2 => 'sse4.2',
    'hv-apicv' => 'hv-avic',
    lbr_fmt => 'lbr-fmt',
};

=head3 normalize_cpu_flag($flag)

Normalize a CPU flag to its QEMU form.

QEMU defines aliases for some CPU flags (see C<x86_cpu_initfn()> in
C<target/i386/cpu.c>). For example, C<sse4_2> and C<sse4-2> are both aliases for
C<sse4.2>.

If C<$flag> has a known alias, return that, otherwise return C<$flag> unchanged.

=cut

sub normalize_cpu_flag($flag) {
    return $qemu_cpu_flag_alias_map->{$flag} // $flag;
}

# Understood CPU flags are written to a file at 'pve-qemu' compile time and
# shipped below this directory by the pve-qemu-kvm package.
my $understood_cpu_flag_dir = "/usr/share/kvm";

sub supported_cpu_flags_names() {
    return @supported_cpu_flags_name_sorted;
}

sub supported_cpu_flags_names_by_arch($arch) {
    my @res = sort map { $_->{name} } $supported_vm_specific_cpu_flags_by_arch->{$arch}->@*;
    return @res;
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

=head3 flag_is_vm_specific($flag)

Return true if `$flag` may be set for a VM's CPU flags configuration.

=cut

sub flag_is_vm_specific($flag) {
    return defined($all_supported_vm_specific_cpu_flags->{$flag});
}

sub flag_descriptions($arch) {
    return { map { $_->{name} => $_->{description} }
        $supported_vm_specific_cpu_flags_by_arch->{$arch}->@* };
}

=head3 query_available_cpu_flags($accel, $vm_specific, $arch)

Retrieve a list of available flags, i.e., flags that will be accepted by PVE in a
processor config when attempting to spawn a VM. Each flag is returned along with a list
of nodes that support it. Flags that are not supported on any node are also returned;
filtering them out is up to the consumer of this API.

B<Parameters:>

=over

=item C<$accel> (C<kvm> | C<tcg>)

Selects which acceleration type flag/node compatibility should be evaluated for.

=item C<$vm_specific> (boolean)

When set to 1, return only VM-specific flags, otherwise return all flags.

=item C<$arch> (C<x86_64> | C<aarch64>)

Specifies which architecture to query flags for. Note that in both scopes (VM-specific
and all), C<aarch64> returns empty lists: this is intended for VM-specific flags, as no
C<aarch64> flags are currently settable for a specific VM, however it is a known
limitation for the "all" scope. PVE does not currently ship a list of understood flags
for C<aarch64>, as it is not as trivial to obtain as for C<x86_64>, whose flags are easy
to parse from QEMU's C<-cpu help> output.

=back

In order to get an accurate picture of which flags can actually be used, two sources are
combined (see C<PVE::QemuServer::query_supported_cpu_flags> for details):

=over

=item 1.

The B<understood> CPU flags, i.e., all flags QEMU accepts as C<-cpu> arguments in
principle, regardless of whether the host CPU actually supports them.

=item 2.

The B<supported> CPU flags: the flags the host CPU actually supports, cached in the node
KV store by C<pvestatd>. This is node-specific.

=back

Each flag from (1) is annotated with the subset of nodes from (2) that report supporting
it.

The PVE-internal C<nested-virt> shorthand is also included in both scopes, with its
C<supported-on> list populated from nodes that report supporting C<svm> or C<vmx>.

=cut

sub query_available_cpu_flags($accel, $vm_specific, $arch) {
    # TODO: a way to get supported flags for aarch64. This is not done because PVE
    # does not currently ship a list of understood flags for aarch64, as it's more difficult
    # to obtain during QEMU build - for x86_64, qemu -cpu help will just list the flags.
    return [] if $arch eq 'aarch64';

    my $descriptions = flag_descriptions($arch);
    my $base =
        !$vm_specific
        ? query_understood_cpu_flags($arch)
        : [supported_cpu_flags_names_by_arch($arch)];
    my $available_flags = {
        map {
            my $entry = { name => $_, 'supported-on' => {} };
            $entry->{description} = $descriptions->{$_} if defined($descriptions->{$_});
            ($_ => $entry);
        } @$base
    };

    my $kv_store = "cpuflags-$accel";
    my $flags = PVE::Cluster::get_node_kv($kv_store);

    $available_flags->{'nested-virt'} //= {
        name => 'nested-virt',
        'supported-on' => {},
        description => $descriptions->{'nested-virt'},
    };

    # In cluster-wide scope, annotate the raw svm/vmx flags so users in the custom CPU model
    # editor get nudged toward the portable 'nested-virt' shorthand instead.
    if (!$vm_specific) {
        for my $raw ('svm', 'vmx') {
            next if !defined($available_flags->{$raw});
            $available_flags->{$raw}->{description} //=
                "Raw nested-virtualization flag. Prefer the 'nested-virt' shorthand"
                . " for portable VM configs - it resolves to svm or vmx based on the"
                . " host CPU.";
        }
    }

    my $add_flag = sub($node, $name) {
        return if !defined($available_flags->{$name});
        $available_flags->{$name}->{'supported-on'}->{$node} = 1;
    };

    for my $node (keys %$flags) {
        # This depends on `pvestatd` storing the flags in space-separated format, which
        # is the case at the time of this commit.
        for (split(' ', $flags->{$node})) {
            # normalize as pvestatd's stored format may drift relative to the recognized
            # flag list, e.g. across upgrades or between QEMU CPUID-flag aliases.
            my $flag = normalize_cpu_flag($_);
            my $pve_alias = undef;
            $pve_alias = 'nested-virt' if $flag eq 'svm' || $flag eq 'vmx';
            next if $vm_specific && !flag_is_vm_specific($flag) && !$pve_alias;
            $add_flag->($node, $flag) if !($vm_specific && $pve_alias);
            $add_flag->($node, $pve_alias) if $pve_alias;
        }
    }

    for my $flag (values %$available_flags) {
        $flag->{'supported-on'} = [sort keys $flag->{'supported-on'}->%*];
    }

    # Make sure 'nested-virt' is always shown first.
    my $nested_virt = delete $available_flags->{'nested-virt'};

    # Order flags that are not supported anywhere in the cluster to the end.
    my @sorted = sort {
        (scalar($a->{'supported-on'}->@*) == 0) <=> (scalar($b->{'supported-on'}->@*) == 0)
            || $a->{name} cmp $b->{name}
    } values %$available_flags;

    return [defined($nested_virt) ? ($nested_virt, @sorted) : @sorted];
}

1;
