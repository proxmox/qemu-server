package PVE::QemuServer::RNG;

use strict;
use warnings;

use PVE::JSONSchema;
use PVE::Tools qw(file_read_firstline);

use PVE::QemuServer::PCI qw(print_pci_addr);

use base 'Exporter';

our @EXPORT_OK = qw(
    parse_rng
    check_rng_source
    print_rng_device_commandline
    print_rng_object_commandline
);

my $rng_fmt = {
    source => {
        type => 'string',
        enum => ['/dev/urandom', '/dev/random', '/dev/hwrng'],
        default_key => 1,
        description => "The file on the host to gather entropy from. Using urandom does *not*"
            . " decrease security in any meaningful way, as it's still seeded from real entropy, and"
            . " the bytes provided will most likely be mixed with real entropy on the guest as well."
            . " '/dev/hwrng' can be used to pass through a hardware RNG from the host.",
    },
    max_bytes => {
        type => 'integer',
        description => "Maximum bytes of entropy allowed to get injected into the guest every"
            . " 'period' milliseconds. Use `0` to disable limiting (potentially dangerous!).",
        optional => 1,

        # default is 1 KiB/s, provides enough entropy to the guest to avoid boot-starvation issues
        # (e.g. systemd etc...) while allowing no chance of overwhelming the host, provided we're
        # reading from /dev/urandom
        default => 1024,
    },
    period => {
        type => 'integer',
        description =>
            "Every 'period' milliseconds the entropy-injection quota is reset, allowing"
            . " the guest to retrieve another 'max_bytes' of entropy.",
        optional => 1,
        default => 1000,
    },
};

PVE::JSONSchema::register_format('pve-qm-rng', $rng_fmt);

our $rngdesc = {
    type => 'string',
    format => $rng_fmt,
    optional => 1,
    description => "Configure a VirtIO-based Random Number Generator.",
};
PVE::JSONSchema::register_standard_option('pve-qm-rng', $rngdesc);

sub parse_rng {
    my ($value) = @_;

    return if !$value;

    my $res = eval { PVE::JSONSchema::parse_property_string($rng_fmt, $value) };
    warn $@ if $@;

    return $res;
}

sub check_rng_source {
    my ($source) = @_;

    # mostly relevant for /dev/hwrng, but doesn't hurt to check others too
    die "cannot create VirtIO RNG device: source file '$source' doesn't exist\n"
        if !-e $source;

    my $rng_current = '/sys/devices/virtual/misc/hw_random/rng_current';
    if ($source eq '/dev/hwrng' && file_read_firstline($rng_current) eq 'none') {
        # Needs to abort, otherwise QEMU crashes on first rng access. Note that rng_current cannot
        # be changed to 'none' manually, so once the VM is past this point, it's no longer an issue.
        die "Cannot start VM with passed-through RNG device: '/dev/hwrng' exists, but"
            . " '$rng_current' is set to 'none'. Ensure that a compatible hardware-RNG is attached"
            . " to the host.\n";
    }
}

sub print_rng_device_commandline {
    my ($id, $rng, $bridges, $arch, $machine) = @_;

    die "no rng device specified\n" if !$rng;

    my $max_bytes = $rng->{max_bytes} // $rng_fmt->{max_bytes}->{default};
    my $period = $rng->{period} // $rng_fmt->{period}->{default};
    my $limiter_str = "";
    if ($max_bytes) {
        $limiter_str = ",max-bytes=$max_bytes,period=$period";
    }

    my $rng_addr = print_pci_addr($id, $bridges, $arch, $machine);

    return "virtio-rng-pci,rng=$id$limiter_str$rng_addr";
}

sub print_rng_object_commandline {
    my ($id, $rng) = @_;

    die "no rng device specified\n" if !$rng;

    my $source_path = $rng->{source};
    check_rng_source($source_path);

    return "rng-random,filename=$source_path,id=$id";
}

1;
