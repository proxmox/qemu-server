package PVE::QemuServer::PCI;

use warnings;
use strict;

use PVE::JSONSchema;
use PVE::Mapping::PCI;
use PVE::SysFSTools;
use PVE::Tools;

use base 'Exporter';

our @EXPORT_OK = qw(
print_pci_addr
print_pcie_addr
print_pcie_root_port
parse_hostpci
);

our $MAX_HOSTPCI_DEVICES = 16;

my $PCIRE = qr/(?:[a-f0-9]{4,}:)?[a-f0-9]{2}:[a-f0-9]{2}(?:\.[a-f0-9])?/;
my $hostpci_fmt = {
    host => {
	default_key => 1,
	optional => 1,
	type => 'string',
	pattern => qr/$PCIRE(;$PCIRE)*/,
	format_description => 'HOSTPCIID[;HOSTPCIID2...]',
	description => <<EODESCR,
Host PCI device pass through. The PCI ID of a host's PCI device or a list
of PCI virtual functions of the host. HOSTPCIID syntax is:

'bus:dev.func' (hexadecimal numbers)

You can us the 'lspci' command to list existing PCI devices.

Either this or the 'mapping' key must be set.
EODESCR
    },
    mapping => {
	optional => 1,
	type => 'string',
	format_description => 'mapping-id',
	format => 'pve-configid',
	description => "The ID of a cluster wide mapping. Either this or the default-key 'host'"
	    ." must be set.",
    },
    rombar => {
	type => 'boolean',
	description =>  "Specify whether or not the device's ROM will be visible in the"
	    ." guest's memory map.",
	optional => 1,
	default => 1,
    },
    romfile => {
	type => 'string',
	pattern => '[^,;]+',
	format_description => 'string',
	description => "Custom pci device rom filename (must be located in /usr/share/kvm/).",
	optional => 1,
    },
    pcie => {
	type => 'boolean',
	description =>  "Choose the PCI-express bus (needs the 'q35' machine model).",
	optional => 1,
	default => 0,
    },
    'x-vga' => {
	type => 'boolean',
	description =>  "Enable vfio-vga device support.",
	optional => 1,
	default => 0,
    },
    'legacy-igd' => {
	type => 'boolean',
	description => "Pass this device in legacy IGD mode, making it the primary and exclusive"
	    ." graphics device in the VM. Requires 'pc-i440fx' machine type and VGA set to 'none'.",
	optional => 1,
	default => 0,
    },
    'mdev' => {
	type => 'string',
	format_description => 'string',
	pattern => '[^/\.:]+',
	optional => 1,
	description => <<EODESCR
The type of mediated device to use.
An instance of this type will be created on startup of the VM and
will be cleaned up when the VM stops.
EODESCR
    },
    'vendor-id' => {
	type => 'string',
	pattern => qr/^0x[0-9a-fA-F]{4}$/,
	format_description => 'hex id',
	optional => 1,
	description => "Override PCI vendor ID visible to guest"
    },
    'device-id' => {
	type => 'string',
	pattern => qr/^0x[0-9a-fA-F]{4}$/,
	format_description => 'hex id',
	optional => 1,
	description => "Override PCI device ID visible to guest"
    },
    'sub-vendor-id' => {
	type => 'string',
	pattern => qr/^0x[0-9a-fA-F]{4}$/,
	format_description => 'hex id',
	optional => 1,
	description => "Override PCI subsystem vendor ID visible to guest"
    },
    'sub-device-id' => {
	type => 'string',
	pattern => qr/^0x[0-9a-fA-F]{4}$/,
	format_description => 'hex id',
	optional => 1,
	description => "Override PCI subsystem device ID visible to guest"
    }
};
PVE::JSONSchema::register_format('pve-qm-hostpci', $hostpci_fmt);

our $hostpcidesc = {
	optional => 1,
	type => 'string', format => 'pve-qm-hostpci',
	description => "Map host PCI devices into guest.",
	verbose_description =>  <<EODESCR,
Map host PCI devices into guest.

NOTE: This option allows direct access to host hardware. So it is no longer
possible to migrate such machines - use with special care.

CAUTION: Experimental! User reported problems with this option.
EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-hostpci", $hostpcidesc);

my $pci_addr_map;
sub get_pci_addr_map {
    $pci_addr_map = {
	piix3 => { bus => 0, addr => 1, conflict_ok => qw(ehci)  },
	ehci => { bus => 0, addr => 1, conflict_ok => qw(piix3) }, # instead of piix3 on arm
	vga => { bus => 0, addr => 2, conflict_ok => qw(legacy-igd) },
	'legacy-igd' => { bus => 0, addr => 2, conflict_ok => qw(vga) }, # legacy-igd requires vga=none
	balloon0 => { bus => 0, addr => 3 },
	watchdog => { bus => 0, addr => 4 },
	scsihw0 => { bus => 0, addr => 5, conflict_ok => qw(pci.3) },
	'pci.3' => { bus => 0, addr => 5, conflict_ok => qw(scsihw0) }, # also used for virtio-scsi-single bridge
	scsihw1 => { bus => 0, addr => 6 },
	ahci0 => { bus => 0, addr => 7 },
	qga0 => { bus => 0, addr => 8 },
	spice => { bus => 0, addr => 9 },
	virtio0 => { bus => 0, addr => 10 },
	virtio1 => { bus => 0, addr => 11 },
	virtio2 => { bus => 0, addr => 12 },
	virtio3 => { bus => 0, addr => 13 },
	virtio4 => { bus => 0, addr => 14 },
	virtio5 => { bus => 0, addr => 15 },
	hostpci0 => { bus => 0, addr => 16 },
	hostpci1 => { bus => 0, addr => 17 },
	net0 => { bus => 0, addr => 18 },
	net1 => { bus => 0, addr => 19 },
	net2 => { bus => 0, addr => 20 },
	net3 => { bus => 0, addr => 21 },
	net4 => { bus => 0, addr => 22 },
	net5 => { bus => 0, addr => 23 },
	vga1 => { bus => 0, addr => 24 },
	vga2 => { bus => 0, addr => 25 },
	vga3 => { bus => 0, addr => 26 },
	hostpci2 => { bus => 0, addr => 27 },
	hostpci3 => { bus => 0, addr => 28 },
	#addr29 : usb-host (pve-usb.cfg)
	'pci.1' => { bus => 0, addr => 30 },
	'pci.2' => { bus => 0, addr => 31 },
	'net6' => { bus => 1, addr => 1 },
	'net7' => { bus => 1, addr => 2 },
	'net8' => { bus => 1, addr => 3 },
	'net9' => { bus => 1, addr => 4 },
	'net10' => { bus => 1, addr => 5 },
	'net11' => { bus => 1, addr => 6 },
	'net12' => { bus => 1, addr => 7 },
	'net13' => { bus => 1, addr => 8 },
	'net14' => { bus => 1, addr => 9 },
	'net15' => { bus => 1, addr => 10 },
	'net16' => { bus => 1, addr => 11 },
	'net17' => { bus => 1, addr => 12 },
	'net18' => { bus => 1, addr => 13 },
	'net19' => { bus => 1, addr => 14 },
	'net20' => { bus => 1, addr => 15 },
	'net21' => { bus => 1, addr => 16 },
	'net22' => { bus => 1, addr => 17 },
	'net23' => { bus => 1, addr => 18 },
	'net24' => { bus => 1, addr => 19 },
	'net25' => { bus => 1, addr => 20 },
	'net26' => { bus => 1, addr => 21 },
	'net27' => { bus => 1, addr => 22 },
	'net28' => { bus => 1, addr => 23 },
	'net29' => { bus => 1, addr => 24 },
	'net30' => { bus => 1, addr => 25 },
	'net31' => { bus => 1, addr => 26 },
	'xhci' => { bus => 1, addr => 27 },
	'pci.4' => { bus => 1, addr => 28 },
	'rng0' => { bus => 1, addr => 29 },
	'pci.2-igd' => { bus => 1, addr => 30 }, # replaces pci.2 in case a legacy IGD device is passed through
	'virtio6' => { bus => 2, addr => 1 },
	'virtio7' => { bus => 2, addr => 2 },
	'virtio8' => { bus => 2, addr => 3 },
	'virtio9' => { bus => 2, addr => 4 },
	'virtio10' => { bus => 2, addr => 5 },
	'virtio11' => { bus => 2, addr => 6 },
	'virtio12' => { bus => 2, addr => 7 },
	'virtio13' => { bus => 2, addr => 8 },
	'virtio14' => { bus => 2, addr => 9 },
	'virtio15' => { bus => 2, addr => 10 },
	'ivshmem' => { bus => 2, addr => 11 },
	'audio0' => { bus => 2, addr => 12 },
	hostpci4 => { bus => 2, addr => 13 },
	hostpci5 => { bus => 2, addr => 14 },
	hostpci6 => { bus => 2, addr => 15 },
	hostpci7 => { bus => 2, addr => 16 },
	hostpci8 => { bus => 2, addr => 17 },
	hostpci9 => { bus => 2, addr => 18 },
	hostpci10 => { bus => 2, addr => 19 },
	hostpci11 => { bus => 2, addr => 20 },
	hostpci12 => { bus => 2, addr => 21 },
	hostpci13 => { bus => 2, addr => 22 },
	hostpci14 => { bus => 2, addr => 23 },
	hostpci15 => { bus => 2, addr => 24 },
	'virtioscsi0' => { bus => 3, addr => 1 },
	'virtioscsi1' => { bus => 3, addr => 2 },
	'virtioscsi2' => { bus => 3, addr => 3 },
	'virtioscsi3' => { bus => 3, addr => 4 },
	'virtioscsi4' => { bus => 3, addr => 5 },
	'virtioscsi5' => { bus => 3, addr => 6 },
	'virtioscsi6' => { bus => 3, addr => 7 },
	'virtioscsi7' => { bus => 3, addr => 8 },
	'virtioscsi8' => { bus => 3, addr => 9 },
	'virtioscsi9' => { bus => 3, addr => 10 },
	'virtioscsi10' => { bus => 3, addr => 11 },
	'virtioscsi11' => { bus => 3, addr => 12 },
	'virtioscsi12' => { bus => 3, addr => 13 },
	'virtioscsi13' => { bus => 3, addr => 14 },
	'virtioscsi14' => { bus => 3, addr => 15 },
	'virtioscsi15' => { bus => 3, addr => 16 },
	'virtioscsi16' => { bus => 3, addr => 17 },
	'virtioscsi17' => { bus => 3, addr => 18 },
	'virtioscsi18' => { bus => 3, addr => 19 },
	'virtioscsi19' => { bus => 3, addr => 20 },
	'virtioscsi20' => { bus => 3, addr => 21 },
	'virtioscsi21' => { bus => 3, addr => 22 },
	'virtioscsi22' => { bus => 3, addr => 23 },
	'virtioscsi23' => { bus => 3, addr => 24 },
	'virtioscsi24' => { bus => 3, addr => 25 },
	'virtioscsi25' => { bus => 3, addr => 26 },
	'virtioscsi26' => { bus => 3, addr => 27 },
	'virtioscsi27' => { bus => 3, addr => 28 },
	'virtioscsi28' => { bus => 3, addr => 29 },
	'virtioscsi29' => { bus => 3, addr => 30 },
	'virtioscsi30' => { bus => 3, addr => 31 },
	'scsihw2' => { bus => 4, addr => 1 },
	'scsihw3' => { bus => 4, addr => 2 },
	'scsihw4' => { bus => 4, addr => 3 },
    } if !defined($pci_addr_map);
    return $pci_addr_map;
}

sub generate_mdev_uuid {
    my ($vmid, $index) = @_;
    return sprintf("%08d-0000-0000-0000-%012d", $index, $vmid);
}

my $get_addr_mapping_from_id = sub {
    my ($map, $id) = @_;

    my $d = $map->{$id};
    return if !defined($d) || !defined($d->{bus}) || !defined($d->{addr});

    return { bus => $d->{bus}, addr => sprintf("0x%x", $d->{addr}) };
};

sub print_pci_addr {
    my ($id, $bridges, $arch, $machine) = @_;

    my $res = '';

    if ($arch =~ m/^sparc/) {
      print "sparc/sparc64 does not support PCI devices, ignoring: $id\n";
      return $res;
    }

    # using same bus slots on all HW, so we need to check special cases here:
    my $busname = 'pci';
    if ($arch eq 'aarch64' && $machine =~ /^virt/) {
	die "aarch64/virt cannot use IDE devices\n" if $id =~ /^ide/;
	$busname = 'pcie';
    }

    my $map = get_pci_addr_map();
    if (my $d = $get_addr_mapping_from_id->($map, $id)) {
	$res = ",bus=$busname.$d->{bus},addr=$d->{addr}";
	$bridges->{$d->{bus}} = 1 if $bridges;
    }

    return $res;
}

my $pcie_addr_map;
sub get_pcie_addr_map {
    $pcie_addr_map = {
	vga => { bus => 'pcie.0', addr => 1 },
	hostpci0 => { bus => "ich9-pcie-port-1", addr => 0 },
	hostpci1 => { bus => "ich9-pcie-port-2", addr => 0 },
	hostpci2 => { bus => "ich9-pcie-port-3", addr => 0 },
	hostpci3 => { bus => "ich9-pcie-port-4", addr => 0 },
	hostpci4 => { bus => "ich9-pcie-port-5", addr => 0 },
	hostpci5 => { bus => "ich9-pcie-port-6", addr => 0 },
	hostpci6 => { bus => "ich9-pcie-port-7", addr => 0 },
	hostpci7 => { bus => "ich9-pcie-port-8", addr => 0 },
	hostpci8 => { bus => "ich9-pcie-port-9", addr => 0 },
	hostpci9 => { bus => "ich9-pcie-port-10", addr => 0 },
	hostpci10 => { bus => "ich9-pcie-port-11", addr => 0 },
	hostpci11 => { bus => "ich9-pcie-port-12", addr => 0 },
	hostpci12 => { bus => "ich9-pcie-port-13", addr => 0 },
	hostpci13 => { bus => "ich9-pcie-port-14", addr => 0 },
	hostpci14 => { bus => "ich9-pcie-port-15", addr => 0 },
	hostpci15 => { bus => "ich9-pcie-port-16", addr => 0 },
	# win7 is picky about pcie assignments
	hostpci0bus0 => { bus => "pcie.0", addr => 16 },
	hostpci1bus0 => { bus => "pcie.0", addr => 17 },
	hostpci2bus0 => { bus => "pcie.0", addr => 18 },
	hostpci3bus0 => { bus => "pcie.0", addr => 19 },
	ivshmem => { bus => 'pcie.0', addr => 20 },
	hostpci4bus0 => { bus => "pcie.0", addr => 9 },
	hostpci5bus0 => { bus => "pcie.0", addr => 10 },
	hostpci6bus0 => { bus => "pcie.0", addr => 11 },
	hostpci7bus0 => { bus => "pcie.0", addr => 12 },
	hostpci8bus0 => { bus => "pcie.0", addr => 13 },
	hostpci9bus0 => { bus => "pcie.0", addr => 14 },
	hostpci10bus0 => { bus => "pcie.0", addr => 15 },
	hostpci11bus0 => { bus => "pcie.0", addr => 21 },
	hostpci12bus0 => { bus => "pcie.0", addr => 22 },
	hostpci13bus0 => { bus => "pcie.0", addr => 23 },
	hostpci14bus0 => { bus => "pcie.0", addr => 24 },
	hostpci15bus0 => { bus => "pcie.0", addr => 25 },
    } if !defined($pcie_addr_map);

    return $pcie_addr_map;
}

sub print_pcie_addr {
    my ($id) = @_;

    my $res = '';

    my $map = get_pcie_addr_map($id);
    if (my $d = $get_addr_mapping_from_id->($map, $id)) {
	$res = ",bus=$d->{bus},addr=$d->{addr}";
    }

    return $res;
}

# Generates the device strings for additional pcie root ports. The first 4 pcie
# root ports are defined in the pve-q35*.cfg files.
sub print_pcie_root_port {
    my ($i) = @_;
    my $res = '';

    my $root_port_addresses = {
	 4 => "10.0",
	 5 => "10.1",
	 6 => "10.2",
	 7 => "10.3",
	 8 => "10.4",
	 9 => "10.5",
	10 => "10.6",
	11 => "10.7",
	12 => "11.0",
	13 => "11.1",
	14 => "11.2",
	15 => "11.3",
    };

    if (defined($root_port_addresses->{$i})) {
	my $id = $i + 1;
	$res = "pcie-root-port,id=ich9-pcie-port-${id}";
	$res .= ",addr=$root_port_addresses->{$i}";
	$res .= ",x-speed=16,x-width=32,multifunction=on,bus=pcie.0";
	$res .= ",port=${id},chassis=${id}";
    }

    return $res;
}

# returns the parsed pci config but parses the 'host' part into
# a list if lists into the 'id' property like this:
#
# {
#   mdev => 1,
#   rombar => ...
#   ...
#   ids => [
#       # this contains a list of alternative devices,
#       [
#           # which are itself lists of ids for one multifunction device
#           {
#               id => "0000:00:00.0",
#               vendor => "...",
#           },
#           {
#               id => "0000:00:00.1",
#               vendor => "...",
#           },
#       ],
#       [
#           ...
#       ],
#       ...
#   ],
# }
sub parse_hostpci {
    my ($value) = @_;

    return if !$value;

    my $res = PVE::JSONSchema::parse_property_string($hostpci_fmt, $value);

    my $alternatives = [];
    my $host = delete $res->{host};
    my $mapping = delete $res->{mapping};

    die "Cannot set both 'host' and 'mapping'.\n" if defined($host) && defined($mapping);

    if ($mapping) {
	# we have no ordinary pci id, must be a mapping
	my $devices = PVE::Mapping::PCI::find_on_current_node($mapping);
	die "PCI device mapping not found for '$mapping'\n" if !$devices || !scalar($devices->@*);

	for my $device ($devices->@*) {
	    eval { PVE::Mapping::PCI::assert_valid($mapping, $device) };
	    die "PCI device mapping invalid (hardware probably changed): $@\n" if $@;
	    push $alternatives->@*, [split(/;/, $device->{path})];
	}
    } elsif ($host) {
	push $alternatives->@*, [split(/;/, $host)];
    } else {
	die "Either 'host' or 'mapping' must be set.\n";
    }

    $res->{ids} = [];
    for my $alternative ($alternatives->@*) {
	my $ids = [];
	foreach my $id ($alternative->@*) {
	    my $devs = PVE::SysFSTools::lspci($id);
	    die "no PCI device found for '$id'\n" if !scalar($devs->@*);
	    push $ids->@*, @$devs;
	}
	if (scalar($ids->@*) > 1) {
	    $res->{'has-multifunction'} = 1;
	    die "cannot use mediated device with multifunction device\n" if $res->{mdev};
	}
	push $res->{ids}->@*, $ids;
    }

    return $res;
}

# parses all hostpci devices from a config and does some sanity checks
# returns a hash like this:
# {
#     hostpci0 => {
#         # hash from parse_hostpci function
#     },
#     hostpci1 => { ... },
#     ...
# }
sub parse_hostpci_devices {
    my ($conf) = @_;

    my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);
    my $legacy_igd = 0;

    my $parsed_devices = {};
    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
	my $id = "hostpci$i";
	my $d = parse_hostpci($conf->{$id});
	next if !$d;

	# check syntax
	die "q35 machine model is not enabled" if !$q35 && $d->{pcie};

	if ($d->{'legacy-igd'}) {
	    die "only one device can be assigned in legacy-igd mode\n"
		if $legacy_igd;
	    $legacy_igd = 1;

	    die "legacy IGD assignment requires VGA mode to be 'none'\n"
		if !defined($conf->{'vga'}) || $conf->{'vga'} ne 'none';
	    die "legacy IGD assignment requires rombar to be enabled\n"
		if defined($d->{rombar}) && !$d->{rombar};
	    die "legacy IGD assignment is not compatible with x-vga\n"
		if $d->{'x-vga'};
	    die "legacy IGD assignment is not compatible with mdev\n"
		if $d->{mdev};
	    die "legacy IGD assignment is not compatible with q35\n"
		if $q35;
	    die "legacy IGD assignment is not compatible with multifunction devices\n"
		if $d->{'has-multifunction'};
	    die "legacy IGD assignment is not compatible with alternate devices\n"
		if scalar($d->{ids}->@*) > 1;
	    # check first device for valid id
	    die "legacy IGD assignment only works for devices on host bus 00:02.0\n"
		if $d->{ids}->[0]->[0]->{id} !~ m/02\.0$/;
	}

	$parsed_devices->{$id} = $d;
    }

    return $parsed_devices;
}

# takes the hash returned by parse_hostpci_devices and for all non mdev gpus,
# selects one of the given alternatives by trying to reserve it
#
# mdev devices must be chosen later when we actually allocate it, but we
# flatten the inner list since there can only be one device per alternative anyway
my sub choose_hostpci_devices {
    my ($devices, $vmid) = @_;

    my $used = {};

    my $add_used_device = sub {
	my ($devices) = @_;
	for my $used_device ($devices->@*) {
	    my $used_id = $used_device->{id};
	    die "device '$used_id' assigned more than once\n" if $used->{$used_id};
	    $used->{$used_id} = 1;
	}
    };

    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
	my $device = $devices->{"hostpci$i"};
	next if !$device;

	if ($device->{mdev}) {
	    $device->{ids} = [ map { $_->[0] } $device->{ids}->@* ];
	    next;
	}

	if (scalar($device->{ids}->@* == 1)) {
	    # we only have one alternative, use that
	    $device->{ids} = $device->{ids}->[0];
	    $add_used_device->($device->{ids});
	    next;
	}

	my $found = 0;
	for my $alternative ($device->{ids}->@*) {
	    my $ids = [map { $_->{id} } @$alternative];

	    next if grep { defined($used->{$_}) } @$ids; # already used
	    eval { reserve_pci_usage($ids, $vmid, 10, undef) };
	    next if $@;

	    # found one that is not used or reserved
	    $add_used_device->($alternative);
	    $device->{ids} = $alternative;
	    $found = 1;
	    last;
	}
	die "could not find a free device for 'hostpci$i'\n" if !$found;
    }

    return $devices;
}

sub print_hostpci_devices {
    my ($vmid, $conf, $devices, $vga, $winversion, $bridges, $arch, $machine_type, $bootorder) = @_;

    my $kvm_off = 0;
    my $gpu_passthrough = 0;
    my $legacy_igd = 0;

    my $pciaddr;
    my $pci_devices = choose_hostpci_devices(parse_hostpci_devices($conf), $vmid);

    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
	my $id = "hostpci$i";
	my $d = $pci_devices->{$id};
	next if !$d;

	$legacy_igd = 1 if $d->{'legacy-igd'};

	if (my $pcie = $d->{pcie}) {
	    # win7 wants to have the pcie devices directly on the pcie bus
	    # instead of in the root port
	    if ($winversion == 7) {
		$pciaddr = print_pcie_addr("${id}bus0");
	    } else {
		# add more root ports if needed, 4 are present by default
		# by pve-q35 cfgs, rest added here on demand.
		if ($i > 3) {
		    push @$devices, '-device', print_pcie_root_port($i);
		}
		$pciaddr = print_pcie_addr($id);
	    }
	} else {
	    my $pci_name = $d->{'legacy-igd'} ? 'legacy-igd' : $id;
	    $pciaddr = print_pci_addr($pci_name, $bridges, $arch, $machine_type);
	}

	my $num_devices = scalar($d->{ids}->@*);
	my $multifunction = $num_devices > 1 && !$d->{mdev};

	my $xvga = '';
	if ($d->{'x-vga'}) {
	    $xvga = ',x-vga=on' if !($conf->{bios} && $conf->{bios} eq 'ovmf');
	    $kvm_off = 1;
	    $vga->{type} = 'none' if !defined($conf->{vga});
	    $gpu_passthrough = 1;
	}

	my $sysfspath;
	if ($d->{mdev}) {
	    my $uuid = generate_mdev_uuid($vmid, $i);
	    $sysfspath = "/sys/bus/mdev/devices/$uuid";
	}

	for (my $j = 0; $j < $num_devices; $j++) {
	    my $pcidevice = $d->{ids}->[$j];
	    my $devicestr = "vfio-pci";

	    if ($sysfspath) {
		$devicestr .= ",sysfsdev=$sysfspath";
	    } else {
		$devicestr .= ",host=$pcidevice->{id}";
	    }

	    my $mf_addr = $multifunction ? ".$j" : '';
	    $devicestr .= ",id=${id}${mf_addr}${pciaddr}${mf_addr}";

	    if ($j == 0) {
		$devicestr .= ',rombar=0' if defined($d->{rombar}) && !$d->{rombar};
		$devicestr .= "$xvga";
		$devicestr .= ",multifunction=on" if $multifunction;
		$devicestr .= ",romfile=/usr/share/kvm/$d->{romfile}" if $d->{romfile};
		$devicestr .= ",bootindex=$bootorder->{$id}" if $bootorder->{$id};
		for my $option (qw(vendor-id device-id sub-vendor-id sub-device-id)) {
		    $devicestr .= ",x-pci-$option=$d->{$option}" if $d->{$option};
		}
	    }


	    push @$devices, '-device', $devicestr;
	    last if $d->{mdev};
	}
    }

    return ($kvm_off, $gpu_passthrough, $legacy_igd, $pci_devices);
}

sub prepare_pci_device {
    my ($vmid, $pciid, $index, $mdev) = @_;

    my $info = PVE::SysFSTools::pci_device_info("$pciid");
    die "cannot prepare PCI pass-through, IOMMU not present\n" if !PVE::SysFSTools::check_iommu_support();
    die "no pci device info for device '$pciid'\n" if !$info;

    if ($mdev) {
	my $uuid = generate_mdev_uuid($vmid, $index);
	PVE::SysFSTools::pci_create_mdev_device($pciid, $uuid, $mdev);
    } else {
	die "can't unbind/bind PCI group to VFIO '$pciid'\n"
	    if !PVE::SysFSTools::pci_dev_group_bind_to_vfio($pciid);
	die "can't reset PCI device '$pciid'\n"
	    if $info->{has_fl_reset} && !PVE::SysFSTools::pci_dev_reset($info);
    }

    return $info;
}

my $RUNDIR = '/run/qemu-server';
my $PCIID_RESERVATION_FILE = "${RUNDIR}/pci-id-reservations";
my $PCIID_RESERVATION_LOCK = "${PCIID_RESERVATION_FILE}.lock";

# a list of PCI ID to VMID reservations, the validity is protected against leakage by either a PID,
# for succesfully started VM processes, or a expiration time for the initial time window between
# reservation and actual VM process start-up.
my $parse_pci_reservation_unlocked = sub {
    my $pciids = {};
    if (my $fh = IO::File->new($PCIID_RESERVATION_FILE, "r")) {
	while (my $line = <$fh>) {
	    if ($line =~ m/^($PCIRE)\s(\d+)\s(time|pid)\:(\d+)$/) {
		$pciids->{$1} = {
		    vmid => $2,
		    "$3" => $4,
		};
	    }
	}
    }
    return $pciids;
};

my $write_pci_reservation_unlocked = sub {
    my ($reservations) = @_;

    my $data = "";
    for my $pci_id (sort keys $reservations->%*) {
	my ($vmid, $pid, $time) = $reservations->{$pci_id}->@{'vmid', 'pid', 'time'};
	if (defined($pid)) {
	    $data .= "$pci_id $vmid pid:$pid\n";
	} else {
	    $data .= "$pci_id $vmid time:$time\n";
	}
    }
    PVE::Tools::file_set_contents($PCIID_RESERVATION_FILE, $data);
};

# removes all PCI device reservations held by the `vmid`
sub remove_pci_reservation {
    my ($vmid) = @_;

    PVE::Tools::lock_file($PCIID_RESERVATION_LOCK, 2, sub {
	my $reservation_list = $parse_pci_reservation_unlocked->();
	for my $id (keys %$reservation_list) {
	    my $reservation = $reservation_list->{$id};
	    next if $reservation->{vmid} != $vmid;
	    delete $reservation_list->{$id};
	}
	$write_pci_reservation_unlocked->($reservation_list);
    });
    die $@ if $@;
}

sub reserve_pci_usage {
    my ($requested_ids, $vmid, $timeout, $pid) = @_;

    $requested_ids = [ $requested_ids ] if !ref($requested_ids);
    return if !scalar(@$requested_ids); # do nothing for empty list

    PVE::Tools::lock_file($PCIID_RESERVATION_LOCK, 5, sub {
	my $reservation_list = $parse_pci_reservation_unlocked->();

	my $ctime = time();
	for my $id ($requested_ids->@*) {
	    my $reservation = $reservation_list->{$id};
	    if ($reservation && $reservation->{vmid} != $vmid) {
		# check time based reservation
		die "PCI device '$id' is currently reserved for use by VMID '$reservation->{vmid}'\n"
		    if defined($reservation->{time}) && $reservation->{time} > $ctime;

		if (my $reserved_pid = $reservation->{pid}) {
		    # check running vm
		    my $running_pid = PVE::QemuServer::Helpers::vm_running_locally($reservation->{vmid});
		    if (defined($running_pid) && $running_pid == $reserved_pid) {
			die "PCI device '$id' already in use by VMID '$reservation->{vmid}'\n";
		    } else {
			warn "leftover PCI reservation found for $id, lets take it...\n";
		    }
		}
	    } elsif ($reservation) {
		# already reserved by the same vmid
		if (my $reserved_time = $reservation->{time}) {
		    if (defined($timeout)) {
			# use the longer timeout
			my $old_timeout = $reservation->{time} - 5 - $ctime;
			$timeout = $old_timeout if $old_timeout > $timeout;
		    }
		} elsif (my $reserved_pid = $reservation->{pid}) {
		    my $running_pid = PVE::QemuServer::Helpers::vm_running_locally($reservation->{vmid});
		    if (defined($running_pid) && $running_pid == $reservation->{pid}) {
			if (defined($pid)) {
			    die "PCI device '$id' already in use by running VMID '$reservation->{vmid}'\n";
			} elsif (defined($timeout)) {
			    # ignore timeout reservation for running vms, can happen with e.g.
			    # qm showcmd
			    return;
			}
		    }
		}
	    }

	    $reservation_list->{$id} = { vmid => $vmid };
	    if (defined($pid)) { # VM started up, we can reserve now with the actual PID
		$reservation_list->{$id}->{pid} = $pid;
	    } elsif (defined($timeout)) { # tempoaray reserve as we don't now the PID yet
		$reservation_list->{$id}->{time} = $ctime + $timeout + 5;
	    }
	}
	$write_pci_reservation_unlocked->($reservation_list);
    });
    die $@ if $@;
}

1;
