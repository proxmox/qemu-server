package PVE::QemuServer::PCI;

use base 'Exporter';

our @EXPORT_OK = qw(
print_pci_addr
print_pcie_addr
print_pcie_root_port
);

my $devices = {
    piix3 => { bus => 0, addr => 1 },
    ehci => { bus => 0, addr => 1 }, # instead of piix3 on arm
    vga => { bus => 0, addr => 2 },
    balloon0 => { bus => 0, addr => 3 },
    watchdog => { bus => 0, addr => 4 },
    scsihw0 => { bus => 0, addr => 5 },
    'pci.3' => { bus => 0, addr => 5 }, #can also be used for virtio-scsi-single bridge
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
};

sub print_pci_addr {
    my ($id, $bridges, $arch, $machine) = @_;

    my $res = '';

    # We use the same bus slots on all hardware, so we need to check special
    # cases here:
    my $busname = 'pci';
    if ($arch eq 'aarch64' && $machine =~ /^virt/) {
	die "aarch64/virt cannot use IDE devices\n"
	    if $id =~ /^ide/;
	$busname = 'pcie';
    }

    if (defined($devices->{$id}->{bus}) && defined($devices->{$id}->{addr})) {
	   my $addr = sprintf("0x%x", $devices->{$id}->{addr});
	   my $bus = $devices->{$id}->{bus};
	   $res = ",bus=$busname.$bus,addr=$addr";
	   $bridges->{$bus} = 1 if $bridges;
    }
    return $res;

}

sub print_pcie_addr {
    my ($id) = @_;

    my $res = '';
    my $devices = {
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
	hostpci11bus0 => { bus => "pcie.0", addr => 20 },
	hostpci12bus0 => { bus => "pcie.0", addr => 21 },
	hostpci13bus0 => { bus => "pcie.0", addr => 22 },
	hostpci14bus0 => { bus => "pcie.0", addr => 23 },
	hostpci15bus0 => { bus => "pcie.0", addr => 24 },
    };

    if (defined($devices->{$id}->{bus}) && defined($devices->{$id}->{addr})) {
	   my $addr = sprintf("0x%x", $devices->{$id}->{addr});
	   my $bus = $devices->{$id}->{bus};
	   $res = ",bus=$bus,addr=$addr";
    }
    return $res;

}

# Generates the device strings for additional pcie root ports. The first 4 pcie
# root ports are defined in the pve-q35*.cfg files.
sub print_pcie_root_port {
    my ($i) = @_;
    my $res = '';

    my $id = $i + 1;

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
	$res = "pcie-root-port,id=ich9-pcie-port-${id}";
	$res .= ",addr=$root_port_addresses->{$i}";
	$res .= ",x-speed=16,x-width=32,multifunction=on,bus=pcie.0";
	$res .= ",port=${id},chassis=${id}";
    }

    return $res;
}

1;
