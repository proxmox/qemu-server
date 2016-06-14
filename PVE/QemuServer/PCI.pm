package PVE::QemuServer::PCI;

use base 'Exporter';

our @EXPORT_OK = qw(
print_pci_addr
print_pcie_addr
);

my $devices = {
    piix3 => { bus => 0, addr => 1 },
    #addr2 : first videocard
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
    my ($id, $bridges) = @_;

    my $res = '';

    if (defined($devices->{$id}->{bus}) && defined($devices->{$id}->{addr})) {
	   my $addr = sprintf("0x%x", $devices->{$id}->{addr});
	   my $bus = $devices->{$id}->{bus};
	   $res = ",bus=pci.$bus,addr=$addr";
	   $bridges->{$bus} = 1 if $bridges;
    }
    return $res;

}

sub print_pcie_addr {
    my ($id) = @_;

    my $res = '';
    my $devices = {
	hostpci0 => { bus => "ich9-pcie-port-1", addr => 0 },
	hostpci1 => { bus => "ich9-pcie-port-2", addr => 0 },
	hostpci2 => { bus => "ich9-pcie-port-3", addr => 0 },
	hostpci3 => { bus => "ich9-pcie-port-4", addr => 0 },
    };

    if (defined($devices->{$id}->{bus}) && defined($devices->{$id}->{addr})) {
	   my $addr = sprintf("0x%x", $devices->{$id}->{addr});
	   my $bus = $devices->{$id}->{bus};
	   $res = ",bus=$bus,addr=$addr";
    }
    return $res;

}
