package PVE::QemuServer::USB;

use strict;
use warnings;
use PVE::QemuServer::PCI qw(print_pci_addr);
use PVE::QemuServer::Machine;
use PVE::QemuServer::Helpers qw(min_version windows_version);
use PVE::JSONSchema;
use base 'Exporter';

our @EXPORT_OK = qw(
parse_usb_device
get_usb_controllers
get_usb_devices
);

my $OLD_MAX_USB = 5;

sub parse_usb_device {
    my ($value) = @_;

    return if !$value;

    my $res = {};
    if ($value =~ m/^(0x)?([0-9A-Fa-f]{4}):(0x)?([0-9A-Fa-f]{4})$/) {
	$res->{vendorid} = $2;
	$res->{productid} = $4;
    } elsif ($value =~ m/^(\d+)\-(\d+(\.\d+)*)$/) {
	$res->{hostbus} = $1;
	$res->{hostport} = $2;
    } elsif ($value =~ m/^spice$/i) {
	$res->{spice} = 1;
    } else {
	return;
    }

    return $res;
}

my sub assert_usb_index_is_useable {
    my ($index, $use_qemu_xhci) = @_;

    die "using usb$index is only possible with machine type >= 7.1 and ostype l26 or windows > 7\n"
	if $index >= $OLD_MAX_USB && !$use_qemu_xhci;

    return undef;
}

sub get_usb_controllers {
    my ($conf, $bridges, $arch, $machine, $format, $max_usb_devices, $machine_version) = @_;

    my $devices = [];
    my $pciaddr = "";

    my $ostype = $conf->{ostype};

    my $use_qemu_xhci = min_version($machine_version, 7, 1)
	&& defined($ostype) && ($ostype eq 'l26' || windows_version($ostype) > 7);

    if ($arch eq 'aarch64') {
        $pciaddr = print_pci_addr('ehci', $bridges, $arch, $machine);
        push @$devices, '-device', "usb-ehci,id=ehci$pciaddr";
    } elsif (!PVE::QemuServer::Machine::machine_type_is_q35($conf)) {
        $pciaddr = print_pci_addr("piix3", $bridges, $arch, $machine);
        push @$devices, '-device', "piix3-usb-uhci,id=uhci$pciaddr.0x2";
    }

    my ($use_usb2, $use_usb3) = 0;
    my $any_usb = 0;
    for (my $i = 0; $i < $max_usb_devices; $i++)  {
	next if !$conf->{"usb$i"};
	assert_usb_index_is_useable($i, $use_qemu_xhci);
	my $d = eval { PVE::JSONSchema::parse_property_string($format,$conf->{"usb$i"}) } or next;
	$any_usb = 1;
	$use_usb3 = 1 if $d->{usb3};
	$use_usb2 = 1 if !$d->{usb3};
    }

    if (!$use_qemu_xhci && $use_usb2 && $arch ne 'aarch64') {
	# include usb device config if still on x86 before-xhci machines and if USB 3 is not used
	push @$devices, '-readconfig', '/usr/share/qemu-server/pve-usb.cfg';
    }

    $pciaddr = print_pci_addr("xhci", $bridges, $arch, $machine);
    if ($use_qemu_xhci && $any_usb) {
	push @$devices, '-device', print_qemu_xhci_controller($pciaddr);
    } elsif ($use_usb3) {
	push @$devices, '-device', "nec-usb-xhci,id=xhci$pciaddr";
    }

    return @$devices;
}

sub get_usb_devices {
    my ($conf, $format, $max_usb_devices, $features, $bootorder, $machine_version) = @_;

    my $devices = [];

    my $ostype = $conf->{ostype};
    my $use_qemu_xhci = min_version($machine_version, 7, 1)
	&& defined($ostype) && ($ostype eq 'l26' || windows_version($ostype) > 7);

    for (my $i = 0; $i < $max_usb_devices; $i++)  {
	my $devname = "usb$i";
	next if !$conf->{$devname};
	assert_usb_index_is_useable($i, $use_qemu_xhci);
	my $d = eval { PVE::JSONSchema::parse_property_string($format,$conf->{$devname}) };
	next if !$d;

	my $port;
	if ($use_qemu_xhci) {
	    $port = $i + 1;
	}

	if (defined($d->{host})) {
	    my $hostdevice = parse_usb_device($d->{host});
	    $hostdevice->{usb3} = $d->{usb3};
	    if ($hostdevice->{spice}) {
		# usb redir support for spice
		my $bus = 'ehci';
		$bus = 'xhci' if ($hostdevice->{usb3} && $features->{spice_usb3}) || $use_qemu_xhci;

		push @$devices, '-chardev', "spicevmc,id=usbredirchardev$i,name=usbredir";
		push @$devices, '-device', print_spice_usbdevice($i, $bus, $port);

		warn "warning: spice usb port set as bootdevice, ignoring\n" if $bootorder->{$devname};
	    } else {
		push @$devices, '-device', print_usbdevice_full($conf, $devname, $hostdevice, $bootorder, $port);
	    }
	}
    }

    return @$devices;
}

sub print_qemu_xhci_controller {
    my ($pciaddr) = @_;
    return "qemu-xhci,p2=15,p3=15,id=xhci$pciaddr";
}

sub print_spice_usbdevice {
    my ($index, $bus, $port) = @_;
    my $device = "usb-redir,chardev=usbredirchardev$index,id=usbredirdev$index,bus=$bus.0";
    if (defined($port)) {
	$device .= ",port=$port";
    }
    return $device;
}

sub print_usbdevice_full {
    my ($conf, $deviceid, $device, $bootorder, $port) = @_;

    return if !$device;
    my $usbdevice = "usb-host";

    # if it is a usb3 device or with newer qemu, attach it to the xhci controller, else omit the bus option
    if($device->{usb3} || defined($port)) {
	$usbdevice .= ",bus=xhci.0";
	$usbdevice .= ",port=$port" if defined($port);
    }

    if (defined($device->{vendorid}) && defined($device->{productid})) {
	$usbdevice .= ",vendorid=0x$device->{vendorid},productid=0x$device->{productid}";
    } elsif (defined($device->{hostbus}) && defined($device->{hostport})) {
	$usbdevice .= ",hostbus=$device->{hostbus},hostport=$device->{hostport}";
    } else {
	die "no usb id or path given\n";
    }

    $usbdevice .= ",id=$deviceid";
    $usbdevice .= ",bootindex=$bootorder->{$deviceid}" if $bootorder->{$deviceid};
    return $usbdevice;
}

1;
