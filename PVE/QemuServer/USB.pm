package PVE::QemuServer::USB;

use strict;
use warnings;
use PVE::QemuServer::PCI qw(print_pci_addr);
use PVE::JSONSchema;
use base 'Exporter';

our @EXPORT_OK = qw(
parse_usb_device
get_usb_controllers
get_usb_devices
);

sub parse_usb_device {
    my ($value) = @_;

    return undef if !$value;

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
	return undef;
    }

    return $res;
}

sub get_usb_controllers {
    my ($conf, $bridges, $isq35, $format, $max_usb_devices) = @_;

    my $devices = [];
    my $pciaddr = "";

    if ($isq35) {
	# the q35 chipset support native usb2, so we enable usb controller
	# by default for this machine type
        push @$devices, '-readconfig', '/usr/share/qemu-server/pve-q35.cfg';
    } else {
        $pciaddr = print_pci_addr("piix3", $bridges);
        push @$devices, '-device', "piix3-usb-uhci,id=uhci$pciaddr.0x2";

        my $use_usb2 = 0;
	for (my $i = 0; $i < $max_usb_devices; $i++)  {
	    next if !$conf->{"usb$i"};
	    my $d = eval { PVE::JSONSchema::parse_property_string($format,$conf->{"usb$i"}) };
	    next if !$d || $d->{usb3}; # do not add usb2 controller if we have only usb3 devices
	    $use_usb2 = 1;
	}
	# include usb device config
	push @$devices, '-readconfig', '/usr/share/qemu-server/pve-usb.cfg' if $use_usb2;
    }

    # add usb3 controller if needed

    my $use_usb3 = 0;
    for (my $i = 0; $i < $max_usb_devices; $i++)  {
	next if !$conf->{"usb$i"};
	my $d = eval { PVE::JSONSchema::parse_property_string($format,$conf->{"usb$i"}) };
	next if !$d || !$d->{usb3};
	$use_usb3 = 1;
    }

    $pciaddr = print_pci_addr("xhci", $bridges);
    push @$devices, '-device', "nec-usb-xhci,id=xhci$pciaddr" if $use_usb3;

    return @$devices;
}

sub get_usb_devices {
    my ($conf, $format, $max_usb_devices) = @_;

    my $devices = [];

    for (my $i = 0; $i < $max_usb_devices; $i++)  {
	next if !$conf->{"usb$i"};
	my $d = eval { PVE::JSONSchema::parse_property_string($format,$conf->{"usb$i"}) };
	next if !$d;

	if (defined($d->{host})) {
	    my $hostdevice = parse_usb_device($d->{host});
	    $hostdevice->{usb3} = $d->{usb3};
	    if (defined($hostdevice->{spice}) && $hostdevice->{spice}) {
		# usb redir support for spice, currently no usb3
		push @$devices, '-chardev', "spicevmc,id=usbredirchardev$i,name=usbredir";
		push @$devices, '-device', "usb-redir,chardev=usbredirchardev$i,id=usbredirdev$i,bus=ehci.0";
	    } else {
		push @$devices, '-device', print_usbdevice_full($conf, "usb$i", $hostdevice);
	    }
	}
    }

    return @$devices;
}

sub print_usbdevice_full {
    my ($conf, $deviceid, $device) = @_;

    return if !$device;
    my $usbdevice = "usb-host";

    # if it is a usb3 device, attach it to the xhci controller, else omit the bus option
    if($device->{usb3}) {
	$usbdevice .= ",bus=xhci.0";
    }

    if (defined($device->{vendorid}) && defined($device->{productid})) {
	$usbdevice .= ",vendorid=0x$device->{vendorid},productid=0x$device->{productid}";
    } elsif (defined($device->{hostbus}) && defined($device->{hostport})) {
	$usbdevice .= ",hostbus=$device->{hostbus},hostport=$device->{hostport}";
    }

    $usbdevice .= ",id=$deviceid";
    return $usbdevice;
}

1;
