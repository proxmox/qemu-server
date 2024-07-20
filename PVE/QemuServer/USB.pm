package PVE::QemuServer::USB;

use strict;
use warnings;
use PVE::QemuServer::PCI qw(print_pci_addr);
use PVE::QemuServer::Machine;
use PVE::QemuServer::Helpers qw(min_version windows_version);
use PVE::JSONSchema;
use PVE::Mapping::USB;
use base 'Exporter';

our @EXPORT_OK = qw(
parse_usb_device
get_usb_controllers
get_usb_devices
);

my $OLD_MAX_USB = 5;
our $MAX_USB_DEVICES = 14;


my $USB_ID_RE = qr/(0x)?([0-9A-Fa-f]{4}):(0x)?([0-9A-Fa-f]{4})/;
my $USB_PATH_RE = qr/(\d+)\-(\d+(\.\d+)*)/;

my $usb_fmt = {
    host => {
	default_key => 1,
	optional => 1,
	type => 'string',
	pattern => qr/(?:(?:$USB_ID_RE)|(?:$USB_PATH_RE)|[Ss][Pp][Ii][Cc][Ee])/,
	format_description => 'HOSTUSBDEVICE|spice',
        description => <<EODESCR,
The Host USB device or port or the value 'spice'. HOSTUSBDEVICE syntax is:

 'bus-port(.port)*' (decimal numbers) or
 'vendor_id:product_id' (hexadeciaml numbers) or
 'spice'

You can use the 'lsusb -t' command to list existing usb devices.

NOTE: This option allows direct access to host hardware. So it is no longer possible to migrate such
machines - use with special care.

The value 'spice' can be used to add a usb redirection devices for spice.

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
    usb3 => {
	optional => 1,
	type => 'boolean',
	description => "Specifies whether if given host option is a USB3 device or port."
	    ." For modern guests (machine version >= 7.1 and ostype l26 and windows > 7), this flag"
	    ." is irrelevant (all devices are plugged into a xhci controller).",
        default => 0,
    },
};

PVE::JSONSchema::register_format('pve-qm-usb', $usb_fmt);

our $usbdesc = {
    optional => 1,
    type => 'string', format => $usb_fmt,
    description => "Configure an USB device (n is 0 to 4, for machine version >= 7.1 and ostype"
	." l26 or windows > 7, n can be up to 14).",
};
PVE::JSONSchema::register_standard_option("pve-qm-usb", $usbdesc);

sub parse_usb_device {
    my ($value, $mapping) = @_;

    return if $value && $mapping; # not a valid configuration

    my $res = {};
    if (defined($value)) {
	if ($value =~ m/^$USB_ID_RE$/) {
	    $res->{vendorid} = $2;
	    $res->{productid} = $4;
	} elsif ($value =~ m/^$USB_PATH_RE$/) {
	    $res->{hostbus} = $1;
	    $res->{hostport} = $2;
	} elsif ($value =~ m/^spice$/i) {
	    $res->{spice} = 1;
	}
    } elsif (defined($mapping)) {
	my $devices = PVE::Mapping::USB::find_on_current_node($mapping);
	die "USB device mapping not found for '$mapping'\n" if !$devices || !scalar($devices->@*);
	die "More than one USB mapping per host not supported\n" if scalar($devices->@*) > 1;
	eval {
	    PVE::Mapping::USB::assert_valid($mapping, $devices->[0]);
	};
	if (my $err = $@) {
	    die "USB Mapping invalid (hardware probably changed): $err\n";
	}
	my $device = $devices->[0];

	if ($device->{path}) {
	    $res = parse_usb_device($device->{path});
	} else {
	    $res = parse_usb_device($device->{id});
	}
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
    my ($conf, $bridges, $arch, $machine, $machine_version) = @_;

    my $devices = [];
    my $pciaddr = "";

    my $ostype = $conf->{ostype};

    my $use_qemu_xhci = min_version($machine_version, 7, 1)
	&& defined($ostype) && ($ostype eq 'l26' || windows_version($ostype) > 7);
    my $is_q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);

    if ($arch eq 'aarch64') {
        push @$devices, '-device', "usb-ehci,id=ehci$pciaddr";
    } elsif ($arch =~ m/^sparc/) {
        print "USB disabled for sparc/sparc64\n";
    } elsif (!$is_q35) {
        $pciaddr = print_pci_addr("piix3", $bridges, $arch, $machine);
        push @$devices, '-device', "piix3-usb-uhci,id=uhci$pciaddr.0x2";
    }

    my ($use_usb2, $use_usb3) = 0;
    my $any_usb = 0;
    for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	next if !$conf->{"usb$i"};
	assert_usb_index_is_useable($i, $use_qemu_xhci);
	my $d = eval { PVE::JSONSchema::parse_property_string($usb_fmt, $conf->{"usb$i"}) } or next;
	$any_usb = 1;
	$use_usb3 = 1 if $d->{usb3};
	$use_usb2 = 1 if !$d->{usb3};
    }

    if (!$use_qemu_xhci && !$is_q35 && $use_usb2 && $arch ne 'aarch64' && $arch !~ m/^sparc/) {
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
    my ($conf, $features, $bootorder, $machine_version) = @_;

    my $devices = [];

    my $ostype = $conf->{ostype};
    my $use_qemu_xhci = min_version($machine_version, 7, 1)
	&& defined($ostype) && ($ostype eq 'l26' || windows_version($ostype) > 7);

    for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	my $devname = "usb$i";
	next if !$conf->{$devname};
	assert_usb_index_is_useable($i, $use_qemu_xhci);
	my $d = eval { PVE::JSONSchema::parse_property_string($usb_fmt, $conf->{$devname}) };
	next if !$d;

	my $port = $use_qemu_xhci ? $i + 1 : undef;

	if ($d->{host} && $d->{host} =~ m/^spice$/) {
	    # usb redir support for spice
	    my $bus = 'ehci';
	    $bus = 'xhci' if ($d->{usb3} && $features->{spice_usb3}) || $use_qemu_xhci;

	    push @$devices, '-chardev', "spicevmc,id=usbredirchardev$i,name=usbredir";
	    push @$devices, '-device', print_spice_usbdevice($i, $bus, $port);

	    warn "warning: spice usb port set as bootdevice, ignoring\n" if $bootorder->{$devname};
	} else {
	    push @$devices, '-device', print_usbdevice_full($conf, $devname, $d, $bootorder, $port);
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
    if ($device->{usb3} || defined($port)) {
	$usbdevice .= ",bus=xhci.0";
	$usbdevice .= ",port=$port" if defined($port);
    }

    my $parsed = parse_usb_device($device->{host}, $device->{mapping});

    if (defined($parsed->{vendorid}) && defined($parsed->{productid})) {
	$usbdevice .= ",vendorid=0x$parsed->{vendorid},productid=0x$parsed->{productid}";
    } elsif (defined($parsed->{hostbus}) && defined($parsed->{hostport})) {
	$usbdevice .= ",hostbus=$parsed->{hostbus},hostport=$parsed->{hostport}";
    } else {
	die "no usb id or path given\n";
    }

    $usbdevice .= ",id=$deviceid";
    $usbdevice .= ",bootindex=$bootorder->{$deviceid}" if $bootorder->{$deviceid};
    return $usbdevice;
}

1;
