package PVE::QemuServer;

use strict;
use POSIX;
use IO::Handle;
use IO::Select;
use IO::File;
use IO::Dir;
use IO::Socket::UNIX;
use File::Basename;
use File::Path;
use File::stat;
use Getopt::Long;
use Digest::SHA1;
use Fcntl ':flock';
use Cwd 'abs_path';
use IPC::Open3;
use Fcntl;
use PVE::SafeSyslog;
use Storable qw(dclone);
use PVE::Exception qw(raise raise_param_exc);
use PVE::Storage;
use PVE::Tools qw(run_command lock_file file_read_firstline);
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);
use PVE::INotify;
use PVE::ProcFSTools;
use Time::HiRes qw(gettimeofday);

my $cpuinfo = PVE::ProcFSTools::read_cpuinfo();

# Note about locking: we use flock on the config file protect
# against concurent actions.
# Aditionaly, we have a 'lock' setting in the config file. This
# can be set to 'migrate' or 'backup'. Most actions are not
# allowed when such lock is set. But you can ignore this kind of
# lock with the --skiplock flag.

cfs_register_file('/qemu-server/', \&parse_vm_config);

PVE::JSONSchema::register_standard_option('skiplock', {
    description => "Ignore locks - only root is allowed to use this option.",
    type => 'boolean', 
    optional => 1,
});

PVE::JSONSchema::register_standard_option('pve-qm-stateuri', {
    description => "Some command save/restore state from this location.",
    type => 'string',
    maxLength => 128,
    optional => 1,
});

#no warnings 'redefine';

unless(defined(&_VZSYSCALLS_H_)) {
    eval 'sub _VZSYSCALLS_H_ () {1;}' unless defined(&_VZSYSCALLS_H_);
    require 'sys/syscall.ph';
    if(defined(&__x86_64__)) {
	eval 'sub __NR_fairsched_vcpus () {499;}' unless defined(&__NR_fairsched_vcpus);
	eval 'sub __NR_fairsched_mknod () {504;}' unless defined(&__NR_fairsched_mknod);
	eval 'sub __NR_fairsched_rmnod () {505;}' unless defined(&__NR_fairsched_rmnod);
	eval 'sub __NR_fairsched_chwt () {506;}' unless defined(&__NR_fairsched_chwt);
	eval 'sub __NR_fairsched_mvpr () {507;}' unless defined(&__NR_fairsched_mvpr);
	eval 'sub __NR_fairsched_rate () {508;}' unless defined(&__NR_fairsched_rate);
	eval 'sub __NR_setluid () {501;}' unless defined(&__NR_setluid);
	eval 'sub __NR_setublimit () {502;}' unless defined(&__NR_setublimit);
    }
    elsif(defined( &__i386__) ) {
	eval 'sub __NR_fairsched_mknod () {500;}' unless defined(&__NR_fairsched_mknod);
	eval 'sub __NR_fairsched_rmnod () {501;}' unless defined(&__NR_fairsched_rmnod);
	eval 'sub __NR_fairsched_chwt () {502;}' unless defined(&__NR_fairsched_chwt);
	eval 'sub __NR_fairsched_mvpr () {503;}' unless defined(&__NR_fairsched_mvpr);
	eval 'sub __NR_fairsched_rate () {504;}' unless defined(&__NR_fairsched_rate);
	eval 'sub __NR_fairsched_vcpus () {505;}' unless defined(&__NR_fairsched_vcpus);
	eval 'sub __NR_setluid () {511;}' unless defined(&__NR_setluid);
	eval 'sub __NR_setublimit () {512;}' unless defined(&__NR_setublimit);
    } else {
	die("no fairsched syscall for this arch");
    }
    require 'asm/ioctl.ph';
    eval 'sub KVM_GET_API_VERSION () { &_IO(0xAE, 0x);}' unless defined(&KVM_GET_API_VERSION);
}

sub fairsched_mknod {
    my ($parent, $weight, $desired) = @_;

    return syscall(&__NR_fairsched_mknod, int($parent), int($weight), int($desired));
}

sub fairsched_rmnod {
    my ($id) = @_;

    return syscall(&__NR_fairsched_rmnod, int($id));
}

sub fairsched_mvpr {
    my ($pid, $newid) = @_;

    return syscall(&__NR_fairsched_mvpr, int($pid), int($newid));
}

sub fairsched_vcpus {
    my ($id, $vcpus) = @_;

    return syscall(&__NR_fairsched_vcpus, int($id), int($vcpus));
}

sub fairsched_rate {
    my ($id, $op, $rate) = @_;

    return syscall(&__NR_fairsched_rate, int($id), int($op), int($rate));
}

use constant FAIRSCHED_SET_RATE  => 0;
use constant FAIRSCHED_DROP_RATE => 1;
use constant FAIRSCHED_GET_RATE  => 2;

sub fairsched_cpulimit {
    my ($id, $limit) = @_;

    my $cpulim1024 = int($limit * 1024 / 100);
    my $op = $cpulim1024 ? FAIRSCHED_SET_RATE : FAIRSCHED_DROP_RATE;

    return fairsched_rate($id, $op, $cpulim1024);
}

my $nodename = PVE::INotify::nodename();

mkdir "/etc/pve/nodes/$nodename";
my $confdir = "/etc/pve/nodes/$nodename/qemu-server";
mkdir $confdir;

my $var_run_tmpdir = "/var/run/qemu-server";
mkdir $var_run_tmpdir;

my $lock_dir = "/var/lock/qemu-server";
mkdir $lock_dir;

my $pcisysfs = "/sys/bus/pci";

my $keymaphash = PVE::Tools::kvmkeymaps();

my $confdesc = {
    onboot => {
	optional => 1,
	type => 'boolean',
	description => "Specifies whether a VM will be started during system bootup.",
	default => 0,
    },
    autostart => {
	optional => 1,
	type => 'boolean',
	description => "Automatic restart after crash (currently ignored).",
	default => 0,
    },
    reboot => {
	optional => 1,
	type => 'boolean',
	description => "Allow reboot. If set to '0' the VM exit on reboot.",
	default => 1,
    },
    lock => {
	optional => 1,
	type => 'string',
	description => "Lock/unlock the VM.",
	enum => [qw(migrate backup)],
    },
    cpulimit => {
	optional => 1,
	type => 'integer',
	description => "Limit of CPU usage in per cent. Note if the computer has 2 CPUs, it has total of 200% CPU time. Value '0' indicates no CPU limit.\n\nNOTE: This option is currently ignored.",
	minimum => 0,
	default => 0,
    },
    cpuunits => {
	optional => 1,
	type => 'integer',
	description => "CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to weights of all the other running VMs.\n\nNOTE: You can disable fair-scheduler configuration by setting this to 0.",
	minimum => 0,
	maximum => 500000,
	default => 1000,
    },
    memory => {
	optional => 1,
	type => 'integer',
	description => "Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.",
	minimum => 16,
	default => 512,
    },
    balloon => {
        optional => 1,
        type => 'integer',
        description => "Amount of target RAM for the VM in MB.",
	minimum => 16,
    },
    keyboard => {
	optional => 1,
	type => 'string',
	description => "Keybord layout for vnc server. Default is read from the datacenter configuration file.",
	enum => [ keys %$keymaphash ],
	default => 'en-us',
    },
    name => {
	optional => 1,
	type => 'string',
	description => "Set a name for the VM. Only used on the configuration web interface.",
    },
    description => {
	optional => 1,
	type => 'string',
	description => "Description for the VM. Only used on the configuration web interface.",
    },
    ostype => {
	optional => 1,
	type => 'string',
        enum => [qw(other wxp w2k w2k3 w2k8 wvista win7 l24 l26)],
	description => <<EODESC,
Used to enable special optimization/features for specific
operating systems:

other  => unspecified OS
wxp    => Microsoft Windows XP
w2k    => Microsoft Windows 2000
w2k3   => Microsoft Windows 2003
w2k8   => Microsoft Windows 2008
wvista => Microsoft Windows Vista
win7   => Microsoft Windows 7
l24    => Linux 2.4 Kernel
l26    => Linux 2.6/3.X Kernel

other|l24|l26                  ... no special behaviour
wxp|w2k|w2k3|w2k8|wvista|win7  ... use --localtime switch
EODESC
    },
    boot => {
	optional => 1,
	type => 'string',
	description => "Boot on floppy (a), hard disk (c), CD-ROM (d), or network (n).",
	pattern => '[acdn]{1,4}',
	default => 'cdn',
    },
    bootdisk => {
	optional => 1,
	type => 'string', format => 'pve-qm-bootdisk',
	description => "Enable booting from specified disk.",
	pattern => '(ide|scsi|virtio)\d+',
    },
    smp => {
	optional => 1,
	type => 'integer',
	description => "The number of CPUs. Please use option -sockets instead.",
	minimum => 1,
	default => 1,
    },
    sockets => {
	optional => 1,
	type => 'integer',
	description => "The number of CPU sockets.",
	minimum => 1,
	default => 1,
    },
    cores => {
	optional => 1,
	type => 'integer',
	description => "The number of cores per socket.",
	minimum => 1,
	default => 1,
    },
    acpi => {
	optional => 1,
	type => 'boolean',
	description => "Enable/disable ACPI.",
	default => 1,
    },
    kvm => {
	optional => 1,
	type => 'boolean',
	description => "Enable/disable KVM hardware virtualization.",
	default => 1,
    },
    tdf => {
	optional => 1,
	type => 'boolean',
	description => "Enable/disable time drift fix.",
	default => 1,
    },
    localtime => {
	optional => 1,
	type => 'boolean',
	description => "Set the real time clock to local time. This is enabled by default if ostype indicates a Microsoft OS.",
    },
    freeze => {
	optional => 1,
	type => 'boolean',
	description => "Freeze CPU at startup (use 'c' monitor command to start execution).",
    },
    vga => {
	optional => 1,
	type => 'string',
	description => "Select VGA type. If you want to use high resolution modes (>= 1280x1024x16) then you should use option 'std' or 'vmware'. Default is 'std' for win7/w2k8, and 'cirrur' for other OS types",
	enum => [qw(std cirrus vmware)],
    },
    watchdog => {
	optional => 1,
	type => 'string', format => 'pve-qm-watchdog',
	typetext => '[[model=]i6300esb|ib700] [,[action=]reset|shutdown|poweroff|pause|debug|none]',
	description => "Create a virtual hardware watchdog device.  Once enabled (by a guest action), the watchdog must be periodically polled by an agent inside the guest or else the guest will be restarted (or execute the action specified)",
    },
    startdate => {
	optional => 1,
	type => 'string',
	typetext => "(now | YYYY-MM-DD | YYYY-MM-DDTHH:MM:SS)",
	description => "Set the initial date of the real time clock. Valid format for date are: 'now' or '2006-06-17T16:01:21' or '2006-06-17'.",
	pattern => '(now|\d{4}-\d{1,2}-\d{1,2}(T\d{1,2}:\d{1,2}:\d{1,2})?)',
	default => 'now',
    },
    args => {
	optional => 1,
	type => 'string',
	description => <<EODESCR,
Note: this option is for experts only. It allows you to pass arbitrary arguments to kvm, for example:

args: -no-reboot -no-hpet
EODESCR
    },
    tablet => {
	optional => 1,
	type => 'boolean',
	default => 1,
	description => "Enable/disable the usb tablet device. This device is usually needed to allow absolute mouse positioning. Else the mouse runs out of sync with normal vnc clients. If you're running lots of console-only guests on one host, you may consider disabling this to save some context switches.",
    },
    migrate_speed => {
	optional => 1,
	type => 'integer',
	description => "Set maximum speed (in MB/s) for migrations. Value 0 is no limit.",
	minimum => 0,
	default => 0,
    },
    migrate_downtime => {
	optional => 1,
	type => 'integer',
	description => "Set maximum tolerated downtime (in seconds) for migrations.",
	minimum => 0,
	default => 1,
    },
    cdrom => {
	optional => 1,
	type => 'string', format => 'pve-qm-drive',
	typetext => 'volume',
	description => "This is an alias for option -ide2",
    },
    cpu => {
	optional => 1,
	description => "Emulated CPU type.",
	type => 'string',
	enum => [ qw(486 athlon pentium pentium2 pentium3 coreduo core2duo kvm32 kvm64 qemu32 qemu64 phenom host) ],
	default => 'qemu64',
    },
};

# what about other qemu settings ?
#cpu => 'string',
#machine => 'string',
#fda => 'file',
#fdb => 'file',
#mtdblock => 'file',
#sd => 'file',
#pflash => 'file',
#snapshot => 'bool',
#bootp => 'file',
##tftp => 'dir',
##smb => 'dir',
#kernel => 'file',
#append => 'string',
#initrd => 'file',
##soundhw => 'string',

while (my ($k, $v) = each %$confdesc) {
    PVE::JSONSchema::register_standard_option("pve-qm-$k", $v);
}

my $MAX_IDE_DISKS = 4;
my $MAX_SCSI_DISKS = 14;
my $MAX_VIRTIO_DISKS = 6;
my $MAX_USB_DEVICES = 5;
my $MAX_NETS = 6;
my $MAX_UNUSED_DISKS = 8;
my $MAX_HOSTPCI_DEVICES = 2;
my $MAX_SERIAL_PORTS = 4;
my $MAX_PARALLEL_PORTS = 3;

my $nic_model_list = ['rtl8139', 'ne2k_pci', 'e1000',  'pcnet',  'virtio',
		      'ne2k_isa', 'i82551', 'i82557b', 'i82559er'];
my $nic_model_list_txt = join(' ', sort @$nic_model_list);

# fixme:
my $netdesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-net',
    typetext => "MODEL=XX:XX:XX:XX:XX:XX [,bridge=<dev>][,rate=<mbps>]",
    description => <<EODESCR,
Specify network devices.

MODEL is one of: $nic_model_list_txt

XX:XX:XX:XX:XX:XX should be an unique MAC address. This is
automatically generated if not specified.

The bridge parameter can be used to automatically add the interface to a bridge device. The Proxmox VE standard bridge is called 'vmbr0'.

Option 'rate' is used to limit traffic bandwidth from and to this interface. It is specified as floating point number, unit is 'Megabytes per second'.

If you specify no bridge, we create a kvm 'user' (NATed) network device, which provides DHCP and DNS services. The following addresses are used:

10.0.2.2   Gateway
10.0.2.3   DNS Server
10.0.2.4   SMB Server

The DHCP server assign addresses to the guest starting from 10.0.2.15.

EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-net", $netdesc);

for (my $i = 0; $i < $MAX_NETS; $i++)  {
    $confdesc->{"net$i"} = $netdesc;
}

my $drivename_hash;

my $idedesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback] [,format=f] [,backup=yes|no] [,aio=native|threads]',
    description => "Use volume as IDE hard disk or CD-ROM (n is 0 to 3).",
};
PVE::JSONSchema::register_standard_option("pve-qm-ide", $idedesc);

my $scsidesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback] [,format=f] [,backup=yes|no] [,aio=native|threads]',
    description => "Use volume as SCSI hard disk or CD-ROM (n is 0 to 13).",
};
PVE::JSONSchema::register_standard_option("pve-qm-scsi", $scsidesc);

my $virtiodesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback] [,format=f] [,backup=yes|no] [,aio=native|threads]',
    description => "Use volume as VIRTIO hard disk (n is 0 to 5).",
};
PVE::JSONSchema::register_standard_option("pve-qm-virtio", $virtiodesc);

my $usbdesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-usb-device',
    typetext => 'host=HOSTUSBDEVICE',
    description => <<EODESCR,
Configure an USB device (n is 0 to 4). This can be used to
pass-through usb devices to the guest. HOSTUSBDEVICE syntax is:

'bus-port(.port)*' (decimal numbers) or
'vendor_id:product_id' (hexadeciaml numbers)

You can use the 'lsusb -t' command to list existing usb devices.

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-usb", $usbdesc);

my $hostpcidesc = {
        optional => 1,
        type => 'string', format => 'pve-qm-hostpci',
        typetext => "HOSTPCIDEVICE",
        description => <<EODESCR,
Map host pci devices. HOSTPCIDEVICE syntax is:

'bus:dev.func' (hexadecimal numbers)

You can us the 'lspci' command to list existing pci devices.

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

Experimental: user reported problems with this option.
EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-hostpci", $hostpcidesc);

my $serialdesc = {
	optional => 1,
	type => 'string',
	pattern => '/dev/ttyS\d+',
	description =>  <<EODESCR,
Map host serial devices (n is 0 to 3).

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

Experimental: user reported problems with this option.
EODESCR
};

my $paralleldesc= {
	optional => 1,
	type => 'string',
	pattern => '/dev/parport\d+',
	description =>  <<EODESCR,
Map host parallel devices (n is 0 to 2).

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

Experimental: user reported problems with this option.
EODESCR
};

for (my $i = 0; $i < $MAX_PARALLEL_PORTS; $i++)  {
    $confdesc->{"parallel$i"} = $paralleldesc;
}

for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++)  {
    $confdesc->{"serial$i"} = $serialdesc;
}

for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
    $confdesc->{"hostpci$i"} = $hostpcidesc;
}

for (my $i = 0; $i < $MAX_IDE_DISKS; $i++)  {
    $drivename_hash->{"ide$i"} = 1;
    $confdesc->{"ide$i"} = $idedesc;
}

for (my $i = 0; $i < $MAX_SCSI_DISKS; $i++)  {
    $drivename_hash->{"scsi$i"} = 1;
    $confdesc->{"scsi$i"} = $scsidesc ;
}

for (my $i = 0; $i < $MAX_VIRTIO_DISKS; $i++)  {
    $drivename_hash->{"virtio$i"} = 1;
    $confdesc->{"virtio$i"} = $virtiodesc;
}

for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
    $confdesc->{"usb$i"} = $usbdesc;
}

my $unuseddesc = {
    optional => 1,
    type => 'string', format => 'pve-volume-id',
    description => "Reference to unused volumes.",
};

for (my $i = 0; $i < $MAX_UNUSED_DISKS; $i++)  {
    $confdesc->{"unused$i"} = $unuseddesc;
}

my $kvm_api_version = 0;

sub kvm_version {

    return $kvm_api_version if $kvm_api_version;

    my $fh = IO::File->new("</dev/kvm") ||
	return 0;

    if (my $v = $fh->ioctl(KVM_GET_API_VERSION(), 0)) {
	$kvm_api_version = $v;
    }

    $fh->close();

    return  $kvm_api_version;
}

my $kvm_user_version;

sub kvm_user_version {

    return $kvm_user_version if $kvm_user_version;

    $kvm_user_version = 'unknown';

    my $tmp = `kvm -help 2>/dev/null`;

    if ($tmp =~ m/^QEMU( PC)? emulator version (\d+\.\d+\.\d+) /) {
	$kvm_user_version = $2;
    }

    return $kvm_user_version;

}

my $kernel_has_vhost_net = -c '/dev/vhost-net';

sub disknames {
    # order is important - used to autoselect boot disk
    return ((map { "ide$_" } (0 .. ($MAX_IDE_DISKS - 1))),
            (map { "scsi$_" } (0 .. ($MAX_SCSI_DISKS - 1))),
            (map { "virtio$_" } (0 .. ($MAX_VIRTIO_DISKS - 1))));
}

sub valid_drivename {
    my $dev = shift;

    return defined($drivename_hash->{$dev});
}

sub option_exists {
    my $key = shift;
    return defined($confdesc->{$key});
}

sub nic_models {
    return $nic_model_list;
}

sub os_list_description {

    return {
	other => 'Other',
	wxp => 'Windows XP',
	w2k => 'Windows 2000',
	w2k3 =>, 'Windows 2003',
	w2k8 => 'Windows 2008',
	wvista => 'Windows Vista',
	win7 => 'Windows 7',
	l24 => 'Linux 2.4',
	l26 => 'Linux 2.6',
    };
}

# a clumsy way to split an argument string into an array,
# we simply pass it to the cli (exec call)
# fixme: use Text::ParseWords::shellwords() ?
sub split_args {
    my ($str) = @_;

    my $args = [];

    return $args if !$str;

    my $cmd = 'perl -e \'foreach my $a (@ARGV) { print "$a\n"; } \' -- ' . $str;

    eval {
	run_command($cmd, outfunc => sub {
	    my $data = shift;
	    push @$args, $data;
	});
    };

    my $err = $@;

    die "unable to parse args: $str\n" if $err;

    return $args;
}

sub disk_devive_info {
    my $dev = shift;

    die "unknown disk device format '$dev'" if $dev !~ m/^(ide|scsi|virtio)(\d+)$/;

    my $bus = $1;
    my $index = $2;
    my $maxdev = 1024;

    if ($bus eq 'ide') {
	$maxdev = 2;
    } elsif ($bus eq 'scsi') {
	$maxdev = 7;
    }

    my $controller = int($index / $maxdev);
    my $unit = $index % $maxdev;


    return { bus => $bus, desc => uc($bus) . " $controller:$unit",
	     controller => $controller, unit => $unit, index => $index };

}

sub qemu_drive_name {
    my ($dev, $media) = @_;

    my $info = disk_devive_info($dev);
    my $mediastr = '';

    if (($info->{bus} eq 'ide') || ($info->{bus} eq 'scsi')) {
	$mediastr = ($media eq 'cdrom') ? "-cd" : "-hd";
	return sprintf("%s%i%s%i", $info->{bus}, $info->{controller},
		       $mediastr, $info->{unit});
    } else {
	return sprintf("%s%i", $info->{bus}, $info->{index});
    }
}

my $cdrom_path;

sub get_cdrom_path {

    return  $cdrom_path if $cdrom_path;

    return $cdrom_path = "/dev/cdrom" if -l "/dev/cdrom";
    return $cdrom_path = "/dev/cdrom1" if -l "/dev/cdrom1";
    return $cdrom_path = "/dev/cdrom2" if -l "/dev/cdrom2";
}

sub get_iso_path {
    my ($storecfg, $vmid, $cdrom) = @_;

    if ($cdrom eq 'cdrom') {
	return get_cdrom_path();
    } elsif ($cdrom eq 'none') {
	return '';
    } elsif ($cdrom =~ m|^/|) {
	return $cdrom;
    } else {
	return PVE::Storage::path($storecfg, $cdrom);
    }
}

# try to convert old style file names to volume IDs
sub filename_to_volume_id {
    my ($vmid, $file, $media) = @_;

    if (!($file eq 'none' || $file eq 'cdrom' ||
	  $file =~ m|^/dev/.+| || $file =~ m/^([^:]+):(.+)$/)) {

	return undef if $file =~ m|/|;

	if ($media && $media eq 'cdrom') {
	    $file = "local:iso/$file";
	} else {
	    $file = "local:$vmid/$file";
	}
    }

    return $file;
}

sub verify_media_type {
    my ($opt, $vtype, $media) = @_;

    return if !$media;

    my $etype;
    if ($media eq 'disk') {
	$etype = 'image';
    } elsif ($media eq 'cdrom') {
	$etype = 'iso';
    } else {
	die "internal error";
    }

    return if ($vtype eq $etype);

    raise_param_exc({ $opt => "unexpected media type ($vtype != $etype)" });
}

sub cleanup_drive_path {
    my ($opt, $storecfg, $drive) = @_;

    # try to convert filesystem paths to volume IDs

    if (($drive->{file} !~ m/^(cdrom|none)$/) &&
	($drive->{file} !~ m|^/dev/.+|) &&
	($drive->{file} !~ m/^([^:]+):(.+)$/) &&
	($drive->{file} !~ m/^\d+$/)) {
	my ($vtype, $volid) = PVE::Storage::path_to_volume_id($storecfg, $drive->{file});
	raise_param_exc({ $opt => "unable to associate path '$drive->{file}' to any storage"}) if !$vtype;
	$drive->{media} = 'cdrom' if !$drive->{media} && $vtype eq 'iso';
	verify_media_type($opt, $vtype, $drive->{media});
	$drive->{file} = $volid;
    }

    $drive->{media} = 'cdrom' if !$drive->{media} && $drive->{file} =~ m/^(cdrom|none)$/;
}

sub create_conf_nolock {
    my ($vmid, $settings) = @_;

    my $filename = config_file($vmid);

    die "configuration file '$filename' already exists\n" if -f $filename;

    my $defaults = load_defaults();

    $settings->{name} = "vm$vmid" if !$settings->{name};
    $settings->{memory} = $defaults->{memory} if !$settings->{memory};

    my $data = '';
    foreach my $opt (keys %$settings) {
	next if !$confdesc->{$opt};

	my $value = $settings->{$opt};
	next if !$value;

	$data .= "$opt: $value\n";
    }

    PVE::Tools::file_set_contents($filename, $data);
}

# ideX = [volume=]volume-id[,media=d][,cyls=c,heads=h,secs=s[,trans=t]]
#        [,snapshot=on|off][,cache=on|off][,format=f][,backup=yes|no]
#        [,aio=native|threads]

sub parse_drive {
    my ($key, $data) = @_;

    my $res = {};

    # $key may be undefined - used to verify JSON parameters
    if (!defined($key)) {
	$res->{interface} = 'unknown'; # should not harm when used to verify parameters
	$res->{index} = 0;
    } elsif ($key =~ m/^([^\d]+)(\d+)$/) {
	$res->{interface} = $1;
	$res->{index} = $2;
    } else {
	return undef;
    }

    foreach my $p (split (/,/, $data)) {
	next if $p =~ m/^\s*$/;

	if ($p =~ m/^(file|volume|cyls|heads|secs|trans|media|snapshot|cache|format|rerror|werror|backup|aio)=(.+)$/) {
	    my ($k, $v) = ($1, $2);

	    $k = 'file' if $k eq 'volume';

	    return undef if defined $res->{$k};

	    $res->{$k} = $v;
	} else {
	    if (!$res->{file} && $p !~ m/=/) {
		$res->{file} = $p;
	    } else {
		return undef;
	    }
	}
    }

    return undef if !$res->{file};

    return undef if $res->{cache} &&
	$res->{cache} !~ m/^(off|none|writethrough|writeback)$/;
    return undef if $res->{snapshot} && $res->{snapshot} !~ m/^(on|off)$/;
    return undef if $res->{cyls} && $res->{cyls} !~ m/^\d+$/;
    return undef if $res->{heads} && $res->{heads} !~ m/^\d+$/;
    return undef if $res->{secs} && $res->{secs} !~ m/^\d+$/;
    return undef if $res->{media} && $res->{media} !~ m/^(disk|cdrom)$/;
    return undef if $res->{trans} && $res->{trans} !~ m/^(none|lba|auto)$/;
    return undef if $res->{format} && $res->{format} !~ m/^(raw|cow|qcow|qcow2|vmdk|cloop)$/;
    return undef if $res->{rerror} && $res->{rerror} !~ m/^(ignore|report|stop)$/;
    return undef if $res->{werror} && $res->{werror} !~ m/^(enospc|ignore|report|stop)$/;
    return undef if $res->{backup} && $res->{backup} !~ m/^(yes|no)$/;
    return undef if $res->{aio} && $res->{aio} !~ m/^(native|threads)$/;

    if ($res->{media} && ($res->{media} eq 'cdrom')) {
	return undef if $res->{snapshot} || $res->{trans} || $res->{format};
	return undef if $res->{heads} || $res->{secs} || $res->{cyls};
	return undef if $res->{interface} eq 'virtio';
    }

    # rerror does not work with scsi drives
    if ($res->{rerror}) {
	return undef if $res->{interface} eq 'scsi';
    }

    return $res;
}

my @qemu_drive_options = qw(heads secs cyls trans media format cache snapshot rerror werror aio);

sub print_drive {
    my ($vmid, $drive) = @_;

    my $opts = '';
    foreach my $o (@qemu_drive_options, 'backup') {
	$opts .= ",$o=$drive->{$o}" if $drive->{$o};
    }

    return "$drive->{file}$opts";
}

sub print_drivedevice_full {
    my ($storecfg, $vmid, $drive) = @_;

    my $device = '';
    my $maxdev = 0;

    if ($drive->{interface} eq 'virtio') {
      my $pciaddr = print_pci_addr("$drive->{interface}$drive->{index}");
      $device = "virtio-blk-pci,drive=drive-$drive->{interface}$drive->{index},id=device-$drive->{interface}$drive->{index}$pciaddr";
    }

    elsif ($drive->{interface} eq 'scsi') {

      $maxdev = 7;
      my $controller = int($drive->{index} / $maxdev);
      my $unit = $drive->{index} % $maxdev;

      $device = "scsi-disk,bus=scsi$controller.0,scsi-id=$unit,drive=drive-$drive->{interface}$drive->{index},id=device-$drive->{interface}$drive->{index}";
    }

    elsif ($drive->{interface} eq 'ide'){

      $maxdev = 2;
      my $controller = int($drive->{index} / $maxdev);
      my $unit = $drive->{index} % $maxdev;

      $device = "ide-drive,bus=ide.$controller,unit=$unit,drive=drive-$drive->{interface}$drive->{index},id=device-$drive->{interface}$drive->{index}";
    }

    if ($drive->{interface} eq 'usb'){
      #  -device ide-drive,bus=ide.1,unit=0,drive=drive-ide0-1-0,id=ide0-1-0
    }

    return $device;
}

sub print_drive_full {
    my ($storecfg, $vmid, $drive) = @_;

    my $opts = '';
    foreach my $o (@qemu_drive_options) {
	$opts .= ",$o=$drive->{$o}" if $drive->{$o};
    }

    # use linux-aio by default (qemu default is threads)
    $opts .= ",aio=native" if !$drive->{aio};

    my $path;
    my $volid = $drive->{file};
    if (drive_is_cdrom($drive)) {
	$path = get_iso_path($storecfg, $vmid, $volid);
    } else {
	if ($volid =~ m|^/|) {
	    $path = $volid;
	} else {
	    $path = PVE::Storage::path($storecfg, $volid);
	}
    }

    my $pathinfo = $path ? "file=$path," : '';

    return "${pathinfo}if=none,id=drive-$drive->{interface}$drive->{index}$opts";
}


sub drive_is_cdrom {
    my ($drive) = @_;

    return $drive && $drive->{media} && ($drive->{media} eq 'cdrom');

}

sub parse_hostpci {
    my ($value) = @_;

    return undef if !$value;

    my $res = {};

    if ($value =~ m/^[a-f0-9]{2}:[a-f0-9]{2}\.[a-f0-9]$/) {
       $res->{pciid} = $value;
    } else {
       return undef;
    }

    return $res;
}

# netX: e1000=XX:XX:XX:XX:XX:XX,bridge=vmbr0,rate=<mbps>
sub parse_net {
    my ($data) = @_;

    my $res = {};

    foreach my $kvp (split(/,/, $data)) {

	if ($kvp =~ m/^(ne2k_pci|e1000|rtl8139|pcnet|virtio|ne2k_isa|i82551|i82557b|i82559er)(=([0-9a-f]{2}(:[0-9a-f]{2}){5}))?$/i) {
	    my $model = lc($1);
	    my $mac = uc($3) || PVE::Tools::random_ether_addr();
	    $res->{model} = $model;
	    $res->{macaddr} = $mac;
	} elsif ($kvp =~ m/^bridge=(\S+)$/) {
	    $res->{bridge} = $1;
	} elsif ($kvp =~ m/^rate=(\d+(\.\d+)?)$/) {
	    $res->{rate} = $1;
	} else {
	    return undef;
	}

    }

    return undef if !$res->{model};

    return $res;
}

sub print_net {
    my $net = shift;

    my $res = "$net->{model}";
    $res .= "=$net->{macaddr}" if $net->{macaddr};
    $res .= ",bridge=$net->{bridge}" if $net->{bridge};
    $res .= ",rate=$net->{rate}" if $net->{rate};

    return $res;
}

sub add_random_macs {
    my ($settings) = @_;

    foreach my $opt (keys %$settings) {
	next if $opt !~ m/^net(\d+)$/;
	my $net = parse_net($settings->{$opt});
	next if !$net;
	$settings->{$opt} = print_net($net);
    }
}

sub add_unused_volume {
    my ($config, $res, $volid) = @_;

    my $key;
    for (my $ind = $MAX_UNUSED_DISKS - 1; $ind >= 0; $ind--) {
	my $test = "unused$ind";
	if (my $vid = $config->{$test}) {
	    return if $vid eq $volid; # do not add duplicates
	} else {
	    $key = $test;
	}
    }

    die "To many unused volume - please delete them first.\n" if !$key;

    $res->{$key} = $volid;
}

# fixme: remove all thos $noerr parameters?

PVE::JSONSchema::register_format('pve-qm-bootdisk', \&verify_bootdisk);
sub verify_bootdisk {
    my ($value, $noerr) = @_;

    return $value if valid_drivename($value);

    return undef if $noerr;

    die "invalid boot disk '$value'\n";
}

PVE::JSONSchema::register_format('pve-qm-net', \&verify_net);
sub verify_net {
    my ($value, $noerr) = @_;

    return $value if parse_net($value);

    return undef if $noerr;

    die "unable to parse network options\n";
}

PVE::JSONSchema::register_format('pve-qm-drive', \&verify_drive);
sub verify_drive {
    my ($value, $noerr) = @_;

    return $value if parse_drive(undef, $value);

    return undef if $noerr;

    die "unable to parse drive options\n";
}

PVE::JSONSchema::register_format('pve-qm-hostpci', \&verify_hostpci);
sub verify_hostpci {
    my ($value, $noerr) = @_;

    return $value if parse_hostpci($value);

    return undef if $noerr;

    die "unable to parse pci id\n";
}

PVE::JSONSchema::register_format('pve-qm-watchdog', \&verify_watchdog);
sub verify_watchdog {
    my ($value, $noerr) = @_;

    return $value if parse_watchdog($value);

    return undef if $noerr;

    die "unable to parse watchdog options\n";
}

sub parse_watchdog {
    my ($value) = @_;

    return undef if !$value;

    my $res = {};

    foreach my $p (split(/,/, $value)) {
	next if $p =~ m/^\s*$/;

	if ($p =~ m/^(model=)?(i6300esb|ib700)$/) {
	    $res->{model} = $2;
	} elsif ($p =~ m/^(action=)?(reset|shutdown|poweroff|pause|debug|none)$/) {
	    $res->{action} = $2;
	} else {
	    return undef;
	}
    }

    return $res;
}

sub parse_usb_device {
    my ($value) = @_;

    return undef if !$value;

    my @dl = split(/,/, $value);
    my $found;

    my $res = {};
    foreach my $v (@dl) {
	if ($v =~ m/^host=([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})$/) {
	    $found = 1;
	    $res->{vendorid} = $1;
	    $res->{productid} = $2;
	} elsif ($v =~ m/^host=(\d+)\-(\d+(\.\d+)*)$/) {
	    $found = 1;
	    $res->{hostbus} = $1;
	    $res->{hostport} = $2;
	} else {
	    return undef;
	}
    }
    return undef if !$found;

    return $res;
}

PVE::JSONSchema::register_format('pve-qm-usb-device', \&verify_usb_device);
sub verify_usb_device {
    my ($value, $noerr) = @_;

    return $value if parse_usb_device($value);

    return undef if $noerr;

    die "unable to parse usb device\n";
}

# add JSON properties for create and set function
sub json_config_properties {
    my $prop = shift;

    foreach my $opt (keys %$confdesc) {
	$prop->{$opt} = $confdesc->{$opt};
    }

    return $prop;
}

sub check_type {
    my ($key, $value) = @_;

    die "unknown setting '$key'\n" if !$confdesc->{$key};

    my $type = $confdesc->{$key}->{type};

    if (!defined($value)) {
	die "got undefined value\n";
    }

    if ($value =~ m/[\n\r]/) {
	die "property contains a line feed\n";
    }

    if ($type eq 'boolean') {
	return 1 if ($value eq '1') || ($value =~ m/^(on|yes|true)$/i);
	return 0 if ($value eq '0') || ($value =~ m/^(off|no|false)$/i);
	die "type check ('boolean') failed - got '$value'\n";
    } elsif ($type eq 'integer') {
	return int($1) if $value =~ m/^(\d+)$/;
	die "type check ('integer') failed - got '$value'\n";
    } elsif ($type eq 'string') {
	if (my $fmt = $confdesc->{$key}->{format}) {
	    if ($fmt eq 'pve-qm-drive') {
		# special case - we need to pass $key to parse_drive()
		my $drive = parse_drive($key, $value);
		return $value if $drive;
		die "unable to parse drive options\n";
	    }
	    PVE::JSONSchema::check_format($fmt, $value);
	    return $value;
	}
	$value =~ s/^\"(.*)\"$/$1/;
	return $value;
    } else {
	die "internal error"
    }
}

sub lock_config {
    my ($vmid, $code, @param) = @_;

    my $filename = config_file_lock($vmid);

    my $res = lock_file($filename, 10, $code, @param);

    die $@ if $@;

    return $res;
}

sub cfs_config_path {
    my ($vmid, $node) = @_;

    $node = $nodename if !$node;
    return "nodes/$node/qemu-server/$vmid.conf";
}

sub check_iommu_support{
    #fixme : need to check IOMMU support
    #http://www.linux-kvm.org/page/How_to_assign_devices_with_VT-d_in_KVM

    my $iommu=1;
    return $iommu;

}

sub config_file {
    my ($vmid, $node) = @_;

    my $cfspath = cfs_config_path($vmid, $node);
    return "/etc/pve/$cfspath";
}

sub config_file_lock {
    my ($vmid) = @_;

    return "$lock_dir/lock-$vmid.conf";
}

sub touch_config {
    my ($vmid) = @_;

    my $conf = config_file($vmid);
    utime undef, undef, $conf;
}

sub create_disks {
    my ($storecfg, $vmid, $settings) = @_;

    my $vollist = [];

    eval {
	foreach_drive($settings, sub {
	    my ($ds, $disk) = @_;

	    return if drive_is_cdrom($disk);

	    my $file = $disk->{file};

	    if ($file =~ m/^(([^:\s]+):)?(\d+(\.\d+)?)$/) {
		my $storeid = $2 || 'local';
		my $size = $3;
		my $defformat = PVE::Storage::storage_default_format($storecfg, $storeid);
		my $fmt = $disk->{format} || $defformat;
		syslog('info', "VM $vmid creating new disk - size is $size GB");

		my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid,
						       $fmt, undef, $size*1024*1024);

		$disk->{file} = $volid;
		delete $disk->{format}; # no longer needed
		push @$vollist, $volid;
		$settings->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	    } else {
		my $path;
		if ($disk->{file} =~ m|^/dev/.+|) {
		    $path = $disk->{file};
		} else {
		    $path = PVE::Storage::path($storecfg, $disk->{file});
		}
		if (!(-f $path || -b $path)) {
		    die "image '$path' does not exists\n";
		}
	    }
	});
    };

    my $err = $@;

    if ($err) {
	syslog('err', "VM $vmid creating disks failed");
	foreach my $volid (@$vollist) {
	    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	    warn $@ if $@;
	}
	die $err;
    }

    return $vollist;
}

sub unlink_image {
    my ($storecfg, $vmid, $volid) = @_;

    die "reject to unlink absolute path '$volid'"
	if $volid =~ m|^/|;

    my ($path, $owner) = PVE::Storage::path($storecfg, $volid);

    die "reject to unlink '$volid' - not owned by this VM"
	if !$owner || ($owner != $vmid);

    syslog('info', "VM $vmid deleting volume '$volid'");

    PVE::Storage::vdisk_free($storecfg, $volid);

    touch_config($vmid);
}

sub destroy_vm {
    my ($storecfg, $vmid) = @_;

    my $conffile = config_file($vmid);

    my $conf = load_config($vmid);

    check_lock($conf);

    # only remove disks owned by this VM
    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

 	return if drive_is_cdrom($drive);

	my $volid = $drive->{file};
	next if !$volid || $volid =~ m|^/|;

	my ($path, $owner) = PVE::Storage::path($storecfg, $volid);
	next if !$path || !$owner || ($owner != $vmid);

	PVE::Storage::vdisk_free($storecfg, $volid);
    });

    unlink $conffile;

    # also remove unused disk
    eval {
	my $dl = PVE::Storage::vdisk_list($storecfg, undef, $vmid);

	eval {
	    PVE::Storage::foreach_volid($dl, sub {
		my ($volid, $sid, $volname, $d) = @_;
		PVE::Storage::vdisk_free($storecfg, $volid);
	    });
	};
	warn $@ if $@;

    };
    warn $@ if $@;
}

# fixme: remove?
sub load_diskinfo_old {
    my ($storecfg, $vmid, $conf) = @_;

    my $info = {};
    my $res = {};
    my $vollist;

    foreach_drive($conf, sub {
	my ($ds, $di) = @_;

	$res->{$ds} = $di;

	return if drive_is_cdrom($di);

	if ($di->{file} =~ m|^/dev/.+|) {
	    $info->{$di->{file}}->{size} = PVE::Storage::file_size_info($di->{file});
	} else {
	    push @$vollist, $di->{file};
	}
    });

    eval {
	my $dl = PVE::Storage::vdisk_list($storecfg, undef, $vmid, $vollist);

	PVE::Storage::foreach_volid($dl, sub {
	    my ($volid, $sid, $volname, $d) = @_;
	    $info->{$volid} = $d;
	});
    };
    warn $@ if $@;

    foreach my $ds (keys %$res) {
	my $di = $res->{$ds};

	$res->{$ds}->{disksize} = $info->{$di->{file}} ?
	    $info->{$di->{file}}->{size} / (1024*1024) : 0;
    }

    return $res;
}

sub load_config {
    my ($vmid) = @_;

    my $cfspath = cfs_config_path($vmid);

    my $conf = PVE::Cluster::cfs_read_file($cfspath);

    die "no such VM ('$vmid')\n" if !defined($conf);

    return $conf;
}

sub parse_vm_config {
    my ($filename, $raw) = @_;

    return undef if !defined($raw);

    my $res = {
	digest => Digest::SHA1::sha1_hex($raw),
    };

    $filename =~ m|/qemu-server/(\d+)\.conf$|
	|| die "got strange filename '$filename'";

    my $vmid = $1;

    while ($raw && $raw =~ s/^(.*?)(\n|$)//) {
	my $line = $1;

	next if $line =~ m/^\#/;

	next if $line =~ m/^\s*$/;

	if ($line =~ m/^(description):\s*(.*\S)\s*$/) {
	    my $key = $1;
	    my $value = PVE::Tools::decode_text($2);
	    $res->{$key} = $value;
	} elsif ($line =~ m/^(args):\s*(.*\S)\s*$/) {
	    my $key = $1;
	    my $value = $2;
	    $res->{$key} = $value;
	} elsif ($line =~ m/^([a-z][a-z_]*\d*):\s*(\S+)\s*$/) {
	    my $key = $1;
	    my $value = $2;
	    eval { $value = check_type($key, $value); };
	    if ($@) {
		warn "vm $vmid - unable to parse value of '$key' - $@";
	    } else {
		my $fmt = $confdesc->{$key}->{format};
		if ($fmt && $fmt eq 'pve-qm-drive') {
		    my $v = parse_drive($key, $value);
		    if (my $volid = filename_to_volume_id($vmid, $v->{file}, $v->{media})) {
			$v->{file} = $volid;
			$value = print_drive($vmid, $v);
		    } else {
			warn "vm $vmid - unable to parse value of '$key'\n";
			next;
		    }
		}

		if ($key eq 'cdrom') {
		    $res->{ide2} = $value;
		} else {
		    $res->{$key} = $value;
		}
	    }
	}
    }

    # convert old smp to sockets
    if ($res->{smp} && !$res->{sockets}) {
	$res->{sockets} = $res->{smp};
    }
    delete $res->{smp};

    return $res;
}

sub change_config {
    my ($vmid, $settings, $unset, $skiplock) = @_;

    lock_config($vmid, &change_config_nolock, $settings, $unset, $skiplock);
}

sub change_config_nolock {
    my ($vmid, $settings, $unset, $skiplock) = @_;

    my $res = {};

    $unset->{ide2} = $unset->{cdrom} if $unset->{cdrom};

    check_lock($settings) if !$skiplock;

    # we do not use 'smp' any longer
    if ($settings->{sockets}) {
	$unset->{smp} = 1;
    } elsif ($settings->{smp}) {
	$settings->{sockets} = $settings->{smp};
	$unset->{smp} = 1;
    }

    my $new_volids = {};

    foreach my $key (keys %$settings) {
	next if $key eq 'digest';
	my $value = $settings->{$key};
	if ($key eq 'description') {
	    $value = PVE::Tools::encode_text($value);
	}
	eval { $value = check_type($key, $value); };
	die "unable to parse value of '$key' - $@" if $@;
	if ($key eq 'cdrom') {
	    $res->{ide2} = $value;
	} else {
	    $res->{$key} = $value;
	}
	if (valid_drivename($key)) {
	    my $drive = PVE::QemuServer::parse_drive($key, $value);
	    $new_volids->{$drive->{file}} = 1 if $drive && $drive->{file};
	}
    }

    my $filename = config_file($vmid);
    my $tmpfn = "$filename.$$.tmp";

    my $fh = new IO::File($filename, "r") ||
	die "unable to read config for VM $vmid\n";

    my $werror = "unable to write config for VM $vmid\n";

    my $out = new IO::File($tmpfn, "w") || die $werror;

    eval {

	my $done;

	while (my $line = <$fh>) {

	    if (($line =~ m/^\#/) || ($line =~ m/^\s*$/)) {
		die $werror unless print $out $line;
		next;
	    }

	    if ($line =~ m/^([a-z][a-z_]*\d*):\s*(.*\S)\s*$/) {
		my $key = $1;
		my $value = $2;

		# remove 'unusedX' settings if we re-add a volume
		next if $key =~ m/^unused/ && $new_volids->{$value};

		# convert 'smp' to 'sockets'
		$key = 'sockets' if $key eq 'smp';

		next if $done->{$key};
		$done->{$key} = 1;

		if (defined($res->{$key})) {
		    $value = $res->{$key};
		    delete $res->{$key};
		}
		if (!defined($unset->{$key})) {
		    die $werror unless print $out "$key: $value\n";
		}

		next;
	    }

	    die "unable to parse config file: $line\n";
	}

	foreach my $key (keys %$res) {

	    if (!defined($unset->{$key})) {
		die $werror unless print $out "$key: $res->{$key}\n";
	    }
	}
    };

    my $err = $@;

    $fh->close();

    if ($err) {
	$out->close();
	unlink $tmpfn;
	die $err;
    }

    if (!$out->close()) {
	$err = "close failed - $!\n";
	unlink $tmpfn;
	die $err;
    }

    if (!rename($tmpfn, $filename)) {
	$err = "rename failed - $!\n";
	unlink $tmpfn;
	die $err;
    }
}

sub load_defaults {

    my $res = {};

    # we use static defaults from our JSON schema configuration
    foreach my $key (keys %$confdesc) {
	if (defined(my $default = $confdesc->{$key}->{default})) {
	    $res->{$key} = $default;
	}
    }

    my $conf = PVE::Cluster::cfs_read_file('datacenter.cfg');
    $res->{keyboard} = $conf->{keyboard} if $conf->{keyboard};

    return $res;
}

sub config_list {
    my $vmlist = PVE::Cluster::get_vmlist();
    my $res = {};
    return $res if !$vmlist || !$vmlist->{ids};
    my $ids = $vmlist->{ids};

    foreach my $vmid (keys %$ids) {
	my $d = $ids->{$vmid};
	next if !$d->{node} || $d->{node} ne $nodename;
	next if !$d->{type} || $d->{type} ne 'qemu';
	$res->{$vmid}->{exists} = 1;
    }
    return $res;
}

# test if VM uses local resources (to prevent migration)
sub check_local_resources {
    my ($conf, $noerr) = @_;

    my $loc_res = 0;

    $loc_res = 1 if $conf->{hostusb}; # old syntax
    $loc_res = 1 if $conf->{hostpci}; # old syntax

    foreach my $k (keys %$conf) {
	$loc_res = 1 if $k =~ m/^(usb|hostpci|serial|parallel)\d+$/;
    }

    die "VM uses local resources\n" if $loc_res && !$noerr;

    return $loc_res;
}

sub check_lock {
    my ($conf) = @_;

    die "VM is locked ($conf->{lock})\n" if $conf->{lock};
}

sub check_cmdline {
    my ($pidfile, $pid) = @_;

    my $fh = IO::File->new("/proc/$pid/cmdline", "r");
    if (defined($fh)) {
	my $line = <$fh>;
	$fh->close;
	return undef if !$line;
	my @param = split(/\0/, $line);

	my $cmd = $param[0];
	return if !$cmd || ($cmd !~ m|kvm$|);

	for (my $i = 0; $i < scalar (@param); $i++) {
	    my $p = $param[$i];
	    next if !$p;
	    if (($p eq '-pidfile') || ($p eq '--pidfile')) {
		my $p = $param[$i+1];
		return 1 if $p && ($p eq $pidfile);
		return undef;
	    }
	}
    }
    return undef;
}

sub check_running {
    my ($vmid, $nocheck) = @_;

    my $filename = config_file($vmid);

    die "unable to find configuration file for VM $vmid - no such machine\n"
	if !$nocheck && ! -f $filename;

    my $pidfile = pidfile_name($vmid);

    if (my $fd = IO::File->new("<$pidfile")) {
	my $st = stat($fd);
	my $line = <$fd>;
	close($fd);

	my $mtime = $st->mtime;
	if ($mtime > time()) {
	    warn "file '$filename' modified in future\n";
	}

	if ($line =~ m/^(\d+)$/) {
	    my $pid = $1;
	    if (check_cmdline($pidfile, $pid)) {
		if (my $pinfo = PVE::ProcFSTools::check_process_running($pid)) {
		    return $pid;
		}
	    }
	}
    }

    return undef;
}

sub vzlist {

    my $vzlist = config_list();

    my $fd = IO::Dir->new($var_run_tmpdir) || return $vzlist;

    while (defined(my $de = $fd->read)) {
	next if $de !~ m/^(\d+)\.pid$/;
	my $vmid = $1;
	next if !defined($vzlist->{$vmid});
	if (my $pid = check_running($vmid)) {
	    $vzlist->{$vmid}->{pid} = $pid;
	}
    }

    return $vzlist;
}

my $storage_timeout_hash = {};

sub disksize {
    my ($storecfg, $conf) = @_;

    my $bootdisk = $conf->{bootdisk};
    return undef if !$bootdisk;
    return undef if !valid_drivename($bootdisk);

    return undef if !$conf->{$bootdisk};

    my $drive = parse_drive($bootdisk, $conf->{$bootdisk});
    return undef if !defined($drive);

    return undef if drive_is_cdrom($drive);

    my $volid = $drive->{file};
    return undef if !$volid;

    my $path;
    my $storeid;
    my $timeoutid;

    if ($volid =~ m|^/|) {
	$path = $timeoutid = $volid;
    } else {
	$storeid = $timeoutid = PVE::Storage::parse_volume_id($volid);
	$path = PVE::Storage::path($storecfg, $volid);
    }

    my $last_timeout = $storage_timeout_hash->{$timeoutid};
    if ($last_timeout) {
	if ((time() - $last_timeout) < 30) {
	    # skip storage with errors
	    return undef ;
	}
	delete $storage_timeout_hash->{$timeoutid};
    }

    my ($size, $format, $used);

    ($size, $format, $used) = PVE::Storage::file_size_info($path, 1);

    if (!defined($format)) {
	# got timeout
	$storage_timeout_hash->{$timeoutid} = time();
	return undef;
    }

    return wantarray ? ($size, $used) : $size;
}

my $last_proc_pid_stat;

sub vmstatus {
    my ($opt_vmid) = @_;

    my $res = {};

    my $storecfg = PVE::Storage::config();

    my $list = vzlist();
    my ($uptime) = PVE::ProcFSTools::read_proc_uptime(1);

    foreach my $vmid (keys %$list) {
	next if $opt_vmid && ($vmid ne $opt_vmid);

	my $cfspath = cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	my $d = {};
	$d->{pid} = $list->{$vmid}->{pid};

	# fixme: better status?
	$d->{status} = $list->{$vmid}->{pid} ? 'running' : 'stopped';

	my ($size, $used) = disksize($storecfg, $conf);
	if (defined($size) && defined($used)) {
	    $d->{disk} = $used;
	    $d->{maxdisk} = $size;
	} else {
	    $d->{disk} = 0;
	    $d->{maxdisk} = 0;
	}

	$d->{cpus} = ($conf->{sockets} || 1) * ($conf->{cores} || 1);
	$d->{name} = $conf->{name} || "VM $vmid";
	$d->{maxmem} = $conf->{memory} ? $conf->{memory}*(1024*1024) : 0;

	$d->{uptime} = 0;
	$d->{cpu} = 0;
	$d->{relcpu} = 0;
	$d->{mem} = 0;

	$d->{netout} = 0;
	$d->{netin} = 0;

	$d->{diskread} = 0;
	$d->{diskwrite} = 0;

	$res->{$vmid} = $d;
    }

    my $netdev = PVE::ProcFSTools::read_proc_net_dev();
    foreach my $dev (keys %$netdev) {
	next if $dev !~ m/^tap([1-9]\d*)i/;
	my $vmid = $1;
	my $d = $res->{$vmid};
	next if !$d;

	$d->{netout} += $netdev->{$dev}->{receive};
	$d->{netin} += $netdev->{$dev}->{transmit};
    }

    my $cpucount = $cpuinfo->{cpus} || 1;
    my $ctime = gettimeofday;

    foreach my $vmid (keys %$list) {

	my $d = $res->{$vmid};
	my $pid = $d->{pid};
	next if !$pid;

	if (my $fh = IO::File->new("/proc/$pid/io", "r")) {
	    my $data = {};
	    while (defined(my $line = <$fh>)) {
		if ($line =~ m/^([rw]char):\s+(\d+)$/) {
		    $data->{$1} = $2;
		}
	    }
	    close($fh);
	    $d->{diskread} = $data->{rchar} || 0;
	    $d->{diskwrite} = $data->{wchar} || 0;
	}

	my $pstat = PVE::ProcFSTools::read_proc_pid_stat($pid);
	next if !$pstat; # not running

	my $used = $pstat->{utime} + $pstat->{stime};

	my $vcpus = $d->{cpus} > $cpucount ? $cpucount : $d->{cpus};

	$d->{uptime} = int(($uptime - $pstat->{starttime})/$cpuinfo->{user_hz});

	if ($pstat->{vsize}) {
	    $d->{mem} = int(($pstat->{rss}/$pstat->{vsize})*$d->{maxmem});
	}

	my $old = $last_proc_pid_stat->{$pid};
	if (!$old) {
	    $last_proc_pid_stat->{$pid} = {
		time => $ctime,
		used => $used,
		cpu => 0,
		relcpu => 0,
	    };
	    next;
	}

	my $dtime = ($ctime -  $old->{time}) * $cpucount * $cpuinfo->{user_hz};

	if ($dtime > 1000) {
	    my $dutime = $used -  $old->{used};

	    $d->{cpu} = $dutime/$dtime;
	    $d->{relcpu} = ($d->{cpu} * $cpucount) / $vcpus;
	    $last_proc_pid_stat->{$pid} = {
		time => $ctime,
		used => $used,
		cpu => $d->{cpu},
		relcpu => $d->{relcpu},
	    };
	} else {
	    $d->{cpu} = $old->{cpu};
	    $d->{relcpu} = $old->{relcpu};
	}
    }

    return $res;
}

sub foreach_drive {
    my ($conf, $func) = @_;

    foreach my $ds (keys %$conf) {
	next if !valid_drivename($ds);

	my $drive = parse_drive($ds, $conf->{$ds});
	next if !$drive;

	&$func($ds, $drive);
    }
}

sub config_to_command {
    my ($storecfg, $vmid, $conf, $defaults, $migrate_uri) = @_;

    my $cmd = [];
    my $pciaddr = '';
    my $kvmver = kvm_user_version();
    my $vernum = 0; # unknown
    if ($kvmver =~ m/^(\d+)\.(\d+)\.(\d+)$/) {
	$vernum = $1*1000000+$2*1000+$3;
    }

    die "detected old qemu-kvm binary ($kvmver)\n" if $vernum < 14000;

    my $have_ovz = -f '/proc/vz/vestat';

    push @$cmd, '/usr/bin/kvm';

    push @$cmd, '-id', $vmid;

    my $use_virtio = 0;

    my $socket = monitor_socket($vmid);
    push @$cmd, '-chardev', "socket,id=monitor,path=$socket,server,nowait";
    push @$cmd, '-mon', "chardev=monitor,mode=readline";

    $socket = vnc_socket($vmid);
    push @$cmd,  '-vnc', "unix:$socket,x509,password";

    push @$cmd, '-pidfile' , pidfile_name($vmid);

    push @$cmd, '-daemonize';

    push @$cmd, '-incoming', $migrate_uri if $migrate_uri;

    # include usb device config
    push @$cmd, '-readconfig', '/usr/share/qemu-server/pve-usb.cfg';

    # enable absolute mouse coordinates (needed by vnc)
    my $tablet = defined($conf->{tablet}) ? $conf->{tablet} : $defaults->{tablet};
    push @$cmd, '-device', 'usb-tablet,bus=ehci.0,port=6' if $tablet;

    # host pci devices
    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
          my $d = parse_hostpci($conf->{"hostpci$i"});
          next if !$d;
	  $pciaddr = print_pci_addr("hostpci$i");
          push @$cmd, '-device', "pci-assign,host=$d->{pciid},id=hostpci$i$pciaddr";
    }

    # usb devices
    for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	my $d = parse_usb_device($conf->{"usb$i"});
	next if !$d;
	if ($d->{vendorid} && $d->{productid}) {
	    push @$cmd, '-device', "usb-host,vendorid=$d->{vendorid},productid=$d->{productid}";
	} elsif (defined($d->{hostbus}) && defined($d->{hostport})) {
	    push @$cmd, '-device', "usb-host,hostbus=$d->{hostbus},hostport=$d->{hostport}";
	}
    }

    # serial devices
    for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++)  {
	if (my $path = $conf->{"serial$i"}) {
	    die "no such serial device\n" if ! -c $path;
	    push @$cmd, '-chardev', "tty,id=serial$i,path=$path";
	    push @$cmd, '-device', "isa-serial,chardev=serial$i";
	}
    }

    # parallel devices
    for (my $i = 0; $i < $MAX_PARALLEL_PORTS; $i++)  {
	if (my $path = $conf->{"parallel$i"}) {
	    die "no such parallel device\n" if ! -c $path;
	    push @$cmd, '-chardev', "parport,id=parallel$i,path=$path";
	    push @$cmd, '-device', "isa-parallel,chardev=parallel$i";
	}
    }

    my $vmname = $conf->{name} || "vm$vmid";

    push @$cmd, '-name', $vmname;

    my $sockets = 1;
    $sockets = $conf->{smp} if $conf->{smp}; # old style - no longer iused
    $sockets = $conf->{sockets} if  $conf->{sockets};

    my $cores = $conf->{cores} || 1;

    my $boot_opt;

    push @$cmd, '-smp', "sockets=$sockets,cores=$cores";

    push @$cmd, '-cpu', $conf->{cpu} if $conf->{cpu};

    push @$cmd, '-nodefaults';

    my $bootorder = $conf->{boot} || $confdesc->{boot}->{default};
    push @$cmd, '-boot', "menu=on,order=$bootorder";

    push @$cmd, '-no-acpi' if defined($conf->{acpi}) && $conf->{acpi} == 0;

    push @$cmd, '-no-reboot' if  defined($conf->{reboot}) && $conf->{reboot} == 0;

    my $vga = $conf->{vga};
    if (!$vga) {
	if ($conf->{ostype} && ($conf->{ostype} eq 'win7' || $conf->{ostype} eq 'w2k8')) {
	    $vga = 'std';
	} else {
	    $vga = 'cirrus';
	}
    }

    push @$cmd, '-vga', $vga if $vga; # for kvm 77 and later

    # time drift fix
    my $tdf = defined($conf->{tdf}) ? $conf->{tdf} : $defaults->{tdf};
    push @$cmd, '-tdf' if $tdf;

    my $nokvm = defined($conf->{kvm}) && $conf->{kvm} == 0 ? 1 : 0;

    if (my $ost = $conf->{ostype}) {
	# other, wxp, w2k, w2k3, w2k8, wvista, win7, l24, l26

	if ($ost =~ m/^w/) { # windows
	    push @$cmd, '-localtime' if !defined($conf->{localtime});

	    # use rtc-td-hack when acpi is enabled
	    if (!(defined($conf->{acpi}) && $conf->{acpi} == 0)) {
		push @$cmd, '-rtc-td-hack';
	    }
	}

	# -tdf ?
	# -no-acpi
	# -no-kvm
	# -win2k-hack ?
    }

    if ($nokvm) {
	push @$cmd, '-no-kvm';
    } else {
	die "No accelerator found!\n" if !$cpuinfo->{hvm};
    }

    push @$cmd, '-localtime' if $conf->{localtime};

    push @$cmd, '-startdate', $conf->{startdate} if $conf->{startdate};

    push @$cmd, '-S' if $conf->{freeze};

    # set keyboard layout
    my $kb = $conf->{keyboard} || $defaults->{keyboard};
    push @$cmd, '-k', $kb if $kb;

    # enable sound
    #my $soundhw = $conf->{soundhw} || $defaults->{soundhw};
    #push @$cmd, '-soundhw', 'es1370';
    #push @$cmd, '-soundhw', $soundhw if $soundhw;
    $pciaddr = print_pci_addr("balloon0");
    push @$cmd, '-device', "virtio-balloon-pci,id=balloon0$pciaddr" if $conf->{balloon};

    if ($conf->{watchdog}) {
	my $wdopts = parse_watchdog($conf->{watchdog});
	$pciaddr = print_pci_addr("watchdog");
	my $watchdog = $wdopts->{model} || 'i6300esb';
	push @$cmd, '-device', "$watchdog$pciaddr";
	push @$cmd, '-watchdog-action', $wdopts->{action} if $wdopts->{action};
    }

    my $vollist = [];
    my $scsicontroller = {};

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	eval {
	    PVE::Storage::parse_volume_id($drive->{file});
	    push @$vollist, $drive->{file};
	}; # ignore errors

	$use_virtio = 1 if $ds =~ m/^virtio/;
        if ($drive->{interface} eq 'scsi') {
           my $maxdev = 7;
           my $controller = int($drive->{index} / $maxdev);
	   $pciaddr = print_pci_addr("scsi$controller");
           push @$cmd, '-device', "lsi,id=scsi$controller$pciaddr" if !$scsicontroller->{$controller};
           my $scsicontroller->{$controller}=1;
        }
	my $tmp = print_drive_full($storecfg, $vmid, $drive);
	$tmp .= ",boot=on" if $conf->{bootdisk} && ($conf->{bootdisk} eq $ds);
	push @$cmd, '-drive', $tmp;
	push @$cmd, '-device',print_drivedevice_full($storecfg,$vmid, $drive);
    });

    push @$cmd, '-m', $conf->{memory} || $defaults->{memory};

    my $foundnet = 0;

    foreach my $k (sort keys %$conf) {
	next if $k !~ m/^net(\d+)$/;
	my $i = int($1);

	die "got strange net id '$i'\n" if $i >= ${MAX_NETS};

	if ($conf->{"net$i"} && (my $net = parse_net($conf->{"net$i"}))) {

	    $foundnet = 1;

	    my $ifname = "tap${vmid}i$i";

	    # kvm uses TUNSETIFF ioctl, and that limits ifname length
	    die "interface name '$ifname' is too long (max 15 character)\n"
		if length($ifname) >= 16;

	    my $device = $net->{model};
	    my $vhostparam = '';
	    if ($net->{model} eq 'virtio') {
		$use_virtio = 1;
		$device = 'virtio-net-pci';
		$vhostparam = ',vhost=on' if $kernel_has_vhost_net;
	    };

	    if ($net->{bridge}) {
		push @$cmd, '-netdev', "type=tap,id=${k},ifname=${ifname},script=/var/lib/qemu-server/pve-bridge$vhostparam";
	    } else {
		push @$cmd, '-netdev', "type=user,id=${k},hostname=$vmname";
	    }

	    # qemu > 0.15 always try to boot from network - we disable that by
	    # not loading the pxe rom file
	    my $extra = (!$conf->{boot} || ($conf->{boot} !~ m/n/)) ?
		"romfile=," : '';
	    $pciaddr = print_pci_addr("${k}");
	    push @$cmd, '-device', "$device,${extra}mac=$net->{macaddr},netdev=${k}$pciaddr";
	}
    }

    push @$cmd, '-net', 'none' if !$foundnet;

    # hack: virtio with fairsched is unreliable, so we do not use fairsched
    # when the VM uses virtio devices.
    if (!$use_virtio && $have_ovz) {

	my $cpuunits = defined($conf->{cpuunits}) ?
	    $conf->{cpuunits} : $defaults->{cpuunits};

	push @$cmd, '-cpuunits', $cpuunits if $cpuunits;

	# fixme: cpulimit is currently ignored
	#push @$cmd, '-cpulimit', $conf->{cpulimit} if $conf->{cpulimit};
    }

    # add custom args
    if ($conf->{args}) {
	my $aa = split_args($conf->{args});
	push @$cmd, @$aa;
    }

    return wantarray ? ($cmd, $vollist) : $cmd;
}

sub vnc_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.vnc";
}

sub monitor_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.mon";
}

sub pidfile_name {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.pid";
}

sub next_migrate_port {

    for (my $p = 60000; $p < 60010; $p++) {

	my $sock = IO::Socket::INET->new(Listen => 5,
					 LocalAddr => 'localhost',
					 LocalPort => $p,
					 ReuseAddr => 1,
					 Proto     => 0);

	if ($sock) {
	    close($sock);
	    return $p;
	}
    }

    die "unable to find free migration port";
}

sub vm_start {
    my ($storecfg, $vmid, $statefile, $skiplock) = @_;

    lock_config($vmid, sub {
	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	if (check_running($vmid)) {
	    my $msg = "VM $vmid already running - start failed\n" ;
	    syslog('err', $msg);
	    die $msg;
	} else {
	    syslog('info', "VM $vmid start");
	}

	my $migrate_uri;
	my $migrate_port = 0;

	if ($statefile) {
	    if ($statefile eq 'tcp') {
		$migrate_port = next_migrate_port();
		$migrate_uri = "tcp:localhost:${migrate_port}";
	    } else {
		if (-f $statefile) {
		    $migrate_uri = "exec:cat $statefile";
		} else {
		    warn "state file '$statefile' does not exist - doing normal startup\n";
		}
	    }
	}

	my $defaults = load_defaults();

	my ($cmd, $vollist) = config_to_command($storecfg, $vmid, $conf, $defaults, $migrate_uri);
	# host pci devices
        for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
          my $d = parse_hostpci($conf->{"hostpci$i"});
          next if !$d;
          my $info = pci_device_info("0000:$d->{pciid}");
          die "IOMMU not present\n" if !check_iommu_support();
          die "no pci device info for device '$d->{pciid}'\n" if !$info;
          die "can't unbind pci device '$d->{pciid}'\n" if !pci_dev_bind_to_stub($info);
          die "can't reset pci device '$d->{pciid}'\n" if !pci_dev_reset($info);
        }

	PVE::Storage::activate_volumes($storecfg, $vollist);

	eval  { run_command($cmd, timeout => $migrate_uri ? undef : 30); };

	my $err = $@;

	if ($err) {
	    my $msg = "start failed: $err";
	    syslog('err', "VM $vmid $msg");
	    die $msg;
	}

	if ($statefile) {

	    if ($statefile eq 'tcp') {
		print "migration listens on port $migrate_port\n";
	    } else {
		unlink $statefile;
		# fixme: send resume - is that necessary ?
		eval  { vm_monitor_command($vmid, "cont", 1) };
	    }
	}

	if (my $migrate_speed =
	    $conf->{migrate_speed} || $defaults->{migrate_speed}) {
	    my $cmd = "migrate_set_speed ${migrate_speed}m";
	    eval { vm_monitor_command($vmid, $cmd, 1); };
	}

	if (my $migrate_downtime =
	    $conf->{migrate_downtime} || $defaults->{migrate_downtime}) {
	    my $cmd = "migrate_set_downtime ${migrate_downtime}";
	    eval { vm_monitor_command($vmid, $cmd, 1); };
	}

	vm_balloonset($vmid, $conf->{balloon}) if $conf->{balloon};
    });
}

sub __read_avail {
    my ($fh, $timeout) = @_;

    my $sel = new IO::Select;
    $sel->add($fh);

    my $res = '';
    my $buf;

    my @ready;
    while (scalar (@ready = $sel->can_read($timeout))) {
	my $count;
	if ($count = $fh->sysread($buf, 8192)) {
	    if ($buf =~ /^(.*)\(qemu\) $/s) {
		$res .= $1;
		last;
	    } else {
		$res .= $buf;
	    }
	} else {
	    if (!defined($count)) {
		die "$!\n";
	    }
	    last;
	}
    }

    die "monitor read timeout\n" if !scalar(@ready);

    return $res;
}

sub vm_monitor_command {
    my ($vmid, $cmdstr, $nolog, $nocheck) = @_;

    my $res;

    syslog("info", "VM $vmid monitor command '$cmdstr'") if !$nolog;

    eval {
	die "VM not running\n" if !check_running($vmid, $nocheck);

	my $sname = monitor_socket($vmid);

	my $sock = IO::Socket::UNIX->new( Peer => $sname ) ||
	    die "unable to connect to VM $vmid socket - $!\n";

	my $timeout = 3;

	# hack: migrate sometime blocks the monitor (when migrate_downtime
	# is set)
	if ($cmdstr =~ m/^(info\s+migrate|migrate\s)/) {
	    $timeout = 60*60; # 1 hour
	}

	# read banner;
	my $data = __read_avail($sock, $timeout);

	if ($data !~ m/^QEMU\s+(\S+)\s+monitor\s/) {
	    die "got unexpected qemu monitor banner\n";
	}

	my $sel = new IO::Select;
	$sel->add($sock);

	if (!scalar(my @ready = $sel->can_write($timeout))) {
	    die "monitor write error - timeout";
	}

	my $fullcmd = "$cmdstr\r";

	my $b;
	if (!($b = $sock->syswrite($fullcmd)) || ($b != length($fullcmd))) {
	    die "monitor write error - $!";
	}

	return if ($cmdstr eq 'q') || ($cmdstr eq 'quit');

	$timeout = 20;

	if ($cmdstr =~ m/^(info\s+migrate|migrate\s)/) {
	    $timeout = 60*60; # 1 hour
	} elsif ($cmdstr =~ m/^(eject|change)/) {
	    $timeout = 60; # note: cdrom mount command is slow
	}
	if ($res = __read_avail($sock, $timeout)) {

	    my @lines = split("\r?\n", $res);

	    shift @lines if $lines[0] !~ m/^unknown command/; # skip echo

	    $res = join("\n", @lines);
	    $res .= "\n";
	}
    };

    my $err = $@;

    if ($err) {
	syslog("err", "VM $vmid monitor command failed - $err");
	die $err;
    }

    return $res;
}

sub vm_commandline {
    my ($storecfg, $vmid) = @_;

    my $conf = load_config($vmid);

    my $defaults = load_defaults();

    my $cmd = config_to_command($storecfg, $vmid, $conf, $defaults);

    return join(' ', @$cmd);
}

sub vm_reset {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	syslog("info", "VM $vmid sending 'reset'");

	vm_monitor_command($vmid, "system_reset", 1);
    });
}

sub vm_shutdown {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	syslog("info", "VM $vmid sending 'shutdown'");

	vm_monitor_command($vmid, "system_powerdown", 1);
    });
}

# Note: use $nockeck to skip tests if VM configuration file exists.
# We need that when migration VMs to other nodes (files already moved) 
sub vm_stop {
    my ($vmid, $skiplock, $nocheck) = @_;

    lock_config($vmid, sub {

	my $pid = check_running($vmid, $nocheck);

	if (!$pid) {
	    syslog('info', "VM $vmid already stopped");
	    return;
	}

	if (!$nocheck) {
	    my $conf = load_config($vmid);
	    check_lock($conf) if !$skiplock;
	}

	syslog("info", "VM $vmid stopping");

	eval { vm_monitor_command($vmid, "quit", 1, $nocheck); };

	my $err = $@;

	if (!$err) {
	    # wait some time
	    my $timeout = 50; # fixme: how long?

	    my $count = 0;
	    while (($count < $timeout) && check_running($vmid, $nocheck)) {
		$count++;
		sleep 1;
	    }

	    if ($count >= $timeout) {
		syslog('info', "VM $vmid still running - terminating now with SIGTERM");
		kill 15, $pid;
	    }
	} else {
	    syslog('info', "VM $vmid quit failed - terminating now with SIGTERM");
	    kill 15, $pid;
	}

	# wait again
	my $timeout = 10;

	my $count = 0;
	while (($count < $timeout) && check_running($vmid, $nocheck)) {
	    $count++;
	    sleep 1;
	}

	if ($count >= $timeout) {
	    syslog('info', "VM $vmid still running - terminating now with SIGKILL\n");
	    kill 9, $pid;
	}

	fairsched_rmnod($vmid); # try to destroy group
    });
}

sub vm_suspend {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	syslog("info", "VM $vmid suspend");

	vm_monitor_command($vmid, "stop", 1);
    });
}

sub vm_resume {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	syslog("info", "VM $vmid resume");

	vm_monitor_command($vmid, "cont", 1);
    });
}

sub vm_sendkey {
    my ($vmid, $skiplock, $key) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	syslog("info", "VM $vmid sending key $key");

	vm_monitor_command($vmid, "sendkey $key", 1);
    });
}

sub vm_destroy {
    my ($storecfg, $vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	syslog("info", "VM $vmid destroy called (removing all data)");

	eval {
	    if (!check_running($vmid)) {
		fairsched_rmnod($vmid); # try to destroy group
		destroy_vm($storecfg, $vmid);
	    } else {
		die "VM is running\n";
	    }
	};

	my $err = $@;

	if ($err) {
	    syslog("err", "VM $vmid destroy failed - $err");
	    die $err;
	}
    });
}

sub vm_stopall {
    my ($timeout) = @_;

    $timeout = 3*60 if !$timeout;

    my $vzlist = vzlist();
    my $count = 0;
    foreach my $vmid (keys %$vzlist) {
	next if !$vzlist->{$vmid}->{pid};
	$count++;
    }

    if ($count) {

	my $msg = "Stopping Qemu Server - sending shutdown requests to all VMs\n";
	syslog('info', $msg);
	print STDERR $msg;

	foreach my $vmid (keys %$vzlist) {
	    next if !$vzlist->{$vmid}->{pid};
	    eval { vm_shutdown($vmid, 1); };
	    print STDERR $@ if $@;
	}

	my $wt = 5;
	my $maxtries = int(($timeout + $wt -1)/$wt);
	my $try = 0;
	while (($try < $maxtries) && $count) {
	    $try++;
	    sleep $wt;

	    $vzlist = vzlist();
	    $count = 0;
	    foreach my $vmid (keys %$vzlist) {
		next if !$vzlist->{$vmid}->{pid};
		$count++;
	    }
	    last if !$count;
	}

	return if !$count;

	foreach my $vmid (keys %$vzlist) {
	    next if !$vzlist->{$vmid}->{pid};

	    $msg = "VM $vmid still running - sending stop now\n";
	    syslog('info', $msg);
	    print $msg;

	    eval { vm_monitor_command($vmid, "quit", 1); };
	    print STDERR $@ if $@;

	}

	$timeout = 30;
	$maxtries = int(($timeout + $wt -1)/$wt);
	$try = 0;
	while (($try < $maxtries) && $count) {
	    $try++;
	    sleep $wt;

	    $vzlist = vzlist();
	    $count = 0;
	    foreach my $vmid (keys %$vzlist) {
		next if !$vzlist->{$vmid}->{pid};
		$count++;
	    }
	    last if !$count;
	}

	return if !$count;

	foreach my $vmid (keys %$vzlist) {
	    next if !$vzlist->{$vmid}->{pid};

	    $msg = "VM $vmid still running - terminating now with SIGTERM\n";
	    syslog('info', $msg);
	    print $msg;
	    kill 15, $vzlist->{$vmid}->{pid};
	}

	# this is called by system shotdown scripts, so remaining
	# processes gets killed anyways (no need to send kill -9 here)

	$msg = "Qemu Server stopped\n";
	syslog('info', $msg);
	print STDERR $msg;
    }
}

# pci helpers

sub file_write {
    my ($filename, $buf) = @_;

    my $fh = IO::File->new($filename, "w");
    return undef if !$fh;

    my $res = print $fh $buf;

    $fh->close();

    return $res;
}

sub pci_device_info {
    my ($name) = @_;

    my $res;

    return undef if $name !~ m/^([a-f0-9]{4}):([a-f0-9]{2}):([a-f0-9]{2})\.([a-f0-9])$/;
    my ($domain, $bus, $slot, $func) = ($1, $2, $3, $4);

    my $irq = file_read_firstline("$pcisysfs/devices/$name/irq");
    return undef if !defined($irq) || $irq !~ m/^\d+$/;

    my $vendor = file_read_firstline("$pcisysfs/devices/$name/vendor");
    return undef if !defined($vendor) || $vendor !~ s/^0x//;

    my $product = file_read_firstline("$pcisysfs/devices/$name/device");
    return undef if !defined($product) || $product !~ s/^0x//;

    $res = {
	name => $name,
	vendor => $vendor,
	product => $product,
	domain => $domain,
	bus => $bus,
	slot => $slot,
	func => $func,
	irq => $irq,
	has_fl_reset => -f "$pcisysfs/devices/$name/reset" || 0,
    };

    return $res;
}

sub pci_dev_reset {
    my ($dev) = @_;

    my $name = $dev->{name};

    my $fn = "$pcisysfs/devices/$name/reset";

    return file_write($fn, "1");
}

sub pci_dev_bind_to_stub {
    my ($dev) = @_;

    my $name = $dev->{name};

    my $testdir = "$pcisysfs/drivers/pci-stub/$name";
    return 1 if -d $testdir;

    my $data = "$dev->{vendor} $dev->{product}";
    return undef if !file_write("$pcisysfs/drivers/pci-stub/new_id", $data);

    my $fn = "$pcisysfs/devices/$name/driver/unbind";
    if (!file_write($fn, $name)) {
	return undef if -f $fn;
    }

    $fn = "$pcisysfs/drivers/pci-stub/bind";
    if (! -d $testdir) {
	return undef if !file_write($fn, $name);
    }

    return -d $testdir;
}

sub print_pci_addr { 
    my ($id) = @_;

    my $res = '';
    my $devices = {
	#addr1 : ide,parallel,serial (motherboard)
	#addr2 : first videocard
	balloon0 => { bus => 0, addr => 3 },
	watchdog => { bus => 0, addr => 4 },
	scsi0 => { bus => 0, addr => 5 },
	scsi1 => { bus => 0, addr => 6 },
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
	#addr29 : usb-host (pve-usb.cfg)
    };

    if (defined($devices->{$id}->{bus}) && defined($devices->{$id}->{addr})) {
	   my $addr = sprintf("0x%x", $devices->{$id}->{addr});
	   $res = ",bus=pci.$devices->{$id}->{bus},addr=$addr";
    }
    return $res;

}

sub vm_balloonset {
    my ($vmid, $value) = @_;

    vm_monitor_command($vmid, "balloon $value", 1);
}

1;
