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
use Digest::SHA;
use Fcntl ':flock';
use Cwd 'abs_path';
use IPC::Open3;
use JSON;
use Fcntl;
use PVE::SafeSyslog;
use Storable qw(dclone);
use PVE::Exception qw(raise raise_param_exc);
use PVE::Storage;
use PVE::Tools qw(run_command lock_file file_read_firstline);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);
use PVE::INotify;
use PVE::ProcFSTools;
use PVE::QMPClient;
use Time::HiRes qw(gettimeofday);

my $cpuinfo = PVE::ProcFSTools::read_cpuinfo();

# Note about locking: we use flock on the config file protect
# against concurent actions.
# Aditionaly, we have a 'lock' setting in the config file. This
# can be set to 'migrate', 'backup', 'snapshot' or 'rollback'. Most actions are not
# allowed when such lock is set. But you can ignore this kind of
# lock with the --skiplock flag.

cfs_register_file('/qemu-server/',
		  \&parse_vm_config,
		  \&write_vm_config);

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

PVE::JSONSchema::register_standard_option('pve-snapshot-name', {
    description => "The name of the snapshot.",
    type => 'string', format => 'pve-configid',
    maxLength => 40,
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
    hotplug => {
        optional => 1,
        type => 'boolean',
        description => "Activate hotplug for disk and network device",
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
	enum => [qw(migrate backup snapshot rollback)],
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
	enum => PVE::Tools::kvmkeymaplist(),
	default => 'en-us',
    },
    name => {
	optional => 1,
	type => 'string', format => 'dns-name',
	description => "Set a name for the VM. Only used on the configuration web interface.",
    },
    scsihw => {
	optional => 1,
	type => 'string',
	description => "scsi controller model",
	enum => [qw(lsi virtio-scsi-pci megasas)],
	default => 'lsi',
    },
    description => {
	optional => 1,
	type => 'string',
	description => "Description for the VM. Only used on the configuration web interface. This is saved as comment inside the configuration file.",
    },
    ostype => {
	optional => 1,
	type => 'string',
        enum => [qw(other wxp w2k w2k3 w2k8 wvista win7 win8 l24 l26)],
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
win8   => Microsoft Windows 8/2012
l24    => Linux 2.4 Kernel
l26    => Linux 2.6/3.X Kernel

other|l24|l26                       ... no special behaviour
wxp|w2k|w2k3|w2k8|wvista|win7|win8  ... use --localtime switch
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
	pattern => '(ide|sata|scsi|virtio)\d+',
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
    agent => {
	optional => 1,
	type => 'boolean',
	description => "Enable/disable Qemu GuestAgent.",
	default => 0,
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
	default => 0,
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
	description => "Select VGA type. If you want to use high resolution modes (>= 1280x1024x16) then you should use option 'std' or 'vmware'. Default is 'std' for win8/win7/w2k8, and 'cirrur' for other OS types",
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
    startup => {
	optional => 1,
	type => 'string', format => 'pve-qm-startup',
	typetext => '[[order=]\d+] [,up=\d+] [,down=\d+] ',
	description => "Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.",
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
	enum => [ qw(486 athlon pentium pentium2 pentium3 coreduo core2duo kvm32 kvm64 qemu32 qemu64 phenom cpu64-rhel6 cpu64-rhel5 Conroe Penryn Nehalem Westmere Opteron_G1 Opteron_G2 Opteron_G3 host) ],
	default => 'qemu64',
    },
    parent => get_standard_option('pve-snapshot-name', {
	optional => 1,
	description => "Parent snapshot name. This is used internally, and should not be modified.",
    }),
    snaptime => {
	optional => 1,
	description => "Timestamp for snapshots.",
	type => 'integer',
	minimum => 0,
    },
    vmstate => {
	optional => 1,
	type => 'string', format => 'pve-volume-id',
	description => "Reference to a volume which stores the VM state. This is used internally for snapshots.",
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
my $MAX_VIRTIO_DISKS = 16;
my $MAX_SATA_DISKS = 6;
my $MAX_USB_DEVICES = 5;
my $MAX_NETS = 32;
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
    typetext => "MODEL=XX:XX:XX:XX:XX:XX [,bridge=<dev>][,rate=<mbps>][,tag=<vlanid>]",
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
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads]',
    description => "Use volume as IDE hard disk or CD-ROM (n is 0 to " .($MAX_IDE_DISKS -1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-ide", $idedesc);

my $scsidesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads]',
    description => "Use volume as SCSI hard disk or CD-ROM (n is 0 to " . ($MAX_SCSI_DISKS - 1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-scsi", $scsidesc);

my $satadesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads]',
    description => "Use volume as SATA hard disk or CD-ROM (n is 0 to " . ($MAX_SATA_DISKS - 1). ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-sata", $satadesc);

my $virtiodesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads]',
    description => "Use volume as VIRTIO hard disk (n is 0 to " . ($MAX_VIRTIO_DISKS - 1) . ").",
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

for (my $i = 0; $i < $MAX_SATA_DISKS; $i++)  {
    $drivename_hash->{"sata$i"} = 1;
    $confdesc->{"sata$i"} = $satadesc;
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

    if ($tmp =~ m/^QEMU( PC)? emulator version (\d+\.\d+(\.\d+)?) /) {
	$kvm_user_version = $2;
    }

    return $kvm_user_version;

}

my $kernel_has_vhost_net = -c '/dev/vhost-net';

sub disknames {
    # order is important - used to autoselect boot disk
    return ((map { "ide$_" } (0 .. ($MAX_IDE_DISKS - 1))),
            (map { "scsi$_" } (0 .. ($MAX_SCSI_DISKS - 1))),
            (map { "virtio$_" } (0 .. ($MAX_VIRTIO_DISKS - 1))),
            (map { "sata$_" } (0 .. ($MAX_SATA_DISKS - 1))));
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
	win8 => 'Windows 8/2012',
	l24 => 'Linux 2.4',
	l26 => 'Linux 2.6',
    };
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
	$etype = 'images';
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

my $parse_size = sub {
    my ($value) = @_;

    return undef if $value !~ m/^(\d+(\.\d+)?)([KMG])?$/;
    my ($size, $unit) = ($1, $3);
    if ($unit) {
	if ($unit eq 'K') {
	    $size = $size * 1024;
	} elsif ($unit eq 'M') {
	    $size = $size * 1024 * 1024;
	} elsif ($unit eq 'G') {
	    $size = $size * 1024 * 1024 * 1024;
	}
    }
    return int($size);
};

my $format_size = sub {
    my ($size) = @_;

    $size = int($size);

    my $kb = int($size/1024);
    return $size if $kb*1024 != $size;

    my $mb = int($kb/1024);
    return "${kb}K" if $mb*1024 != $kb;

    my $gb = int($mb/1024);
    return "${mb}M" if $gb*1024 != $mb;

    return "${gb}G";
};

# ideX = [volume=]volume-id[,media=d][,cyls=c,heads=h,secs=s[,trans=t]]
#        [,snapshot=on|off][,cache=on|off][,format=f][,backup=yes|no]
#        [,rerror=ignore|report|stop][,werror=enospc|ignore|report|stop]
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

	if ($p =~ m/^(file|volume|cyls|heads|secs|trans|media|snapshot|cache|format|rerror|werror|backup|aio|bps|mbps|bps_rd|mbps_rd|bps_wr|mbps_wr|iops|iops_rd|iops_wr|size)=(.+)$/) {
	    my ($k, $v) = ($1, $2);

	    $k = 'file' if $k eq 'volume';

	    return undef if defined $res->{$k};

	    if ($k eq 'bps' || $k eq 'bps_rd' || $k eq 'bps_wr') {
		return undef if !$v || $v !~ m/^\d+/;
		$k = "m$k";
		$v = sprintf("%.3f", $v / (1024*1024));
	    }
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
	$res->{cache} !~ m/^(off|none|writethrough|writeback|unsafe|directsync)$/;
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

    
    return undef if $res->{mbps_rd} && $res->{mbps};
    return undef if $res->{mbps_wr} && $res->{mbps};

    return undef if $res->{mbps} && $res->{mbps} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_rd} && $res->{mbps_rd} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_wr} && $res->{mbps_wr} !~ m/^\d+(\.\d+)?$/;

    return undef if $res->{iops_rd} && $res->{iops};
    return undef if $res->{iops_wr} && $res->{iops};
    return undef if $res->{iops} && $res->{iops} !~ m/^\d+$/;
    return undef if $res->{iops_rd} && $res->{iops_rd} !~ m/^\d+$/;
    return undef if $res->{iops_wr} && $res->{iops_wr} !~ m/^\d+$/;


    if ($res->{size}) {
	return undef if !defined($res->{size} = &$parse_size($res->{size})); 
    }

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

my @qemu_drive_options = qw(heads secs cyls trans media format cache snapshot rerror werror aio iops iops_rd iops_wr);

sub print_drive {
    my ($vmid, $drive) = @_;

    my $opts = '';
    foreach my $o (@qemu_drive_options, 'mbps', 'mbps_rd', 'mbps_wr', 'backup') {
	$opts .= ",$o=$drive->{$o}" if $drive->{$o};
    }

    if ($drive->{size}) {
	$opts .= ",size=" . &$format_size($drive->{size});
    }

    return "$drive->{file}$opts";
}

sub scsi_inquiry {
    my($fh, $noerr) = @_;

    my $SG_IO = 0x2285;
    my $SG_GET_VERSION_NUM = 0x2282;

    my $versionbuf = "\x00" x 8;
    my $ret = ioctl($fh, $SG_GET_VERSION_NUM, $versionbuf);
    if (!$ret) {
	die "scsi ioctl SG_GET_VERSION_NUM failoed - $!\n" if !$noerr;
	return undef;
    }
    my $version = unpack("I", $versionbuf);
    if ($version < 30000) {
	die "scsi generic interface too old\n"  if !$noerr;
	return undef;
    }

    my $buf = "\x00" x 36;
    my $sensebuf = "\x00" x 8;
    my $cmd = pack("C x3 C x11", 0x12, 36);

    # see /usr/include/scsi/sg.h
    my $sg_io_hdr_t = "i i C C s I P P P I I i P C C C C S S i I I";

    my $packet = pack($sg_io_hdr_t, ord('S'), -3, length($cmd),
		      length($sensebuf), 0, length($buf), $buf,
		      $cmd, $sensebuf, 6000);

    $ret = ioctl($fh, $SG_IO, $packet);
    if (!$ret) {
	die "scsi ioctl SG_IO failed - $!\n" if !$noerr;
	return undef;
    }

    my @res = unpack($sg_io_hdr_t, $packet);
    if ($res[17] || $res[18]) {
	die "scsi ioctl SG_IO status error - $!\n" if !$noerr;
	return undef;
    }

    my $res = {};
    ($res->{device}, $res->{removable}, $res->{venodor},
     $res->{product}, $res->{revision}) = unpack("C C x6 A8 A16 A4", $buf);

    return $res;
}

sub path_is_scsi {
    my ($path) = @_;

    my $fh = IO::File->new("+<$path") || return undef;
    my $res = scsi_inquiry($fh, 1);
    close($fh);

    return $res;
}

sub print_drivedevice_full {
    my ($storecfg, $conf, $vmid, $drive, $bridges) = @_;

    my $device = '';
    my $maxdev = 0;

    if ($drive->{interface} eq 'virtio') {
	my $pciaddr = print_pci_addr("$drive->{interface}$drive->{index}", $bridges);
	$device = "virtio-blk-pci,drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}$pciaddr";
    } elsif ($drive->{interface} eq 'scsi') {
	$maxdev = ($conf->{scsihw} && $conf->{scsihw} ne 'lsi') ? 256 : 7;
	my $controller = int($drive->{index} / $maxdev);
	my $unit = $drive->{index} % $maxdev;
	my $devicetype = 'hd';
        my $path = '';
        if (drive_is_cdrom($drive)) {
              $devicetype = 'cd';
          } else {
              if ($drive->{file} =~ m|^/|) {
                  $path = $drive->{file};
              } else {
                  $path = PVE::Storage::path($storecfg, $drive->{file});
              }

	      if($path =~ m/^iscsi\:\/\//){
		 $devicetype = 'generic';
	      }
	      else {
		 $devicetype = 'block' if path_is_scsi($path);
	      }
         }

        if (!$conf->{scsihw} || $conf->{scsihw} eq 'lsi'){
            $device = "scsi-$devicetype,bus=scsihw$controller.0,scsi-id=$unit,drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}" if !$conf->{scsihw} || $conf->{scsihw} eq 'lsi';
        } else {
            $device = "scsi-$devicetype,bus=scsihw$controller.0,channel=0,scsi-id=0,lun=$drive->{index},drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}";
        }

    } elsif ($drive->{interface} eq 'ide'){
	$maxdev = 2;
	my $controller = int($drive->{index} / $maxdev);
	my $unit = $drive->{index} % $maxdev;
	my $devicetype = ($drive->{media} && $drive->{media} eq 'cdrom') ? "cd" : "hd";

	$device = "ide-$devicetype,bus=ide.$controller,unit=$unit,drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}";
    } elsif ($drive->{interface} eq 'sata'){
	my $controller = int($drive->{index} / $MAX_SATA_DISKS);
	my $unit = $drive->{index} % $MAX_SATA_DISKS;
	$device = "ide-drive,bus=ahci$controller.$unit,drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}";
    } elsif ($drive->{interface} eq 'usb') {
	die "implement me";
	#  -device ide-drive,bus=ide.1,unit=0,drive=drive-ide0-1-0,id=ide0-1-0
    } else {
	die "unsupported interface type";
    }

    $device .= ",bootindex=$drive->{bootindex}" if $drive->{bootindex};

    return $device;
}

sub print_drive_full {
    my ($storecfg, $vmid, $drive) = @_;

    my $opts = '';
    foreach my $o (@qemu_drive_options) {
	next if $o eq 'bootindex';
	$opts .= ",$o=$drive->{$o}" if $drive->{$o};
    }

    foreach my $o (qw(bps bps_rd bps_wr)) {
	my $v = $drive->{"m$o"};
	$opts .= ",$o=" . int($v*1024*1024) if $v;
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
	if (!$drive->{cache} && ($path =~ m|^/dev/| || $path =~ m|\.raw$|)) {
	    $opts .= ",cache=none";
	}
    }

    my $pathinfo = $path ? "file=$path," : '';

    return "${pathinfo}if=none,id=drive-$drive->{interface}$drive->{index}$opts";
}

sub print_netdevice_full {
    my ($vmid, $conf, $net, $netid, $bridges) = @_;

    my $bootorder = $conf->{boot} || $confdesc->{boot}->{default};

    my $device = $net->{model};
    if ($net->{model} eq 'virtio') {
         $device = 'virtio-net-pci';
     };

    # qemu > 0.15 always try to boot from network - we disable that by
    # not loading the pxe rom file
    my $extra = ($bootorder !~ m/n/) ? "romfile=," : '';
    my $pciaddr = print_pci_addr("$netid", $bridges);
    my $tmpstr = "$device,${extra}mac=$net->{macaddr},netdev=$netid$pciaddr,id=$netid";
    $tmpstr .= ",bootindex=$net->{bootindex}" if $net->{bootindex} ;
    return $tmpstr;
}

sub print_netdev_full {
    my ($vmid, $conf, $net, $netid) = @_;

    my $i = '';
    if ($netid =~ m/^net(\d+)$/) {
        $i = int($1);
    }

    die "got strange net id '$i'\n" if $i >= ${MAX_NETS};

    my $ifname = "tap${vmid}i$i";

    # kvm uses TUNSETIFF ioctl, and that limits ifname length
    die "interface name '$ifname' is too long (max 15 character)\n"
        if length($ifname) >= 16;

    my $vhostparam = '';
    $vhostparam = ',vhost=on' if $kernel_has_vhost_net && $net->{model} eq 'virtio';

    my $vmname = $conf->{name} || "vm$vmid";

    if ($net->{bridge}) {
        return "type=tap,id=$netid,ifname=${ifname},script=/var/lib/qemu-server/pve-bridge$vhostparam";
    } else {
        return "type=user,id=$netid,hostname=$vmname";
    }
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
        } elsif ($kvp =~ m/^tag=(\d+)$/) {
            $res->{tag} = $1;
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
    $res .= ",tag=$net->{tag}" if $net->{tag};

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
    my ($config, $volid) = @_;

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

    $config->{$key} = $volid;

    return $key;
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

PVE::JSONSchema::register_format('pve-qm-startup', \&verify_startup);
sub verify_startup {
    my ($value, $noerr) = @_;

    return $value if parse_startup($value);

    return undef if $noerr;

    die "unable to parse startup options\n";
}

sub parse_startup {
    my ($value) = @_;

    return undef if !$value;

    my $res = {};

    foreach my $p (split(/,/, $value)) {
	next if $p =~ m/^\s*$/;

	if ($p =~ m/^(order=)?(\d+)$/) {
	    $res->{order} = $2;
	} elsif ($p =~ m/^up=(\d+)$/) {
	    $res->{up} = $1;
	} elsif ($p =~ m/^down=(\d+)$/) {
	    $res->{down} = $1;
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
	if ($v =~ m/^host=(0x)?([0-9A-Fa-f]{4}):(0x)?([0-9A-Fa-f]{4})$/) {
	    $found = 1;
	    $res->{vendorid} = $2;
	    $res->{productid} = $4;
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
	next if $opt eq 'parent' || $opt eq 'snaptime' || $opt eq 'vmstate';
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

sub lock_config_full {
    my ($vmid, $timeout, $code, @param) = @_;

    my $filename = config_file_lock($vmid);

    my $res = lock_file($filename, $timeout, $code, @param);

    die $@ if $@;

    return $res;
}

sub lock_config {
    my ($vmid, $code, @param) = @_;

    return lock_config_full($vmid, 10, $code, @param);
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

sub destroy_vm {
    my ($storecfg, $vmid, $keep_empty_config) = @_;

    my $conffile = config_file($vmid);

    my $conf = load_config($vmid);

    check_lock($conf);

    # only remove disks owned by this VM
    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

 	return if drive_is_cdrom($drive);

	my $volid = $drive->{file};
	return if !$volid || $volid =~ m|^/|;

	my ($path, $owner) = PVE::Storage::path($storecfg, $volid);
	return if !$path || !$owner || ($owner != $vmid);

	PVE::Storage::vdisk_free($storecfg, $volid);
    });

    if ($keep_empty_config) {
	PVE::Tools::file_set_contents($conffile, "memory: 128\n");
    } else {
	unlink $conffile;
    }

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

sub load_config {
    my ($vmid, $node) = @_;

    my $cfspath = cfs_config_path($vmid, $node);

    my $conf = PVE::Cluster::cfs_read_file($cfspath);

    die "no such VM ('$vmid')\n" if !defined($conf);

    return $conf;
}

sub parse_vm_config {
    my ($filename, $raw) = @_;

    return undef if !defined($raw);

    my $res = {
	digest => Digest::SHA::sha1_hex($raw),
	snapshots => {},
    };

    $filename =~ m|/qemu-server/(\d+)\.conf$|
	|| die "got strange filename '$filename'";

    my $vmid = $1;

    my $conf = $res;
    my $descr = '';

    my @lines = split(/\n/, $raw);
    foreach my $line (@lines) {
	next if $line =~ m/^\s*$/;
	
	if ($line =~ m/^\[([a-z][a-z0-9_\-]+)\]\s*$/i) {
	    my $snapname = $1;
	    $conf->{description} = $descr if $descr;
	    $descr = '';
	    $conf = $res->{snapshots}->{$snapname} = {}; 
	    next;
	}

	if ($line =~ m/^\#(.*)\s*$/) {
	    $descr .= PVE::Tools::decode_text($1) . "\n";
	    next;
	}

	if ($line =~ m/^(description):\s*(.*\S)\s*$/) {
	    $descr .= PVE::Tools::decode_text($2);
	} elsif ($line =~ m/snapstate:\s*(prepare|delete)\s*$/) {
	    $conf->{snapstate} = $1;
	} elsif ($line =~ m/^(args):\s*(.*\S)\s*$/) {
	    my $key = $1;
	    my $value = $2;
	    $conf->{$key} = $value;
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
		    $conf->{ide2} = $value;
		} else {
		    $conf->{$key} = $value;
		}
	    }
	}
    }

    $conf->{description} = $descr if $descr;

    delete $res->{snapstate}; # just to be sure

    return $res;
}

sub write_vm_config {
    my ($filename, $conf) = @_;

    delete $conf->{snapstate}; # just to be sure

    if ($conf->{cdrom}) {
	die "option ide2 conflicts with cdrom\n" if $conf->{ide2};
	$conf->{ide2} = $conf->{cdrom};
	delete $conf->{cdrom};
    }

    # we do not use 'smp' any longer
    if ($conf->{sockets}) {
	delete $conf->{smp};
    } elsif ($conf->{smp}) {
	$conf->{sockets} = $conf->{smp};
	delete $conf->{cores};
	delete $conf->{smp};
    }

    my $used_volids = {};

    my $cleanup_config = sub {
	my ($cref) = @_;

	foreach my $key (keys %$cref) {
	    next if $key eq 'digest' || $key eq 'description' || $key eq 'snapshots' ||
		$key eq 'snapstate';
	    my $value = $cref->{$key};
	    eval { $value = check_type($key, $value); };
	    die "unable to parse value of '$key' - $@" if $@;

	    $cref->{$key} = $value;

	    if (valid_drivename($key)) {
		my $drive = PVE::QemuServer::parse_drive($key, $value);
		$used_volids->{$drive->{file}} = 1 if $drive && $drive->{file};
	    }
	}
    };

    &$cleanup_config($conf);
    foreach my $snapname (keys %{$conf->{snapshots}}) {
	&$cleanup_config($conf->{snapshots}->{$snapname});
    }

    # remove 'unusedX' settings if we re-add a volume
    foreach my $key (keys %$conf) {
	my $value = $conf->{$key};
	if ($key =~ m/^unused/ && $used_volids->{$value}) {
	    delete $conf->{$key};
	}
    }
  
    my $generate_raw_config = sub {
	my ($conf) = @_;

	my $raw = '';

	# add description as comment to top of file
	my $descr = $conf->{description} || '';
	foreach my $cl (split(/\n/, $descr)) {
	    $raw .= '#' .  PVE::Tools::encode_text($cl) . "\n";
	}

	foreach my $key (sort keys %$conf) {
	    next if $key eq 'digest' || $key eq 'description' || $key eq 'snapshots';
	    $raw .= "$key: $conf->{$key}\n";
	}
	return $raw;
    };

    my $raw = &$generate_raw_config($conf);
    foreach my $snapname (sort keys %{$conf->{snapshots}}) {
	$raw .= "\n[$snapname]\n";
	$raw .= &$generate_raw_config($conf->{snapshots}->{$snapname});
    }

    return $raw;
}

sub update_config_nolock {
    my ($vmid, $conf, $skiplock) = @_;

    check_lock($conf) if !$skiplock;

    my $cfspath = cfs_config_path($vmid);

    PVE::Cluster::cfs_write_file($cfspath, $conf);
}

sub update_config {
    my ($vmid, $conf, $skiplock) = @_;

    lock_config($vmid, &update_config_nolock, $conf, $skiplock);
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

# check is used storages are available on all nodes (use by migrate)
sub check_storage_availability {
    my ($storecfg, $conf, $node) = @_;

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	my $volid = $drive->{file};
	return if !$volid;

	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	return if !$sid;

	# check if storage is available on both nodes
	my $scfg = PVE::Storage::storage_check_node($storecfg, $sid);
	PVE::Storage::storage_check_node($storecfg, $sid, $node);
   });
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
    my ($vmid, $nocheck, $node) = @_;

    my $filename = config_file($vmid, $node);

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

    return $drive->{size};
}

my $last_proc_pid_stat;

# get VM status information
# This must be fast and should not block ($full == false)
# We only query KVM using QMP if $full == true (this can be slow)
sub vmstatus {
    my ($opt_vmid, $full) = @_;

    my $res = {};

    my $storecfg = PVE::Storage::config();

    my $list = vzlist();
    my ($uptime) = PVE::ProcFSTools::read_proc_uptime(1);

    my $cpucount = $cpuinfo->{cpus} || 1;

    foreach my $vmid (keys %$list) {
	next if $opt_vmid && ($vmid ne $opt_vmid);

	my $cfspath = cfs_config_path($vmid);
	my $conf = PVE::Cluster::cfs_read_file($cfspath) || {};

	my $d = {};
	$d->{pid} = $list->{$vmid}->{pid};

	# fixme: better status?
	$d->{status} = $list->{$vmid}->{pid} ? 'running' : 'stopped';

	my $size = disksize($storecfg, $conf);
	if (defined($size)) {
	    $d->{disk} = 0; # no info available
	    $d->{maxdisk} = $size;
	} else {
	    $d->{disk} = 0;
	    $d->{maxdisk} = 0;
	}

	$d->{cpus} = ($conf->{sockets} || 1) * ($conf->{cores} || 1);
	$d->{cpus} = $cpucount if $d->{cpus} > $cpucount;

	$d->{name} = $conf->{name} || "VM $vmid";
	$d->{maxmem} = $conf->{memory} ? $conf->{memory}*(1024*1024) : 0;

	$d->{uptime} = 0;
	$d->{cpu} = 0;
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

    my $ctime = gettimeofday;

    foreach my $vmid (keys %$list) {

	my $d = $res->{$vmid};
	my $pid = $d->{pid};
	next if !$pid;

	my $pstat = PVE::ProcFSTools::read_proc_pid_stat($pid);
	next if !$pstat; # not running

	my $used = $pstat->{utime} + $pstat->{stime};

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
	    };
	    next;
	}

	my $dtime = ($ctime -  $old->{time}) * $cpucount * $cpuinfo->{user_hz};

	if ($dtime > 1000) {
	    my $dutime = $used -  $old->{used};

	    $d->{cpu} = (($dutime/$dtime)* $cpucount) / $d->{cpus};
	    $last_proc_pid_stat->{$pid} = {
		time => $ctime,
		used => $used,
		cpu => $d->{cpu},
	    };
	} else {
	    $d->{cpu} = $old->{cpu};
	}
    }

    return $res if !$full;

    my $qmpclient = PVE::QMPClient->new();

    my $blockstatscb = sub {
	my ($vmid, $resp) = @_;
	my $data = $resp->{'return'} || [];
	my $totalrdbytes = 0;
	my $totalwrbytes = 0;
	for my $blockstat (@$data) {
	    $totalrdbytes = $totalrdbytes + $blockstat->{stats}->{rd_bytes};
	    $totalwrbytes = $totalwrbytes + $blockstat->{stats}->{wr_bytes};
	}
	$res->{$vmid}->{diskread} = $totalrdbytes;
	$res->{$vmid}->{diskwrite} = $totalwrbytes;
    };

    my $statuscb = sub {
	my ($vmid, $resp) = @_;
	$qmpclient->queue_cmd($vmid, $blockstatscb, 'query-blockstats');

	my $status = 'unknown';
	if (!defined($status = $resp->{'return'}->{status})) {
	    warn "unable to get VM status\n";
	    return;
	}

	$res->{$vmid}->{qmpstatus} = $resp->{'return'}->{status};
    };

    foreach my $vmid (keys %$list) {
	next if $opt_vmid && ($vmid ne $opt_vmid);
	next if !$res->{$vmid}->{pid}; # not running
	$qmpclient->queue_cmd($vmid, $statuscb, 'query-status');
    }

    $qmpclient->queue_execute();

    foreach my $vmid (keys %$list) {
	next if $opt_vmid && ($vmid ne $opt_vmid);
	$res->{$vmid}->{qmpstatus} = $res->{$vmid}->{status} if !$res->{$vmid}->{qmpstatus};
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

sub foreach_volid {
    my ($conf, $func) = @_;
    
    my $volhash = {};

    my $test_volid = sub {
	my ($volid, $is_cdrom) = @_;

	return if !$volid;
	
	$volhash->{$volid} = $is_cdrom || 0;
    };

    PVE::QemuServer::foreach_drive($conf, sub {
	my ($ds, $drive) = @_;
	&$test_volid($drive->{file}, drive_is_cdrom($drive));
    });

    foreach my $snapname (keys %{$conf->{snapshots}}) {
	my $snap = $conf->{snapshots}->{$snapname};
	&$test_volid($snap->{vmstate}, 0);
	PVE::QemuServer::foreach_drive($snap, sub {
	    my ($ds, $drive) = @_;
	    &$test_volid($drive->{file}, drive_is_cdrom($drive));
        });
    }

    foreach my $volid (keys %$volhash) {
	&$func($volid, $volhash->{$volid});	
    }
}

sub config_to_command {
    my ($storecfg, $vmid, $conf, $defaults) = @_;

    my $cmd = [];
    my $globalFlags = [];
    my $machineFlags = [];
    my $rtcFlags = [];
    my $devices = [];
    my $pciaddr = '';
    my $bridges = {};
    my $kvmver = kvm_user_version();
    my $vernum = 0; # unknown
    if ($kvmver =~ m/^(\d+)\.(\d+)$/) {
	$vernum = $1*1000000+$2*1000;
    } elsif ($kvmver =~ m/^(\d+)\.(\d+)\.(\d+)$/) {
	$vernum = $1*1000000+$2*1000+$3;
    }

    die "detected old qemu-kvm binary ($kvmver)\n" if $vernum < 15000;

    my $have_ovz = -f '/proc/vz/vestat';

    push @$cmd, '/usr/bin/kvm';

    push @$cmd, '-id', $vmid;

    my $use_virtio = 0;

    my $qmpsocket = qmp_socket($vmid);
    push @$cmd, '-chardev', "socket,id=qmp,path=$qmpsocket,server,nowait";
    push @$cmd, '-mon', "chardev=qmp,mode=control";

    my $socket = vnc_socket($vmid);
    push @$cmd,  '-vnc', "unix:$socket,x509,password";

    push @$cmd, '-pidfile' , pidfile_name($vmid);

    push @$cmd, '-daemonize';

    my $use_usb2 = 0;
    for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	next if !$conf->{"usb$i"};
	$use_usb2 = 1;
    }
    # include usb device config
    push @$devices, '-readconfig', '/usr/share/qemu-server/pve-usb.cfg' if $use_usb2;

    # enable absolute mouse coordinates (needed by vnc)
    my $tablet = defined($conf->{tablet}) ? $conf->{tablet} : $defaults->{tablet};
    if ($tablet) {
	if ($use_usb2) {
	    push @$devices, '-device', 'usb-tablet,bus=ehci.0,port=6';
	} else {
	    push @$devices, '-usbdevice', 'tablet';
	}
    }

    # host pci devices
    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
          my $d = parse_hostpci($conf->{"hostpci$i"});
          next if !$d;
	  $pciaddr = print_pci_addr("hostpci$i", $bridges);
          push @$devices, '-device', "pci-assign,host=$d->{pciid},id=hostpci$i$pciaddr";
    }

    # usb devices
    for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	my $d = parse_usb_device($conf->{"usb$i"});
	next if !$d;
	if ($d->{vendorid} && $d->{productid}) {
	    push @$devices, '-device', "usb-host,vendorid=0x$d->{vendorid},productid=0x$d->{productid}";
	} elsif (defined($d->{hostbus}) && defined($d->{hostport})) {
	    push @$devices, '-device', "usb-host,hostbus=$d->{hostbus},hostport=$d->{hostport}";
	}
    }

    # serial devices
    for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++)  {
	if (my $path = $conf->{"serial$i"}) {
	    die "no such serial device\n" if ! -c $path;
	    push @$devices, '-chardev', "tty,id=serial$i,path=$path";
	    push @$devices, '-device', "isa-serial,chardev=serial$i";
	}
    }

    # parallel devices
    for (my $i = 0; $i < $MAX_PARALLEL_PORTS; $i++)  {
	if (my $path = $conf->{"parallel$i"}) {
	    die "no such parallel device\n" if ! -c $path;
	    push @$devices, '-chardev', "parport,id=parallel$i,path=$path";
	    push @$devices, '-device', "isa-parallel,chardev=parallel$i";
	}
    }

    my $vmname = $conf->{name} || "vm$vmid";

    push @$cmd, '-name', $vmname;

    my $sockets = 1;
    $sockets = $conf->{smp} if $conf->{smp}; # old style - no longer iused
    $sockets = $conf->{sockets} if  $conf->{sockets};

    my $cores = $conf->{cores} || 1;

    push @$cmd, '-smp', "sockets=$sockets,cores=$cores";

    push @$cmd, '-cpu', $conf->{cpu} if $conf->{cpu};

    push @$cmd, '-nodefaults';

    my $bootorder = $conf->{boot} || $confdesc->{boot}->{default};

    my $bootindex_hash = {};
    my $i = 1;
    foreach my $o (split(//, $bootorder)) {
	$bootindex_hash->{$o} = $i*100;
	$i++;
    }

    push @$cmd, '-boot', "menu=on";

    push @$cmd, '-no-acpi' if defined($conf->{acpi}) && $conf->{acpi} == 0;

    push @$cmd, '-no-reboot' if  defined($conf->{reboot}) && $conf->{reboot} == 0;

    my $vga = $conf->{vga};
    if (!$vga) {
	if ($conf->{ostype} && ($conf->{ostype} eq 'win8' || $conf->{ostype} eq 'win7' || $conf->{ostype} eq 'w2k8')) {
	    $vga = 'std';
	} else {
	    $vga = 'cirrus';
	}
    }

    push @$cmd, '-vga', $vga if $vga; # for kvm 77 and later

    # time drift fix
    my $tdf = defined($conf->{tdf}) ? $conf->{tdf} : $defaults->{tdf};

    my $nokvm = defined($conf->{kvm}) && $conf->{kvm} == 0 ? 1 : 0;
    my $useLocaltime = $conf->{localtime};

    if (my $ost = $conf->{ostype}) {
	# other, wxp, w2k, w2k3, w2k8, wvista, win7, win8, l24, l26

	if ($ost =~ m/^w/) { # windows
	    $useLocaltime = 1 if !defined($conf->{localtime});

	    # use time drift fix when acpi is enabled
	    if (!(defined($conf->{acpi}) && $conf->{acpi} == 0)) {
		$tdf = 1 if !defined($conf->{tdf});
	    }
	}

	if ($ost eq 'win7' || $ost eq 'win8' || $ost eq 'w2k8' || 
	    $ost eq 'wvista') {
	    push @$globalFlags, 'kvm-pit.lost_tick_policy=discard';
	    push @$cmd, '-no-hpet';
	}
    }

    push @$rtcFlags, 'driftfix=slew' if $tdf;

    if ($nokvm) {
	push @$machineFlags, 'accel=tcg';
    } else {
	die "No accelerator found!\n" if !$cpuinfo->{hvm};
    }

    if ($conf->{startdate}) {
	push @$rtcFlags, "base=$conf->{startdate}";
    } elsif ($useLocaltime) {
	push @$rtcFlags, 'base=localtime';
    }

    push @$cmd, '-S' if $conf->{freeze};

    # set keyboard layout
    my $kb = $conf->{keyboard} || $defaults->{keyboard};
    push @$cmd, '-k', $kb if $kb;

    # enable sound
    #my $soundhw = $conf->{soundhw} || $defaults->{soundhw};
    #push @$cmd, '-soundhw', 'es1370';
    #push @$cmd, '-soundhw', $soundhw if $soundhw;

    if($conf->{agent}) {
	my $qgasocket = qga_socket($vmid);
	my $pciaddr = print_pci_addr("qga0", $bridges);
	push @$devices, '-chardev', "socket,path=$qgasocket,server,nowait,id=qga0";
	push @$devices, '-device', "virtio-serial,id=qga0$pciaddr";
	push @$devices, '-device', 'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0';
    }

    $pciaddr = print_pci_addr("balloon0", $bridges);
    push @$devices, '-device', "virtio-balloon-pci,id=balloon0$pciaddr" if $conf->{balloon};

    if ($conf->{watchdog}) {
	my $wdopts = parse_watchdog($conf->{watchdog});
	$pciaddr = print_pci_addr("watchdog", $bridges);
	my $watchdog = $wdopts->{model} || 'i6300esb';
	push @$devices, '-device', "$watchdog$pciaddr";
	push @$devices, '-watchdog-action', $wdopts->{action} if $wdopts->{action};
    }

    my $vollist = [];
    my $scsicontroller = {};
    my $ahcicontroller = {};
    my $scsihw = defined($conf->{scsihw}) ? $conf->{scsihw} : $defaults->{scsihw};

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	if (PVE::Storage::parse_volume_id($drive->{file}, 1)) {
	    push @$vollist, $drive->{file};
	}

	$use_virtio = 1 if $ds =~ m/^virtio/;

	if (drive_is_cdrom ($drive)) {
	    if ($bootindex_hash->{d}) {
		$drive->{bootindex} = $bootindex_hash->{d};
		$bootindex_hash->{d} += 1;
	    }
	} else {
	    if ($bootindex_hash->{c}) {
		$drive->{bootindex} = $bootindex_hash->{c} if $conf->{bootdisk} && ($conf->{bootdisk} eq $ds);
		$bootindex_hash->{c} += 1;
	    }
	}

        if ($drive->{interface} eq 'scsi') {

	    my $maxdev = ($scsihw ne 'lsi') ? 256 : 7;
	    my $controller = int($drive->{index} / $maxdev);
	    $pciaddr = print_pci_addr("scsihw$controller", $bridges);
	    push @$devices, '-device', "$scsihw,id=scsihw$controller$pciaddr" if !$scsicontroller->{$controller};
	    $scsicontroller->{$controller}=1;
        }

        if ($drive->{interface} eq 'sata') {
           my $controller = int($drive->{index} / $MAX_SATA_DISKS);
           $pciaddr = print_pci_addr("ahci$controller", $bridges);
           push @$devices, '-device', "ahci,id=ahci$controller,multifunction=on$pciaddr" if !$ahcicontroller->{$controller};
           $ahcicontroller->{$controller}=1;
        }

	push @$devices, '-drive',print_drive_full($storecfg, $vmid, $drive);
	push @$devices, '-device',print_drivedevice_full($storecfg, $conf, $vmid, $drive, $bridges);
    });

    push @$cmd, '-m', $conf->{memory} || $defaults->{memory};

    for (my $i = 0; $i < $MAX_NETS; $i++) {
         next if !$conf->{"net$i"};
         my $d = parse_net($conf->{"net$i"});
         next if !$d;

         $use_virtio = 1 if $d->{model} eq 'virtio';

         if ($bootindex_hash->{n}) {
            $d->{bootindex} = $bootindex_hash->{n};
            $bootindex_hash->{n} += 1;
         }

         my $netdevfull = print_netdev_full($vmid,$conf,$d,"net$i");
         push @$devices, '-netdev', $netdevfull;

         my $netdevicefull = print_netdevice_full($vmid,$conf,$d,"net$i",$bridges);
         push @$devices, '-device', $netdevicefull;
    }

    #bridges
    while (my ($k, $v) = each %$bridges) {
	$pciaddr = print_pci_addr("pci.$k");
	unshift @$devices, '-device', "pci-bridge,id=pci.$k,chassis_nr=$k$pciaddr" if $k > 0;
    }


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
	my $aa = PVE::Tools::split_args($conf->{args});
	push @$cmd, @$aa;
    }

    push @$cmd, @$devices;
    push @$cmd, '-rtc', join(',', @$rtcFlags) 
	if scalar(@$rtcFlags);
    push @$cmd, '-machine', join(',', @$machineFlags) 
	if scalar(@$machineFlags);
    push @$cmd, '-global', join(',', @$globalFlags)
	if scalar(@$globalFlags);

    return wantarray ? ($cmd, $vollist) : $cmd;
}

sub vnc_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.vnc";
}

sub qmp_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.qmp";
}

sub qga_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.qga";
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

sub vm_devices_list {
    my ($vmid) = @_;

    my $res = vm_mon_cmd($vmid, 'query-pci');

    my $devices = {};
    foreach my $pcibus (@$res) {
	foreach my $device (@{$pcibus->{devices}}) {
	    next if !$device->{'qdev_id'};
	    $devices->{$device->{'qdev_id'}} = $device;
	}
    }

    return $devices;
}

sub vm_deviceplug {
    my ($storecfg, $conf, $vmid, $deviceid, $device) = @_;

    return 1 if !check_running($vmid) || !$conf->{hotplug};

    my $devices_list = vm_devices_list($vmid);
    return 1 if defined($devices_list->{$deviceid});

    qemu_bridgeadd($storecfg, $conf, $vmid, $deviceid); #add bridge if we need it for the device

    if ($deviceid =~ m/^(virtio)(\d+)$/) {
        return undef if !qemu_driveadd($storecfg, $vmid, $device);
        my $devicefull = print_drivedevice_full($storecfg, $conf, $vmid, $device);
        qemu_deviceadd($vmid, $devicefull);
        if(!qemu_deviceaddverify($vmid, $deviceid)) {
           qemu_drivedel($vmid, $deviceid);
           return undef;
        }
    }

    if ($deviceid =~ m/^(scsihw)(\d+)$/) {
        my $scsihw = defined($conf->{scsihw}) ? $conf->{scsihw} : "lsi";
        my $pciaddr = print_pci_addr($deviceid);
        my $devicefull = "$scsihw,id=$deviceid$pciaddr";
        qemu_deviceadd($vmid, $devicefull);
        return undef if(!qemu_deviceaddverify($vmid, $deviceid));
    }

    if ($deviceid =~ m/^(scsi)(\d+)$/) {
        return 1 if ($conf->{scsihw} && $conf->{scsihw} ne 'lsi'); #virtio-scsi not yet support hotplug
        return undef if !qemu_findorcreatescsihw($storecfg,$conf, $vmid, $device);
        return undef if !qemu_driveadd($storecfg, $vmid, $device);
        my $devicefull = print_drivedevice_full($storecfg, $conf, $vmid, $device);
        if(!qemu_deviceadd($vmid, $devicefull)) {
           qemu_drivedel($vmid, $deviceid);
           return undef;
        }
    }

    if ($deviceid =~ m/^(net)(\d+)$/) {
        return undef if !qemu_netdevadd($vmid, $conf, $device, $deviceid);
        my $netdevicefull = print_netdevice_full($vmid, $conf, $device, $deviceid);
        qemu_deviceadd($vmid, $netdevicefull);
        if(!qemu_deviceaddverify($vmid, $deviceid)) {
           qemu_netdevdel($vmid, $deviceid);
           return undef;
        }
    }

    if ($deviceid =~ m/^(pci\.)(\d+)$/) {
	my $bridgeid = $2;
	my $pciaddr = print_pci_addr($deviceid);
	my $devicefull = "pci-bridge,id=pci.$bridgeid,chassis_nr=$bridgeid$pciaddr";
	qemu_deviceadd($vmid, $devicefull);
	return undef if !qemu_deviceaddverify($vmid, $deviceid);
    }

    return 1;
}

sub vm_deviceunplug {
    my ($vmid, $conf, $deviceid) = @_;

    return 1 if !check_running ($vmid) || !$conf->{hotplug};

    my $devices_list = vm_devices_list($vmid);
    return 1 if !defined($devices_list->{$deviceid});

    die "can't unplug bootdisk" if $conf->{bootdisk} && $conf->{bootdisk} eq $deviceid;

    if ($deviceid =~ m/^(virtio)(\d+)$/) {
        return undef if !qemu_drivedel($vmid, $deviceid);
        qemu_devicedel($vmid, $deviceid);
        return undef if !qemu_devicedelverify($vmid, $deviceid);
    }

    if ($deviceid =~ m/^(lsi)(\d+)$/) {
        return undef if !qemu_devicedel($vmid, $deviceid);
    }

    if ($deviceid =~ m/^(scsi)(\d+)$/) {
        return undef if !qemu_devicedel($vmid, $deviceid);
        return undef if !qemu_drivedel($vmid, $deviceid);
    }

    if ($deviceid =~ m/^(net)(\d+)$/) {
        return undef if !qemu_netdevdel($vmid, $deviceid);
        qemu_devicedel($vmid, $deviceid);
        return undef if !qemu_devicedelverify($vmid, $deviceid);
    }

    return 1;
}

sub qemu_deviceadd {
    my ($vmid, $devicefull) = @_;

    my $ret = vm_human_monitor_command($vmid, "device_add $devicefull");
    $ret =~ s/^\s+//;
    # Otherwise, if the command succeeds, no output is sent. So any non-empty string shows an error
    return 1 if $ret eq "";
    syslog("err", "error on hotplug device : $ret");
    return undef;

}

sub qemu_devicedel {
    my($vmid, $deviceid) = @_;

    my $ret = vm_human_monitor_command($vmid, "device_del $deviceid");
    $ret =~ s/^\s+//;
    return 1 if $ret eq "";
    syslog("err", "detaching device $deviceid failed : $ret");
    return undef;
}

sub qemu_driveadd {
    my($storecfg, $vmid, $device) = @_;

    my $drive = print_drive_full($storecfg, $vmid, $device);
    my $ret = vm_human_monitor_command($vmid, "drive_add auto $drive");
    # If the command succeeds qemu prints: "OK"
    if ($ret !~ m/OK/s) {
        syslog("err", "adding drive failed: $ret");
        return undef;
    }
    return 1;
}

sub qemu_drivedel {
    my($vmid, $deviceid) = @_;

    my $ret = vm_human_monitor_command($vmid, "drive_del drive-$deviceid");
    $ret =~ s/^\s+//;
    if ($ret =~ m/Device \'.*?\' not found/s) {
        # NB: device not found errors mean the drive was auto-deleted and we ignore the error
    }
    elsif ($ret ne "") {
      syslog("err", "deleting drive $deviceid failed : $ret");
      return undef;
    }
    return 1;
}

sub qemu_deviceaddverify {
    my ($vmid,$deviceid) = @_;

    for (my $i = 0; $i <= 5; $i++) {
         my $devices_list = vm_devices_list($vmid);
         return 1 if defined($devices_list->{$deviceid});
         sleep 1;
    }
    syslog("err", "error on hotplug device $deviceid");
    return undef;
}


sub qemu_devicedelverify {
    my ($vmid,$deviceid) = @_;

    #need to verify the device is correctly remove as device_del is async and empty return is not reliable
    for (my $i = 0; $i <= 5; $i++) {
         my $devices_list = vm_devices_list($vmid);
         return 1 if !defined($devices_list->{$deviceid});
         sleep 1;
    }
    syslog("err", "error on hot-unplugging device $deviceid");
    return undef;
}

sub qemu_findorcreatescsihw {
    my ($storecfg, $conf, $vmid, $device) = @_;

    my $maxdev = ($conf->{scsihw} && $conf->{scsihw} ne 'lsi') ? 256 : 7;
    my $controller = int($device->{index} / $maxdev);
    my $scsihwid="scsihw$controller";
    my $devices_list = vm_devices_list($vmid);

    if(!defined($devices_list->{$scsihwid})) {
       return undef if !vm_deviceplug($storecfg, $conf, $vmid, $scsihwid);
    }
    return 1;
}

sub qemu_bridgeadd {
    my ($storecfg, $conf, $vmid, $device) = @_;

    my $bridges = {};
    my $bridgeid = undef;
    print_pci_addr($device, $bridges);

    while (my ($k, $v) = each %$bridges) {
	$bridgeid = $k;
    }
    return if $bridgeid < 1;
    my $bridge = "pci.$bridgeid";
    my $devices_list = vm_devices_list($vmid);

    if(!defined($devices_list->{$bridge})) {
	return undef if !vm_deviceplug($storecfg, $conf, $vmid, $bridge);
    }
    return 1;
}

sub qemu_netdevadd {
    my ($vmid, $conf, $device, $deviceid) = @_;

    my $netdev = print_netdev_full($vmid, $conf, $device, $deviceid);
    my $ret = vm_human_monitor_command($vmid, "netdev_add $netdev");
    $ret =~ s/^\s+//;

    #if the command succeeds, no output is sent. So any non-empty string shows an error
    return 1 if $ret eq "";
    syslog("err", "adding netdev failed: $ret");
    return undef;
}

sub qemu_netdevdel {
    my ($vmid, $deviceid) = @_;

    my $ret = vm_human_monitor_command($vmid, "netdev_del $deviceid");
    $ret =~ s/^\s+//;
    #if the command succeeds, no output is sent. So any non-empty string shows an error
    return 1 if $ret eq "";
    syslog("err", "deleting netdev failed: $ret");
    return undef;
}

sub qemu_block_set_io_throttle {
    my ($vmid, $deviceid, $bps, $bps_rd, $bps_wr, $iops, $iops_rd, $iops_wr) = @_;

    return if !check_running($vmid) ;

    $bps = 0 if !$bps;
    $bps_rd = 0 if !$bps_rd;
    $bps_wr = 0 if !$bps_wr;
    $iops = 0 if !$iops;
    $iops_rd = 0 if !$iops_rd;
    $iops_wr = 0 if !$iops_wr;

    vm_mon_cmd($vmid, "block_set_io_throttle", device => $deviceid, bps => int($bps), bps_rd => int($bps_rd), bps_wr => int($bps_wr), iops => int($iops), iops_rd => int($iops_rd), iops_wr => int($iops_wr));

}

# old code, only used to shutdown old VM after update
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

# old code, only used to shutdown old VM after update
sub vm_monitor_command {
    my ($vmid, $cmdstr, $nocheck) = @_;

    my $res;

    eval {
	die "VM $vmid not running\n" if !check_running($vmid, $nocheck);

	my $sname = "${var_run_tmpdir}/$vmid.mon";

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

	# syslog('info', "VM $vmid monitor command: $cmdstr");

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

sub qemu_block_resize {
    my ($vmid, $deviceid, $storecfg, $volid, $size) = @_;

    my $running = PVE::QemuServer::check_running($vmid);

    return if !PVE::Storage::volume_resize($storecfg, $volid, $size, $running);

    return if !$running;

    vm_mon_cmd($vmid, "block_resize", device => $deviceid, size => int($size));

}

sub qemu_volume_snapshot {
    my ($vmid, $deviceid, $storecfg, $volid, $snap) = @_;

    my $running = PVE::QemuServer::check_running($vmid);

    return if !PVE::Storage::volume_snapshot($storecfg, $volid, $snap, $running);

    return if !$running;

    vm_mon_cmd($vmid, "snapshot-drive", device => $deviceid, name => $snap);

}

sub qemu_volume_snapshot_delete {
    my ($vmid, $deviceid, $storecfg, $volid, $snap) = @_;

    my $running = PVE::QemuServer::check_running($vmid);

    return if !PVE::Storage::volume_snapshot_delete($storecfg, $volid, $snap, $running);

    return if !$running;

    vm_mon_cmd($vmid, "delete-drive-snapshot", device => $deviceid, name => $snap);
}

sub qga_freezefs {
    my ($vmid) = @_;

    #need to impplement call to qemu-ga
}

sub qga_unfreezefs {
    my ($vmid) = @_;

    #need to impplement call to qemu-ga
}

sub vm_start {
    my ($storecfg, $vmid, $statefile, $skiplock, $migratedfrom) = @_;

    lock_config($vmid, sub {
	my $conf = load_config($vmid, $migratedfrom);

	check_lock($conf) if !$skiplock;

	die "VM $vmid already running\n" if check_running($vmid, undef, $migratedfrom);

	my $defaults = load_defaults();

	# set environment variable useful inside network script
	$ENV{PVE_MIGRATED_FROM} = $migratedfrom if $migratedfrom;

	my ($cmd, $vollist) = config_to_command($storecfg, $vmid, $conf, $defaults);

	my $migrate_port = 0;

	if ($statefile) {
	    if ($statefile eq 'tcp') {
		$migrate_port = next_migrate_port();
		my $migrate_uri = "tcp:localhost:${migrate_port}";
		push @$cmd, '-incoming', $migrate_uri;
		push @$cmd, '-S';
	    } else {
		push @$cmd, '-loadstate', $statefile;
	    }
	}

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

	eval  { run_command($cmd, timeout => $statefile ? undef : 30,
		    umask => 0077); };
	my $err = $@;
	die "start failed: $err" if $err;

	print "migration listens on port $migrate_port\n" if $migrate_port;

	if ($statefile && $statefile ne 'tcp')  {
	    eval { vm_mon_cmd($vmid, "cont"); };
	    warn $@ if $@;
	}

	# always set migrate speed (overwrite kvm default of 32m)
	# we set a very hight default of 8192m which is basically unlimited
	my $migrate_speed = $defaults->{migrate_speed} || 8192;
	$migrate_speed = $conf->{migrate_speed} || $migrate_speed;
	$migrate_speed = $migrate_speed * 1048576;
	eval {
	    vm_mon_cmd($vmid, "migrate_set_speed", value => $migrate_speed);
	};

	my $migrate_downtime = $defaults->{migrate_downtime};
	$migrate_downtime = $conf->{migrate_downtime} if defined($conf->{migrate_downtime});
	if (defined($migrate_downtime)) {
	    eval { vm_mon_cmd($vmid, "migrate_set_downtime", value => $migrate_downtime); };
	}

	if($migratedfrom) {
	    my $capabilities = {};
	    $capabilities->{capability} =  "xbzrle";
	    $capabilities->{state} = JSON::true;
	    eval { PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate-set-capabilities", capabilities => [$capabilities]); };
	}

	vm_balloonset($vmid, $conf->{balloon}) if $conf->{balloon};

    });
}

sub vm_mon_cmd {
    my ($vmid, $execute, %params) = @_;

    my $cmd = { execute => $execute, arguments => \%params };
    vm_qmp_command($vmid, $cmd);
}

sub vm_mon_cmd_nocheck {
    my ($vmid, $execute, %params) = @_;

    my $cmd = { execute => $execute, arguments => \%params };
    vm_qmp_command($vmid, $cmd, 1);
}

sub vm_qmp_command {
    my ($vmid, $cmd, $nocheck) = @_;

    my $res;

    my $timeout;
    if ($cmd->{arguments} && $cmd->{arguments}->{timeout}) {
	$timeout = $cmd->{arguments}->{timeout};
	delete $cmd->{arguments}->{timeout};
    }
 
    eval {
	die "VM $vmid not running\n" if !check_running($vmid, $nocheck);
	my $sname = PVE::QemuServer::qmp_socket($vmid);
	if (-e $sname) {
	    my $qmpclient = PVE::QMPClient->new();

	    $res = $qmpclient->cmd($vmid, $cmd, $timeout);
	} elsif (-e "${var_run_tmpdir}/$vmid.mon") {
	    die "can't execute complex command on old monitor - stop/start your vm to fix the problem\n"
		if scalar(%{$cmd->{arguments}});
	    vm_monitor_command($vmid, $cmd->{execute}, $nocheck);
	} else {
	    die "unable to open monitor socket\n";
	}
    };
    if (my $err = $@) {
	syslog("err", "VM $vmid qmp command failed - $err");
	die $err;
    }

    return $res;
}

sub vm_human_monitor_command {
    my ($vmid, $cmdline) = @_;

    my $res;

    my $cmd = {
	execute => 'human-monitor-command',
	arguments => { 'command-line' => $cmdline},
    };

    return vm_qmp_command($vmid, $cmd);
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

	vm_mon_cmd($vmid, "system_reset");
    });
}

sub get_vm_volumes {
    my ($conf) = @_;

    my $vollist = [];
    foreach_volid($conf, sub {
	my ($volid, $is_cdrom) = @_;

	return if $volid =~ m|^/|;

	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	return if !$sid;

	push @$vollist, $volid;
    });

    return $vollist;
}

sub vm_stop_cleanup {
    my ($storecfg, $vmid, $conf, $keepActive) = @_;

    eval {
	fairsched_rmnod($vmid); # try to destroy group

	if (!$keepActive) {
	    my $vollist = get_vm_volumes($conf);
	    PVE::Storage::deactivate_volumes($storecfg, $vollist);
	}

	foreach my $ext (qw(mon qmp pid vnc qga)) {
	    unlink "/var/run/qemu-server/${vmid}.$ext";
	}
    };
    warn $@ if $@; # avoid errors - just warn
}

# Note: use $nockeck to skip tests if VM configuration file exists.
# We need that when migration VMs to other nodes (files already moved)
# Note: we set $keepActive in vzdump stop mode - volumes need to stay active
sub vm_stop {
    my ($storecfg, $vmid, $skiplock, $nocheck, $timeout, $shutdown, $force, $keepActive, $migratedfrom) = @_;

    $force = 1 if !defined($force) && !$shutdown;

    if ($migratedfrom){
	my $pid = check_running($vmid, $nocheck, $migratedfrom);
	kill 15, $pid if $pid;
	my $conf = load_config($vmid, $migratedfrom);
	vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive);
	return;
    }

    lock_config($vmid, sub {

	my $pid = check_running($vmid, $nocheck);
	return if !$pid;

	my $conf;
	if (!$nocheck) {
	    $conf = load_config($vmid);
	    check_lock($conf) if !$skiplock;
	    if (!defined($timeout) && $shutdown && $conf->{startup}) {
		my $opts = parse_startup($conf->{startup});
		$timeout = $opts->{down} if $opts->{down};
	    }
	}

	$timeout = 60 if !defined($timeout);

	eval {
	    if ($shutdown) {
		$nocheck ? vm_mon_cmd_nocheck($vmid, "system_powerdown") : vm_mon_cmd($vmid, "system_powerdown");

	    } else {
		$nocheck ? vm_mon_cmd_nocheck($vmid, "quit") : vm_mon_cmd($vmid, "quit");
	    }
	};
	my $err = $@;

	if (!$err) {
	    my $count = 0;
	    while (($count < $timeout) && check_running($vmid, $nocheck)) {
		$count++;
		sleep 1;
	    }

	    if ($count >= $timeout) {
		if ($force) {
		    warn "VM still running - terminating now with SIGTERM\n";
		    kill 15, $pid;
		} else {
		    die "VM quit/powerdown failed - got timeout\n";
		}
	    } else {
		vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive) if $conf;
		return;
	    }
	} else {
	    if ($force) {
		warn "VM quit/powerdown failed - terminating now with SIGTERM\n";
		kill 15, $pid;
	    } else {
		die "VM quit/powerdown failed\n";
	    }
	}

	# wait again
	$timeout = 10;

	my $count = 0;
	while (($count < $timeout) && check_running($vmid, $nocheck)) {
	    $count++;
	    sleep 1;
	}

	if ($count >= $timeout) {
	    warn "VM still running - terminating now with SIGKILL\n";
	    kill 9, $pid;
	    sleep 1;
	}

	vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive) if $conf;
   });
}

sub vm_suspend {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	vm_mon_cmd($vmid, "stop");
    });
}

sub vm_resume {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	vm_mon_cmd($vmid, "cont");
    });
}

sub vm_sendkey {
    my ($vmid, $skiplock, $key) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	# there is no qmp command, so we use the human monitor command
	vm_human_monitor_command($vmid, "sendkey $key");
    });
}

sub vm_destroy {
    my ($storecfg, $vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !$skiplock;

	if (!check_running($vmid)) {
	    fairsched_rmnod($vmid); # try to destroy group
	    destroy_vm($storecfg, $vmid);
	} else {
	    die "VM $vmid is running - destroy failed\n";
	}
    });
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
    my ($id, $bridges) = @_;

    my $res = '';
    my $devices = {
	#addr1 : ide,parallel,serial (motherboard)
	#addr2 : first videocard
	balloon0 => { bus => 0, addr => 3 },
	watchdog => { bus => 0, addr => 4 },
	scsihw0 => { bus => 0, addr => 5 },
	scsihw1 => { bus => 0, addr => 6 },
	ahci0 => { bus => 0, addr => 7 },
	qga0 => { bus => 0, addr => 8 },
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
    };

    if (defined($devices->{$id}->{bus}) && defined($devices->{$id}->{addr})) {
	   my $addr = sprintf("0x%x", $devices->{$id}->{addr});
	   my $bus = $devices->{$id}->{bus};
	   $res = ",bus=pci.$bus,addr=$addr";
	   $bridges->{$bus} = 1 if $bridges;
    }
    return $res;

}

sub vm_balloonset {
    my ($vmid, $value) = @_;

    vm_mon_cmd($vmid, "balloon", value => $value);
}

# vzdump restore implementaion

sub archive_read_firstfile {
    my $archive = shift;

    die "ERROR: file '$archive' does not exist\n" if ! -f $archive;

    # try to detect archive type first
    my $pid = open (TMP, "tar tf '$archive'|") ||
	die "unable to open file '$archive'\n";
    my $firstfile = <TMP>;
    kill 15, $pid;
    close TMP;

    die "ERROR: archive contaions no data\n" if !$firstfile;
    chomp $firstfile;

    return $firstfile;
}

sub restore_cleanup {
    my $statfile = shift;

    print STDERR "starting cleanup\n";

    if (my $fd = IO::File->new($statfile, "r")) {
	while (defined(my $line = <$fd>)) {
	    if ($line =~ m/vzdump:([^\s:]*):(\S+)$/) {
		my $volid = $2;
		eval {
		    if ($volid =~ m|^/|) {
			unlink $volid || die 'unlink failed\n';
		    } else {
			my $cfg = cfs_read_file('storage.cfg');
			PVE::Storage::vdisk_free($cfg, $volid);
		    }
		    print STDERR "temporary volume '$volid' sucessfuly removed\n";
		};
		print STDERR "unable to cleanup '$volid' - $@" if $@;
	    } else {
		print STDERR "unable to parse line in statfile - $line";
	    }
	}
	$fd->close();
    }
}

sub restore_archive {
    my ($archive, $vmid, $user, $opts) = @_;

    if ($archive ne '-') {
	my $firstfile = archive_read_firstfile($archive);
	die "ERROR: file '$archive' dos not lock like a QemuServer vzdump backup\n"
	    if $firstfile ne 'qemu-server.conf';
    }

    my $tocmd = "/usr/lib/qemu-server/qmextract";

    $tocmd .= " --storage " . PVE::Tools::shellquote($opts->{storage}) if $opts->{storage};
    $tocmd .= " --pool " . PVE::Tools::shellquote($opts->{pool}) if $opts->{pool};
    $tocmd .= ' --prealloc' if $opts->{prealloc};
    $tocmd .= ' --info' if $opts->{info};

    # tar option "xf" does not autodetect compression when read from STDIN,
    # so we pipe to zcat
    my $cmd = "zcat -f|tar xf " . PVE::Tools::shellquote($archive) . " " .
	PVE::Tools::shellquote("--to-command=$tocmd");

    my $tmpdir = "/var/tmp/vzdumptmp$$";
    mkpath $tmpdir;

    local $ENV{VZDUMP_TMPDIR} = $tmpdir;
    local $ENV{VZDUMP_VMID} = $vmid;
    local $ENV{VZDUMP_USER} = $user;

    my $conffile = PVE::QemuServer::config_file($vmid);
    my $tmpfn = "$conffile.$$.tmp";

    # disable interrupts (always do cleanups)
    local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = sub {
	print STDERR "got interrupt - ignored\n";
    };

    eval {
	# enable interrupts
	local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = $SIG{PIPE} = sub {
	    die "interrupted by signal\n";
	};

	if ($archive eq '-') {
	    print "extracting archive from STDIN\n";
	    run_command($cmd, input => "<&STDIN");
	} else {
	    print "extracting archive '$archive'\n";
	    run_command($cmd);
	}

	return if $opts->{info};

	# read new mapping
	my $map = {};
	my $statfile = "$tmpdir/qmrestore.stat";
	if (my $fd = IO::File->new($statfile, "r")) {
	    while (defined (my $line = <$fd>)) {
		if ($line =~ m/vzdump:([^\s:]*):(\S+)$/) {
		    $map->{$1} = $2 if $1;
		} else {
		    print STDERR "unable to parse line in statfile - $line\n";
		}
	    }
	    $fd->close();
	}

	my $confsrc = "$tmpdir/qemu-server.conf";

	my $srcfd = new IO::File($confsrc, "r") ||
	    die "unable to open file '$confsrc'\n";

	my $outfd = new IO::File ($tmpfn, "w") ||
	    die "unable to write config for VM $vmid\n";

	my $netcount = 0;

	while (defined (my $line = <$srcfd>)) {
	    next if $line =~ m/^\#vzdump\#/;
	    next if $line =~ m/^lock:/;
	    next if $line =~ m/^unused\d+:/;

	    if (($line =~ m/^(vlan(\d+)):\s*(\S+)\s*$/)) {
		# try to convert old 1.X settings
		my ($id, $ind, $ethcfg) = ($1, $2, $3);
		foreach my $devconfig (PVE::Tools::split_list($ethcfg)) {
		    my ($model, $macaddr) = split(/\=/, $devconfig);
		    $macaddr = PVE::Tools::random_ether_addr() if !$macaddr || $opts->{unique};
		    my $net = {
			model => $model,
			bridge => "vmbr$ind",
			macaddr => $macaddr,
		    };
		    my $netstr = print_net($net);
		    print $outfd "net${netcount}: $netstr\n";
		    $netcount++;
		}
	    } elsif (($line =~ m/^(net\d+):\s*(\S+)\s*$/) && ($opts->{unique})) {
		my ($id, $netstr) = ($1, $2);
		my $net = parse_net($netstr);
		$net->{macaddr} = PVE::Tools::random_ether_addr() if $net->{macaddr};
		$netstr = print_net($net);
		print $outfd "$id: $netstr\n";
	    } elsif ($line =~ m/^((ide|scsi|virtio|sata)\d+):\s*(\S+)\s*$/) {
		my $virtdev = $1;
		my $value = $2;
		if ($line =~ m/backup=no/) {
		    print $outfd "#$line";
		} elsif ($virtdev && $map->{$virtdev}) {
		    my $di = PVE::QemuServer::parse_drive($virtdev, $value);
		    $di->{file} = $map->{$virtdev};
		    $value = PVE::QemuServer::print_drive($vmid, $di);
		    print $outfd "$virtdev: $value\n";
		} else {
		    print $outfd $line;
		}
	    } else {
		print $outfd $line;
	    }
	}

	$srcfd->close();
	$outfd->close();
    };
    my $err = $@;

    if ($err) {

	unlink $tmpfn;

	restore_cleanup("$tmpdir/qmrestore.stat") if !$opts->{info};

	die $err;
    }

    rmtree $tmpdir;

    rename $tmpfn, $conffile ||
	die "unable to commit configuration file '$conffile'\n";
};


# Internal snapshots

# NOTE: Snapshot create/delete involves several non-atomic
# action, and can take a long time.
# So we try to avoid locking the file and use 'lock' variable
# inside the config file instead.

my $snapshot_copy_config = sub {
    my ($source, $dest) = @_;

    foreach my $k (keys %$source) {
	next if $k eq 'snapshots';
	next if $k eq 'snapstate';
	next if $k eq 'snaptime';
	next if $k eq 'vmstate';
	next if $k eq 'lock';
	next if $k eq 'digest';
	next if $k eq 'description';
	next if $k =~ m/^unused\d+$/;
		
	$dest->{$k} = $source->{$k};
    }
};

my $snapshot_apply_config = sub {
    my ($conf, $snap) = @_;

    # copy snapshot list
    my $newconf = {
	snapshots => $conf->{snapshots},
    };

    # keep description and list of unused disks
    foreach my $k (keys %$conf) {
	next if !($k =~ m/^unused\d+$/ || $k eq 'description');
	$newconf->{$k} = $conf->{$k};
    }

    &$snapshot_copy_config($snap, $newconf);

    return $newconf;
};

sub foreach_writable_storage {
    my ($conf, $func) = @_;

    my $sidhash = {};

    foreach my $ds (keys %$conf) {
	next if !valid_drivename($ds);

	my $drive = parse_drive($ds, $conf->{$ds});
	next if !$drive;
	next if drive_is_cdrom($drive);

	my $volid = $drive->{file};

	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	$sidhash->{$sid} = $sid if $sid;	
    }

    foreach my $sid (sort keys %$sidhash) {
	&$func($sid);
    }
}

my $alloc_vmstate_volid = sub {
    my ($storecfg, $vmid, $conf, $snapname) = @_;
    
    # Note: we try to be smart when selecting a $target storage

    my $target;

    # search shared storage first
    foreach_writable_storage($conf, sub {
	my ($sid) = @_;
	my $scfg = PVE::Storage::storage_config($storecfg, $sid);
	return if !$scfg->{shared};

	$target = $sid if !$target || $scfg->{path}; # prefer file based storage
    });

    if (!$target) {
	# now search local storage
	foreach_writable_storage($conf, sub {
	    my ($sid) = @_;
	    my $scfg = PVE::Storage::storage_config($storecfg, $sid);
	    return if $scfg->{shared};

	    $target = $sid if !$target || $scfg->{path}; # prefer file based storage;
	});
    }

    $target = 'local' if !$target;

    my $driver_state_size = 500; # assume 32MB is enough to safe all driver state;
    # we abort live save after $conf->{memory}, so we need at max twice that space
    my $size = $conf->{memory}*2 + $driver_state_size;

    my $name = "vm-$vmid-state-$snapname";
    my $scfg = PVE::Storage::storage_config($storecfg, $target);
    $name .= ".raw" if $scfg->{path}; # add filename extension for file base storage
    my $volid = PVE::Storage::vdisk_alloc($storecfg, $target, $vmid, 'raw', $name, $size*1024);

    return $volid;
};

my $snapshot_prepare = sub {
    my ($vmid, $snapname, $save_vmstate, $comment) = @_;

    my $snap;

    my $updatefn =  sub {

	my $conf = load_config($vmid);

	check_lock($conf);

	$conf->{lock} = 'snapshot';

	die "snapshot name '$snapname' already used\n" 
	    if defined($conf->{snapshots}->{$snapname}); 

	my $storecfg = PVE::Storage::config();

	foreach_drive($conf, sub {
	    my ($ds, $drive) = @_;

	    return if drive_is_cdrom($drive);
	    my $volid = $drive->{file};

	    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	    if ($storeid) {
		my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
		die "can't snapshot volume '$volid'\n"		
		    if !(($scfg->{path} && $volname =~ m/\.qcow2$/) ||
			 ($scfg->{type} eq 'nexenta') || 
			 ($scfg->{type} eq 'rbd') || 
			 ($scfg->{type} eq 'sheepdog'));
	    } elsif ($volid =~ m|^(/.+)$| && -e $volid) {
		die "snapshot device '$volid' is not possible\n";
	    } else {
		die "can't snapshot volume '$volid'\n";
	    }
	});


	$snap = $conf->{snapshots}->{$snapname} = {};

	if ($save_vmstate && check_running($vmid)) {
	    $snap->{vmstate} = &$alloc_vmstate_volid($storecfg, $vmid, $conf, $snapname);
	}

	&$snapshot_copy_config($conf, $snap);

	$snap->{snapstate} = "prepare";
	$snap->{snaptime} = time();
	$snap->{description} = $comment if $comment;

	update_config_nolock($vmid, $conf, 1);
    };

    lock_config($vmid, $updatefn);

    return $snap;
};

my $snapshot_commit = sub {
    my ($vmid, $snapname) = @_;

    my $updatefn = sub {

	my $conf = load_config($vmid);

	die "missing snapshot lock\n" 
	    if !($conf->{lock} && $conf->{lock} eq 'snapshot'); 

	my $snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap); 

	die "wrong snapshot state\n" 
	    if !($snap->{snapstate} && $snap->{snapstate} eq "prepare"); 
	
	delete $snap->{snapstate};
	delete $conf->{lock};

	my $newconf = &$snapshot_apply_config($conf, $snap);

	$newconf->{parent} = $snapname;

	update_config_nolock($vmid, $newconf, 1);
    };

    lock_config($vmid, $updatefn);
};

sub snapshot_rollback {
    my ($vmid, $snapname) = @_;

    my $snap;

    my $prepare = 1;

    my $storecfg = PVE::Storage::config();
 
    my $updatefn = sub {

	my $conf = load_config($vmid);

	$snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap); 

	die "unable to rollback to incomplete snapshot (snapstate = $snap->{snapstate})\n" 
	    if $snap->{snapstate};

	if ($prepare) {
	    check_lock($conf);
	    vm_stop($storecfg, $vmid, undef, undef, 5, undef, undef);
	}

	die "unable to rollback vm $vmid: vm is running\n"
	    if check_running($vmid);

	if ($prepare) {
	    $conf->{lock} = 'rollback';
	} else {
	    die "got wrong lock\n" if !($conf->{lock} && $conf->{lock} eq 'rollback');
	    delete $conf->{lock};
	}

	if (!$prepare) {
	    # copy snapshot config to current config
	    $conf = &$snapshot_apply_config($conf, $snap);
	    $conf->{parent} = $snapname;
	}

 	update_config_nolock($vmid, $conf, 1);

	if (!$prepare && $snap->{vmstate}) {
	    my $statefile = PVE::Storage::path($storecfg, $snap->{vmstate});
	    # fixme: this only forws for files currently
	    vm_start($storecfg, $vmid, $statefile);
	}

    };

    lock_config($vmid, $updatefn);
    
    foreach_drive($snap, sub {
	my ($ds, $drive) = @_;

	return if drive_is_cdrom($drive);

	my $volid = $drive->{file};
	my $device = "drive-$ds";

	PVE::Storage::volume_snapshot_rollback($storecfg, $volid, $snapname);
    });

    $prepare = 0;
    lock_config($vmid, $updatefn);
}

my $savevm_wait = sub {
    my ($vmid) = @_;

    for(;;) {
	my $stat = PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "query-savevm");
	if (!$stat->{status}) {
	    die "savevm not active\n";
	} elsif ($stat->{status} eq 'active') {
	    sleep(1);
	    next;
	} elsif ($stat->{status} eq 'completed') {
	    last;
	} else {
	    die "query-savevm returned status '$stat->{status}'\n";
	}
    }
};

sub snapshot_create {
    my ($vmid, $snapname, $save_vmstate, $freezefs, $comment) = @_;

    my $snap = &$snapshot_prepare($vmid, $snapname, $save_vmstate, $comment);

    $freezefs = $save_vmstate = 0 if !$snap->{vmstate}; # vm is not running

    my $drivehash = {};

    my $running = check_running($vmid);

    eval {
	# create internal snapshots of all drives

	my $storecfg = PVE::Storage::config();

	if ($running) {
	    if ($snap->{vmstate}) {
		my $path = PVE::Storage::path($storecfg, $snap->{vmstate});	
		vm_mon_cmd($vmid, "savevm-start", statefile => $path);
		&$savevm_wait($vmid);
	    } else {
		vm_mon_cmd($vmid, "savevm-start");
 	    }
	};

	qga_freezefs($vmid) if $running && $freezefs;
 
	foreach_drive($snap, sub {
	    my ($ds, $drive) = @_;

	    return if drive_is_cdrom($drive);

	    my $volid = $drive->{file};
	    my $device = "drive-$ds";

	    qemu_volume_snapshot($vmid, $device, $storecfg, $volid, $snapname);
	    $drivehash->{$ds} = 1;
       });
    };
    my $err = $@;

    eval { gqa_unfreezefs($vmid) if $running && $freezefs; };
    warn $@ if $@;

    eval { vm_mon_cmd($vmid, "savevm-end") if $running; };
    warn $@ if $@;

    if ($err) {
	warn "snapshot create failed: starting cleanup\n";
	eval { snapshot_delete($vmid, $snapname, 0, $drivehash); };
	warn $@ if $@;
	die $err;
    }

    &$snapshot_commit($vmid, $snapname);
}

# Note: $drivehash is only set when called from snapshot_create.
sub snapshot_delete {
    my ($vmid, $snapname, $force, $drivehash) = @_;

    my $prepare = 1;

    my $snap;
    my $unused = [];

    my $unlink_parent = sub {
	my ($confref, $new_parent) = @_;

	if ($confref->{parent} && $confref->{parent} eq $snapname) {
	    if ($new_parent) {
		$confref->{parent} = $new_parent;
	    } else {
		delete $confref->{parent};
	    }
	}
    };
 
    my $updatefn =  sub {
	my ($remove_drive) = @_;

	my $conf = load_config($vmid);

	check_lock($conf) if !$drivehash;

	$snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap); 

	# remove parent refs
	&$unlink_parent($conf, $snap->{parent});
	foreach my $sn (keys %{$conf->{snapshots}}) {
	    next if $sn eq $snapname;
	    &$unlink_parent($conf->{snapshots}->{$sn}, $snap->{parent});
	}

	if ($remove_drive) {
	    if ($remove_drive eq 'vmstate') {
		delete $snap->{$remove_drive};
	    } else {
		my $drive = parse_drive($remove_drive, $snap->{$remove_drive});
		my $volid = $drive->{file};
		delete $snap->{$remove_drive};
		add_unused_volume($conf, $volid);
	    }
	}

	if ($prepare) {
	    $snap->{snapstate} = 'delete';
	} else {
	    delete $conf->{snapshots}->{$snapname};
	    delete $conf->{lock} if $drivehash;
	    foreach my $volid (@$unused) {
		add_unused_volume($conf, $volid);
	    }
	}

	update_config_nolock($vmid, $conf, 1);
    };

    lock_config($vmid, $updatefn);

    # now remove vmstate file

    my $storecfg = PVE::Storage::config();

    if ($snap->{vmstate}) {
	eval {  PVE::Storage::vdisk_free($storecfg, $snap->{vmstate}); };
	if (my $err = $@) {
	    die $err if !$force;
	    warn $err;
	}
	# save changes (remove vmstate from snapshot)
	lock_config($vmid, $updatefn, 'vmstate') if !$force;
    };

    # now remove all internal snapshots
    foreach_drive($snap, sub {
	my ($ds, $drive) = @_;

	return if drive_is_cdrom($drive);

	my $volid = $drive->{file};
	my $device = "drive-$ds";

	if (!$drivehash || $drivehash->{$ds}) {
	    eval { qemu_volume_snapshot_delete($vmid, $device, $storecfg, $volid, $snapname); };
	    if (my $err = $@) {
		die $err if !$force;
		warn $err;
	    }
	}

	# save changes (remove drive fron snapshot)
	lock_config($vmid, $updatefn, $ds) if !$force;
	push @$unused, $volid;
    });

    # now cleanup config
    $prepare = 0;
    lock_config($vmid, $updatefn);
}

1;
