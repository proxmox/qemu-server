package PVE::QemuServer;

use strict;
use warnings;
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
use PVE::Tools qw(run_command lock_file lock_file_full file_read_firstline dir_glob_foreach);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);
use PVE::INotify;
use PVE::ProcFSTools;
use PVE::QMPClient;
use PVE::RPCEnvironment;
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
        type => 'string', format => 'pve-hotplug-features',
        description => "Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Value '1' is an alias for the default 'network,disk,usb'.",
        default => 'network,disk,usb',
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
        description => "Amount of target RAM for the VM in MB. Using zero disables the ballon driver.",
	minimum => 0,
    },
    shares => {
        optional => 1,
        type => 'integer',
        description => "Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning",
	minimum => 0,
	maximum => 50000,
	default => 1000,
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
	enum => [qw(lsi lsi53c810 virtio-scsi-pci virtio-scsi-single megasas pvscsi)],
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
        enum => [qw(other wxp w2k w2k3 w2k8 wvista win7 win8 l24 l26 solaris)],
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
solaris => solaris/opensolaris/openindiania kernel

other|l24|l26|solaris                       ... no special behaviour
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
    numa => {
	optional => 1,
	type => 'boolean',
	description => "Enable/disable Numa.",
	default => 0,
    },
    vcpus => {
	optional => 1,
	type => 'integer',
	description => "Number of hotplugged vcpus.",
	minimum => 1,
	default => 0,
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
	description => "Select VGA type. If you want to use high resolution modes (>= 1280x1024x16) then you should use option 'std' or 'vmware'. Default is 'std' for win8/win7/w2k8, and 'cirrur' for other OS types. Option 'qxl' enables the SPICE display sever. You can also run without any graphic card using a serial devive as terminal.",
	enum => [qw(std cirrus vmware qxl serial0 serial1 serial2 serial3 qxl2 qxl3 qxl4)],
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
    template => {
	optional => 1,
	type => 'boolean',
	description => "Enable/disable Template.",
	default => 0,
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
	description => "Enable/disable the usb tablet device. This device is usually needed to allow absolute mouse positioning with VNC. Else the mouse runs out of sync with normal VNC clients. If you're running lots of console-only guests on one host, you may consider disabling this to save some context switches. This is turned of by default if you use spice (vga=qxl).",
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
	type => 'number',
	description => "Set maximum tolerated downtime (in seconds) for migrations.",
	minimum => 0,
	default => 0.1,
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
	enum => [ qw(486 athlon pentium pentium2 pentium3 coreduo core2duo kvm32 kvm64 qemu32 qemu64 phenom Conroe Penryn Nehalem Westmere SandyBridge IvyBridge Haswell Broadwell Opteron_G1 Opteron_G2 Opteron_G3 Opteron_G4 Opteron_G5 host) ],
	default => 'kvm64',
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
    machine => {
	description => "Specific the Qemu machine type.",
	type => 'string',
	pattern => '(pc|pc(-i440fx)?-\d+\.\d+|q35|pc-q35-\d+\.\d+)',
	maxLength => 40,
	optional => 1,
    },
    smbios1 => {
	description => "Specify SMBIOS type 1 fields.",
	type => 'string', format => 'pve-qm-smbios1',
	typetext => "[manufacturer=str][,product=str][,version=str][,serial=str] [,uuid=uuid][,sku=str][,family=str]",
	maxLength => 256,
	optional => 1,
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
my $MAX_HOSTPCI_DEVICES = 4;
my $MAX_SERIAL_PORTS = 4;
my $MAX_PARALLEL_PORTS = 3;
my $MAX_NUMA = 8;
my $MAX_MEM = 4194304;
my $STATICMEM = 1024;

my $numadesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-numanode',
    typetext => "cpus=<id[-id],memory=<mb>[[,hostnodes=<id[-id]>] [,policy=<preferred|bind|interleave>]]",
    description => "numa topology",
};
PVE::JSONSchema::register_standard_option("pve-qm-numanode", $numadesc);

for (my $i = 0; $i < $MAX_NUMA; $i++)  {
    $confdesc->{"numa$i"} = $numadesc;
}

my $nic_model_list = ['rtl8139', 'ne2k_pci', 'e1000',  'pcnet',  'virtio',
		      'ne2k_isa', 'i82551', 'i82557b', 'i82559er', 'vmxnet3',
		      'e1000-82540em', 'e1000-82544gc', 'e1000-82545em'];
my $nic_model_list_txt = join(' ', sort @$nic_model_list);

my $netdesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-net',
    typetext => "MODEL=XX:XX:XX:XX:XX:XX [,bridge=<dev>][,queues=<nbqueues>][,rate=<mbps>] [,tag=<vlanid>][,firewall=0|1],link_down=0|1]",
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
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads] [,discard=ignore|on]',
    description => "Use volume as IDE hard disk or CD-ROM (n is 0 to " .($MAX_IDE_DISKS -1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-ide", $idedesc);

my $scsidesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads] [,discard=ignore|on]',
    description => "Use volume as SCSI hard disk or CD-ROM (n is 0 to " . ($MAX_SCSI_DISKS - 1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-scsi", $scsidesc);

my $satadesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads]  [,discard=ignore|on]',
    description => "Use volume as SATA hard disk or CD-ROM (n is 0 to " . ($MAX_SATA_DISKS - 1). ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-sata", $satadesc);

my $virtiodesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-drive',
    typetext => '[volume=]volume,] [,media=cdrom|disk] [,cyls=c,heads=h,secs=s[,trans=t]] [,snapshot=on|off] [,cache=none|writethrough|writeback|unsafe|directsync] [,format=f] [,backup=yes|no] [,rerror=ignore|report|stop] [,werror=enospc|ignore|report|stop] [,aio=native|threads]  [,discard=ignore|on] [,iothread=on]',
    description => "Use volume as VIRTIO hard disk (n is 0 to " . ($MAX_VIRTIO_DISKS - 1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-virtio", $virtiodesc);

my $usbdesc = {
    optional => 1,
    type => 'string', format => 'pve-qm-usb-device',
    typetext => 'host=HOSTUSBDEVICE|spice',
    description => <<EODESCR,
Configure an USB device (n is 0 to 4). This can be used to
pass-through usb devices to the guest. HOSTUSBDEVICE syntax is:

'bus-port(.port)*' (decimal numbers) or
'vendor_id:product_id' (hexadeciaml numbers)

You can use the 'lsusb -t' command to list existing usb devices.

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

The value 'spice' can be used to add a usb redirection devices for spice.

EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-usb", $usbdesc);

my $hostpcidesc = {
        optional => 1,
        type => 'string', format => 'pve-qm-hostpci',
        typetext => "[host=]HOSTPCIDEVICE [,driver=kvm|vfio] [,rombar=on|off] [,pcie=0|1] [,x-vga=on|off]",
        description => <<EODESCR,
Map host pci devices. HOSTPCIDEVICE syntax is:

'bus:dev.func' (hexadecimal numbers)

You can us the 'lspci' command to list existing pci devices.

The 'rombar' option determines whether or not the device's ROM will be visible in the guest's memory map (default is 'on').

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

Experimental: user reported problems with this option.
EODESCR
};
PVE::JSONSchema::register_standard_option("pve-qm-hostpci", $hostpcidesc);

my $serialdesc = {
	optional => 1,
	type => 'string',
	pattern => '(/dev/.+|socket)',
	description =>  <<EODESCR,
Create a serial device inside the VM (n is 0 to 3), and pass through a host serial device (i.e. /dev/ttyS0), or create a unix socket on the host side (use 'qm terminal' to open a terminal connection).

Note: This option allows direct access to host hardware. So it is no longer possible to migrate such machines - use with special care.

Experimental: user reported problems with this option.
EODESCR
};

my $paralleldesc= {
	optional => 1,
	type => 'string',
        pattern => '/dev/parport\d+|/dev/usb/lp\d+',
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

    if ($tmp =~ m/^QEMU( PC)? emulator version (\d+\.\d+(\.\d+)?)[,\s]/) {
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

sub parse_hotplug_features {
    my ($data) = @_;

    my $res = {};

    return $res if $data eq '0';
    
    $data = $confdesc->{hotplug}->{default} if $data eq '1';

    foreach my $feature (PVE::Tools::split_list($data)) {
	if ($feature =~ m/^(network|disk|cpu|memory|usb)$/) {
	    $res->{$1} = 1;
	} else {
	    warn "ignoring unknown hotplug feature '$feature'\n";
	}
    }
    return $res;
}

PVE::JSONSchema::register_format('pve-hotplug-features', \&pve_verify_hotplug_features);
sub pve_verify_hotplug_features {
    my ($value, $noerr) = @_;

    return $value if parse_hotplug_features($value);

    return undef if $noerr;

    die "unable to parse hotplug option\n";
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
#        [,aio=native|threads][,discard=ignore|on][,iothread=on]

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

	if ($p =~ m/^(file|volume|cyls|heads|secs|trans|media|snapshot|cache|format|rerror|werror|backup|aio|bps|mbps|mbps_max|bps_rd|mbps_rd|mbps_rd_max|bps_wr|mbps_wr|mbps_wr_max|iops|iops_max|iops_rd|iops_rd_max|iops_wr|iops_wr_max|size|discard|iothread)=(.+)$/) {
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

    if($res->{file} =~ m/\.(raw|cow|qcow|qcow2|vmdk|cloop)$/){
	$res->{format} = $1;
    }

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
    return undef if $res->{discard} && $res->{discard} !~ m/^(ignore|on)$/;
    return undef if $res->{iothread} && $res->{iothread} !~ m/^(on)$/;

    return undef if $res->{mbps_rd} && $res->{mbps};
    return undef if $res->{mbps_wr} && $res->{mbps};

    return undef if $res->{mbps} && $res->{mbps} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_max} && $res->{mbps_max} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_rd} && $res->{mbps_rd} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_rd_max} && $res->{mbps_rd_max} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_wr} && $res->{mbps_wr} !~ m/^\d+(\.\d+)?$/;
    return undef if $res->{mbps_wr_max} && $res->{mbps_wr_max} !~ m/^\d+(\.\d+)?$/;

    return undef if $res->{iops_rd} && $res->{iops};
    return undef if $res->{iops_wr} && $res->{iops};


    return undef if $res->{iops} && $res->{iops} !~ m/^\d+$/;
    return undef if $res->{iops_max} && $res->{iops_max} !~ m/^\d+$/;
    return undef if $res->{iops_rd} && $res->{iops_rd} !~ m/^\d+$/;
    return undef if $res->{iops_rd_max} && $res->{iops_rd_max} !~ m/^\d+$/;
    return undef if $res->{iops_wr} && $res->{iops_wr} !~ m/^\d+$/;
    return undef if $res->{iops_wr_max} && $res->{iops_wr_max} !~ m/^\d+$/;


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

my @qemu_drive_options = qw(heads secs cyls trans media format cache snapshot rerror werror aio discard iops iops_rd iops_wr iops_max iops_rd_max iops_wr_max);

sub print_drive {
    my ($vmid, $drive) = @_;

    my $opts = '';
    foreach my $o (@qemu_drive_options, 'mbps', 'mbps_rd', 'mbps_wr', 'mbps_max', 'mbps_rd_max', 'mbps_wr_max', 'backup', 'iothread') {
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
    my $cmd = pack("C x3 C x1", 0x12, 36);

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
    (my $byte0, my $byte1, $res->{vendor},
     $res->{product}, $res->{revision}) = unpack("C C x6 A8 A16 A4", $buf);

    $res->{removable} = $byte1 & 128 ? 1 : 0;
    $res->{type} = $byte0 & 31;

    return $res;
}

sub path_is_scsi {
    my ($path) = @_;

    my $fh = IO::File->new("+<$path") || return undef;
    my $res = scsi_inquiry($fh, 1);
    close($fh);

    return $res;
}

sub machine_type_is_q35 {
    my ($conf) = @_;

    return $conf->{machine} && ($conf->{machine} =~ m/q35/) ? 1 : 0;
}

sub print_tabletdevice_full {
    my ($conf) = @_;

    my $q35 = machine_type_is_q35($conf);

    # we use uhci for old VMs because tablet driver was buggy in older qemu
    my $usbbus = $q35 ? "ehci" : "uhci";

    return "usb-tablet,id=tablet,bus=$usbbus.0,port=1";
}

sub print_drivedevice_full {
    my ($storecfg, $conf, $vmid, $drive, $bridges) = @_;

    my $device = '';
    my $maxdev = 0;

    if ($drive->{interface} eq 'virtio') {
	my $pciaddr = print_pci_addr("$drive->{interface}$drive->{index}", $bridges);
	$device = "virtio-blk-pci,drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}$pciaddr";
	$device .= ",iothread=iothread-$drive->{interface}$drive->{index}" if $drive->{iothread};
    } elsif ($drive->{interface} eq 'scsi') {
	if ($conf->{scsihw} && ($conf->{scsihw} =~ m/^lsi/)) {
	    $maxdev = 7;
	} elsif ($conf->{scsihw} && ($conf->{scsihw} =~ m/^virtio-scsi-single/)) {
	    $maxdev = 1;
	} else {
	    $maxdev = 256;
	}

	my $controller = int($drive->{index} / $maxdev);
        my $controller_prefix = ($conf->{scsihw} && $conf->{scsihw} =~ m/^virtio-scsi-single/) ? "virtioscsi" : "scsihw";

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
	      } else {
		  if (my $info = path_is_scsi($path)) {
		      if ($info->{type} == 0) {
			  $devicetype = 'block';
		      } elsif ($info->{type} == 1) { # tape
			  $devicetype = 'generic';
		      }
		  }
	      }
         }

        if (!$conf->{scsihw} || ($conf->{scsihw} =~ m/^lsi/)){
            $device = "scsi-$devicetype,bus=$controller_prefix$controller.0,scsi-id=$unit,drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}";
        } else {
            $device = "scsi-$devicetype,bus=$controller_prefix$controller.0,channel=0,scsi-id=0,lun=$drive->{index},drive=drive-$drive->{interface}$drive->{index},id=$drive->{interface}$drive->{index}";
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

sub get_initiator_name {
    my $initiator;

    my $fh = IO::File->new('/etc/iscsi/initiatorname.iscsi') || return undef;
    while (defined(my $line = <$fh>)) {
	next if $line !~ m/^\s*InitiatorName\s*=\s*([\.\-:\w]+)/;
	$initiator = $1;
	last;
    }
    $fh->close();

    return $initiator;
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
    }

    $opts .= ",cache=none" if !$drive->{cache} && !drive_is_cdrom($drive);

    my $detectzeroes = $drive->{discard} ? "unmap" : "on";
    $opts .= ",detect-zeroes=$detectzeroes" if !drive_is_cdrom($drive);

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

    my $pciaddr = print_pci_addr("$netid", $bridges);
    my $tmpstr = "$device,mac=$net->{macaddr},netdev=$netid$pciaddr,id=$netid";
    if ($net->{queues} && $net->{queues} > 1 && $net->{model} eq 'virtio'){
	#Consider we have N queues, the number of vectors needed is 2*N + 2 (plus one config interrupt and control vq)
	my $vectors = $net->{queues} * 2 + 2;
	$tmpstr .= ",vectors=$vectors,mq=on";
    }
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

    my $netdev = "";

    if ($net->{bridge}) {
        $netdev = "type=tap,id=$netid,ifname=${ifname},script=/var/lib/qemu-server/pve-bridge,downscript=/var/lib/qemu-server/pve-bridgedown$vhostparam";
    } else {
        $netdev = "type=user,id=$netid,hostname=$vmname";
    }

    $netdev .= ",queues=$net->{queues}" if ($net->{queues} && $net->{model} eq 'virtio');

    return $netdev;
}

sub drive_is_cdrom {
    my ($drive) = @_;

    return $drive && $drive->{media} && ($drive->{media} eq 'cdrom');

}

sub parse_numa {
    my ($data) = @_;

    my $res = {};

    foreach my $kvp (split(/,/, $data)) {

	if ($kvp =~ m/^memory=(\S+)$/) {
	    $res->{memory} = $1;
	} elsif ($kvp =~ m/^policy=(preferred|bind|interleave)$/) {
	    $res->{policy} = $1;
	} elsif ($kvp =~ m/^cpus=(\d+)(-(\d+))?$/) {
	    $res->{cpus}->{start} = $1;
	    $res->{cpus}->{end} = $3;
	} elsif ($kvp =~ m/^hostnodes=(\d+)(-(\d+))?$/) {
	    $res->{hostnodes}->{start} = $1;
	    $res->{hostnodes}->{end} = $3;
	} else {
	    return undef;
	}
    }

    return $res;
}

sub parse_hostpci {
    my ($value) = @_;

    return undef if !$value;


    my @list = split(/,/, $value);
    my $found;

    my $res = {};
    foreach my $kv (@list) {

	if ($kv =~ m/^(host=)?([a-f0-9]{2}:[a-f0-9]{2})(\.([a-f0-9]))?$/) {
	    $found = 1;
	    if(defined($4)){
		push @{$res->{pciid}}, { id => $2 , function => $4};

	    }else{
		my $pcidevices = lspci($2);
	        $res->{pciid} = $pcidevices->{$2};
	    }
	} elsif ($kv =~ m/^driver=(kvm|vfio)$/) {
	    $res->{driver} = $1;
	} elsif ($kv =~ m/^rombar=(on|off)$/) {
	    $res->{rombar} = $1;
	} elsif ($kv =~ m/^x-vga=(on|off)$/) {
	    $res->{'x-vga'} = $1;
	} elsif ($kv =~ m/^pcie=(\d+)$/) {
	    $res->{pcie} = 1 if $1 == 1;
	} else {
	    warn "unknown hostpci setting '$kv'\n";
	}
    }

    return undef if !$found;

    return $res;
}

# netX: e1000=XX:XX:XX:XX:XX:XX,bridge=vmbr0,rate=<mbps>
sub parse_net {
    my ($data) = @_;

    my $res = {};

    foreach my $kvp (split(/,/, $data)) {

	if ($kvp =~ m/^(ne2k_pci|e1000|e1000-82540em|e1000-82544gc|e1000-82545em|rtl8139|pcnet|virtio|ne2k_isa|i82551|i82557b|i82559er|vmxnet3)(=([0-9a-f]{2}(:[0-9a-f]{2}){5}))?$/i) {
	    my $model = lc($1);
	    my $mac = defined($3) ? uc($3) : PVE::Tools::random_ether_addr();
	    $res->{model} = $model;
	    $res->{macaddr} = $mac;
	} elsif ($kvp =~ m/^bridge=(\S+)$/) {
	    $res->{bridge} = $1;
	} elsif ($kvp =~ m/^queues=(\d+)$/) {
	    $res->{queues} = $1;
	} elsif ($kvp =~ m/^rate=(\d+(\.\d+)?)$/) {
	    $res->{rate} = $1;
        } elsif ($kvp =~ m/^tag=(\d+)$/) {
            $res->{tag} = $1;
        } elsif ($kvp =~ m/^firewall=([01])$/) {
	    $res->{firewall} = $1;
	} elsif ($kvp =~ m/^link_down=([01])$/) {
	    $res->{link_down} = $1;
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
    $res .= ",firewall=1" if $net->{firewall};
    $res .= ",link_down=1" if $net->{link_down};
    $res .= ",queues=$net->{queues}" if $net->{queues};

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

sub vm_is_volid_owner {
    my ($storecfg, $vmid, $volid) = @_;

    if ($volid !~  m|^/|) {
	my ($path, $owner);
	eval { ($path, $owner) = PVE::Storage::path($storecfg, $volid); };
	if ($owner && ($owner == $vmid)) {
	    return 1;
	}
    }

    return undef;
}

sub vmconfig_delete_pending_option {
    my ($conf, $key) = @_;

    delete $conf->{pending}->{$key};
    my $pending_delete_hash = { $key => 1 };
    foreach my $opt (PVE::Tools::split_list($conf->{pending}->{delete})) {
	$pending_delete_hash->{$opt} = 1;
    }
    $conf->{pending}->{delete} = join(',', keys %$pending_delete_hash);
}

sub vmconfig_undelete_pending_option {
    my ($conf, $key) = @_;

    my $pending_delete_hash = {};
    foreach my $opt (PVE::Tools::split_list($conf->{pending}->{delete})) {
	$pending_delete_hash->{$opt} = 1;
    }
    delete $pending_delete_hash->{$key};

    my @keylist = keys %$pending_delete_hash;
    if (scalar(@keylist)) {
	$conf->{pending}->{delete} = join(',', @keylist);
    } else {
	delete $conf->{pending}->{delete};
    }
}

sub vmconfig_register_unused_drive {
    my ($storecfg, $vmid, $conf, $drive) = @_;

    if (!drive_is_cdrom($drive)) {
	my $volid = $drive->{file};
	if (vm_is_volid_owner($storecfg, $vmid, $volid)) {
	    add_unused_volume($conf, $volid, $vmid);
	}
    }
}

sub vmconfig_cleanup_pending {
    my ($conf) = @_;

    # remove pending changes when nothing changed
    my $changes;
    foreach my $opt (keys %{$conf->{pending}}) {
	if (defined($conf->{$opt}) && ($conf->{pending}->{$opt} eq  $conf->{$opt})) {
	    $changes = 1;
	    delete $conf->{pending}->{$opt};
	}
    }

    # remove delete if option is not set
    my $pending_delete_hash = {};
    foreach my $opt (PVE::Tools::split_list($conf->{pending}->{delete})) {
	if (defined($conf->{$opt})) {
	    $pending_delete_hash->{$opt} = 1;
	} else {
	    $changes = 1;
	}
    }

    my @keylist = keys %$pending_delete_hash;
    if (scalar(@keylist)) {
	$conf->{pending}->{delete} = join(',', @keylist);
    } else {
	delete $conf->{pending}->{delete};
    }

    return $changes;
}

my $valid_smbios1_options = {
    manufacturer => '\S+',
    product => '\S+',
    version => '\S+',
    serial => '\S+',
    uuid => '[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',
    sku => '\S+',
    family => '\S+',
};

# smbios: [manufacturer=str][,product=str][,version=str][,serial=str][,uuid=uuid][,sku=str][,family=str]
sub parse_smbios1 {
    my ($data) = @_;

    my $res = {};

    foreach my $kvp (split(/,/, $data)) {
	return undef if $kvp !~ m/^(\S+)=(.+)$/;
	my ($k, $v) = split(/=/, $kvp);
	return undef if !defined($k) || !defined($v);
	return undef if !$valid_smbios1_options->{$k};
	return undef if $v !~ m/^$valid_smbios1_options->{$k}$/;
	$res->{$k} = $v;
    }

    return $res;
}

sub print_smbios1 {
    my ($smbios1) = @_;

    my $data = '';
    foreach my $k (keys %$smbios1) {
	next if !defined($smbios1->{$k});
	next if !$valid_smbios1_options->{$k};
	$data .= ',' if $data;
	$data .= "$k=$smbios1->{$k}";
    }
    return $data;
}

PVE::JSONSchema::register_format('pve-qm-smbios1', \&verify_smbios1);
sub verify_smbios1 {
    my ($value, $noerr) = @_;

    return $value if parse_smbios1($value);

    return undef if $noerr;

    die "unable to parse smbios (type 1) options\n";
}

PVE::JSONSchema::register_format('pve-qm-bootdisk', \&verify_bootdisk);
sub verify_bootdisk {
    my ($value, $noerr) = @_;

    return $value if valid_drivename($value);

    return undef if $noerr;

    die "invalid boot disk '$value'\n";
}

PVE::JSONSchema::register_format('pve-qm-numanode', \&verify_numa);
sub verify_numa {
    my ($value, $noerr) = @_;

    return $value if parse_numa($value);

    return undef if $noerr;

    die "unable to parse numa options\n";
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
	} elsif ($v =~ m/^spice$/) {
	    $found = 1;
	    $res->{spice} = 1;
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
    } elsif ($type eq 'number') {
        return $value if $value =~ m/^(\d+)(\.\d+)?$/;
        die "type check ('number') failed - got '$value'\n";
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

sub lock_config_mode {
    my ($vmid, $timeout, $shared, $code, @param) = @_;

    my $filename = config_file_lock($vmid);

    my $res = lock_file_full($filename, $timeout, $shared, $code, @param);

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
	pending => {},
    };

    $filename =~ m|/qemu-server/(\d+)\.conf$|
	|| die "got strange filename '$filename'";

    my $vmid = $1;

    my $conf = $res;
    my $descr = '';
    my $section = '';

    my @lines = split(/\n/, $raw);
    foreach my $line (@lines) {
	next if $line =~ m/^\s*$/;

	if ($line =~ m/^\[PENDING\]\s*$/i) {
	    $section = 'pending';
	    $conf->{description} = $descr if $descr;
	    $descr = '';
	    $conf = $res->{$section} = {};
	    next;

	} elsif ($line =~ m/^\[([a-z][a-z0-9_\-]+)\]\s*$/i) {
	    $section = $1;
	    $conf->{description} = $descr if $descr;
	    $descr = '';
	    $conf = $res->{snapshots}->{$section} = {};
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
	} elsif ($line =~ m/^delete:\s*(.*\S)\s*$/) {
	    my $value = $1;
	    if ($section eq 'pending') {
		$conf->{delete} = $value; # we parse this later
	    } else {
		warn "vm $vmid - propertry 'delete' is only allowed in [PENDING]\n";
	    }
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
	my ($cref, $pending, $snapname) = @_;

	foreach my $key (keys %$cref) {
	    next if $key eq 'digest' || $key eq 'description' || $key eq 'snapshots' ||
		$key eq 'snapstate' || $key eq 'pending';
	    my $value = $cref->{$key};
	    if ($key eq 'delete') {
		die "propertry 'delete' is only allowed in [PENDING]\n"
		    if !$pending;
		# fixme: check syntax?
		next;
	    }
	    eval { $value = check_type($key, $value); };
	    die "unable to parse value of '$key' - $@" if $@;

	    $cref->{$key} = $value;

	    if (!$snapname && valid_drivename($key)) {
		my $drive = parse_drive($key, $value);
		$used_volids->{$drive->{file}} = 1 if $drive && $drive->{file};
	    }
	}
    };

    &$cleanup_config($conf);

    &$cleanup_config($conf->{pending}, 1);

    foreach my $snapname (keys %{$conf->{snapshots}}) {
	die "internal error" if $snapname eq 'pending';
	&$cleanup_config($conf->{snapshots}->{$snapname}, undef, $snapname);
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
	    next if $key eq 'digest' || $key eq 'description' || $key eq 'pending' || $key eq 'snapshots';
	    $raw .= "$key: $conf->{$key}\n";
	}
	return $raw;
    };

    my $raw = &$generate_raw_config($conf);

    if (scalar(keys %{$conf->{pending}})){
	$raw .= "\n[PENDING]\n";
	$raw .= &$generate_raw_config($conf->{pending});
    }

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
	next if $k =~ m/^usb/ && ($conf->{$k} eq 'spice');
	$loc_res = 1 if $k =~ m/^(usb|hostpci|serial|parallel)\d+$/;
    }

    die "VM uses local resources\n" if $loc_res && !$noerr;

    return $loc_res;
}

# check if used storages are available on all nodes (use by migrate)
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

# list nodes where all VM images are available (used by has_feature API)
sub shared_nodes {
    my ($conf, $storecfg) = @_;

    my $nodelist = PVE::Cluster::get_nodelist();
    my $nodehash = { map { $_ => 1 } @$nodelist };
    my $nodename = PVE::INotify::nodename();

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	my $volid = $drive->{file};
	return if !$volid;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	if ($storeid) {
	    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	    if ($scfg->{disable}) {
		$nodehash = {};
	    } elsif (my $avail = $scfg->{nodes}) {
		foreach my $node (keys %$nodehash) {
		    delete $nodehash->{$node} if !$avail->{$node};
		}
	    } elsif (!$scfg->{shared}) {
		foreach my $node (keys %$nodehash) {
		    delete $nodehash->{$node} if $node ne $nodename
		}
	    }
	}
    });

    return $nodehash
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
	return if !$cmd || ($cmd !~ m|kvm$| && $cmd !~ m|qemu-system-x86_64$|);

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
	$d->{cpus} = $conf->{vcpus} if $conf->{vcpus};

	$d->{name} = $conf->{name} || "VM $vmid";
	$d->{maxmem} = $conf->{memory} ? $conf->{memory}*(1024*1024) : 0;

	if ($conf->{balloon}) {
	    $d->{balloon_min} = $conf->{balloon}*(1024*1024);
	    $d->{shares} = defined($conf->{shares}) ? $conf->{shares} : 1000;
	}

	$d->{uptime} = 0;
	$d->{cpu} = 0;
	$d->{mem} = 0;

	$d->{netout} = 0;
	$d->{netin} = 0;

	$d->{diskread} = 0;
	$d->{diskwrite} = 0;

        $d->{template} = is_template($conf);

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

    my $ballooncb = sub {
	my ($vmid, $resp) = @_;

	my $info = $resp->{'return'};
	return if !$info->{max_mem};

	my $d = $res->{$vmid};

	# use memory assigned to VM
	$d->{maxmem} = $info->{max_mem};
	$d->{balloon} = $info->{actual};

	if (defined($info->{total_mem}) && defined($info->{free_mem})) {
	    $d->{mem} = $info->{total_mem} - $info->{free_mem};
	    $d->{freemem} = $info->{free_mem};
	}

    };

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
	# this fails if ballon driver is not loaded, so this must be
	# the last commnand (following command are aborted if this fails).
	$qmpclient->queue_cmd($vmid, $ballooncb, 'query-balloon');

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

    $qmpclient->queue_execute(undef, 1);

    foreach my $vmid (keys %$list) {
	next if $opt_vmid && ($vmid ne $opt_vmid);
	$res->{$vmid}->{qmpstatus} = $res->{$vmid}->{status} if !$res->{$vmid}->{qmpstatus};
    }

    return $res;
}

sub foreach_dimm {
    my ($conf, $vmid, $memory, $sockets, $func) = @_;

    my $dimm_id = 0;
    my $current_size = 1024;
    my $dimm_size = 512;
    return if $current_size == $memory;

    for (my $j = 0; $j < 8; $j++) {
	for (my $i = 0; $i < 32; $i++) {
	    my $name = "dimm${dimm_id}";
	    $dimm_id++;
	    my $numanode = $i % $sockets;
	    $current_size += $dimm_size;
	    &$func($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory);
	    return  $current_size if $current_size >= $memory;
	}
	$dimm_size *= 2;
    }
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

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;
	&$test_volid($drive->{file}, drive_is_cdrom($drive));
    });

    foreach my $snapname (keys %{$conf->{snapshots}}) {
	my $snap = $conf->{snapshots}->{$snapname};
	&$test_volid($snap->{vmstate}, 0);
	foreach_drive($snap, sub {
	    my ($ds, $drive) = @_;
	    &$test_volid($drive->{file}, drive_is_cdrom($drive));
        });
    }

    foreach my $volid (keys %$volhash) {
	&$func($volid, $volhash->{$volid});
    }
}

sub vga_conf_has_spice {
    my ($vga) = @_;

    return 0 if !$vga || $vga !~ m/^qxl([234])?$/;

    return $1 || 1;
}

sub config_to_command {
    my ($storecfg, $vmid, $conf, $defaults, $forcemachine) = @_;

    my $cmd = [];
    my $globalFlags = [];
    my $machineFlags = [];
    my $rtcFlags = [];
    my $cpuFlags = [];
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

    my $q35 = machine_type_is_q35($conf);
    my $hotplug_features = parse_hotplug_features(defined($conf->{hotplug}) ? $conf->{hotplug} : '1');
    my $machine_type = $forcemachine || $conf->{machine};

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

    if ($conf->{smbios1}) {
	push @$cmd, '-smbios', "type=1,$conf->{smbios1}";
    }

    if ($q35) {
	# the q35 chipset support native usb2, so we enable usb controller
	# by default for this machine type
        push @$devices, '-readconfig', '/usr/share/qemu-server/pve-q35.cfg';
    } else {
        $pciaddr = print_pci_addr("piix3", $bridges);
        push @$devices, '-device', "piix3-usb-uhci,id=uhci$pciaddr.0x2";

        my $use_usb2 = 0;
	for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	    next if !$conf->{"usb$i"};
	    $use_usb2 = 1;
	}
	# include usb device config
	push @$devices, '-readconfig', '/usr/share/qemu-server/pve-usb.cfg' if $use_usb2;
    }

    my $vga = $conf->{vga};

    my $qxlnum = vga_conf_has_spice($vga);
    $vga = 'qxl' if $qxlnum;

    if (!$vga) {
	if ($conf->{ostype} && ($conf->{ostype} eq 'win8' ||
				$conf->{ostype} eq 'win7' ||
				$conf->{ostype} eq 'w2k8')) {
	    $vga = 'std';
	} else {
	    $vga = 'cirrus';
	}
    }

    # enable absolute mouse coordinates (needed by vnc)
    my $tablet;
    if (defined($conf->{tablet})) {
	$tablet = $conf->{tablet};
    } else {
	$tablet = $defaults->{tablet};
	$tablet = 0 if $qxlnum; # disable for spice because it is not needed
	$tablet = 0 if $vga =~ m/^serial\d+$/; # disable if we use serial terminal (no vga card)
    }

    push @$devices, '-device', print_tabletdevice_full($conf) if $tablet;

    # host pci devices
    for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
	my $d = parse_hostpci($conf->{"hostpci$i"});
	next if !$d;

	my $pcie = $d->{pcie};
	if($pcie){
	    die "q35 machine model is not enabled" if !$q35;
	    $pciaddr = print_pcie_addr("hostpci$i");
	}else{
	    $pciaddr = print_pci_addr("hostpci$i", $bridges);
	}

	my $rombar = $d->{rombar} && $d->{rombar} eq 'off' ? ",rombar=0" : "";
	my $driver = $d->{driver} && $d->{driver} eq 'vfio' ? "vfio-pci" : "pci-assign";
	my $xvga = $d->{'x-vga'} && $d->{'x-vga'} eq 'on' ? ",x-vga=on" : "";
	if ($xvga && $xvga ne '') {
	    push @$cpuFlags, 'kvm=off';
	    $vga = 'none';
	}
	$driver = "vfio-pci" if $xvga ne '';
	my $pcidevices = $d->{pciid};
	my $multifunction = 1 if @$pcidevices > 1;

	my $j=0;
        foreach my $pcidevice (@$pcidevices) {

	    my $id = "hostpci$i";
	    $id .= ".$j" if $multifunction;
	    my $addr = $pciaddr;
	    $addr .= ".$j" if $multifunction;
	    my $devicestr = "$driver,host=$pcidevice->{id}.$pcidevice->{function},id=$id$addr";

	    if($j == 0){
		$devicestr .= "$rombar$xvga";
		$devicestr .= ",multifunction=on" if $multifunction;
	    }

	    push @$devices, '-device', $devicestr;
	    $j++;
	}
    }

    # usb devices
    for (my $i = 0; $i < $MAX_USB_DEVICES; $i++)  {
	my $d = parse_usb_device($conf->{"usb$i"});
	next if !$d;
	if ($d->{vendorid} && $d->{productid}) {
	    push @$devices, '-device', "usb-host,vendorid=0x$d->{vendorid},productid=0x$d->{productid}";
	} elsif (defined($d->{hostbus}) && defined($d->{hostport})) {
	    push @$devices, '-device', "usb-host,hostbus=$d->{hostbus},hostport=$d->{hostport}";
	} elsif ($d->{spice}) {
	    # usb redir support for spice
	    push @$devices, '-chardev', "spicevmc,id=usbredirchardev$i,name=usbredir";
	    push @$devices, '-device', "usb-redir,chardev=usbredirchardev$i,id=usbredirdev$i,bus=ehci.0";
	}
    }

    # serial devices
    for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++)  {
	if (my $path = $conf->{"serial$i"}) {
	    if ($path eq 'socket') {
		my $socket = "/var/run/qemu-server/${vmid}.serial$i";
		push @$devices, '-chardev', "socket,id=serial$i,path=$socket,server,nowait";
		push @$devices, '-device', "isa-serial,chardev=serial$i";
	    } else {
		die "no such serial device\n" if ! -c $path;
		push @$devices, '-chardev', "tty,id=serial$i,path=$path";
		push @$devices, '-device', "isa-serial,chardev=serial$i";
	    }
	}
    }

    # parallel devices
    for (my $i = 0; $i < $MAX_PARALLEL_PORTS; $i++)  {
	if (my $path = $conf->{"parallel$i"}) {
	    die "no such parallel device\n" if ! -c $path;
	    my $devtype = $path =~ m!^/dev/usb/lp! ? 'tty' : 'parport';
	    push @$devices, '-chardev', "$devtype,id=parallel$i,path=$path";
	    push @$devices, '-device', "isa-parallel,chardev=parallel$i";
	}
    }

    my $vmname = $conf->{name} || "vm$vmid";

    push @$cmd, '-name', $vmname;

    my $sockets = 1;
    $sockets = $conf->{smp} if $conf->{smp}; # old style - no longer iused
    $sockets = $conf->{sockets} if  $conf->{sockets};

    my $cores = $conf->{cores} || 1;

    my $maxcpus = $sockets * $cores;

    my $vcpus = $conf->{vcpus} ? $conf->{vcpus} : $maxcpus;

    my $allowed_vcpus = $cpuinfo->{cpus};

    die "MAX $maxcpus vcpus allowed per VM on this node\n"
	if ($allowed_vcpus < $maxcpus);

    push @$cmd, '-smp', "$vcpus,sockets=$sockets,cores=$cores,maxcpus=$maxcpus";

    push @$cmd, '-nodefaults';

    my $bootorder = $conf->{boot} || $confdesc->{boot}->{default};

    my $bootindex_hash = {};
    my $i = 1;
    foreach my $o (split(//, $bootorder)) {
	$bootindex_hash->{$o} = $i*100;
	$i++;
    }

    push @$cmd, '-boot', "menu=on,strict=on,reboot-timeout=1000";

    push @$cmd, '-no-acpi' if defined($conf->{acpi}) && $conf->{acpi} == 0;

    push @$cmd, '-no-reboot' if  defined($conf->{reboot}) && $conf->{reboot} == 0;

    push @$cmd, '-vga', $vga if $vga && $vga !~ m/^serial\d+$/; # for kvm 77 and later

    # time drift fix
    my $tdf = defined($conf->{tdf}) ? $conf->{tdf} : $defaults->{tdf};

    my $nokvm = defined($conf->{kvm}) && $conf->{kvm} == 0 ? 1 : 0;
    my $useLocaltime = $conf->{localtime};

    if (my $ost = $conf->{ostype}) {
	# other, wxp, w2k, w2k3, w2k8, wvista, win7, win8, l24, l26, solaris

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
	    if (qemu_machine_feature_enabled ($machine_type, $kvmver, 2, 3)) {
		push @$cpuFlags , 'hv_spinlocks=0x1fff' if !$nokvm;
		push @$cpuFlags , 'hv_vapic' if !$nokvm;
		push @$cpuFlags , 'hv_time' if !$nokvm;

	    } else { 
		push @$cpuFlags , 'hv_spinlocks=0xffff' if !$nokvm;
	    }
	}

	if ($ost eq 'win7' || $ost eq 'win8') {
	    push @$cpuFlags , 'hv_relaxed' if !$nokvm;
	}
    }

    push @$rtcFlags, 'driftfix=slew' if $tdf;

    if ($nokvm) {
	push @$machineFlags, 'accel=tcg';
    } else {
	die "No accelerator found!\n" if !$cpuinfo->{hvm};
    }

    if ($machine_type) {
	push @$machineFlags, "type=${machine_type}";
    }

    if ($conf->{startdate}) {
	push @$rtcFlags, "base=$conf->{startdate}";
    } elsif ($useLocaltime) {
	push @$rtcFlags, 'base=localtime';
    }

    my $cpu = $nokvm ? "qemu64" : "kvm64";
    $cpu = $conf->{cpu} if $conf->{cpu};

    push @$cpuFlags , '+lahf_lm' if $cpu eq 'kvm64';

    push @$cpuFlags , '+x2apic' if !$nokvm && $conf->{ostype} ne 'solaris';

    push @$cpuFlags , '-x2apic' if $conf->{ostype} eq 'solaris';

    push @$cpuFlags, '+sep' if $cpu eq 'kvm64' || $cpu eq 'kvm32';

    if (qemu_machine_feature_enabled ($machine_type, $kvmver, 2, 3)) {

	push @$cpuFlags , '+kvm_pv_unhalt' if !$nokvm;
	push @$cpuFlags , '+kvm_pv_eoi' if !$nokvm;
    }

    $cpu .= "," . join(',', @$cpuFlags) if scalar(@$cpuFlags);

    push @$cmd, '-cpu', "$cpu,enforce";

    my $memory = $conf->{memory} || $defaults->{memory};
    my $static_memory = 0;
    my $dimm_memory = 0;

    if ($hotplug_features->{memory}) {
	die "Numa need to be enabled for memory hotplug\n" if !$conf->{numa};
	die "Total memory is bigger than ${MAX_MEM}MB\n" if $memory > $MAX_MEM;
	$static_memory = $STATICMEM;
	die "minimum memory must be ${static_memory}MB\n" if($memory < $static_memory);
	$dimm_memory = $memory - $static_memory;
	push @$cmd, '-m', "size=${static_memory},slots=255,maxmem=${MAX_MEM}M";

    } else {

	$static_memory = $memory;
	push @$cmd, '-m', $static_memory;
    }

    if ($conf->{numa}) {

	my $numa_totalmemory = undef;
	for (my $i = 0; $i < $MAX_NUMA; $i++) {
	    next if !$conf->{"numa$i"};
	    my $numa = parse_numa($conf->{"numa$i"});
	    next if !$numa;
	    # memory
	    die "missing numa node$i memory value\n" if !$numa->{memory};
	    my $numa_memory = $numa->{memory};
	    $numa_totalmemory += $numa_memory;
	    my $numa_object = "memory-backend-ram,id=ram-node$i,size=${numa_memory}M";

	    # cpus
	    my $cpus_start = $numa->{cpus}->{start};
	    die "missing numa node$i cpus\n" if !defined($cpus_start);
	    my $cpus_end = $numa->{cpus}->{end} if defined($numa->{cpus}->{end});
	    my $cpus = $cpus_start;
	    if (defined($cpus_end)) {
		$cpus .= "-$cpus_end";
		die "numa node$i :  cpu range $cpus is incorrect\n" if $cpus_end <= $cpus_start;
	    }

	    # hostnodes
	    my $hostnodes_start = $numa->{hostnodes}->{start};
	    if (defined($hostnodes_start)) {
		my $hostnodes_end = $numa->{hostnodes}->{end} if defined($numa->{hostnodes}->{end});
		my $hostnodes = $hostnodes_start;
		if (defined($hostnodes_end)) {
		    $hostnodes .= "-$hostnodes_end";
		    die "host node $hostnodes range is incorrect\n" if $hostnodes_end <= $hostnodes_start;
		}

		my $hostnodes_end_range = defined($hostnodes_end) ? $hostnodes_end : $hostnodes_start;
		for (my $i = $hostnodes_start; $i <= $hostnodes_end_range; $i++ ) {
		    die "host numa node$i don't exist\n" if ! -d "/sys/devices/system/node/node$i/";
		}

		# policy
		my $policy = $numa->{policy};
		die "you need to define a policy for hostnode $hostnodes\n" if !$policy;
		$numa_object .= ",host-nodes=$hostnodes,policy=$policy";
	    }

	    push @$cmd, '-object', $numa_object;
	    push @$cmd, '-numa', "node,nodeid=$i,cpus=$cpus,memdev=ram-node$i";
	}

	die "total memory for NUMA nodes must be equal to vm static memory\n"
	    if $numa_totalmemory && $numa_totalmemory != $static_memory;

	#if no custom tology, we split memory and cores across numa nodes
	if(!$numa_totalmemory) {

	    my $numa_memory = ($static_memory / $sockets) . "M";

	    for (my $i = 0; $i < $sockets; $i++)  {

		my $cpustart = ($cores * $i);
		my $cpuend = ($cpustart + $cores - 1) if $cores && $cores > 1;
		my $cpus = $cpustart;
		$cpus .= "-$cpuend" if $cpuend;

		push @$cmd, '-object', "memory-backend-ram,size=$numa_memory,id=ram-node$i";
		push @$cmd, '-numa', "node,nodeid=$i,cpus=$cpus,memdev=ram-node$i";
	    }
	}
    }

    if ($hotplug_features->{memory}) {
	foreach_dimm($conf, $vmid, $memory, $sockets, sub {
	    my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;
	    push @$cmd, "-object" , "memory-backend-ram,id=mem-$name,size=${dimm_size}M";
	    push @$cmd, "-device", "pc-dimm,id=$name,memdev=mem-$name,node=$numanode";

	    #if dimm_memory is not aligned to dimm map
	    if($current_size > $memory) {
	         $conf->{memory} = $current_size;
	         update_config_nolock($vmid, $conf, 1);
	    }
	});
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
	my $qgasocket = qmp_socket($vmid, 1);
	my $pciaddr = print_pci_addr("qga0", $bridges);
	push @$devices, '-chardev', "socket,path=$qgasocket,server,nowait,id=qga0";
	push @$devices, '-device', "virtio-serial,id=qga0$pciaddr";
	push @$devices, '-device', 'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0';
    }

    my $spice_port;

    if ($qxlnum) {
	if ($qxlnum > 1) {
	    if ($conf->{ostype} && $conf->{ostype} =~ m/^w/){
		for(my $i = 1; $i < $qxlnum; $i++){
		    my $pciaddr = print_pci_addr("vga$i", $bridges);
		    push @$cmd, '-device', "qxl,id=vga$i,ram_size=67108864,vram_size=33554432$pciaddr";
		}
	    } else {
		# assume other OS works like Linux
		push @$cmd, '-global', 'qxl-vga.ram_size=134217728';
		push @$cmd, '-global', 'qxl-vga.vram_size=67108864';
	    }
	}

	my $pciaddr = print_pci_addr("spice", $bridges);

	$spice_port = PVE::Tools::next_spice_port();

	push @$devices, '-spice', "tls-port=${spice_port},addr=127.0.0.1,tls-ciphers=DES-CBC3-SHA,seamless-migration=on";

	push @$devices, '-device', "virtio-serial,id=spice$pciaddr";
	push @$devices, '-chardev', "spicevmc,id=vdagent,name=vdagent";
	push @$devices, '-device', "virtserialport,chardev=vdagent,name=com.redhat.spice.0";
    }

    # enable balloon by default, unless explicitly disabled
    if (!defined($conf->{balloon}) || $conf->{balloon}) {
	$pciaddr = print_pci_addr("balloon0", $bridges);
	push @$devices, '-device', "virtio-balloon-pci,id=balloon0$pciaddr";
    }

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

    # Add iscsi initiator name if available
    if (my $initiator = get_initiator_name()) {
	push @$devices, '-iscsi', "initiator-name=$initiator";
    }

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

	if($drive->{interface} eq 'virtio'){
           push @$cmd, '-object', "iothread,id=iothread-$ds" if $drive->{iothread};
	}

        if ($drive->{interface} eq 'scsi') {

	    my $maxdev = 0;
	    if ($scsihw =~ m/^lsi/) {
		$maxdev = 7;
	    } elsif ($scsihw =~ m/^virtio-scsi-single/) {
		$maxdev = 1;
	    } else {
		$maxdev = 256;
	    }

	    my $controller = int($drive->{index} / $maxdev);
	    my $controller_prefix = $scsihw =~ m/^virtio-scsi-single/ ? "virtioscsi" : "scsihw";
	    $pciaddr = print_pci_addr("$controller_prefix$controller", $bridges);
	    my $scsihw_type = $scsihw =~ m/^virtio-scsi-single/ ? "virtio-scsi-pci" : $scsihw; 
	    push @$devices, '-device', "$scsihw_type,id=$controller_prefix$controller$pciaddr" if !$scsicontroller->{$controller};
	    $scsicontroller->{$controller}=1;
        }

        if ($drive->{interface} eq 'sata') {
           my $controller = int($drive->{index} / $MAX_SATA_DISKS);
           $pciaddr = print_pci_addr("ahci$controller", $bridges);
           push @$devices, '-device', "ahci,id=ahci$controller,multifunction=on$pciaddr" if !$ahcicontroller->{$controller};
           $ahcicontroller->{$controller}=1;
        }

	my $drive_cmd = print_drive_full($storecfg, $vmid, $drive);
	push @$devices, '-drive',$drive_cmd;
	push @$devices, '-device', print_drivedevice_full($storecfg, $conf, $vmid, $drive, $bridges);
    });

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

    if (!$q35) {
	# add pci bridges
        if (qemu_machine_feature_enabled ($machine_type, $kvmver, 2, 3)) {
	   $bridges->{1} = 1;
	   $bridges->{2} = 1;
	}

	$bridges->{3} = 1 if $scsihw =~ m/^virtio-scsi-single/;

	while (my ($k, $v) = each %$bridges) {
	    $pciaddr = print_pci_addr("pci.$k");
	    unshift @$devices, '-device', "pci-bridge,id=pci.$k,chassis_nr=$k$pciaddr" if $k > 0;
	}
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

    return wantarray ? ($cmd, $vollist, $spice_port) : $cmd;
}

sub vnc_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.vnc";
}

sub spice_port {
    my ($vmid) = @_;

    my $res = vm_mon_cmd($vmid, 'query-spice');

    return $res->{'tls-port'} || $res->{'port'} || die "no spice port\n";
}

sub qmp_socket {
    my ($vmid, $qga) = @_;
    my $sockettype = $qga ? 'qga' : 'qmp';
    return "${var_run_tmpdir}/$vmid.$sockettype";
}

sub pidfile_name {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.pid";
}

sub vm_devices_list {
    my ($vmid) = @_;

    my $res = vm_mon_cmd($vmid, 'query-pci');
    my $devices = {};
    foreach my $pcibus (@$res) {
	foreach my $device (@{$pcibus->{devices}}) {
	    next if !$device->{'qdev_id'};
	    if ($device->{'pci_bridge'}) {
		$devices->{$device->{'qdev_id'}} = 1;
		foreach my $bridge_device (@{$device->{'pci_bridge'}->{devices}}) {
		    next if !$bridge_device->{'qdev_id'};
		    $devices->{$bridge_device->{'qdev_id'}} = 1;
		    $devices->{$device->{'qdev_id'}}++;
		}
	    } else {
		$devices->{$device->{'qdev_id'}} = 1;
	    }
	}
    }

    my $resblock = vm_mon_cmd($vmid, 'query-block');
    foreach my $block (@$resblock) {
	if($block->{device} =~ m/^drive-(\S+)/){
		$devices->{$1} = 1;
	}
    }

    my $resmice = vm_mon_cmd($vmid, 'query-mice');
    foreach my $mice (@$resmice) {
	if ($mice->{name} eq 'QEMU HID Tablet') {
	    $devices->{tablet} = 1;
	    last;
	}
    }

    return $devices;
}

sub vm_deviceplug {
    my ($storecfg, $conf, $vmid, $deviceid, $device) = @_;

    my $q35 = machine_type_is_q35($conf);

    my $devices_list = vm_devices_list($vmid);
    return 1 if defined($devices_list->{$deviceid});

    qemu_add_pci_bridge($storecfg, $conf, $vmid, $deviceid); # add PCI bridge if we need it for the device

    if ($deviceid eq 'tablet') {

	qemu_deviceadd($vmid, print_tabletdevice_full($conf));

    } elsif ($deviceid =~ m/^(virtio)(\d+)$/) {

	qemu_iothread_add($vmid, $deviceid, $device);

        qemu_driveadd($storecfg, $vmid, $device);
        my $devicefull = print_drivedevice_full($storecfg, $conf, $vmid, $device);

        qemu_deviceadd($vmid, $devicefull);
	eval { qemu_deviceaddverify($vmid, $deviceid); };
	if (my $err = $@) {
	    eval { qemu_drivedel($vmid, $deviceid); };
	    warn $@ if $@;
	    die $err;
        }

    } elsif ($deviceid =~ m/^(scsihw)(\d+)$/) {

        my $scsihw = defined($conf->{scsihw}) ? $conf->{scsihw} : "lsi";
        my $pciaddr = print_pci_addr($deviceid);
        my $devicefull = "$scsihw,id=$deviceid$pciaddr";

        qemu_deviceadd($vmid, $devicefull);
        qemu_deviceaddverify($vmid, $deviceid);

    } elsif ($deviceid =~ m/^(scsi)(\d+)$/) {

        qemu_findorcreatescsihw($storecfg,$conf, $vmid, $device);
        qemu_driveadd($storecfg, $vmid, $device);
        
	my $devicefull = print_drivedevice_full($storecfg, $conf, $vmid, $device);
	eval { qemu_deviceadd($vmid, $devicefull); };
	if (my $err = $@) {
	    eval { qemu_drivedel($vmid, $deviceid); };
	    warn $@ if $@;
	    die $err;
        }

    } elsif ($deviceid =~ m/^(net)(\d+)$/) {

        return undef if !qemu_netdevadd($vmid, $conf, $device, $deviceid);
        my $netdevicefull = print_netdevice_full($vmid, $conf, $device, $deviceid);
        qemu_deviceadd($vmid, $netdevicefull);
        eval { qemu_deviceaddverify($vmid, $deviceid); };
	if (my $err = $@) {
	    eval { qemu_netdevdel($vmid, $deviceid); };
	    warn $@ if $@;
	    die $err;
        }

    } elsif (!$q35 && $deviceid =~ m/^(pci\.)(\d+)$/) {

	my $bridgeid = $2;
	my $pciaddr = print_pci_addr($deviceid);
	my $devicefull = "pci-bridge,id=pci.$bridgeid,chassis_nr=$bridgeid$pciaddr";
	
	qemu_deviceadd($vmid, $devicefull);
	qemu_deviceaddverify($vmid, $deviceid);

    } else {
	die "can't hotplug device '$deviceid'\n";	
    }

    return 1;
}

# fixme: this should raise exceptions on error!
sub vm_deviceunplug {
    my ($vmid, $conf, $deviceid) = @_;

    my $devices_list = vm_devices_list($vmid);
    return 1 if !defined($devices_list->{$deviceid});

    die "can't unplug bootdisk" if $conf->{bootdisk} && $conf->{bootdisk} eq $deviceid;

    if ($deviceid eq 'tablet') {

	qemu_devicedel($vmid, $deviceid);

    } elsif ($deviceid =~ m/^(virtio)(\d+)$/) {

        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
        qemu_drivedel($vmid, $deviceid);
	qemu_iothread_del($conf, $vmid, $deviceid);

    } elsif ($deviceid =~ m/^(scsihw)(\d+)$/) {
    
	qemu_devicedel($vmid, $deviceid);
	qemu_devicedelverify($vmid, $deviceid);
    
    } elsif ($deviceid =~ m/^(scsi)(\d+)$/) {

        qemu_devicedel($vmid, $deviceid);
        qemu_drivedel($vmid, $deviceid);
	qemu_deletescsihw($conf, $vmid, $deviceid);  

    } elsif ($deviceid =~ m/^(net)(\d+)$/) {

        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
        qemu_netdevdel($vmid, $deviceid);

    } else {
	die "can't unplug device '$deviceid'\n";
    }

    return 1;
}

sub qemu_deviceadd {
    my ($vmid, $devicefull) = @_;

    $devicefull = "driver=".$devicefull;
    my %options =  split(/[=,]/, $devicefull);

    vm_mon_cmd($vmid, "device_add" , %options);
}

sub qemu_devicedel {
    my ($vmid, $deviceid) = @_;

    my $ret = vm_mon_cmd($vmid, "device_del", id => $deviceid);
}

sub qemu_iothread_add {
    my($vmid, $deviceid, $device) = @_;

    if ($device->{iothread}) {
	my $iothreads = vm_iothreads_list($vmid);
	qemu_objectadd($vmid, "iothread-$deviceid", "iothread") if !$iothreads->{"iothread-$deviceid"};
    }
}

sub qemu_iothread_del {
    my($conf, $vmid, $deviceid) = @_;

    my $device = parse_drive($deviceid, $conf->{$deviceid});
    if ($device->{iothread}) {
	my $iothreads = vm_iothreads_list($vmid);
	qemu_objectdel($vmid, "iothread-$deviceid") if $iothreads->{"iothread-$deviceid"};
    }
}

sub qemu_objectadd {
    my($vmid, $objectid, $qomtype) = @_;

    vm_mon_cmd($vmid, "object-add", id => $objectid, "qom-type" => $qomtype);

    return 1;
}

sub qemu_objectdel {
    my($vmid, $objectid) = @_;

    vm_mon_cmd($vmid, "object-del", id => $objectid);

    return 1;
}

sub qemu_driveadd {
    my ($storecfg, $vmid, $device) = @_;

    my $drive = print_drive_full($storecfg, $vmid, $device);
    $drive =~ s/\\/\\\\/g;
    my $ret = vm_human_monitor_command($vmid, "drive_add auto \"$drive\"");

    # If the command succeeds qemu prints: "OK"
    return 1 if $ret =~ m/OK/s;

    die "adding drive failed: $ret\n";
}

sub qemu_drivedel {
    my($vmid, $deviceid) = @_;

    my $ret = vm_human_monitor_command($vmid, "drive_del drive-$deviceid");
    $ret =~ s/^\s+//;
    
    return 1 if $ret eq "";
  
    # NB: device not found errors mean the drive was auto-deleted and we ignore the error
    return 1 if $ret =~ m/Device \'.*?\' not found/s; 
    
    die "deleting drive $deviceid failed : $ret\n";
}

sub qemu_deviceaddverify {
    my ($vmid, $deviceid) = @_;

    for (my $i = 0; $i <= 5; $i++) {
         my $devices_list = vm_devices_list($vmid);
         return 1 if defined($devices_list->{$deviceid});
         sleep 1;
    }

    die "error on hotplug device '$deviceid'\n";
}


sub qemu_devicedelverify {
    my ($vmid, $deviceid) = @_;

    # need to verify that the device is correctly removed as device_del 
    # is async and empty return is not reliable

    for (my $i = 0; $i <= 5; $i++) {
         my $devices_list = vm_devices_list($vmid);
         return 1 if !defined($devices_list->{$deviceid});
         sleep 1;
    }

    die "error on hot-unplugging device '$deviceid'\n";
}

sub qemu_findorcreatescsihw {
    my ($storecfg, $conf, $vmid, $device) = @_;

    my $maxdev = ($conf->{scsihw} && ($conf->{scsihw} !~ m/^lsi/)) ? 256 : 7;
    my $controller = int($device->{index} / $maxdev);
    my $scsihwid="scsihw$controller";
    my $devices_list = vm_devices_list($vmid);

    if(!defined($devices_list->{$scsihwid})) {
	vm_deviceplug($storecfg, $conf, $vmid, $scsihwid);
    }

    return 1;
}

sub qemu_deletescsihw {
    my ($conf, $vmid, $opt) = @_;

    my $device = parse_drive($opt, $conf->{$opt});

    my $maxdev = ($conf->{scsihw} && ($conf->{scsihw} !~ m/^lsi/)) ? 256 : 7;
    my $controller = int($device->{index} / $maxdev);

    my $devices_list = vm_devices_list($vmid);
    foreach my $opt (keys %{$devices_list}) {
	if (PVE::QemuServer::valid_drivename($opt)) {
	    my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
	    if($drive->{interface} eq 'scsi' && $drive->{index} < (($maxdev-1)*($controller+1))) {
		return 1;
	    }
	}
    }

    my $scsihwid="scsihw$controller";

    vm_deviceunplug($vmid, $conf, $scsihwid);

    return 1;
}

sub qemu_add_pci_bridge {
    my ($storecfg, $conf, $vmid, $device) = @_;

    my $bridges = {};

    my $bridgeid;

    print_pci_addr($device, $bridges);

    while (my ($k, $v) = each %$bridges) {
	$bridgeid = $k;
    }
    return 1 if !defined($bridgeid) || $bridgeid < 1;

    my $bridge = "pci.$bridgeid";
    my $devices_list = vm_devices_list($vmid);

    if (!defined($devices_list->{$bridge})) {
	vm_deviceplug($storecfg, $conf, $vmid, $bridge);
    }

    return 1;
}

sub qemu_set_link_status {
    my ($vmid, $device, $up) = @_;

    vm_mon_cmd($vmid, "set_link", name => $device, 
	       up => $up ? JSON::true : JSON::false);
}

sub qemu_netdevadd {
    my ($vmid, $conf, $device, $deviceid) = @_;

    my $netdev = print_netdev_full($vmid, $conf, $device, $deviceid);
    my %options =  split(/[=,]/, $netdev);

    vm_mon_cmd($vmid, "netdev_add",  %options);
    return 1;
}

sub qemu_netdevdel {
    my ($vmid, $deviceid) = @_;

    vm_mon_cmd($vmid, "netdev_del", id => $deviceid);
}

sub qemu_cpu_hotplug {
    my ($vmid, $conf, $vcpus) = @_;

    my $sockets = 1;
    $sockets = $conf->{smp} if $conf->{smp}; # old style - no longer iused
    $sockets = $conf->{sockets} if  $conf->{sockets};
    my $cores = $conf->{cores} || 1;
    my $maxcpus = $sockets * $cores;

    $vcpus = $maxcpus if !$vcpus;

    die "you can't add more vcpus than maxcpus\n"
	if $vcpus > $maxcpus;

    my $currentvcpus = $conf->{vcpus} || $maxcpus;
    die "online cpu unplug is not yet possible\n"
	if $vcpus < $currentvcpus;

    my $currentrunningvcpus = vm_mon_cmd($vmid, "query-cpus");
    die "vcpus in running vm is different than configuration\n"
	if scalar(@{$currentrunningvcpus}) != $currentvcpus;

    for (my $i = $currentvcpus; $i < $vcpus; $i++) {
	vm_mon_cmd($vmid, "cpu-add", id => int($i));
    }
}

sub qemu_memory_hotplug {
    my ($vmid, $conf, $defaults, $opt, $value) = @_;

    return $value if !check_running($vmid);
 
    my $memory = $conf->{memory} || $defaults->{memory};
    $value = $defaults->{memory} if !$value; 
    return $value if $value == $memory;

    my $static_memory = $STATICMEM;
    my $dimm_memory = $memory - $static_memory;

    die "memory can't be lower than $static_memory MB" if $value < $static_memory;
    die "memory unplug is not yet available" if $value < $memory;
    die "you cannot add more memory than $MAX_MEM MB!\n" if $memory > $MAX_MEM;


    my $sockets = 1;
    $sockets = $conf->{sockets} if $conf->{sockets};

    foreach_dimm($conf, $vmid, $value, $sockets, sub {
	my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;

	    return if $current_size <= $conf->{memory};

	    eval { vm_mon_cmd($vmid, "object-add", 'qom-type' => "memory-backend-ram", id => "mem-$name", props => { size => int($dimm_size*1024*1024) } ) };
	    if (my $err = $@) {
	        eval { qemu_objectdel($vmid, "mem-$name"); };
	        die $err;
	    }

	    eval { vm_mon_cmd($vmid, "device_add", driver => "pc-dimm", id => "$name", memdev => "mem-$name", node => $numanode) };
	    if (my $err = $@) {
	        eval { qemu_objectdel($vmid, "mem-$name"); };
	        die $err;
	    }
	    #update conf after each succesful module hotplug
	    $conf->{memory} = $current_size;
	    update_config_nolock($vmid, $conf, 1);
    });
}

sub qemu_block_set_io_throttle {
    my ($vmid, $deviceid, $bps, $bps_rd, $bps_wr, $iops, $iops_rd, $iops_wr) = @_;

    return if !check_running($vmid) ;

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

    my $running = check_running($vmid);

    return if !PVE::Storage::volume_resize($storecfg, $volid, $size, $running);

    return if !$running;

    vm_mon_cmd($vmid, "block_resize", device => $deviceid, size => int($size));

}

sub qemu_volume_snapshot {
    my ($vmid, $deviceid, $storecfg, $volid, $snap) = @_;

    my $running = check_running($vmid);

    return if !PVE::Storage::volume_snapshot($storecfg, $volid, $snap, $running);

    return if !$running;

    vm_mon_cmd($vmid, "snapshot-drive", device => $deviceid, name => $snap);

}

sub qemu_volume_snapshot_delete {
    my ($vmid, $deviceid, $storecfg, $volid, $snap) = @_;

    my $running = check_running($vmid);

    return if !PVE::Storage::volume_snapshot_delete($storecfg, $volid, $snap, $running);

    return if !$running;

    vm_mon_cmd($vmid, "delete-drive-snapshot", device => $deviceid, name => $snap);
}

sub set_migration_caps {
    my ($vmid) = @_;

    my $cap_ref = [];

    my $enabled_cap = {
	"auto-converge" => 1,
	"xbzrle" => 0,
	"x-rdma-pin-all" => 0,
	"zero-blocks" => 0,
    };

    my $supported_capabilities = vm_mon_cmd_nocheck($vmid, "query-migrate-capabilities");

    for my $supported_capability (@$supported_capabilities) {
	push @$cap_ref, {
	    capability => $supported_capability->{capability},
	    state => $enabled_cap->{$supported_capability->{capability}} ? JSON::true : JSON::false,
	};
    }

    vm_mon_cmd_nocheck($vmid, "migrate-set-capabilities", capabilities => $cap_ref);
}

my $fast_plug_option = {
    'lock' => 1,
    'name' => 1,
    'onboot' => 1, 
    'shares' => 1,
    'startup' => 1,
};

# hotplug changes in [PENDING]
# $selection hash can be used to only apply specified options, for
# example: { cores => 1 } (only apply changed 'cores')
# $errors ref is used to return error messages
sub vmconfig_hotplug_pending {
    my ($vmid, $conf, $storecfg, $selection, $errors) = @_;

    my $defaults = load_defaults();

    # commit values which do not have any impact on running VM first
    # Note: those option cannot raise errors, we we do not care about
    # $selection and always apply them.

    my $add_error = sub {
	my ($opt, $msg) = @_;
	$errors->{$opt} = "hotplug problem - $msg";
    };

    my $changes = 0;
    foreach my $opt (keys %{$conf->{pending}}) { # add/change
	if ($fast_plug_option->{$opt}) {
	    $conf->{$opt} = $conf->{pending}->{$opt};
	    delete $conf->{pending}->{$opt};
	    $changes = 1;
	}
    }

    if ($changes) {
	update_config_nolock($vmid, $conf, 1);
	$conf = load_config($vmid); # update/reload
    }

    my $hotplug_features = parse_hotplug_features(defined($conf->{hotplug}) ? $conf->{hotplug} : '1');

    my @delete = PVE::Tools::split_list($conf->{pending}->{delete});
    foreach my $opt (@delete) {
	next if $selection && !$selection->{$opt};
	eval {
	    if ($opt eq 'hotplug') {
		die "skip\n" if ($conf->{hotplug} =~ /memory/);
	    } elsif ($opt eq 'tablet') {
		die "skip\n" if !$hotplug_features->{usb};
		if ($defaults->{tablet}) {
		    vm_deviceplug($storecfg, $conf, $vmid, $opt);
		} else {
		    vm_deviceunplug($vmid, $conf, $opt);
		}
	    } elsif ($opt eq 'vcpus') {
		die "skip\n" if !$hotplug_features->{cpu};
		qemu_cpu_hotplug($vmid, $conf, undef);
            } elsif ($opt eq 'balloon') {
		# enable balloon device is not hotpluggable
		die "skip\n" if !defined($conf->{balloon}) || $conf->{balloon};
	    } elsif ($fast_plug_option->{$opt}) {
		# do nothing
	    } elsif ($opt =~ m/^net(\d+)$/) {
		die "skip\n" if !$hotplug_features->{network};
		vm_deviceunplug($vmid, $conf, $opt);
	    } elsif (valid_drivename($opt)) {
		die "skip\n" if !$hotplug_features->{disk} || $opt =~ m/(ide|sata)(\d+)/;
		vm_deviceunplug($vmid, $conf, $opt);
		vmconfig_register_unused_drive($storecfg, $vmid, $conf, parse_drive($opt, $conf->{$opt}));
	    } elsif ($opt =~ m/^memory$/) {
		die "skip\n" if !$hotplug_features->{memory};
		qemu_memory_hotplug($vmid, $conf, $defaults, $opt);
	    } else {
		die "skip\n";
	    }
	};
	if (my $err = $@) {
	    &$add_error($opt, $err) if $err ne "skip\n";
	} else {
	    # save new config if hotplug was successful
	    delete $conf->{$opt};
	    vmconfig_undelete_pending_option($conf, $opt);
	    update_config_nolock($vmid, $conf, 1);
	    $conf = load_config($vmid); # update/reload
	}
    }

    foreach my $opt (keys %{$conf->{pending}}) {
	next if $selection && !$selection->{$opt};
	my $value = $conf->{pending}->{$opt};
	eval {
	    if ($opt eq 'hotplug') {
		die "skip\n" if ($value =~ /memory/) || ($value !~ /memory/ && $conf->{hotplug} =~ /memory/);
	    } elsif ($opt eq 'tablet') {
		die "skip\n" if !$hotplug_features->{usb};
		if ($value == 1) {
		    vm_deviceplug($storecfg, $conf, $vmid, $opt);
		} elsif ($value == 0) {
		    vm_deviceunplug($vmid, $conf, $opt);
		}
	    } elsif ($opt eq 'vcpus') {
		die "skip\n" if !$hotplug_features->{cpu};
		qemu_cpu_hotplug($vmid, $conf, $value);
	    } elsif ($opt eq 'balloon') {
		# enable/disable balloning device is not hotpluggable
		my $old_balloon_enabled =  !!(!defined($conf->{balloon}) || $conf->{balloon});
		my $new_balloon_enabled =  !!(!defined($conf->{pending}->{balloon}) || $conf->{pending}->{balloon});		
		die "skip\n" if $old_balloon_enabled != $new_balloon_enabled;

		# allow manual ballooning if shares is set to zero
		if ((defined($conf->{shares}) && ($conf->{shares} == 0))) {
		    my $balloon = $conf->{pending}->{balloon} || $conf->{memory} || $defaults->{memory};
		    vm_mon_cmd($vmid, "balloon", value => $balloon*1024*1024);
		}
	    } elsif ($opt =~ m/^net(\d+)$/) { 
		# some changes can be done without hotplug
		vmconfig_update_net($storecfg, $conf, $hotplug_features->{network}, 
				    $vmid, $opt, $value);
	    } elsif (valid_drivename($opt)) {
		# some changes can be done without hotplug
		vmconfig_update_disk($storecfg, $conf, $hotplug_features->{disk},
				     $vmid, $opt, $value, 1);
	    } elsif ($opt =~ m/^memory$/) { #dimms
		die "skip\n" if !$hotplug_features->{memory};
		$value = qemu_memory_hotplug($vmid, $conf, $defaults, $opt, $value);
	    } else {
		die "skip\n";  # skip non-hot-pluggable options
	    }
	};
	if (my $err = $@) {
	    &$add_error($opt, $err) if $err ne "skip\n";
	} else {
	    # save new config if hotplug was successful
	    $conf->{$opt} = $value;
	    delete $conf->{pending}->{$opt};
	    update_config_nolock($vmid, $conf, 1);
	    $conf = load_config($vmid); # update/reload
	}
    }
}

sub vmconfig_apply_pending {
    my ($vmid, $conf, $storecfg) = @_;

    # cold plug

    my @delete = PVE::Tools::split_list($conf->{pending}->{delete});
    foreach my $opt (@delete) { # delete
	die "internal error" if $opt =~ m/^unused/;
	$conf = load_config($vmid); # update/reload
	if (!defined($conf->{$opt})) {
	    vmconfig_undelete_pending_option($conf, $opt);
	    update_config_nolock($vmid, $conf, 1);
	} elsif (valid_drivename($opt)) {
	    vmconfig_register_unused_drive($storecfg, $vmid, $conf, parse_drive($opt, $conf->{$opt}));
	    vmconfig_undelete_pending_option($conf, $opt);
	    delete $conf->{$opt};
	    update_config_nolock($vmid, $conf, 1);
	} else {
	    vmconfig_undelete_pending_option($conf, $opt);
	    delete $conf->{$opt};
	    update_config_nolock($vmid, $conf, 1);
	}
    }

    $conf = load_config($vmid); # update/reload

    foreach my $opt (keys %{$conf->{pending}}) { # add/change
	$conf = load_config($vmid); # update/reload

	if (defined($conf->{$opt}) && ($conf->{$opt} eq $conf->{pending}->{$opt})) {
	    # skip if nothing changed
	} elsif (valid_drivename($opt)) {
	    vmconfig_register_unused_drive($storecfg, $vmid, $conf, parse_drive($opt, $conf->{$opt}))
		if defined($conf->{$opt});
	    $conf->{$opt} = $conf->{pending}->{$opt};
	} else {
	    $conf->{$opt} = $conf->{pending}->{$opt};
	}

	delete $conf->{pending}->{$opt};
	update_config_nolock($vmid, $conf, 1);
    }
}

my $safe_num_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a != $b;
};

my $safe_string_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a ne $b;
};

sub vmconfig_update_net {
    my ($storecfg, $conf, $hotplug, $vmid, $opt, $value) = @_;

    my $newnet = parse_net($value);

    if ($conf->{$opt}) {
	my $oldnet = parse_net($conf->{$opt});

	if (&$safe_string_ne($oldnet->{model}, $newnet->{model}) ||
	    &$safe_string_ne($oldnet->{macaddr}, $newnet->{macaddr}) ||
	    &$safe_num_ne($oldnet->{queues}, $newnet->{queues}) ||
	    !($newnet->{bridge} && $oldnet->{bridge})) { # bridge/nat mode change

            # for non online change, we try to hot-unplug
	    die "skip\n" if !$hotplug;
	    vm_deviceunplug($vmid, $conf, $opt);
	} else {

	    die "internal error" if $opt !~ m/net(\d+)/;
	    my $iface = "tap${vmid}i$1";
		
	    if (&$safe_num_ne($oldnet->{rate}, $newnet->{rate})) {
		PVE::Network::tap_rate_limit($iface, $newnet->{rate});
	    }

	    if (&$safe_string_ne($oldnet->{bridge}, $newnet->{bridge}) ||
		&$safe_num_ne($oldnet->{tag}, $newnet->{tag}) ||
		&$safe_num_ne($oldnet->{firewall}, $newnet->{firewall})) {
		PVE::Network::tap_unplug($iface);
		PVE::Network::tap_plug($iface, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall});
	    }

	    if (&$safe_string_ne($oldnet->{link_down}, $newnet->{link_down})) {
		qemu_set_link_status($vmid, $opt, !$newnet->{link_down});
	    }

	    return 1;
	}
    }
    
    if ($hotplug) {
	vm_deviceplug($storecfg, $conf, $vmid, $opt, $newnet);
    } else {
	die "skip\n";
    }
}

sub vmconfig_update_disk {
    my ($storecfg, $conf, $hotplug, $vmid, $opt, $value, $force) = @_;

    # fixme: do we need force?

    my $drive = parse_drive($opt, $value);

    if ($conf->{$opt}) {

	if (my $old_drive = parse_drive($opt, $conf->{$opt}))  {

	    my $media = $drive->{media} || 'disk';
	    my $oldmedia = $old_drive->{media} || 'disk';
	    die "unable to change media type\n" if $media ne $oldmedia;

	    if (!drive_is_cdrom($old_drive)) {

		if ($drive->{file} ne $old_drive->{file}) {  

		    die "skip\n" if !$hotplug;

		    # unplug and register as unused
		    vm_deviceunplug($vmid, $conf, $opt);
		    vmconfig_register_unused_drive($storecfg, $vmid, $conf, $old_drive)
       
		} else {
		    # update existing disk

		    # skip non hotpluggable value
		    if (&$safe_num_ne($drive->{discard}, $old_drive->{discard}) || 
			&$safe_string_ne($drive->{iothread}, $old_drive->{iothread}) ||
			&$safe_string_ne($drive->{cache}, $old_drive->{cache})) {
			die "skip\n";
		    }

		    # apply throttle
		    if (&$safe_num_ne($drive->{mbps}, $old_drive->{mbps}) ||
			&$safe_num_ne($drive->{mbps_rd}, $old_drive->{mbps_rd}) ||
			&$safe_num_ne($drive->{mbps_wr}, $old_drive->{mbps_wr}) ||
			&$safe_num_ne($drive->{iops}, $old_drive->{iops}) ||
			&$safe_num_ne($drive->{iops_rd}, $old_drive->{iops_rd}) ||
			&$safe_num_ne($drive->{iops_wr}, $old_drive->{iops_wr}) ||
			&$safe_num_ne($drive->{mbps_max}, $old_drive->{mbps_max}) ||
			&$safe_num_ne($drive->{mbps_rd_max}, $old_drive->{mbps_rd_max}) ||
			&$safe_num_ne($drive->{mbps_wr_max}, $old_drive->{mbps_wr_max}) ||
			&$safe_num_ne($drive->{iops_max}, $old_drive->{iops_max}) ||
			&$safe_num_ne($drive->{iops_rd_max}, $old_drive->{iops_rd_max}) ||
			&$safe_num_ne($drive->{iops_wr_max}, $old_drive->{iops_wr_max})) {
			
			qemu_block_set_io_throttle($vmid,"drive-$opt",
						   ($drive->{mbps} || 0)*1024*1024,
						   ($drive->{mbps_rd} || 0)*1024*1024,
						   ($drive->{mbps_wr} || 0)*1024*1024,
						   $drive->{iops} || 0,
						   $drive->{iops_rd} || 0,
						   $drive->{iops_wr} || 0,
						   ($drive->{mbps_max} || 0)*1024*1024,
						   ($drive->{mbps_rd_max} || 0)*1024*1024,
						   ($drive->{mbps_wr_max} || 0)*1024*1024,
						   $drive->{iops_max} || 0,
						   $drive->{iops_rd_max} || 0,
						   $drive->{iops_wr_max} || 0);

		    }
		    
		    return 1;
	        }

	    } else { # cdrom
		
		if ($drive->{file} eq 'none') {
		    vm_mon_cmd($vmid, "eject",force => JSON::true,device => "drive-$opt");
		} else {
		    my $path = get_iso_path($storecfg, $vmid, $drive->{file});
		    vm_mon_cmd($vmid, "eject", force => JSON::true,device => "drive-$opt"); # force eject if locked
		    vm_mon_cmd($vmid, "change", device => "drive-$opt",target => "$path") if $path;
		}
		
		return 1;
	    }
	}
    }

    die "skip\n" if !$hotplug || $opt =~ m/(ide|sata)(\d+)/;   
    # hotplug new disks
    vm_deviceplug($storecfg, $conf, $vmid, $opt, $drive);
}

sub vm_start {
    my ($storecfg, $vmid, $statefile, $skiplock, $migratedfrom, $paused, $forcemachine, $spice_ticket) = @_;

    lock_config($vmid, sub {
	my $conf = load_config($vmid, $migratedfrom);

	die "you can't start a vm if it's a template\n" if is_template($conf);

	check_lock($conf) if !$skiplock;

	die "VM $vmid already running\n" if check_running($vmid, undef, $migratedfrom);

	if (!$statefile && scalar(keys %{$conf->{pending}})) {
	    vmconfig_apply_pending($vmid, $conf, $storecfg);
	    $conf = load_config($vmid); # update/reload
	}

	my $defaults = load_defaults();

	# set environment variable useful inside network script
	$ENV{PVE_MIGRATED_FROM} = $migratedfrom if $migratedfrom;

	my ($cmd, $vollist, $spice_port) = config_to_command($storecfg, $vmid, $conf, $defaults, $forcemachine);

	my $migrate_port = 0;
	my $migrate_uri;
	if ($statefile) {
	    if ($statefile eq 'tcp') {
		my $localip = "localhost";
		my $datacenterconf = PVE::Cluster::cfs_read_file('datacenter.cfg');
		if ($datacenterconf->{migration_unsecure}) {
			my $nodename = PVE::INotify::nodename();
			$localip = PVE::Cluster::remote_node_ip($nodename, 1);
		}
		$migrate_port = PVE::Tools::next_migrate_port();
		$migrate_uri = "tcp:${localip}:${migrate_port}";
		push @$cmd, '-incoming', $migrate_uri;
		push @$cmd, '-S';
	    } else {
		push @$cmd, '-loadstate', $statefile;
	    }
	} elsif ($paused) {
	    push @$cmd, '-S';
	}

	# host pci devices
        for (my $i = 0; $i < $MAX_HOSTPCI_DEVICES; $i++)  {
          my $d = parse_hostpci($conf->{"hostpci$i"});
          next if !$d;
	  my $pcidevices = $d->{pciid};
	  foreach my $pcidevice (@$pcidevices) {
		my $pciid = $pcidevice->{id}.".".$pcidevice->{function};

		my $info = pci_device_info("0000:$pciid");
		die "IOMMU not present\n" if !check_iommu_support();
		die "no pci device info for device '$pciid'\n" if !$info;

		if ($d->{driver} && $d->{driver} eq "vfio") {
		    die "can't unbind/bind pci group to vfio '$pciid'\n" if !pci_dev_group_bind_to_vfio($pciid);
		} else {
		    die "can't unbind/bind to stub pci device '$pciid'\n" if !pci_dev_bind_to_stub($info);
		}

		die "can't reset pci device '$pciid'\n" if $info->{has_fl_reset} and !pci_dev_reset($info);
	  }
        }

	PVE::Storage::activate_volumes($storecfg, $vollist);

	eval  { run_command($cmd, timeout => $statefile ? undef : 30,
		    umask => 0077); };
	my $err = $@;
	die "start failed: $err" if $err;

	print "migration listens on $migrate_uri\n" if $migrate_uri;

	if ($statefile && $statefile ne 'tcp')  {
	    eval { vm_mon_cmd_nocheck($vmid, "cont"); };
	    warn $@ if $@;
	}

	if ($migratedfrom) {

	    eval {
		set_migration_caps($vmid);
	    };
	    warn $@ if $@;

	    if ($spice_port) {
	        print "spice listens on port $spice_port\n";
		if ($spice_ticket) {
		    vm_mon_cmd_nocheck($vmid, "set_password", protocol => 'spice', password => $spice_ticket);
		    vm_mon_cmd_nocheck($vmid, "expire_password", protocol => 'spice', time => "+30");
		}
	    }

	} else {

	    if (!$statefile && (!defined($conf->{balloon}) || $conf->{balloon})) {
		vm_mon_cmd_nocheck($vmid, "balloon", value => $conf->{balloon}*1024*1024)
		    if $conf->{balloon};
	    }

	    foreach my $opt (keys %$conf) {
		next if $opt !~  m/^net\d+$/;
		my $nicconf = parse_net($conf->{$opt});
		qemu_set_link_status($vmid, $opt, 0) if $nicconf->{link_down};
	    }
	}
	
	vm_mon_cmd_nocheck($vmid, 'qom-set',
		    path => "machine/peripheral/balloon0",
		    property => "guest-stats-polling-interval",
		    value => 2) if (!defined($conf->{balloon}) || $conf->{balloon});

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
	my $sname = qmp_socket($vmid);
	if (-e $sname) { # test if VM is reasonambe new and supports qmp/qga
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
    my ($storecfg, $vmid, $conf, $keepActive, $apply_pending_changes) = @_;

    eval {
	fairsched_rmnod($vmid); # try to destroy group

	if (!$keepActive) {
	    my $vollist = get_vm_volumes($conf);
	    PVE::Storage::deactivate_volumes($storecfg, $vollist);
	}
	
	foreach my $ext (qw(mon qmp pid vnc qga)) {
	    unlink "/var/run/qemu-server/${vmid}.$ext";
	}
	
	vmconfig_apply_pending($vmid, $conf, $storecfg) if $apply_pending_changes;
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
	vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive, 0);
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
		if (defined($conf) && $conf->{agent}) {
		    vm_qmp_command($vmid, { execute => "guest-shutdown" }, $nocheck);
		} else {
		    vm_qmp_command($vmid, { execute => "system_powerdown" }, $nocheck);
		}
	    } else {
		vm_qmp_command($vmid, { execute => "quit" }, $nocheck);
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
		vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive, 1) if $conf;
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

	vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive, 1) if $conf;
   });
}

sub vm_suspend {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !($skiplock || ($conf->{lock} && $conf->{lock} eq 'backup'));

	vm_mon_cmd($vmid, "stop");
    });
}

sub vm_resume {
    my ($vmid, $skiplock) = @_;

    lock_config($vmid, sub {

	my $conf = load_config($vmid);

	check_lock($conf) if !($skiplock || ($conf->{lock} && $conf->{lock} eq 'backup'));

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

sub pci_dev_bind_to_vfio {
    my ($dev) = @_;

    my $name = $dev->{name};

    my $vfio_basedir = "$pcisysfs/drivers/vfio-pci";

    if (!-d $vfio_basedir) {
	system("/sbin/modprobe vfio-pci >/dev/null 2>/dev/null");
    }
    die "Cannot find vfio-pci module!\n" if !-d $vfio_basedir;

    my $testdir = "$vfio_basedir/$name";
    return 1 if -d $testdir;

    my $data = "$dev->{vendor} $dev->{product}";
    return undef if !file_write("$vfio_basedir/new_id", $data);

    my $fn = "$pcisysfs/devices/$name/driver/unbind";
    if (!file_write($fn, $name)) {
	return undef if -f $fn;
    }

    $fn = "$vfio_basedir/bind";
    if (! -d $testdir) {
	return undef if !file_write($fn, $name);
    }

    return -d $testdir;
}

sub pci_dev_group_bind_to_vfio {
    my ($pciid) = @_;

    my $vfio_basedir = "$pcisysfs/drivers/vfio-pci";

    if (!-d $vfio_basedir) {
	system("/sbin/modprobe vfio-pci >/dev/null 2>/dev/null");
    }
    die "Cannot find vfio-pci module!\n" if !-d $vfio_basedir;

    # get IOMMU group devices
    opendir(my $D, "$pcisysfs/devices/0000:$pciid/iommu_group/devices/") || die "Cannot open iommu_group: $!\n";
      my @devs = grep /^0000:/, readdir($D);
    closedir($D);

    foreach my $pciid (@devs) {
	$pciid =~ m/^([:\.\da-f]+)$/ or die "PCI ID $pciid not valid!\n";

        # pci bridges, switches or root ports are not supported
        # they have a pci_bus subdirectory so skip them
        next if (-e "$pcisysfs/devices/$pciid/pci_bus");

	my $info = pci_device_info($1);
	pci_dev_bind_to_vfio($info) || die "Cannot bind $pciid to vfio\n";
    }

    return 1;
}

sub print_pci_addr {
    my ($id, $bridges) = @_;

    my $res = '';
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

# vzdump restore implementaion

sub tar_archive_read_firstfile {
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

sub tar_restore_cleanup {
    my ($storecfg, $statfile) = @_;

    print STDERR "starting cleanup\n";

    if (my $fd = IO::File->new($statfile, "r")) {
	while (defined(my $line = <$fd>)) {
	    if ($line =~ m/vzdump:([^\s:]*):(\S+)$/) {
		my $volid = $2;
		eval {
		    if ($volid =~ m|^/|) {
			unlink $volid || die 'unlink failed\n';
		    } else {
			PVE::Storage::vdisk_free($storecfg, $volid);
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

    my $format = $opts->{format};
    my $comp;

    if ($archive =~ m/\.tgz$/ || $archive =~ m/\.tar\.gz$/) {
	$format = 'tar' if !$format;
	$comp = 'gzip';
    } elsif ($archive =~ m/\.tar$/) {
	$format = 'tar' if !$format;
    } elsif ($archive =~ m/.tar.lzo$/) {
	$format = 'tar' if !$format;
	$comp = 'lzop';
    } elsif ($archive =~ m/\.vma$/) {
	$format = 'vma' if !$format;
    } elsif ($archive =~ m/\.vma\.gz$/) {
	$format = 'vma' if !$format;
	$comp = 'gzip';
    } elsif ($archive =~ m/\.vma\.lzo$/) {
	$format = 'vma' if !$format;
	$comp = 'lzop';
    } else {
	$format = 'vma' if !$format; # default
    }

    # try to detect archive format
    if ($format eq 'tar') {
	return restore_tar_archive($archive, $vmid, $user, $opts);
    } else {
	return restore_vma_archive($archive, $vmid, $user, $opts, $comp);
    }
}

sub restore_update_config_line {
    my ($outfd, $cookie, $vmid, $map, $line, $unique) = @_;

    return if $line =~ m/^\#qmdump\#/;
    return if $line =~ m/^\#vzdump\#/;
    return if $line =~ m/^lock:/;
    return if $line =~ m/^unused\d+:/;
    return if $line =~ m/^parent:/;
    return if $line =~ m/^template:/; # restored VM is never a template

    if (($line =~ m/^(vlan(\d+)):\s*(\S+)\s*$/)) {
	# try to convert old 1.X settings
	my ($id, $ind, $ethcfg) = ($1, $2, $3);
	foreach my $devconfig (PVE::Tools::split_list($ethcfg)) {
	    my ($model, $macaddr) = split(/\=/, $devconfig);
	    $macaddr = PVE::Tools::random_ether_addr() if !$macaddr || $unique;
	    my $net = {
		model => $model,
		bridge => "vmbr$ind",
		macaddr => $macaddr,
	    };
	    my $netstr = print_net($net);

	    print $outfd "net$cookie->{netcount}: $netstr\n";
	    $cookie->{netcount}++;
	}
    } elsif (($line =~ m/^(net\d+):\s*(\S+)\s*$/) && $unique) {
	my ($id, $netstr) = ($1, $2);
	my $net = parse_net($netstr);
	$net->{macaddr} = PVE::Tools::random_ether_addr() if $net->{macaddr};
	$netstr = print_net($net);
	print $outfd "$id: $netstr\n";
    } elsif ($line =~ m/^((ide|scsi|virtio|sata)\d+):\s*(\S+)\s*$/) {
	my $virtdev = $1;
	my $value = $3;
	if ($line =~ m/backup=no/) {
	    print $outfd "#$line";
	} elsif ($virtdev && $map->{$virtdev}) {
	    my $di = parse_drive($virtdev, $value);
	    delete $di->{format}; # format can change on restore
	    $di->{file} = $map->{$virtdev};
	    $value = print_drive($vmid, $di);
	    print $outfd "$virtdev: $value\n";
	} else {
	    print $outfd $line;
	}
    } else {
	print $outfd $line;
    }
}

sub scan_volids {
    my ($cfg, $vmid) = @_;

    my $info = PVE::Storage::vdisk_list($cfg, undef, $vmid);

    my $volid_hash = {};
    foreach my $storeid (keys %$info) {
	foreach my $item (@{$info->{$storeid}}) {
	    next if !($item->{volid} && $item->{size});
	    $item->{path} = PVE::Storage::path($cfg, $item->{volid});
	    $volid_hash->{$item->{volid}} = $item;
	}
    }

    return $volid_hash;
}

sub get_used_paths {
    my ($vmid, $storecfg, $conf, $scan_snapshots, $skip_drive) = @_;

    my $used_path = {};

    my $scan_config = sub {
	my ($cref, $snapname) = @_;

	foreach my $key (keys %$cref) {
	    my $value = $cref->{$key};
	    if (valid_drivename($key)) {
		next if $skip_drive && $key eq $skip_drive;
		my $drive = parse_drive($key, $value);
		next if !$drive || !$drive->{file} || drive_is_cdrom($drive);
		if ($drive->{file} =~ m!^/!) {
		    $used_path->{$drive->{file}}++; # = 1;
		} else {
		    my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);
		    next if !$storeid;
		    my $scfg = PVE::Storage::storage_config($storecfg, $storeid, 1);
		    next if !$scfg;
		    my $path = PVE::Storage::path($storecfg, $drive->{file}, $snapname);
		    $used_path->{$path}++; # = 1;
		}
	    }
	}
    };

    &$scan_config($conf);

    undef $skip_drive;

    if ($scan_snapshots) {
	foreach my $snapname (keys %{$conf->{snapshots}}) {
	    &$scan_config($conf->{snapshots}->{$snapname}, $snapname);
	}
    }

    return $used_path;
}

sub update_disksize {
    my ($vmid, $conf, $volid_hash) = @_;

    my $changes;

    my $used = {};

    # Note: it is allowed to define multiple storages with same path (alias), so
    # we need to check both 'volid' and real 'path' (two different volid can point
    # to the same path).

    my $usedpath = {};

    # update size info
    foreach my $opt (keys %$conf) {
	if (valid_drivename($opt)) {
	    my $drive = parse_drive($opt, $conf->{$opt});
	    my $volid = $drive->{file};
	    next if !$volid;

	    $used->{$volid} = 1;
	    if ($volid_hash->{$volid} &&
		(my $path = $volid_hash->{$volid}->{path})) {
		$usedpath->{$path} = 1;
	    }

	    next if drive_is_cdrom($drive);
	    next if !$volid_hash->{$volid};

	    $drive->{size} = $volid_hash->{$volid}->{size};
	    my $new = print_drive($vmid, $drive);
	    if ($new ne $conf->{$opt}) {
		$changes = 1;
		$conf->{$opt} = $new;
	    }
	}
    }

    # remove 'unusedX' entry if volume is used
    foreach my $opt (keys %$conf) {
	next if $opt !~ m/^unused\d+$/;
	my $volid = $conf->{$opt};
	my $path = $volid_hash->{$volid}->{path} if $volid_hash->{$volid};
	if ($used->{$volid} || ($path && $usedpath->{$path})) {
	    $changes = 1;
	    delete $conf->{$opt};
	}
    }

    foreach my $volid (sort keys %$volid_hash) {
	next if $volid =~ m/vm-$vmid-state-/;
	next if $used->{$volid};
	my $path = $volid_hash->{$volid}->{path};
	next if !$path; # just to be sure
	next if $usedpath->{$path};
	$changes = 1;
	add_unused_volume($conf, $volid);
	$usedpath->{$path} = 1; # avoid to add more than once (aliases)
    }

    return $changes;
}

sub rescan {
    my ($vmid, $nolock) = @_;

    my $cfg = PVE::Cluster::cfs_read_file("storage.cfg");

    my $volid_hash = scan_volids($cfg, $vmid);

    my $updatefn =  sub {
	my ($vmid) = @_;

	my $conf = load_config($vmid);

	check_lock($conf);

	my $vm_volids = {};
	foreach my $volid (keys %$volid_hash) {
	    my $info = $volid_hash->{$volid};
	    $vm_volids->{$volid} = $info if $info->{vmid} && $info->{vmid} == $vmid;
	}

	my $changes = update_disksize($vmid, $conf, $vm_volids);

	update_config_nolock($vmid, $conf, 1) if $changes;
    };

    if (defined($vmid)) {
	if ($nolock) {
	    &$updatefn($vmid);
	} else {
	    lock_config($vmid, $updatefn, $vmid);
	}
    } else {
	my $vmlist = config_list();
	foreach my $vmid (keys %$vmlist) {
	    if ($nolock) {
		&$updatefn($vmid);
	    } else {
		lock_config($vmid, $updatefn, $vmid);
	    }
	}
    }
}

sub restore_vma_archive {
    my ($archive, $vmid, $user, $opts, $comp) = @_;

    my $input = $archive eq '-' ? "<&STDIN" : undef;
    my $readfrom = $archive;

    my $uncomp = '';
    if ($comp) {
	$readfrom = '-';
	my $qarchive = PVE::Tools::shellquote($archive);
	if ($comp eq 'gzip') {
	    $uncomp = "zcat $qarchive|";
	} elsif ($comp eq 'lzop') {
	    $uncomp = "lzop -d -c $qarchive|";
	} else {
	    die "unknown compression method '$comp'\n";
	}

    }

    my $tmpdir = "/var/tmp/vzdumptmp$$";
    rmtree $tmpdir;

    # disable interrupts (always do cleanups)
    local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = sub {
	warn "got interrupt - ignored\n";
    };

    my $mapfifo = "/var/tmp/vzdumptmp$$.fifo";
    POSIX::mkfifo($mapfifo, 0600);
    my $fifofh;

    my $openfifo = sub {
	open($fifofh, '>', $mapfifo) || die $!;
    };

    my $cmd = "${uncomp}vma extract -v -r $mapfifo $readfrom $tmpdir";

    my $oldtimeout;
    my $timeout = 5;

    my $devinfo = {};

    my $rpcenv = PVE::RPCEnvironment::get();

    my $conffile = config_file($vmid);
    my $tmpfn = "$conffile.$$.tmp";

    # Note: $oldconf is undef if VM does not exists
    my $oldconf = PVE::Cluster::cfs_read_file(cfs_config_path($vmid));

    my $print_devmap = sub {
	my $virtdev_hash = {};

	my $cfgfn = "$tmpdir/qemu-server.conf";

	# we can read the config - that is already extracted
	my $fh = IO::File->new($cfgfn, "r") ||
	    "unable to read qemu-server.conf - $!\n";

	while (defined(my $line = <$fh>)) {
	    if ($line =~ m/^\#qmdump\#map:(\S+):(\S+):(\S*):(\S*):$/) {
		my ($virtdev, $devname, $storeid, $format) = ($1, $2, $3, $4);
		die "archive does not contain data for drive '$virtdev'\n"
		    if !$devinfo->{$devname};
		if (defined($opts->{storage})) {
		    $storeid = $opts->{storage} || 'local';
		} elsif (!$storeid) {
		    $storeid = 'local';
		}
		$format = 'raw' if !$format;
		$devinfo->{$devname}->{devname} = $devname;
		$devinfo->{$devname}->{virtdev} = $virtdev;
		$devinfo->{$devname}->{format} = $format;
		$devinfo->{$devname}->{storeid} = $storeid;

		# check permission on storage
		my $pool = $opts->{pool}; # todo: do we need that?
		if ($user ne 'root@pam') {
		    $rpcenv->check($user, "/storage/$storeid", ['Datastore.AllocateSpace']);
		}

		$virtdev_hash->{$virtdev} = $devinfo->{$devname};
	    }
	}

	foreach my $devname (keys %$devinfo) {
	    die "found no device mapping information for device '$devname'\n"
		if !$devinfo->{$devname}->{virtdev};
	}

	my $cfg = cfs_read_file('storage.cfg');

	# create empty/temp config
	if ($oldconf) {
	    PVE::Tools::file_set_contents($conffile, "memory: 128\n");
	    foreach_drive($oldconf, sub {
		my ($ds, $drive) = @_;

		return if drive_is_cdrom($drive);

		my $volid = $drive->{file};

		return if !$volid || $volid =~ m|^/|;

		my ($path, $owner) = PVE::Storage::path($cfg, $volid);
		return if !$path || !$owner || ($owner != $vmid);

		# Note: only delete disk we want to restore
		# other volumes will become unused
		if ($virtdev_hash->{$ds}) {
		    PVE::Storage::vdisk_free($cfg, $volid);
		}
	    });
	}

	my $map = {};
	foreach my $virtdev (sort keys %$virtdev_hash) {
	    my $d = $virtdev_hash->{$virtdev};
	    my $alloc_size = int(($d->{size} + 1024 - 1)/1024);
	    my $scfg = PVE::Storage::storage_config($cfg, $d->{storeid});

	    # test if requested format is supported
	    my ($defFormat, $validFormats) = PVE::Storage::storage_default_format($cfg, $d->{storeid});
	    my $supported = grep { $_ eq $d->{format} } @$validFormats;
	    $d->{format} = $defFormat if !$supported;

	    my $volid = PVE::Storage::vdisk_alloc($cfg, $d->{storeid}, $vmid,
						  $d->{format}, undef, $alloc_size);
	    print STDERR "new volume ID is '$volid'\n";
	    $d->{volid} = $volid;
	    my $path = PVE::Storage::path($cfg, $volid);

	    my $write_zeros = 1;
	    # fixme: what other storages types initialize volumes with zero?
	    if ($scfg->{type} eq 'dir' || $scfg->{type} eq 'nfs' || $scfg->{type} eq 'glusterfs' ||
		$scfg->{type} eq 'sheepdog' || $scfg->{type} eq 'rbd') {
		$write_zeros = 0;
	    }

	    print $fifofh "${write_zeros}:$d->{devname}=$path\n";

	    print "map '$d->{devname}' to '$path' (write zeros = ${write_zeros})\n";
	    $map->{$virtdev} = $volid;
	}

	$fh->seek(0, 0) || die "seek failed - $!\n";

	my $outfd = new IO::File ($tmpfn, "w") ||
	    die "unable to write config for VM $vmid\n";

	my $cookie = { netcount => 0 };
	while (defined(my $line = <$fh>)) {
	    restore_update_config_line($outfd, $cookie, $vmid, $map, $line, $opts->{unique});
	}

	$fh->close();
	$outfd->close();
    };

    eval {
	# enable interrupts
	local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = $SIG{PIPE} = sub {
	    die "interrupted by signal\n";
	};
	local $SIG{ALRM} = sub { die "got timeout\n"; };

	$oldtimeout = alarm($timeout);

	my $parser = sub {
	    my $line = shift;

	    print "$line\n";

	    if ($line =~ m/^DEV:\sdev_id=(\d+)\ssize:\s(\d+)\sdevname:\s(\S+)$/) {
		my ($dev_id, $size, $devname) = ($1, $2, $3);
		$devinfo->{$devname} = { size => $size, dev_id => $dev_id };
	    } elsif ($line =~ m/^CTIME: /) {
		# we correctly received the vma config, so we can disable
		# the timeout now for disk allocation (set to 10 minutes, so
		# that we always timeout if something goes wrong)
		alarm(600);
		&$print_devmap();
		print $fifofh "done\n";
		my $tmp = $oldtimeout || 0;
		$oldtimeout = undef;
		alarm($tmp);
		close($fifofh);
	    }
	};

	print "restore vma archive: $cmd\n";
	run_command($cmd, input => $input, outfunc => $parser, afterfork => $openfifo);
    };
    my $err = $@;

    alarm($oldtimeout) if $oldtimeout;

    unlink $mapfifo;

    if ($err) {
	rmtree $tmpdir;
	unlink $tmpfn;

	my $cfg = cfs_read_file('storage.cfg');
	foreach my $devname (keys %$devinfo) {
	    my $volid = $devinfo->{$devname}->{volid};
	    next if !$volid;
	    eval {
		if ($volid =~ m|^/|) {
		    unlink $volid || die 'unlink failed\n';
		} else {
		    PVE::Storage::vdisk_free($cfg, $volid);
		}
		print STDERR "temporary volume '$volid' sucessfuly removed\n";
	    };
	    print STDERR "unable to cleanup '$volid' - $@" if $@;
	}
	die $err;
    }

    rmtree $tmpdir;

    rename($tmpfn, $conffile) ||
	die "unable to commit configuration file '$conffile'\n";

    PVE::Cluster::cfs_update(); # make sure we read new file

    eval { rescan($vmid, 1); };
    warn $@ if $@;
}

sub restore_tar_archive {
    my ($archive, $vmid, $user, $opts) = @_;

    if ($archive ne '-') {
	my $firstfile = tar_archive_read_firstfile($archive);
	die "ERROR: file '$archive' dos not lock like a QemuServer vzdump backup\n"
	    if $firstfile ne 'qemu-server.conf';
    }

    my $storecfg = cfs_read_file('storage.cfg');

    # destroy existing data - keep empty config
    my $vmcfgfn = config_file($vmid);
    destroy_vm($storecfg, $vmid, 1) if -f $vmcfgfn;

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

    my $conffile = config_file($vmid);
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

	my $cookie = { netcount => 0 };
	while (defined (my $line = <$srcfd>)) {
	    restore_update_config_line($outfd, $cookie, $vmid, $map, $line, $opts->{unique});
	}

	$srcfd->close();
	$outfd->close();
    };
    my $err = $@;

    if ($err) {

	unlink $tmpfn;

	tar_restore_cleanup($storecfg, "$tmpdir/qmrestore.stat") if !$opts->{info};

	die $err;
    }

    rmtree $tmpdir;

    rename $tmpfn, $conffile ||
	die "unable to commit configuration file '$conffile'\n";

    PVE::Cluster::cfs_update(); # make sure we read new file

    eval { rescan($vmid, 1); };
    warn $@ if $@;
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

	die "you can't take a snapshot if it's a template\n"
	    if is_template($conf);

	check_lock($conf);

	$conf->{lock} = 'snapshot';

	die "snapshot name '$snapname' already used\n"
	    if defined($conf->{snapshots}->{$snapname});

	my $storecfg = PVE::Storage::config();
	die "snapshot feature is not available" if !has_feature('snapshot', $conf, $storecfg);

	$snap = $conf->{snapshots}->{$snapname} = {};

	if ($save_vmstate && check_running($vmid)) {
	    $snap->{vmstate} = &$alloc_vmstate_volid($storecfg, $vmid, $conf, $snapname);
	}

	&$snapshot_copy_config($conf, $snap);

	$snap->{snapstate} = "prepare";
	$snap->{snaptime} = time();
	$snap->{description} = $comment if $comment;

	# always overwrite machine if we save vmstate. This makes sure we
	# can restore it later using correct machine type
	$snap->{machine} = get_current_qemu_machine($vmid) if $snap->{vmstate};

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

	my $has_machine_config = defined($conf->{machine});

	my $snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap);

	die "wrong snapshot state\n"
	    if !($snap->{snapstate} && $snap->{snapstate} eq "prepare");

	delete $snap->{snapstate};
	delete $conf->{lock};

	my $newconf = &$snapshot_apply_config($conf, $snap);

	delete $newconf->{machine} if !$has_machine_config;

	$newconf->{parent} = $snapname;

	update_config_nolock($vmid, $newconf, 1);
    };

    lock_config($vmid, $updatefn);
};

sub snapshot_rollback {
    my ($vmid, $snapname) = @_;

    my $prepare = 1;

    my $storecfg = PVE::Storage::config();

    my $conf = load_config($vmid);

    my $get_snapshot_config = sub {

	die "you can't rollback if vm is a template\n" if is_template($conf);

	my $res = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($res);

	return $res;
    };

    my $snap = &$get_snapshot_config();

    foreach_drive($snap, sub {
	my ($ds, $drive) = @_;

	return if drive_is_cdrom($drive);

	my $volid = $drive->{file};

	PVE::Storage::volume_rollback_is_possible($storecfg, $volid, $snapname);
    });

    my $updatefn = sub {

	$conf = load_config($vmid);

	$snap = &$get_snapshot_config();

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

	my $forcemachine;

	if (!$prepare) {
	    my $has_machine_config = defined($conf->{machine});

	    # copy snapshot config to current config
	    $conf = &$snapshot_apply_config($conf, $snap);
	    $conf->{parent} = $snapname;

	    # Note: old code did not store 'machine', so we try to be smart
	    # and guess the snapshot was generated with kvm 1.4 (pc-i440fx-1.4).
	    $forcemachine = $conf->{machine} || 'pc-i440fx-1.4';
	    # we remove the 'machine' configuration if not explicitly specified
	    # in the original config.
	    delete $conf->{machine} if $snap->{vmstate} && !$has_machine_config;
	}

 	update_config_nolock($vmid, $conf, 1);

	if (!$prepare && $snap->{vmstate}) {
	    my $statefile = PVE::Storage::path($storecfg, $snap->{vmstate});
	    vm_start($storecfg, $vmid, $statefile, undef, undef, undef, $forcemachine);
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
	my $stat = vm_mon_cmd_nocheck($vmid, "query-savevm");
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
    my ($vmid, $snapname, $save_vmstate, $comment) = @_;

    my $snap = &$snapshot_prepare($vmid, $snapname, $save_vmstate, $comment);

    $save_vmstate = 0 if !$snap->{vmstate}; # vm is not running

    my $config = load_config($vmid);

    my $running = check_running($vmid);

    my $freezefs = $running && $config->{agent};
    $freezefs = 0 if $snap->{vmstate}; # not needed if we save RAM

    my $drivehash = {};

    if ($freezefs) {
	eval { vm_mon_cmd($vmid, "guest-fsfreeze-freeze"); };
	warn "guest-fsfreeze-freeze problems - $@" if $@;
    }

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

    if ($running) {
	eval { vm_mon_cmd($vmid, "savevm-end")  };
	warn $@ if $@;

	if ($freezefs) {
	    eval { vm_mon_cmd($vmid, "guest-fsfreeze-thaw"); };
	    warn "guest-fsfreeze-thaw problems - $@" if $@;
	}

	# savevm-end is async, we need to wait
	for (;;) {
	    my $stat = vm_mon_cmd_nocheck($vmid, "query-savevm");
	    if (!$stat->{bytes}) {
		last;
	    } else {
		print "savevm not yet finished\n";
		sleep(1);
		next;
	    }
	}
    }

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

	if (!$drivehash) {
	    check_lock($conf);
	    die "you can't delete a snapshot if vm is a template\n"
		if is_template($conf);
	}

	$snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap);

	# remove parent refs
	if (!$prepare) {
	    &$unlink_parent($conf, $snap->{parent});
	    foreach my $sn (keys %{$conf->{snapshots}}) {
		next if $sn eq $snapname;
		&$unlink_parent($conf->{snapshots}->{$sn}, $snap->{parent});
	    }
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

sub has_feature {
    my ($feature, $conf, $storecfg, $snapname, $running) = @_;

    my $err;
    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	return if drive_is_cdrom($drive);
	my $volid = $drive->{file};
	$err = 1 if !PVE::Storage::volume_has_feature($storecfg, $feature, $volid, $snapname, $running);
    });

    return $err ? 0 : 1;
}

sub template_create {
    my ($vmid, $conf, $disk) = @_;

    my $storecfg = PVE::Storage::config();

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;

	return if drive_is_cdrom($drive);
	return if $disk && $ds ne $disk;

	my $volid = $drive->{file};
	return if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);

	my $voliddst = PVE::Storage::vdisk_create_base($storecfg, $volid);
	$drive->{file} = $voliddst;
	$conf->{$ds} = print_drive($vmid, $drive);
	update_config_nolock($vmid, $conf, 1);
    });
}

sub is_template {
    my ($conf) = @_;

    return 1 if defined $conf->{template} && $conf->{template} == 1;
}

sub qemu_img_convert {
    my ($src_volid, $dst_volid, $size, $snapname) = @_;

    my $storecfg = PVE::Storage::config();
    my ($src_storeid, $src_volname) = PVE::Storage::parse_volume_id($src_volid, 1);
    my ($dst_storeid, $dst_volname) = PVE::Storage::parse_volume_id($dst_volid, 1);

    if ($src_storeid && $dst_storeid) {
	my $src_scfg = PVE::Storage::storage_config($storecfg, $src_storeid);
	my $dst_scfg = PVE::Storage::storage_config($storecfg, $dst_storeid);

	my $src_format = qemu_img_format($src_scfg, $src_volname);
	my $dst_format = qemu_img_format($dst_scfg, $dst_volname);

	my $src_path = PVE::Storage::path($storecfg, $src_volid, $snapname);
	my $dst_path = PVE::Storage::path($storecfg, $dst_volid);

	my $cmd = [];
	push @$cmd, '/usr/bin/qemu-img', 'convert', '-t', 'writeback', '-p', '-n';
	push @$cmd, '-s', $snapname if($snapname && $src_format eq "qcow2");
	push @$cmd, '-f', $src_format, '-O', $dst_format, $src_path, $dst_path;

	my $parser = sub {
	    my $line = shift;
	    if($line =~ m/\((\S+)\/100\%\)/){
		my $percent = $1;
		my $transferred = int($size * $percent / 100);
		my $remaining = $size - $transferred;

		print "transferred: $transferred bytes remaining: $remaining bytes total: $size bytes progression: $percent %\n";
	    }

	};

	eval  { run_command($cmd, timeout => undef, outfunc => $parser); };
	my $err = $@;
	die "copy failed: $err" if $err;
    }
}

sub qemu_img_format {
    my ($scfg, $volname) = @_;

    if ($scfg->{path} && $volname =~ m/\.(raw|qcow2|qed|vmdk)$/) {
	return $1;
    } elsif ($scfg->{type} eq 'iscsi') {
	return "host_device";
    } else {
	return "raw";
    }
}

sub qemu_drive_mirror {
    my ($vmid, $drive, $dst_volid, $vmiddst) = @_;

    my $count = 0;
    my $old_len = 0;
    my $frozen = undef;
    my $maxwait = 120;

    my $storecfg = PVE::Storage::config();
    my ($dst_storeid, $dst_volname) = PVE::Storage::parse_volume_id($dst_volid);

    my $dst_scfg = PVE::Storage::storage_config($storecfg, $dst_storeid);

    my $format;
    if ($dst_volname =~ m/\.(raw|qcow2)$/){
	$format = $1;
    }

    my $dst_path = PVE::Storage::path($storecfg, $dst_volid);

    my $opts = { timeout => 10, device => "drive-$drive", mode => "existing", sync => "full", target => $dst_path };
    $opts->{format} = $format if $format;

    #fixme : sometime drive-mirror timeout, but works fine after.
    # (I have see the problem with big volume > 200GB), so we need to eval
    eval { vm_mon_cmd($vmid, "drive-mirror", %$opts); };
    # ignore errors here

    eval {
	while (1) {
	    my $stats = vm_mon_cmd($vmid, "query-block-jobs");
	    my $stat = @$stats[0];
	    die "mirroring job seem to have die. Maybe do you have bad sectors?" if !$stat;
	    die "error job is not mirroring" if $stat->{type} ne "mirror";

	    my $busy = $stat->{busy};

	    if (my $total = $stat->{len}) {
		my $transferred = $stat->{offset} || 0;
		my $remaining = $total - $transferred;
		my $percent = sprintf "%.2f", ($transferred * 100 / $total);

		print "transferred: $transferred bytes remaining: $remaining bytes total: $total bytes progression: $percent % busy: $busy\n";
	    }

	    if ($stat->{len} == $stat->{offset}) {
		if ($busy eq 'false') {

		    last if $vmiddst != $vmid;

		    # try to switch the disk if source and destination are on the same guest
		    eval { vm_mon_cmd($vmid, "block-job-complete", device => "drive-$drive") };
		    last if !$@;
		    die $@ if $@ !~ m/cannot be completed/;
		}

		if ($count > $maxwait) {
		    # if too much writes to disk occurs at the end of migration
		    #the disk needs to be freezed to be able to complete the migration
		    vm_suspend($vmid,1);
		    $frozen = 1;
		}
		$count ++
	    }
	    $old_len = $stat->{offset};
	    sleep 1;
	}

	vm_resume($vmid, 1) if $frozen;

    };
    my $err = $@;

    my $cancel_job = sub {
	vm_mon_cmd($vmid, "block-job-cancel", device => "drive-$drive");
	while (1) {
	    my $stats = vm_mon_cmd($vmid, "query-block-jobs");
	    my $stat = @$stats[0];
	    last if !$stat;
	    sleep 1;
	}
    };

    if ($err) {
	eval { &$cancel_job(); };
	die "mirroring error: $err";
    }

    if ($vmiddst != $vmid) {
	# if we clone a disk for a new target vm, we don't switch the disk
	&$cancel_job(); # so we call block-job-cancel
    }
}

sub clone_disk {
    my ($storecfg, $vmid, $running, $drivename, $drive, $snapname,
	$newvmid, $storage, $format, $full, $newvollist) = @_;

    my $newvolid;

    if (!$full) {
	print "create linked clone of drive $drivename ($drive->{file})\n";
	$newvolid = PVE::Storage::vdisk_clone($storecfg,  $drive->{file}, $newvmid, $snapname);
	push @$newvollist, $newvolid;
    } else {
	my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file});
	$storeid = $storage if $storage;

	my ($defFormat, $validFormats) = PVE::Storage::storage_default_format($storecfg, $storeid);
	if (!$format) {
	    $format = $drive->{format} || $defFormat;
	}

	# test if requested format is supported - else use default
	my $supported = grep { $_ eq $format } @$validFormats;
	$format = $defFormat if !$supported;

	my ($size) = PVE::Storage::volume_size_info($storecfg, $drive->{file}, 3);

	print "create full clone of drive $drivename ($drive->{file})\n";
	$newvolid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $newvmid, $format, undef, ($size/1024));
	push @$newvollist, $newvolid;

	if (!$running || $snapname) {
	    qemu_img_convert($drive->{file}, $newvolid, $size, $snapname);
	} else {
	    qemu_drive_mirror($vmid, $drivename, $newvolid, $newvmid);
	}
    }

    my ($size) = PVE::Storage::volume_size_info($storecfg, $newvolid, 3);

    my $disk = $drive;
    $disk->{format} = undef;
    $disk->{file} = $newvolid;
    $disk->{size} = $size;

    return $disk;
}

# this only works if VM is running
sub get_current_qemu_machine {
    my ($vmid) = @_;

    my $cmd = { execute => 'query-machines', arguments => {} };
    my $res = vm_qmp_command($vmid, $cmd);

    my ($current, $default);
    foreach my $e (@$res) {
	$default = $e->{name} if $e->{'is-default'};
	$current = $e->{name} if $e->{'is-current'};
    }

    # fallback to the default machine if current is not supported by qemu
    return $current || $default || 'pc';
}

sub qemu_machine_feature_enabled {
    my ($machine, $kvmver, $version_major, $version_minor) = @_;

    my $current_major;
    my $current_minor;

    if ($machine && $machine =~ m/^(pc(-i440fx|-q35)?-(\d+)\.(\d+))/) {

	$current_major = $3;
	$current_minor = $4;

    } elsif ($kvmver =~ m/^(\d+)\.(\d+)/) {

	$current_major = $1;
	$current_minor = $2;
    }

    return 1 if $current_major >= $version_major && $current_minor >= $version_minor;


}

sub lspci {

    my $devices = {};

    dir_glob_foreach("$pcisysfs/devices", '[a-f0-9]{4}:([a-f0-9]{2}:[a-f0-9]{2})\.([0-9])', sub {
            my (undef, $id, $function) = @_;
	    my $res = { id => $id, function => $function};
	    push @{$devices->{$id}}, $res;
    });

    return $devices;
}

sub vm_iothreads_list {
    my ($vmid) = @_;

    my $res = vm_mon_cmd($vmid, 'query-iothreads');

    my $iothreads = {};
    foreach my $iothread (@$res) {
	$iothreads->{ $iothread->{id} } = $iothread->{"thread-id"};
    }

    return $iothreads;
}

1;
