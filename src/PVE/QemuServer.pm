package PVE::QemuServer;

use strict;
use warnings;

use Cwd 'abs_path';
use Digest::SHA;
use Fcntl ':flock';
use Fcntl;
use File::Basename;
use File::Copy qw(copy);
use File::Path;
use Getopt::Long;
use IO::Dir;
use IO::File;
use IO::Handle;
use IO::Select;
use IO::Socket::UNIX;
use IPC::Open3;
use JSON;
use MIME::Base64;
use POSIX;
use Storable qw(dclone);
use Time::HiRes qw(gettimeofday usleep);
use URI::Escape;
use UUID;

use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file);
use PVE::CGroup;
use PVE::CpuSet;
use PVE::DataCenterConfig;
use PVE::Exception qw(raise raise_param_exc);
use PVE::Format qw(render_duration render_bytes);
use PVE::GuestHelpers qw(safe_string_ne safe_num_ne safe_boolean_ne);
use PVE::Mapping::Dir;
use PVE::Mapping::PCI;
use PVE::Mapping::USB;
use PVE::Network::SDN::Vnets;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option parse_property_string);
use PVE::ProcFSTools;
use PVE::PBSClient;
use PVE::RESTEnvironment qw(log_warn);
use PVE::RPCEnvironment;
use PVE::SafeSyslog;
use PVE::Storage;
use PVE::SysFSTools;
use PVE::Systemd;
use PVE::Tools
    qw(run_command file_read_firstline file_get_contents dir_glob_foreach get_host_arch $IPV6RE);

use PVE::QMPClient;
use PVE::QemuConfig;
use PVE::QemuConfig::NoWrite;
use PVE::QemuMigrate::Helpers;
use PVE::QemuServer::Agent qw(qga_check_running);
use PVE::QemuServer::Blockdev;
use PVE::QemuServer::BlockJob;
use PVE::QemuServer::Helpers
    qw(config_aware_timeout get_iscsi_initiator_name min_version kvm_user_version windows_version);
use PVE::QemuServer::Cloudinit;
use PVE::QemuServer::CGroup;
use PVE::QemuServer::CPUConfig
    qw(print_cpu_device get_cpu_options get_cpu_bitness is_native_arch get_amd_sev_object get_amd_sev_type);
use PVE::QemuServer::Drive qw(
    is_valid_drivename
    checked_volume_format
    drive_is_cloudinit
    drive_is_cdrom
    drive_is_read_only
    parse_drive
    print_drive
    storage_allows_io_uring_default
);
use PVE::QemuServer::Machine;
use PVE::QemuServer::Memory qw(get_current_memory);
use PVE::QemuServer::MetaInfo;
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::Network;
use PVE::QemuServer::OVMF;
use PVE::QemuServer::PCI qw(print_pci_addr print_pcie_addr print_pcie_root_port parse_hostpci);
use PVE::QemuServer::QemuImage;
use PVE::QemuServer::QMPHelpers qw(qemu_deviceadd qemu_devicedel qemu_objectadd qemu_objectdel);
use PVE::QemuServer::RNG qw(parse_rng print_rng_device_commandline print_rng_object_commandline);
use PVE::QemuServer::RunState;
use PVE::QemuServer::StateFile;
use PVE::QemuServer::USB;
use PVE::QemuServer::Virtiofs qw(max_virtiofs start_all_virtiofsd);
use PVE::QemuServer::DBusVMState;

my $have_ha_config;
eval {
    require PVE::HA::Config;
    $have_ha_config = 1;
};

my sub vm_is_ha_managed {
    my ($vmid) = @_;
    die "cannot check if VM is managed by HA, missing HA Config module!\n" if !$have_ha_config;
    return PVE::HA::Config::vm_is_ha_managed($vmid);
}

my $cpuinfo = PVE::ProcFSTools::read_cpuinfo();

# Note about locking: we use flock on the config file protect against concurrent actions.
# Additionally, we have a 'lock' setting in the config file. This  can be set to 'migrate',
# 'backup', 'snapshot' or 'rollback'. Most actions are not allowed when such lock is set.
# But you can ignore this kind of lock with the --skiplock flag.

cfs_register_file(
    '/qemu-server/', \&parse_vm_config, \&write_vm_config,
);

PVE::JSONSchema::register_standard_option(
    'pve-qm-stateuri',
    {
        description => "Some command save/restore state from this location.",
        type => 'string',
        maxLength => 128,
        optional => 1,
    },
);

# FIXME: remove in favor of just using the INotify one, it's cached there exactly the same way
my $nodename_cache;

sub nodename {
    $nodename_cache //= PVE::INotify::nodename();
    return $nodename_cache;
}

my $watchdog_fmt = {
    model => {
        default_key => 1,
        type => 'string',
        enum => [qw(i6300esb ib700)],
        description => "Watchdog type to emulate.",
        default => 'i6300esb',
        optional => 1,
    },
    action => {
        type => 'string',
        enum => [qw(reset shutdown poweroff pause debug none)],
        description =>
            "The action to perform if after activation the guest fails to poll the watchdog in time.",
        optional => 1,
    },
};
PVE::JSONSchema::register_format('pve-qm-watchdog', $watchdog_fmt);

my $agent_fmt = {
    enabled => {
        description =>
            "Enable/disable communication with a QEMU Guest Agent (QGA) running in the VM.",
        type => 'boolean',
        default => 0,
        default_key => 1,
    },
    fstrim_cloned_disks => {
        description => "Run fstrim after moving a disk or migrating the VM.",
        type => 'boolean',
        optional => 1,
        default => 0,
    },
    'freeze-fs-on-backup' => {
        description => "Freeze/thaw guest filesystems on backup for consistency.",
        type => 'boolean',
        optional => 1,
        default => 1,
    },
    type => {
        description => "Select the agent type",
        type => 'string',
        default => 'virtio',
        optional => 1,
        enum => [qw(virtio isa)],
    },
};

my $vga_fmt = {
    type => {
        description => "Select the VGA type. Using type 'cirrus' is not recommended.",
        type => 'string',
        default => 'std',
        optional => 1,
        default_key => 1,
        enum => [
            qw(cirrus qxl qxl2 qxl3 qxl4 none serial0 serial1 serial2 serial3 std virtio virtio-gl vmware)
        ],
    },
    memory => {
        description => "Sets the VGA memory (in MiB). Has no effect with serial display.",
        type => 'integer',
        optional => 1,
        minimum => 4,
        maximum => 512,
    },
    clipboard => {
        description =>
            'Enable a specific clipboard. If not set, depending on the display type the'
            . ' SPICE one will be added. Migration with VNC clipboard is not yet supported!',
        type => 'string',
        enum => ['vnc'],
        optional => 1,
    },
};

my $ivshmem_fmt = {
    size => {
        type => 'integer',
        minimum => 1,
        description => "The size of the file in MB.",
    },
    name => {
        type => 'string',
        pattern => '[a-zA-Z0-9\-]+',
        optional => 1,
        format_description => 'string',
        description =>
            "The name of the file. Will be prefixed with 'pve-shm-'. Default is the VMID. Will be deleted when the VM is stopped.",
    },
};

my $audio_fmt = {
    device => {
        type => 'string',
        enum => [qw(ich9-intel-hda intel-hda AC97)],
        description => "Configure an audio device.",
    },
    driver => {
        type => 'string',
        enum => ['spice', 'none'],
        default => 'spice',
        optional => 1,
        description => "Driver backend for the audio device.",
    },
};

my $spice_enhancements_fmt = {
    foldersharing => {
        type => 'boolean',
        optional => 1,
        default => '0',
        description =>
            "Enable folder sharing via SPICE. Needs Spice-WebDAV daemon installed in the VM.",
    },
    videostreaming => {
        type => 'string',
        enum => ['off', 'all', 'filter'],
        default => 'off',
        optional => 1,
        description => "Enable video streaming. Uses compression for detected video streams.",
    },
};

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
        type => 'string',
        format => 'pve-hotplug-features',
        description => "Selectively enable hotplug features. This is a comma separated list of"
            . " hotplug features: 'network', 'disk', 'cpu', 'memory', 'usb' and 'cloudinit'. Use '0' to disable"
            . " hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`."
            . " USB hotplugging is possible for guests with machine version >= 7.1 and ostype l26 or"
            . " windows > 7.",
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
        enum => [
            qw(backup clone create migrate rollback snapshot snapshot-delete suspending suspended)],
    },
    cpulimit => {
        optional => 1,
        type => 'number',
        description => "Limit of CPU usage.",
        verbose_description => "Limit of CPU usage.\n\nNOTE: If the computer has 2 CPUs, it has"
            . " total of '2' CPU time. Value '0' indicates no CPU limit.",
        minimum => 0,
        maximum => 128,
        default => 0,
    },
    cpuunits => {
        optional => 1,
        type => 'integer',
        description => "CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.",
        verbose_description =>
            "CPU weight for a VM. Argument is used in the kernel fair scheduler."
            . " The larger the number is, the more CPU time this VM gets. Number is relative to"
            . " weights of all the other running VMs.",
        minimum => 1,
        maximum => 262144,
        default => 'cgroup v1: 1024, cgroup v2: 100',
    },
    memory => {
        optional => 1,
        type => 'string',
        description => "Memory properties.",
        format => $PVE::QemuServer::Memory::memory_fmt,
    },
    'amd-sev' => {
        description => "Secure Encrypted Virtualization (SEV) features by AMD CPUs",
        optional => 1,
        format => 'pve-qemu-sev-fmt',
        type => 'string',
    },
    balloon => {
        optional => 1,
        type => 'integer',
        description =>
            "Amount of target RAM for the VM in MiB. Using zero disables the ballon driver.",
        minimum => 0,
    },
    shares => {
        optional => 1,
        type => 'integer',
        description =>
            "Amount of memory shares for auto-ballooning. The larger the number is, the"
            . " more memory this VM gets. Number is relative to weights of all other running VMs."
            . " Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.",
        minimum => 0,
        maximum => 50000,
        default => 1000,
    },
    keyboard => {
        optional => 1,
        type => 'string',
        description =>
            "Keyboard layout for VNC server. This option is generally not required and"
            . " is often better handled from within the guest OS.",
        enum => PVE::Tools::kvmkeymaplist(),
        default => undef,
    },
    name => {
        optional => 1,
        type => 'string',
        format => 'dns-name',
        description => "Set a name for the VM. Only used on the configuration web interface.",
    },
    scsihw => {
        optional => 1,
        type => 'string',
        description => "SCSI controller model",
        enum => [qw(lsi lsi53c810 virtio-scsi-pci virtio-scsi-single megasas pvscsi)],
        default => 'lsi',
    },
    description => {
        optional => 1,
        type => 'string',
        description => "Description for the VM. Shown in the web-interface VM's summary."
            . " This is saved as comment inside the configuration file.",
        maxLength => 1024 * 8,
    },
    ostype => {
        optional => 1,
        type => 'string',
        # NOTE: When extending, also consider extending `%guest_types` in `Import/ESXi.pm`.
        enum => [qw(other wxp w2k w2k3 w2k8 wvista win7 win8 win10 win11 l24 l26 solaris)],
        description => "Specify guest operating system.",
        verbose_description => <<EODESC,
Specify guest operating system. This is used to enable special
optimization/features for specific operating systems:

[horizontal]
other;; unspecified OS
wxp;; Microsoft Windows XP
w2k;; Microsoft Windows 2000
w2k3;; Microsoft Windows 2003
w2k8;; Microsoft Windows 2008
wvista;; Microsoft Windows Vista
win7;; Microsoft Windows 7
win8;; Microsoft Windows 8/2012/2012r2
win10;; Microsoft Windows 10/2016/2019
win11;; Microsoft Windows 11/2022/2025
l24;; Linux 2.4 Kernel
l26;; Linux 2.6 - 6.X Kernel
solaris;; Solaris/OpenSolaris/OpenIndiania kernel
EODESC
    },
    boot => {
        optional => 1,
        type => 'string',
        format => 'pve-qm-boot',
        description =>
            "Specify guest boot order. Use the 'order=' sub-property as usage with no"
            . " key or 'legacy=' is deprecated.",
    },
    bootdisk => {
        optional => 1,
        type => 'string',
        format => 'pve-qm-bootdisk',
        description =>
            "Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.",
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
        description => "Enable/disable NUMA.",
        default => 0,
    },
    hugepages => {
        optional => 1,
        type => 'string',
        description => "Enable/disable hugepages memory.",
        enum => [qw(any 2 1024)],
    },
    keephugepages => {
        optional => 1,
        type => 'boolean',
        default => 0,
        description =>
            "Use together with hugepages. If enabled, hugepages will not not be deleted"
            . " after VM shutdown and can be used for subsequent starts.",
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
        description =>
            "Enable/disable communication with the QEMU Guest Agent and its properties.",
        type => 'string',
        format => $agent_fmt,
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
        description =>
            "Set the real time clock (RTC) to local time. This is enabled by default if"
            . " the `ostype` indicates a Microsoft Windows OS.",
    },
    freeze => {
        optional => 1,
        type => 'boolean',
        description => "Freeze CPU at startup (use 'c' monitor command to start execution).",
    },
    vga => {
        optional => 1,
        type => 'string',
        format => $vga_fmt,
        description => "Configure the VGA hardware.",
        verbose_description => "Configure the VGA Hardware. If you want to use high resolution"
            . " modes (>= 1280x1024x16) you may need to increase the vga memory option. Since QEMU"
            . " 2.9 the default VGA display type is 'std' for all OS types besides some Windows"
            . " versions (XP and older) which use 'cirrus'. The 'qxl' option enables the SPICE"
            . " display server. For win* OS you can select how many independent displays you want,"
            . " Linux guests can add displays them self.\nYou can also run without any graphic card,"
            . " using a serial device as terminal.",
    },
    watchdog => {
        optional => 1,
        type => 'string',
        format => 'pve-qm-watchdog',
        description => "Create a virtual hardware watchdog device.",
        verbose_description =>
            "Create a virtual hardware watchdog device. Once enabled (by a guest"
            . " action), the watchdog must be periodically polled by an agent inside the guest or"
            . " else the watchdog will reset the guest (or execute the respective action specified)",
    },
    startdate => {
        optional => 1,
        type => 'string',
        typetext => "(now | YYYY-MM-DD | YYYY-MM-DDTHH:MM:SS)",
        description => "Set the initial date of the real time clock. Valid format for date are:"
            . "'now' or '2006-06-17T16:01:21' or '2006-06-17'.",
        pattern => '(now|\d{4}-\d{1,2}-\d{1,2}(T\d{1,2}:\d{1,2}:\d{1,2})?)',
        default => 'now',
    },
    startup => get_standard_option('pve-startup-order'),
    template => {
        optional => 1,
        type => 'boolean',
        description => "Enable/disable Template.",
        default => 0,
    },
    args => {
        optional => 1,
        type => 'string',
        description => "Arbitrary arguments passed to kvm.",
        verbose_description => <<EODESCR,
Arbitrary arguments passed to kvm, for example:

args: -no-reboot -smbios 'type=0,vendor=FOO'

NOTE: this option is for experts only.
EODESCR
    },
    tablet => {
        optional => 1,
        type => 'boolean',
        default => 1,
        description => "Enable/disable the USB tablet device.",
        verbose_description =>
            "Enable/disable the USB tablet device. This device is usually needed"
            . " to allow absolute mouse positioning with VNC. Else the mouse runs out of sync with"
            . " normal VNC clients. If you're running lots of console-only guests on one host, you"
            . " may consider disabling this to save some context switches. This is turned off by"
            . " default if you use spice (`qm set <vmid> --vga qxl`).",
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
        description => "Set maximum tolerated downtime (in seconds) for migrations. Should the"
            . " migration not be able to converge in the very end, because too much newly dirtied"
            . " RAM needs to be transferred, the limit will be increased automatically step-by-step"
            . " until migration can converge.",
        minimum => 0,
        default => 0.1,
    },
    cdrom => {
        optional => 1,
        type => 'string',
        format => 'pve-qm-ide',
        typetext => '<volume>',
        description => "This is an alias for option -ide2",
    },
    cpu => {
        optional => 1,
        description => "Emulated CPU type.",
        type => 'string',
        format => 'pve-vm-cpu-conf',
    },
    parent => get_standard_option(
        'pve-snapshot-name',
        {
            optional => 1,
            description =>
                "Parent snapshot name. This is used internally, and should not be modified.",
        },
    ),
    snaptime => {
        optional => 1,
        description => "Timestamp for snapshots.",
        type => 'integer',
        minimum => 0,
    },
    vmstate => {
        optional => 1,
        type => 'string',
        format => 'pve-volume-id',
        description =>
            "Reference to a volume which stores the VM state. This is used internally"
            . " for snapshots.",
    },
    vmstatestorage => get_standard_option(
        'pve-storage-id',
        {
            description => "Default storage for VM state volumes/files.",
            optional => 1,
        },
    ),
    runningmachine => get_standard_option(
        'pve-qemu-machine',
        {
            description =>
                "Specifies the QEMU machine type of the running vm. This is used internally"
                . " for snapshots.",
        },
    ),
    runningcpu => {
        description => "Specifies the QEMU '-cpu' parameter of the running vm. This is used"
            . " internally for snapshots.",
        optional => 1,
        type => 'string',
        pattern => $PVE::QemuServer::CPUConfig::qemu_cmdline_cpu_re,
        format_description => 'QEMU -cpu parameter',
    },
    machine => get_standard_option('pve-qemu-machine'),
    arch => {
        description => "Virtual processor architecture. Defaults to the host.",
        optional => 1,
        type => 'string',
        enum => [qw(x86_64 aarch64)],
    },
    smbios1 => {
        description => "Specify SMBIOS type 1 fields.",
        type => 'string',
        format => 'pve-qm-smbios1',
        maxLength => 512,
        optional => 1,
    },
    protection => {
        optional => 1,
        type => 'boolean',
        description => "Sets the protection flag of the VM. This will disable the remove VM and"
            . " remove disk operations.",
        default => 0,
    },
    bios => {
        optional => 1,
        type => 'string',
        enum => [qw(seabios ovmf)],
        description => "Select BIOS implementation.",
        default => 'seabios',
    },
    vmgenid => {
        type => 'string',
        pattern => '(?:[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}|[01])',
        format_description => 'UUID',
        description =>
            "Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0'"
            . " to disable explicitly.",
        verbose_description => "The VM generation ID (vmgenid) device exposes a 128-bit integer"
            . " value identifier to the guest OS. This allows to notify the guest operating system"
            . " when the virtual machine is executed with a different configuration (e.g. snapshot"
            . " execution or creation from a template). The guest operating system notices the"
            . " change, and is then able to react as appropriate by marking its copies of"
            . " distributed databases as dirty, re-initializing its random number generator, etc.\n"
            . "Note that auto-creation only works when done through API/CLI create or update methods"
            . ", but not when manually editing the config file.",
        default => "1 (autogenerated)",
        optional => 1,
    },
    hookscript => {
        type => 'string',
        format => 'pve-volume-id',
        optional => 1,
        description => "Script that will be executed during various steps in the vms lifetime.",
    },
    ivshmem => {
        type => 'string',
        format => $ivshmem_fmt,
        description =>
            "Inter-VM shared memory. Useful for direct communication between VMs, or to"
            . " the host.",
        optional => 1,
    },
    audio0 => {
        type => 'string',
        format => $audio_fmt,
        description => "Configure a audio device, useful in combination with QXL/Spice.",
        optional => 1,
    },
    spice_enhancements => {
        type => 'string',
        format => $spice_enhancements_fmt,
        description => "Configure additional enhancements for SPICE.",
        optional => 1,
    },
    tags => {
        type => 'string',
        format => 'pve-tag-list',
        description => 'Tags of the VM. This is only meta information.',
        optional => 1,
    },
    rng0 => {
        type => 'string',
        format => 'pve-qm-rng',
        description => "Configure a VirtIO-based Random Number Generator.",
        optional => 1,
    },
    meta => {
        type => 'string',
        format => $PVE::QemuServer::MetaInfo::meta_info_fmt,
        description => "Some (read-only) meta-information about this guest.",
        optional => 1,
    },
    affinity => {
        type => 'string',
        format => 'pve-cpuset',
        description =>
            "List of host cores used to execute guest processes, for example: 0,5,8-11",
        optional => 1,
    },
};

my $cicustom_fmt = {
    meta => {
        type => 'string',
        optional => 1,
        description => 'Specify a custom file containing all meta data passed to the VM via"
	    ." cloud-init. This is provider specific meaning configdrive2 and nocloud differ.',
        format => 'pve-volume-id',
        format_description => 'volume',
    },
    network => {
        type => 'string',
        optional => 1,
        description =>
            'To pass a custom file containing all network data to the VM via cloud-init.',
        format => 'pve-volume-id',
        format_description => 'volume',
    },
    user => {
        type => 'string',
        optional => 1,
        description =>
            'To pass a custom file containing all user data to the VM via cloud-init.',
        format => 'pve-volume-id',
        format_description => 'volume',
    },
    vendor => {
        type => 'string',
        optional => 1,
        description =>
            'To pass a custom file containing all vendor data to the VM via cloud-init.',
        format => 'pve-volume-id',
        format_description => 'volume',
    },
};
PVE::JSONSchema::register_format('pve-qm-cicustom', $cicustom_fmt);

# any new option might need to be added to $cloudinitoptions in PVE::API2::Qemu
my $confdesc_cloudinit = {
    citype => {
        optional => 1,
        type => 'string',
        description =>
            'Specifies the cloud-init configuration format. The default depends on the'
            . ' configured operating system type (`ostype`. We use the `nocloud` format for Linux,'
            . ' and `configdrive2` for windows.',
        enum => ['configdrive2', 'nocloud', 'opennebula'],
    },
    ciuser => {
        optional => 1,
        type => 'string',
        description =>
            "cloud-init: User name to change ssh keys and password for instead of the"
            . " image's configured default user.",
    },
    cipassword => {
        optional => 1,
        type => 'string',
        description => 'cloud-init: Password to assign the user. Using this is generally not'
            . ' recommended. Use ssh keys instead. Also note that older cloud-init versions do not'
            . ' support hashed passwords.',
    },
    ciupgrade => {
        optional => 1,
        type => 'boolean',
        description => 'cloud-init: do an automatic package upgrade after the first boot.',
        default => 1,
    },
    cicustom => {
        optional => 1,
        type => 'string',
        description => 'cloud-init: Specify custom files to replace the automatically generated'
            . ' ones at start.',
        format => 'pve-qm-cicustom',
    },
    searchdomain => {
        optional => 1,
        type => 'string',
        description => 'cloud-init: Sets DNS search domains for a container. Create will'
            . ' automatically use the setting from the host if neither searchdomain nor nameserver'
            . ' are set.',
    },
    nameserver => {
        optional => 1,
        type => 'string',
        format => 'address-list',
        description => 'cloud-init: Sets DNS server IP address for a container. Create will'
            . ' automatically use the setting from the host if neither searchdomain nor nameserver'
            . ' are set.',
    },
    sshkeys => {
        optional => 1,
        type => 'string',
        format => 'urlencoded',
        description => "cloud-init: Setup public SSH keys (one key per line, OpenSSH format).",
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

my $MAX_NETS = 32;
my $MAX_SERIAL_PORTS = 4;
my $MAX_PARALLEL_PORTS = 3;

for (my $i = 0; $i < $PVE::QemuServer::Memory::MAX_NUMA; $i++) {
    $confdesc->{"numa$i"} = $PVE::QemuServer::Memory::numadesc;
}

for (my $i = 0; $i < max_virtiofs(); $i++) {
    $confdesc->{"virtiofs$i"} = get_standard_option('pve-qm-virtiofs');
}

for (my $i = 0; $i < $MAX_NETS; $i++) {
    $confdesc->{"net$i"} = $PVE::QemuServer::Network::netdesc;
    $confdesc_cloudinit->{"ipconfig$i"} = $PVE::QemuServer::Network::ipconfigdesc;
}

foreach my $key (keys %$confdesc_cloudinit) {
    $confdesc->{$key} = $confdesc_cloudinit->{$key};
}

PVE::JSONSchema::register_format('pve-cpuset', \&pve_verify_cpuset);

sub pve_verify_cpuset {
    my ($set_text, $noerr) = @_;

    my ($count, $members) = eval { PVE::CpuSet::parse_cpuset($set_text) };

    if ($@) {
        return if $noerr;
        die "unable to parse cpuset option\n";
    }

    return PVE::CpuSet->new($members)->short_string();
}

PVE::JSONSchema::register_format('pve-volume-id-or-qm-path', \&verify_volume_id_or_qm_path);

sub verify_volume_id_or_qm_path {
    my ($volid, $noerr) = @_;

    return $volid if $volid eq 'none' || $volid eq 'cdrom';

    return verify_volume_id_or_absolute_path($volid, $noerr);
}

PVE::JSONSchema::register_format(
    'pve-volume-id-or-absolute-path',
    \&verify_volume_id_or_absolute_path,
);

sub verify_volume_id_or_absolute_path {
    my ($volid, $noerr) = @_;

    return $volid if $volid =~ m|^/|;

    $volid = eval { PVE::JSONSchema::check_format('pve-volume-id', $volid, '') };
    if ($@) {
        return if $noerr;
        die $@;
    }
    return $volid;
}

my $serialdesc = {
    optional => 1,
    type => 'string',
    pattern => '(/dev/.+|socket)',
    description => "Create a serial device inside the VM (n is 0 to 3)",
    verbose_description => <<EODESCR,
Create a serial device inside the VM (n is 0 to 3), and pass through a
host serial device (i.e. /dev/ttyS0), or create a unix socket on the
host side (use 'qm terminal' to open a terminal connection).

NOTE: If you pass through a host serial device, it is no longer possible to migrate such machines -
use with special care.

CAUTION: Experimental! User reported problems with this option.
EODESCR
};

my $paralleldesc = {
    optional => 1,
    type => 'string',
    pattern => '/dev/parport\d+|/dev/usb/lp\d+',
    description => "Map host parallel devices (n is 0 to 2).",
    verbose_description => <<EODESCR,
Map host parallel devices (n is 0 to 2).

NOTE: This option allows direct access to host hardware. So it is no longer possible to migrate such
machines - use with special care.

CAUTION: Experimental! User reported problems with this option.
EODESCR
};

for (my $i = 0; $i < $MAX_PARALLEL_PORTS; $i++) {
    $confdesc->{"parallel$i"} = $paralleldesc;
}

for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++) {
    $confdesc->{"serial$i"} = $serialdesc;
}

for (my $i = 0; $i < $PVE::QemuServer::PCI::MAX_HOSTPCI_DEVICES; $i++) {
    $confdesc->{"hostpci$i"} = $PVE::QemuServer::PCI::hostpcidesc;
}

for my $key (keys %{$PVE::QemuServer::Drive::drivedesc_hash}) {
    $confdesc->{$key} = $PVE::QemuServer::Drive::drivedesc_hash->{$key};
}

for (my $i = 0; $i < $PVE::QemuServer::USB::MAX_USB_DEVICES; $i++) {
    $confdesc->{"usb$i"} = $PVE::QemuServer::USB::usbdesc;
}

my $boot_fmt = {
    legacy => {
        optional => 1,
        default_key => 1,
        type => 'string',
        description => "Boot on floppy (a), hard disk (c), CD-ROM (d), or network (n)."
            . " Deprecated, use 'order=' instead.",
        pattern => '[acdn]{1,4}',
        format_description => "[acdn]{1,4}",

        # note: this is also the fallback if boot: is not given at all
        default => 'cdn',
    },
    order => {
        optional => 1,
        type => 'string',
        format => 'pve-qm-bootdev-list',
        format_description => "device[;device...]",
        description => <<EODESC,
The guest will attempt to boot from devices in the order they appear here.

Disks, optical drives and passed-through storage USB devices will be directly
booted from, NICs will load PXE, and PCIe devices will either behave like disks
(e.g. NVMe) or load an option ROM (e.g. RAID controller, hardware NIC).

Note that only devices in this list will be marked as bootable and thus loaded
by the guest firmware (BIOS/UEFI). If you require multiple disks for booting
(e.g. software-raid), you need to specify all of them here.

Overrides the deprecated 'legacy=[acdn]*' value when given.
EODESC
    },
};
PVE::JSONSchema::register_format('pve-qm-boot', $boot_fmt);

PVE::JSONSchema::register_format('pve-qm-bootdev', \&verify_bootdev);

sub verify_bootdev {
    my ($dev, $noerr) = @_;

    my $special = $dev =~ m/^efidisk/ || $dev =~ m/^tpmstate/;
    return $dev if PVE::QemuServer::Drive::is_valid_drivename($dev) && !$special;

    my $check = sub {
        my ($base) = @_;
        return 0 if $dev !~ m/^$base\d+$/;
        return 0 if !$confdesc->{$dev};
        return 1;
    };

    return $dev if $check->("net");
    return $dev if $check->("usb");
    return $dev if $check->("hostpci");

    return if $noerr;
    die "invalid boot device '$dev'\n";
}

sub print_bootorder {
    my ($devs) = @_;
    return "" if !@$devs;
    my $data = { order => join(';', @$devs) };
    return PVE::JSONSchema::print_property_string($data, $boot_fmt);
}

my $kvm_api_version = 0;

sub kvm_version {
    return $kvm_api_version if $kvm_api_version;

    open my $fh, '<', '/dev/kvm' or return;

    # 0xae00 => KVM_GET_API_VERSION
    $kvm_api_version = ioctl($fh, 0xae00, 0);
    close($fh);

    return $kvm_api_version;
}

my sub extract_version {
    my ($machine_type, $version) = @_;
    $version = kvm_user_version() if !defined($version);
    return PVE::QemuServer::Machine::extract_version($machine_type, $version);
}

sub kernel_has_vhost_net {
    return -c '/dev/vhost-net';
}

sub option_exists {
    my $key = shift;
    return defined($confdesc->{$key});
}

# try to convert old style file names to volume IDs
sub filename_to_volume_id {
    my ($vmid, $file, $media) = @_;

    if (!(
        $file eq 'none'
        || $file eq 'cdrom'
        || $file =~ m|^/dev/.+|
        || $file =~ m/^([^:]+):(.+)$/
    )) {

        return if $file =~ m|/|;

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

    if (
        ($drive->{file} !~ m/^(cdrom|none)$/)
        && ($drive->{file} !~ m|^/dev/.+|)
        && ($drive->{file} !~ m/^([^:]+):(.+)$/)
        && ($drive->{file} !~ m/^\d+$/)
    ) {
        my ($vtype, $volid) = PVE::Storage::path_to_volume_id($storecfg, $drive->{file});
        raise_param_exc({ $opt => "unable to associate path '$drive->{file}' to any storage" })
            if !$vtype;
        $drive->{media} = 'cdrom' if !$drive->{media} && $vtype eq 'iso';
        verify_media_type($opt, $vtype, $drive->{media});
        $drive->{file} = $volid;
    }

    $drive->{media} = 'cdrom' if !$drive->{media} && $drive->{file} =~ m/^(cdrom|none)$/;
}

sub parse_hotplug_features {
    my ($data) = @_;

    my $res = {};

    return $res if $data eq '0';

    $data = $confdesc->{hotplug}->{default} if $data eq '1';

    foreach my $feature (PVE::Tools::split_list($data)) {
        if ($feature =~ m/^(network|disk|cpu|memory|usb|cloudinit)$/) {
            $res->{$1} = 1;
        } else {
            die "invalid hotplug feature '$feature'\n";
        }
    }
    return $res;
}

PVE::JSONSchema::register_format('pve-hotplug-features', \&pve_verify_hotplug_features);

sub pve_verify_hotplug_features {
    my ($value, $noerr) = @_;

    return $value if parse_hotplug_features($value);

    return if $noerr;

    die "unable to parse hotplug option\n";
}

sub assert_clipboard_config {
    my ($vga) = @_;

    my $clipboard_regex = qr/^(std|cirrus|vmware|virtio|qxl)/;

    if (
        $vga->{'clipboard'}
        && $vga->{'clipboard'} eq 'vnc'
        && $vga->{type}
        && $vga->{type} !~ $clipboard_regex
    ) {
        die "vga type $vga->{type} is not compatible with VNC clipboard\n";
    }
}

sub print_tabletdevice_full {
    my ($conf, $arch) = @_;

    my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);

    # we use uhci for old VMs because tablet driver was buggy in older qemu
    my $usbbus;
    if ($q35 || $arch eq 'aarch64') {
        $usbbus = 'ehci';
    } else {
        $usbbus = 'uhci';
    }

    return "usb-tablet,id=tablet,bus=$usbbus.0,port=1";
}

sub print_keyboarddevice_full {
    my ($conf, $arch) = @_;

    return if $arch ne 'aarch64';

    return "usb-kbd,id=keyboard,bus=ehci.0,port=2";
}

sub print_drivedevice_full {
    my ($storecfg, $conf, $vmid, $drive, $bridges, $arch, $machine_type) = @_;

    my $device = '';
    my $maxdev = 0;

    my $machine_version = extract_version($machine_type, kvm_user_version());

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);
    if ($drive->{interface} eq 'virtio') {
        my $pciaddr = print_pci_addr("$drive_id", $bridges, $arch);
        $device = 'virtio-blk-pci';
        # for the switch to -blockdev, there is no blockdev for 'none'
        if (!min_version($machine_version, 10, 0) || $drive->{file} ne 'none') {
            $device .= ",drive=drive-$drive_id";
        }
        $device .= ",id=${drive_id}${pciaddr}";
        $device .= ",iothread=iothread-$drive_id" if $drive->{iothread};
    } elsif ($drive->{interface} eq 'scsi') {

        my ($maxdev, $controller, $controller_prefix) = scsihw_infos($conf, $drive);
        my $unit = $drive->{index} % $maxdev;

        my $device_type =
            PVE::QemuServer::Drive::get_scsi_device_type($drive, $storecfg, $machine_version);

        if (!$conf->{scsihw} || $conf->{scsihw} =~ m/^lsi/ || $conf->{scsihw} eq 'pvscsi') {
            $device = "scsi-$device_type,bus=$controller_prefix$controller.0,scsi-id=$unit";
        } else {
            $device = "scsi-$device_type,bus=$controller_prefix$controller.0,channel=0,scsi-id=0"
                . ",lun=$drive->{index}";
        }
        # for the switch to -blockdev, there is no blockdev for 'none'
        if (!min_version($machine_version, 10, 0) || $drive->{file} ne 'none') {
            $device .= ",drive=drive-$drive_id";
        }
        $device .= ",id=$drive_id";

        # for the switch to -blockdev, the SCSI device ID needs to be explicitly specified
        if (min_version($machine_version, 10, 0)) {
            $device .= ",device_id=drive-${drive_id}";
        }

        if ($drive->{ssd} && ($device_type eq 'block' || $device_type eq 'hd')) {
            $device .= ",rotation_rate=1";
        }
        $device .= ",wwn=$drive->{wwn}" if $drive->{wwn};

        # only scsi-hd and scsi-cd support passing vendor and product information
        if ($device_type eq 'hd' || $device_type eq 'cd') {
            if (my $vendor = $drive->{vendor}) {
                $device .= ",vendor=$vendor";
            }
            if (my $product = $drive->{product}) {
                $device .= ",product=$product";
            }
        }

    } elsif ($drive->{interface} eq 'ide' || $drive->{interface} eq 'sata') {
        my $maxdev = ($drive->{interface} eq 'sata') ? $PVE::QemuServer::Drive::MAX_SATA_DISKS : 2;
        my $controller = int($drive->{index} / $maxdev);
        my $unit = $drive->{index} % $maxdev;

        # machine type q35 only supports unit=0 for IDE rather than 2 units. This wasn't handled
        # correctly before, so e.g. index=2 was mapped to controller=1,unit=0 rather than
        # controller=2,unit=0. Note that odd indices never worked, as they would be mapped to
        # unit=1, so to keep backwards compat for migration, it suffices to keep even ones as they
        # were before. Move odd ones up by 2 where they don't clash.
        if (PVE::QemuServer::Machine::machine_type_is_q35($conf) && $drive->{interface} eq 'ide') {
            $controller += 2 * ($unit % 2);
            $unit = 0;
        }

        my $device_type = ($drive->{media} && $drive->{media} eq 'cdrom') ? "cd" : "hd";

        $device = "ide-$device_type";
        if ($drive->{interface} eq 'ide') {
            $device .= ",bus=ide.$controller,unit=$unit";
        } else {
            $device .= ",bus=ahci$controller.$unit";
        }
        if (!min_version($machine_version, 10, 0) || $drive->{file} ne 'none') {
            $device .= ",drive=drive-$drive_id";
        }
        $device .= ",id=$drive_id";

        if ($device_type eq 'hd') {
            if (my $model = $drive->{model}) {
                $model = URI::Escape::uri_unescape($model);
                $device .= ",model=$model";
            }
            if ($drive->{ssd}) {
                $device .= ",rotation_rate=1";
            }
        }
        $device .= ",wwn=$drive->{wwn}" if $drive->{wwn};
    } elsif ($drive->{interface} eq 'usb') {
        die "implement me";
        #  -device ide-drive,bus=ide.1,unit=0,drive=drive-ide0-1-0,id=ide0-1-0
    } else {
        die "unsupported interface type";
    }

    $device .= ",bootindex=$drive->{bootindex}" if $drive->{bootindex};

    if (my $serial = $drive->{serial}) {
        $serial = URI::Escape::uri_unescape($serial);
        $device .= ",serial=$serial";
    }

    if (min_version($machine_version, 10, 0)) { # for the switch to -blockdev
        if (!drive_is_cdrom($drive)) {
            my $write_cache = 'on';
            if (my $cache = $drive->{cache}) {
                $write_cache = 'off' if $cache eq 'writethrough' || $cache eq 'directsync';
            }
            $device .= ",write-cache=$write_cache";
        }
        for my $o (qw(rerror werror)) {
            $device .= ",$o=$drive->{$o}" if defined($drive->{$o});
        }
    }

    return $device;
}

sub print_drive_commandline_full {
    my ($storecfg, $vmid, $drive, $live_restore_name) = @_;

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($drive);

    my ($storeid) = PVE::Storage::parse_volume_id($drive->{file}, 1);
    my $scfg = $storeid ? PVE::Storage::storage_config($storecfg, $storeid) : undef;
    my $vtype = $storeid ? (PVE::Storage::parse_volname($storecfg, $drive->{file}))[0] : undef;

    my ($path, $format) =
        PVE::QemuServer::Drive::get_path_and_format($storecfg, $drive, $live_restore_name);

    my $is_rbd = $path =~ m/^rbd:/;

    my $opts = '';
    my @qemu_drive_options = qw(media cache rerror werror discard);
    foreach my $o (@qemu_drive_options) {
        $opts .= ",$o=$drive->{$o}" if defined($drive->{$o});
    }

    # snapshot only accepts on|off
    if (defined($drive->{snapshot})) {
        my $v = $drive->{snapshot} ? 'on' : 'off';
        $opts .= ",snapshot=$v";
    }

    if (defined($drive->{ro})) { # ro maps to QEMUs `readonly`, which accepts `on` or `off` only
        $opts .= ",readonly=" . ($drive->{ro} ? 'on' : 'off');
    }

    foreach my $type (['', '-total'], [_rd => '-read'], [_wr => '-write']) {
        my ($dir, $qmpname) = @$type;
        if (my $v = $drive->{"mbps$dir"}) {
            $opts .= ",throttling.bps$qmpname=" . int($v * 1024 * 1024);
        }
        if (my $v = $drive->{"mbps${dir}_max"}) {
            $opts .= ",throttling.bps$qmpname-max=" . int($v * 1024 * 1024);
        }
        if (my $v = $drive->{"bps${dir}_max_length"}) {
            $opts .= ",throttling.bps$qmpname-max-length=$v";
        }
        if (my $v = $drive->{"iops${dir}"}) {
            $opts .= ",throttling.iops$qmpname=$v";
        }
        if (my $v = $drive->{"iops${dir}_max"}) {
            $opts .= ",throttling.iops$qmpname-max=$v";
        }
        if (my $v = $drive->{"iops${dir}_max_length"}) {
            $opts .= ",throttling.iops$qmpname-max-length=$v";
        }
    }

    if ($live_restore_name) {
        $format = "rbd" if $is_rbd;
        die "$drive_id: Proxmox Backup Server backed drive cannot auto-detect the format\n"
            if !$format;
        $opts .= ",format=alloc-track,file.driver=$format";
    } elsif ($format) {
        $opts .= ",format=$format";
    }

    my $cache_direct = PVE::QemuServer::Drive::drive_uses_cache_direct($drive, $scfg);

    $opts .= ",cache=none" if !$drive->{cache} && $cache_direct;

    my $aio = PVE::QemuServer::Drive::aio_cmdline_option($scfg, $drive, $cache_direct);
    $opts .= ",aio=$aio";

    die "$drive_id: explicit media parameter is required for iso images\n"
        if !defined($drive->{media}) && defined($vtype) && $vtype eq 'iso';

    if (!drive_is_cdrom($drive)) {
        my $detectzeroes = PVE::QemuServer::Drive::detect_zeroes_cmdline_option($drive);

        # note: 'detect-zeroes' works per blockdev and we want it to persist
        # after the alloc-track is removed, so put it on 'file' directly
        my $dz_param = $live_restore_name ? "file.detect-zeroes" : "detect-zeroes";
        $opts .= ",$dz_param=$detectzeroes" if $detectzeroes;
    }

    if ($live_restore_name) {
        $opts .= ",backing=$live_restore_name";
        $opts .= ",auto-remove=on";
    }

    # my $file_param = $live_restore_name ? "file.file.filename" : "file";
    my $file_param = "file";
    if ($live_restore_name) {
        # non-rbd drivers require the underlying file to be a separate block
        # node, so add a second .file indirection
        $file_param .= ".file" if !$is_rbd;
        $file_param .= ".filename";
    }
    my $pathinfo = $path ? "$file_param=$path," : '';

    return "${pathinfo}if=none,id=drive-$drive->{interface}$drive->{index}$opts";
}

sub print_pbs_blockdev {
    my ($pbs_conf, $pbs_name) = @_;
    my $blockdev = "driver=pbs,node-name=$pbs_name,read-only=on";
    $blockdev .= ",repository=$pbs_conf->{repository}";
    $blockdev .= ",namespace=$pbs_conf->{namespace}" if $pbs_conf->{namespace};
    $blockdev .= ",snapshot=$pbs_conf->{snapshot}";
    $blockdev .= ",archive=$pbs_conf->{archive}";
    $blockdev .= ",keyfile=$pbs_conf->{keyfile}" if $pbs_conf->{keyfile};
    return $blockdev;
}

sub print_netdevice_full {
    my ($vmid, $conf, $net, $netid, $bridges, $use_old_bios_files, $arch, $machine_version) = @_;

    my $device = $net->{model};
    if ($net->{model} eq 'virtio') {
        $device = 'virtio-net-pci';
    }

    my $pciaddr = print_pci_addr("$netid", $bridges, $arch);
    my $tmpstr = "$device,mac=$net->{macaddr},netdev=$netid$pciaddr,id=$netid";
    if ($net->{queues} && $net->{queues} > 1 && $net->{model} eq 'virtio') {
        # Consider we have N queues, the number of vectors needed is 2 * N + 2, i.e., one per in
        # and out of each queue plus one config interrupt and control vector queue
        my $vectors = $net->{queues} * 2 + 2;
        $tmpstr .= ",vectors=$vectors,mq=on";
        if (min_version($machine_version, 7, 1)) {
            $tmpstr .= ",packed=on";
        }
    }

    if (min_version($machine_version, 7, 1) && $net->{model} eq 'virtio') {
        $tmpstr .= ",rx_queue_size=1024,tx_queue_size=256";
    }

    $tmpstr .= ",bootindex=$net->{bootindex}" if $net->{bootindex};

    my $mtu = $net->{mtu};

    if ($net->{model} eq 'virtio' && $net->{bridge}) {
        my $bridge_mtu = PVE::Network::read_bridge_mtu($net->{bridge});

        if (!defined($mtu) || $mtu == 1) {
            $mtu = $bridge_mtu;
        } elsif ($mtu < 576) {
            die "netdev $netid: MTU '$mtu' is smaller than the IP minimum MTU '576'\n";
        } elsif ($mtu > $bridge_mtu) {
            die "netdev $netid: MTU '$mtu' is bigger than the bridge MTU '$bridge_mtu'\n";
        }

        $tmpstr .= ",host_mtu=$mtu" if $mtu != 1500;
    } elsif (defined($mtu)) {
        warn
            "WARN: netdev $netid: ignoring MTU '$mtu', not using VirtIO or no bridge configured.\n";
    }

    if ($use_old_bios_files) {
        my $romfile;
        if ($device eq 'virtio-net-pci') {
            $romfile = 'pxe-virtio.rom';
        } elsif ($device eq 'e1000') {
            $romfile = 'pxe-e1000.rom';
        } elsif ($device eq 'e1000e') {
            $romfile = 'pxe-e1000e.rom';
        } elsif ($device eq 'ne2k') {
            $romfile = 'pxe-ne2k_pci.rom';
        } elsif ($device eq 'pcnet') {
            $romfile = 'pxe-pcnet.rom';
        } elsif ($device eq 'rtl8139') {
            $romfile = 'pxe-rtl8139.rom';
        }
        $tmpstr .= ",romfile=$romfile" if $romfile;
    }

    return $tmpstr;
}

sub print_netdev_full {
    my ($vmid, $conf, $arch, $net, $netid, $hotplug) = @_;

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
    if (is_native_arch($arch)) {
        $vhostparam = ',vhost=on' if kernel_has_vhost_net() && $net->{model} eq 'virtio';
    }

    my $vmname = $conf->{name} || "vm$vmid";

    my $netdev = "";
    my $script = $hotplug ? "pve-bridge-hotplug" : "pve-bridge";

    if ($net->{bridge}) {
        $netdev = "type=tap,id=$netid,ifname=${ifname},script=/usr/libexec/qemu-server/$script"
            . ",downscript=/usr/libexec/qemu-server/pve-bridgedown$vhostparam";
    } else {
        $netdev = "type=user,id=$netid,hostname=$vmname";
    }

    $netdev .= ",queues=$net->{queues}" if ($net->{queues} && $net->{model} eq 'virtio');

    return $netdev;
}

my $vga_map = {
    'cirrus' => 'cirrus-vga',
    'std' => 'VGA',
    'vmware' => 'vmware-svga',
    'virtio' => 'virtio-vga',
    'virtio-gl' => 'virtio-vga-gl',
};

sub print_vga_device {
    my ($conf, $vga, $arch, $machine_version, $id, $qxlnum, $bridges) = @_;

    my $type = $vga_map->{ $vga->{type} };
    if ($arch eq 'aarch64' && defined($type) && $type eq 'virtio-vga') {
        $type = 'virtio-gpu';
    }
    my $vgamem_mb = $vga->{memory};

    my $max_outputs = '';
    if ($qxlnum) {
        $type = $id ? 'qxl' : 'qxl-vga';

        if (!$conf->{ostype} || $conf->{ostype} =~ m/^(?:l\d\d)|(?:other)$/) {
            # set max outputs so linux can have up to 4 qxl displays with one device
            if (min_version($machine_version, 4, 1)) {
                $max_outputs = ",max_outputs=4";
            }
        }
    }

    die "no device-type for $vga->{type}\n" if !$type;

    my $memory = "";
    if ($vgamem_mb) {
        if ($vga->{type} =~ /^virtio/) {
            my $bytes = PVE::Tools::convert_size($vgamem_mb, "mb" => "b");
            $memory = ",max_hostmem=$bytes";
        } elsif ($qxlnum) {
            # from https://www.spice-space.org/multiple-monitors.html
            $memory = ",vgamem_mb=$vga->{memory}";
            my $ram = $vgamem_mb * 4;
            my $vram = $vgamem_mb * 2;
            $memory .= ",ram_size_mb=$ram,vram_size_mb=$vram";
        } else {
            $memory = ",vgamem_mb=$vga->{memory}";
        }
    } elsif ($qxlnum && $id) {
        $memory = ",ram_size=67108864,vram_size=33554432";
    }

    my $edidoff = "";
    if ($type eq 'VGA' && windows_version($conf->{ostype})) {
        $edidoff = ",edid=off" if (!defined($conf->{bios}) || $conf->{bios} ne 'ovmf');
    }

    my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);
    my $vgaid = "vga" . ($id // '');
    my $pciaddr;
    if ($q35 && $vgaid eq 'vga') {
        # the first display uses pcie.0 bus on q35 machines
        $pciaddr = print_pcie_addr($vgaid);
    } else {
        $pciaddr = print_pci_addr($vgaid, $bridges, $arch);
    }

    if ($vga->{type} eq 'virtio-gl') {
        my $base = '/usr/lib/x86_64-linux-gnu/lib';
        die "missing libraries for '$vga->{type}' detected! Please install 'libgl1' and 'libegl1'\n"
            if !-e "${base}EGL.so.1" || !-e "${base}GL.so.1";

        die
            "no DRM render node detected (/dev/dri/renderD*), no GPU? - needed for '$vga->{type}' display\n"
            if !PVE::Tools::dir_glob_regex('/dev/dri/', "renderD.*");
    }

    return "$type,id=${vgaid}${memory}${max_outputs}${pciaddr}${edidoff}";
}

sub vm_is_volid_owner {
    my ($storecfg, $vmid, $volid) = @_;

    if ($volid !~ m|^/|) {
        my ($path, $owner);
        eval { ($path, $owner) = PVE::Storage::path($storecfg, $volid); };
        if ($owner && ($owner == $vmid)) {
            return 1;
        }
    }

    return;
}

sub vmconfig_register_unused_drive {
    my ($storecfg, $vmid, $conf, $drive) = @_;

    if (drive_is_cloudinit($drive)) {
        eval { PVE::Storage::vdisk_free($storecfg, $drive->{file}) };
        warn $@ if $@;
        delete $conf->{'special-sections'}->{cloudinit};
    } elsif (!drive_is_cdrom($drive)) {
        my $volid = $drive->{file};
        if (vm_is_volid_owner($storecfg, $vmid, $volid)) {
            PVE::QemuConfig->add_unused_volume($conf, $volid, $vmid);
        }
    }
}

# smbios: [manufacturer=str][,product=str][,version=str][,serial=str][,uuid=uuid][,sku=str][,family=str][,base64=bool]
my $smbios1_fmt = {
    uuid => {
        type => 'string',
        pattern => '[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',
        format_description => 'UUID',
        description => "Set SMBIOS1 UUID.",
        optional => 1,
    },
    version => {
        type => 'string',
        pattern => '[A-Za-z0-9+\/]+={0,2}',
        format_description => 'Base64 encoded string',
        description => "Set SMBIOS1 version.",
        optional => 1,
    },
    serial => {
        type => 'string',
        pattern => '[A-Za-z0-9+\/]+={0,2}',
        format_description => 'Base64 encoded string',
        description => "Set SMBIOS1 serial number.",
        optional => 1,
    },
    manufacturer => {
        type => 'string',
        pattern => '[A-Za-z0-9+\/]+={0,2}',
        format_description => 'Base64 encoded string',
        description => "Set SMBIOS1 manufacturer.",
        optional => 1,
    },
    product => {
        type => 'string',
        pattern => '[A-Za-z0-9+\/]+={0,2}',
        format_description => 'Base64 encoded string',
        description => "Set SMBIOS1 product ID.",
        optional => 1,
    },
    sku => {
        type => 'string',
        pattern => '[A-Za-z0-9+\/]+={0,2}',
        format_description => 'Base64 encoded string',
        description => "Set SMBIOS1 SKU string.",
        optional => 1,
    },
    family => {
        type => 'string',
        pattern => '[A-Za-z0-9+\/]+={0,2}',
        format_description => 'Base64 encoded string',
        description => "Set SMBIOS1 family string.",
        optional => 1,
    },
    base64 => {
        type => 'boolean',
        description => 'Flag to indicate that the SMBIOS values are base64 encoded',
        optional => 1,
    },
};

sub parse_smbios1 {
    my ($data) = @_;

    my $res = eval { parse_property_string($smbios1_fmt, $data) };
    warn $@ if $@;
    return $res;
}

sub print_smbios1 {
    my ($smbios1) = @_;
    return PVE::JSONSchema::print_property_string($smbios1, $smbios1_fmt);
}

PVE::JSONSchema::register_format('pve-qm-smbios1', $smbios1_fmt);

sub parse_watchdog {
    my ($value) = @_;

    return if !$value;

    my $res = eval { parse_property_string($watchdog_fmt, $value) };
    warn $@ if $@;
    return $res;
}

sub parse_guest_agent {
    my ($conf) = @_;

    return {} if !defined($conf->{agent});

    my $res = eval { parse_property_string($agent_fmt, $conf->{agent}) };
    warn $@ if $@;

    # if the agent is disabled ignore the other potentially set properties
    return {} if !$res->{enabled};
    return $res;
}

sub get_qga_key {
    my ($conf, $key) = @_;
    return undef if !defined($conf->{agent});

    my $agent = parse_guest_agent($conf);
    return $agent->{$key};
}

sub parse_vga {
    my ($value) = @_;

    return {} if !$value;
    my $res = eval { parse_property_string($vga_fmt, $value) };
    warn $@ if $@;
    return $res;
}

sub qemu_created_version_fixups {
    my ($conf, $forcemachine, $kvmver) = @_;

    my $meta = PVE::QemuServer::MetaInfo::parse_meta_info($conf->{meta}) // {};
    my $forced_vers = PVE::QemuServer::Machine::extract_version($forcemachine);

    # check if we need to apply some handling for VMs that always use the latest machine version but
    # had a machine version transition happen that affected HW such that, e.g., an OS config change
    # would be required (we do not want to pin machine version for non-windows OS type)
    my $machine_conf = PVE::QemuServer::Machine::parse_machine($conf->{machine});
    if (
        (!defined($machine_conf->{type}) || $machine_conf->{type} =~ m/^(?:pc|q35|virt)$/) # non-versioned machine
        && (!defined($meta->{'creation-qemu'})
            || !min_version($meta->{'creation-qemu'}, 6, 1)) # created before 6.1
        && (!$forced_vers || min_version($forced_vers, 6, 1)) # handle snapshot-rollback/migrations
        && min_version($kvmver, 6, 1) # only need to apply the change since 6.1
    ) {
        my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);
        if ($q35 && $conf->{ostype} && $conf->{ostype} eq 'l26') {
            # this changed to default-on in Q 6.1 for q35 machines, it will mess with PCI slot view
            # and thus with the predictable interface naming of systemd
            return ['-global', 'ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off'];
        }
    }
    return;
}

# add JSON properties for create and set function
sub json_config_properties {
    my ($prop, $with_disk_alloc) = @_;

    my $skip_json_config_opts = {
        parent => 1,
        snaptime => 1,
        vmstate => 1,
        runningmachine => 1,
        runningcpu => 1,
        meta => 1,
    };

    foreach my $opt (keys %$confdesc) {
        next if $skip_json_config_opts->{$opt};

        if ($with_disk_alloc && is_valid_drivename($opt)) {
            $prop->{$opt} = $PVE::QemuServer::Drive::drivedesc_hash_with_alloc->{$opt};
        } else {
            $prop->{$opt} = $confdesc->{$opt};
        }
    }

    return $prop;
}

# Properties that we can read from an OVF file
sub json_ovf_properties {
    my $prop = {};

    for my $device (PVE::QemuServer::Drive::valid_drive_names()) {
        $prop->{$device} = {
            type => 'string',
            format => 'pve-volume-id-or-absolute-path',
            description => "Disk image that gets imported to $device",
            optional => 1,
        };
    }

    $prop->{cores} = {
        type => 'integer',
        description => "The number of CPU cores.",
        optional => 1,
    };
    $prop->{memory} = {
        type => 'integer',
        description => "Amount of RAM for the VM in MB.",
        optional => 1,
    };
    $prop->{name} = {
        type => 'string',
        description => "Name of the VM.",
        optional => 1,
    };

    return $prop;
}

# return copy of $confdesc_cloudinit to generate documentation
sub cloudinit_config_properties {

    return dclone($confdesc_cloudinit);
}

sub cloudinit_pending_properties {
    my $p = {
        map { $_ => 1 } keys $confdesc_cloudinit->%*, name => 1,
    };
    $p->{"net$_"} = 1 for 0 .. ($MAX_NETS - 1);
    return $p;
}

sub check_type {
    my ($key, $value, $schema) = @_;

    die "check_type: no schema defined\n" if !$schema;

    die "unknown setting '$key'\n" if !$schema->{$key};

    my $type = $schema->{$key}->{type};

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
        if (my $fmt = $schema->{$key}->{format}) {
            PVE::JSONSchema::check_format($fmt, $value);
            return $value;
        }
        $value =~ s/^\"(.*)\"$/$1/;
        return $value;
    } else {
        die "internal error";
    }
}

sub destroy_vm {
    my ($storecfg, $vmid, $skiplock, $replacement_conf, $purge_unreferenced) = @_;

    eval { PVE::QemuConfig::cleanup_fleecing_images($vmid, $storecfg) };
    log_warn("attempt to clean up left-over fleecing images failed - $@") if $@;

    my $conf = PVE::QemuConfig->load_config($vmid);

    if (!$skiplock && !PVE::QemuConfig->has_lock($conf, 'suspended')) {
        PVE::QemuConfig->check_lock($conf);
    }

    if ($conf->{template}) {
        # check if any base image is still used by a linked clone
        PVE::QemuConfig->foreach_volume_full(
            $conf,
            { include_unused => 1 },
            sub {
                my ($ds, $drive) = @_;
                return if drive_is_cdrom($drive);

                my $volid = $drive->{file};
                return if !$volid || $volid =~ m|^/|;

                die "base volume '$volid' is still in use by linked cloned\n"
                    if PVE::Storage::volume_is_base_and_used($storecfg, $volid);

            },
        );
    }

    my $volids = {};
    my $remove_owned_drive = sub {
        my ($ds, $drive) = @_;
        return if drive_is_cdrom($drive, 1);

        my $volid = $drive->{file};
        return if !$volid || $volid =~ m|^/|;
        return if $volids->{$volid};

        my ($path, $owner) = PVE::Storage::path($storecfg, $volid);
        return if !$path || !$owner || ($owner != $vmid);

        $volids->{$volid} = 1;
        eval { PVE::Storage::vdisk_free($storecfg, $volid) };
        warn "Could not remove disk '$volid', check manually: $@" if $@;
    };

    # only remove disks owned by this VM (referenced in the config)
    my $include_opts = {
        include_unused => 1,
        extra_keys => ['vmstate'],
    };
    PVE::QemuConfig->foreach_volume_full($conf, $include_opts, $remove_owned_drive);

    for my $snap (values %{ $conf->{snapshots} }) {
        next if !defined($snap->{vmstate});
        my $drive = PVE::QemuConfig->parse_volume('vmstate', $snap->{vmstate}, 1);
        next if !defined($drive);
        $remove_owned_drive->('vmstate', $drive);
    }

    PVE::QemuConfig->foreach_volume_full($conf->{pending}, $include_opts, $remove_owned_drive);

    if ($purge_unreferenced) { # also remove unreferenced disk
        my $vmdisks = PVE::Storage::vdisk_list($storecfg, undef, $vmid, undef, 'images');
        PVE::Storage::foreach_volid(
            $vmdisks,
            sub {
                my ($volid, $sid, $volname, $d) = @_;
                eval { PVE::Storage::vdisk_free($storecfg, $volid) };
                warn $@ if $@;
            },
        );
    }

    eval { PVE::QemuServer::Network::delete_ifaces_ipams_ips($conf, $vmid) };
    warn $@ if $@;

    if (defined $replacement_conf) {
        PVE::QemuConfig->write_config($vmid, $replacement_conf);
    } else {
        PVE::QemuConfig->destroy_config($vmid);
    }
}

my $fleecing_section_schema = {
    'fleecing-images' => {
        type => 'string',
        format => 'pve-volume-id-list',
        description => "For internal use only. List of fleecing images allocated during backup."
            . " If no backup is running, these are left-overs that failed to be removed.",
        optional => 1,
    },
};

sub parse_vm_config {
    my ($filename, $raw, $strict) = @_;

    return if !defined($raw);

    # note that pending, snapshot and special sections are currently skipped when a backup is taken
    my $res = {
        digest => Digest::SHA::sha1_hex($raw),
        snapshots => {},
        pending => undef,
        'special-sections' => {},
    };

    my $handle_error = sub {
        my ($msg) = @_;

        if ($strict) {
            die $msg;
        } else {
            warn $msg;
        }
    };

    $filename =~ m|/qemu-server/(\d+)\.conf$|
        || die "got strange filename '$filename'";

    my $vmid = $1;

    my $conf = $res;
    my $descr;
    my $finish_description = sub {
        if (defined($descr)) {
            $descr =~ s/\s+$//;
            $conf->{description} = $descr;
        }
        $descr = undef;
    };

    my $special_schemas = {
        cloudinit => $confdesc, # not actually used right now, see below
        fleecing => $fleecing_section_schema,
    };
    my $special_sections_re_string = join('|', keys $special_schemas->%*);
    my $special_sections_re_1 = qr/($special_sections_re_string)/;

    my $section = { name => '', type => 'main', schema => $confdesc };

    my @lines = split(/\n/, $raw);
    foreach my $line (@lines) {
        next if $line =~ m/^\s*$/;

        if ($line =~ m/^\[PENDING\]\s*$/i) {
            $section = { name => 'pending', type => 'pending', schema => $confdesc };
            $finish_description->();
            $handle_error->("vm $vmid - duplicate section: $section->{name}\n")
                if defined($res->{ $section->{name} });
            $conf = $res->{ $section->{name} } = {};
            next;
        } elsif ($line =~ m/^\[special:$special_sections_re_1\]\s*$/i) {
            $section = { name => $1, type => 'special', schema => $special_schemas->{$1} };
            $finish_description->();
            $handle_error->("vm $vmid - duplicate special section: $section->{name}\n")
                if defined($res->{'special-sections'}->{ $section->{name} });
            $conf = $res->{'special-sections'}->{ $section->{name} } = {};
            next;

        } elsif ($line =~ m/^\[([a-z][a-z0-9_\-]+)\]\s*$/i) {
            $section = { name => $1, type => 'snapshot', schema => $confdesc };
            $finish_description->();
            $handle_error->("vm $vmid - duplicate snapshot section: $section->{name}\n")
                if defined($res->{snapshots}->{ $section->{name} });
            $conf = $res->{snapshots}->{ $section->{name} } = {};
            next;
        } elsif ($line =~ m/^\[([^\]]*)\]\s*$/i) {
            my $unknown_section = $1;
            $section = undef;
            $finish_description->();
            $handle_error->("vm $vmid - skipping unknown section: '$unknown_section'\n");
            next;
        }

        next if !defined($section);

        if ($line =~ m/^\#(.*)$/) {
            $descr = '' if !defined($descr);
            $descr .= PVE::Tools::decode_text($1) . "\n";
            next;
        }

        if ($line =~ m/^(description):\s*(.*\S)\s*$/) {
            $descr = '' if !defined($descr);
            $descr .= PVE::Tools::decode_text($2);
        } elsif ($line =~ m/snapstate:\s*(prepare|delete)\s*$/) {
            $conf->{snapstate} = $1;
        } elsif ($line =~ m/^(args):\s*(.*\S)\s*$/) {
            my $key = $1;
            my $value = $2;
            $conf->{$key} = $value;
        } elsif ($line =~ m/^delete:\s*(.*\S)\s*$/) {
            my $value = $1;
            if ($section->{name} eq 'pending' && $section->{type} eq 'pending') {
                $conf->{delete} = $value; # we parse this later
            } else {
                $handle_error->("vm $vmid - property 'delete' is only allowed in [PENDING]\n");
            }
        } elsif ($line =~ m/^([a-z][a-z_\-]*\d*):\s*(.+?)\s*$/) {
            my $key = $1;
            my $value = $2;
            if ($section->{name} eq 'cloudinit' && $section->{type} eq 'special') {
                # ignore validation only used for informative purpose
                $conf->{$key} = $value;
                next;
            }
            eval { $value = check_type($key, $value, $section->{schema}); };
            if ($@) {
                $handle_error->("vm $vmid - unable to parse value of '$key' - $@");
            } else {
                $key = 'ide2' if $key eq 'cdrom';
                my $fmt = $section->{schema}->{$key}->{format};
                if ($fmt && $fmt =~ /^pve-qm-(?:ide|scsi|virtio|sata)$/) {
                    my $v = parse_drive($key, $value);
                    if (my $volid = filename_to_volume_id($vmid, $v->{file}, $v->{media})) {
                        $v->{file} = $volid;
                        $value = print_drive($v);
                    } else {
                        $handle_error->("vm $vmid - unable to parse value of '$key'\n");
                        next;
                    }
                }

                $conf->{$key} = $value;
            }
        } else {
            $handle_error->("vm $vmid - unable to parse config: $line\n");
        }
    }

    $finish_description->();
    delete $res->{snapstate}; # just to be sure

    $res->{pending} = {} if !defined($res->{pending});

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
            next
                if $key eq 'digest'
                || $key eq 'description'
                || $key eq 'snapshots'
                || $key eq 'snapstate'
                || $key eq 'pending'
                || $key eq 'special-sections';
            my $value = $cref->{$key};
            if ($key eq 'delete') {
                die "propertry 'delete' is only allowed in [PENDING]\n"
                    if !$pending;
                # fixme: check syntax?
                next;
            }
            eval { $value = check_type($key, $value, $confdesc); };
            die "unable to parse value of '$key' - $@" if $@;

            $cref->{$key} = $value;

            if (!$snapname && is_valid_drivename($key)) {
                my $drive = parse_drive($key, $value);
                $used_volids->{ $drive->{file} } = 1 if $drive && $drive->{file};
            }
        }
    };

    &$cleanup_config($conf);

    &$cleanup_config($conf->{pending}, 1);

    foreach my $snapname (keys %{ $conf->{snapshots} }) {
        die "internal error: snapshot name '$snapname' is forbidden" if lc($snapname) eq 'pending';
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
        my ($conf, $pending) = @_;

        my $raw = '';

        # add description as comment to top of file
        if (defined(my $descr = $conf->{description})) {
            if ($descr) {
                foreach my $cl (split(/\n/, $descr)) {
                    $raw .= '#' . PVE::Tools::encode_text($cl) . "\n";
                }
            } else {
                $raw .= "#\n" if $pending;
            }
        }

        foreach my $key (sort keys %$conf) {
            next if $key =~ /^(digest|description|pending|snapshots|special-sections)$/;
            $raw .= "$key: $conf->{$key}\n";
        }
        return $raw;
    };

    my $raw = &$generate_raw_config($conf);

    if (scalar(keys %{ $conf->{pending} })) {
        $raw .= "\n[PENDING]\n";
        $raw .= &$generate_raw_config($conf->{pending}, 1);
    }

    for my $special (sort keys $conf->{'special-sections'}->%*) {
        next if $special eq 'cloudinit' && !PVE::QemuConfig->has_cloudinit($conf);
        $raw .= "\n[special:$special]\n";
        $raw .= &$generate_raw_config($conf->{'special-sections'}->{$special});
    }

    foreach my $snapname (sort keys %{ $conf->{snapshots} }) {
        $raw .= "\n[$snapname]\n";
        $raw .= &$generate_raw_config($conf->{snapshots}->{$snapname});
    }

    return $raw;
}

sub load_defaults {

    my $res = {};

    # we use static defaults from our JSON schema configuration
    foreach my $key (keys %$confdesc) {
        if (defined(my $default = $confdesc->{$key}->{default})) {
            $res->{$key} = $default;
        }
    }

    return $res;
}

sub config_list {
    my $vmlist = PVE::Cluster::get_vmlist();
    my $res = {};
    return $res if !$vmlist || !$vmlist->{ids};
    my $ids = $vmlist->{ids};
    my $nodename = nodename();

    foreach my $vmid (keys %$ids) {
        my $d = $ids->{$vmid};
        next if !$d->{node} || $d->{node} ne $nodename;
        next if !$d->{type} || $d->{type} ne 'qemu';
        $res->{$vmid}->{exists} = 1;
    }
    return $res;
}

# check if used storages are available on all nodes (use by migrate)
sub check_storage_availability {
    my ($storecfg, $conf, $node) = @_;

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;

            my $volid = $drive->{file};
            return if !$volid;

            my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
            return if !$sid;

            # check if storage is available on both nodes
            my $scfg = PVE::Storage::storage_check_enabled($storecfg, $sid);
            PVE::Storage::storage_check_enabled($storecfg, $sid, $node);

            my ($vtype) = PVE::Storage::parse_volname($storecfg, $volid);

            die "$volid: content type '$vtype' is not available on storage '$sid'\n"
                if !$scfg->{content}->{$vtype};
        },
    );
}

# list nodes where all VM images are available (used by has_feature API)
sub shared_nodes {
    my ($conf, $storecfg) = @_;

    my $nodelist = PVE::Cluster::get_nodelist();
    my $nodehash = { map { $_ => 1 } @$nodelist };
    my $nodename = nodename();

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
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
                        delete $nodehash->{$node} if $node ne $nodename;
                    }
                }
            }
        },
    );

    return $nodehash;
}

sub check_local_storage_availability {
    my ($conf, $storecfg) = @_;

    my $nodelist = PVE::Cluster::get_nodelist();
    my $nodehash = { map { $_ => {} } @$nodelist };

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;

            my $volid = $drive->{file};
            return if !$volid;

            my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
            if ($storeid) {
                my $scfg = PVE::Storage::storage_config($storecfg, $storeid);

                if ($scfg->{disable}) {
                    foreach my $node (keys %$nodehash) {
                        $nodehash->{$node}->{unavailable_storages}->{$storeid} = 1;
                    }
                } elsif (my $avail = $scfg->{nodes}) {
                    foreach my $node (keys %$nodehash) {
                        if (!$avail->{$node}) {
                            $nodehash->{$node}->{unavailable_storages}->{$storeid} = 1;
                        }
                    }
                }
            }
        },
    );

    foreach my $node (values %$nodehash) {
        if (my $unavail = $node->{unavailable_storages}) {
            $node->{unavailable_storages} = [sort keys %$unavail];
        }
    }

    return $nodehash;
}

# Compat only, use assert_config_exists_on_node and vm_running_locally where possible
sub check_running {
    my ($vmid, $nocheck, $node) = @_;

    # $nocheck is set when called during a migration, in which case the config
    # file might still or already reside on the *other* node
    # - because rename has already happened, and current node is source
    # - because rename hasn't happened yet, and current node is target
    # - because rename has happened, current node is target, but hasn't yet
    # processed it yet
    PVE::QemuConfig::assert_config_exists_on_node($vmid, $node) if !$nocheck;
    return PVE::QemuServer::Helpers::vm_running_locally($vmid);
}

sub vzlist {

    my $vzlist = config_list();

    my $fd = IO::Dir->new($PVE::QemuServer::Helpers::var_run_tmpdir) || return $vzlist;

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

# Iterate over all PIDs inside a VMID's cgroup slice and accumulate their PSS (proportional set
# size) to get a relatively telling effective memory usage of all processes involved with a VM.
my sub get_vmid_total_cgroup_memory_usage {
    my ($vmid) = @_;

    my $memory_usage = 0;
    if (my $procs_fh = IO::File->new("/sys/fs/cgroup/qemu.slice/${vmid}.scope/cgroup.procs", "r")) {
        while (my $pid = <$procs_fh>) {
            chomp($pid);

            open(my $smaps_fh, '<', "/proc/${pid}/smaps_rollup")
                or $!{ENOENT}
                or die "failed to open PSS memory-stat from process - $!\n";
            next if !defined($smaps_fh);

            while (my $line = <$smaps_fh>) {
                if ($line =~ m/^Pss:\s+([0-9]+) kB$/) {
                    $memory_usage += int($1) * 1024;
                    last; # end inner while loop, go to next $pid
                }
            }
            close $smaps_fh;
        }
        close($procs_fh);
    }

    return $memory_usage;
}

our $vmstatus_return_properties = {
    vmid => get_standard_option('pve-vmid'),
    status => {
        description => "QEMU process status.",
        type => 'string',
        enum => ['stopped', 'running'],
    },
    mem => {
        description => "Currently used memory in bytes.",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    maxmem => {
        description => "Maximum memory in bytes.",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    memhost => {
        description => "Current memory usage on the host.",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    maxdisk => {
        description => "Root disk size in bytes.",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    diskread => {
        description =>
            "The amount of bytes the guest read from it's block devices since the guest"
            . " was started. (Note: This info is not available for all storage types.)",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    diskwrite => {
        description =>
            "The amount of bytes the guest wrote from it's block devices since the guest"
            . " was started. (Note: This info is not available for all storage types.)",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    name => {
        description => "VM (host)name.",
        type => 'string',
        optional => 1,
    },
    netin => {
        description =>
            "The amount of traffic in bytes that was sent to the guest over the network"
            . " since it was started.",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    netout => {
        description =>
            "The amount of traffic in bytes that was sent from the guest over the network"
            . " since it was started.",
        type => 'integer',
        optional => 1,
        renderer => 'bytes',
    },
    qmpstatus => {
        description => "VM run state from the 'query-status' QMP monitor command.",
        type => 'string',
        optional => 1,
    },
    pid => {
        description => "PID of the QEMU process, if the VM is running.",
        type => 'integer',
        optional => 1,
    },
    uptime => {
        description => "Uptime in seconds.",
        type => 'integer',
        optional => 1,
        renderer => 'duration',
    },
    cpu => {
        description => "Current CPU usage.",
        type => 'number',
        optional => 1,
    },
    cpus => {
        description => "Maximum usable CPUs.",
        type => 'number',
        optional => 1,
    },
    lock => {
        description => "The current config lock, if any.",
        type => 'string',
        optional => 1,
    },
    tags => {
        description => "The current configured tags, if any",
        type => 'string',
        optional => 1,
    },
    'running-machine' => {
        description => "The currently running machine type (if running).",
        type => 'string',
        optional => 1,
    },
    'running-qemu' => {
        description => "The QEMU version the VM is currently using (if running).",
        type => 'string',
        optional => 1,
    },
    template => {
        description => "Determines if the guest is a template.",
        type => 'boolean',
        optional => 1,
        default => 0,
    },
    serial => {
        description => "Guest has serial device configured.",
        type => 'boolean',
        optional => 1,
    },
    pressurecpusome => {
        description => "CPU Some pressure stall average over the last 10 seconds.",
        type => 'number',
        optional => 1,
    },
    pressurecpufull => {
        description => "CPU Full pressure stall average over the last 10 seconds.",
        type => 'number',
        optional => 1,
    },
    pressureiosome => {
        description => "IO Some pressure stall average over the last 10 seconds.",
        type => 'number',
        optional => 1,
    },
    pressureiofull => {
        description => "IO Full pressure stall average over the last 10 seconds.",
        type => 'number',
        optional => 1,
    },
    pressurememorysome => {
        description => "Memory Some pressure stall average over the last 10 seconds.",
        type => 'number',
        optional => 1,
    },
    pressurememoryfull => {
        description => "Memory Full pressure stall average over the last 10 seconds.",
        type => 'number',
        optional => 1,
    },
};

my $last_proc_pid_stat;

# get VM status information
# This must be fast and should not block ($full == false)
# We only query KVM using QMP if $full == true (this can be slow)
sub vmstatus {
    my ($opt_vmid, $full) = @_;

    my $res = {};

    my $storecfg = PVE::Storage::config();

    my $list = vzlist();
    my $defaults = load_defaults();

    my ($uptime) = PVE::ProcFSTools::read_proc_uptime(1);

    my $cpucount = $cpuinfo->{cpus} || 1;

    foreach my $vmid (keys %$list) {
        next if $opt_vmid && ($vmid ne $opt_vmid);

        my $conf = PVE::QemuConfig->load_config($vmid);

        my $d = { vmid => int($vmid) };
        $d->{pid} = int($list->{$vmid}->{pid}) if $list->{$vmid}->{pid};

        # fixme: better status?
        $d->{status} = $list->{$vmid}->{pid} ? 'running' : 'stopped';

        my $size = PVE::QemuServer::Drive::bootdisk_size($storecfg, $conf);
        if (defined($size)) {
            $d->{disk} = 0; # no info available
            $d->{maxdisk} = $size;
        } else {
            $d->{disk} = 0;
            $d->{maxdisk} = 0;
        }

        $d->{cpus} =
            ($conf->{sockets} || $defaults->{sockets}) * ($conf->{cores} || $defaults->{cores});
        $d->{cpus} = $cpucount if $d->{cpus} > $cpucount;
        $d->{cpus} = $conf->{vcpus} if $conf->{vcpus};

        $d->{name} = $conf->{name} || "VM $vmid";
        $d->{maxmem} = get_current_memory($conf->{memory}) * (1024 * 1024);

        if ($conf->{balloon}) {
            $d->{balloon_min} = $conf->{balloon} * (1024 * 1024);
            $d->{shares} =
                defined($conf->{shares})
                ? $conf->{shares}
                : $defaults->{shares};
        }

        $d->{uptime} = 0;
        $d->{cpu} = 0;
        $d->{mem} = 0;
        $d->{memhost} = 0;

        $d->{netout} = 0;
        $d->{netin} = 0;

        $d->{diskread} = 0;
        $d->{diskwrite} = 0;

        $d->{template} = 1 if PVE::QemuConfig->is_template($conf);

        $d->{serial} = 1 if conf_has_serial($conf);
        $d->{lock} = $conf->{lock} if $conf->{lock};
        $d->{tags} = $conf->{tags} if defined($conf->{tags});

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

        if ($full) {
            $d->{nics}->{$dev}->{netout} = int($netdev->{$dev}->{receive});
            $d->{nics}->{$dev}->{netin} = int($netdev->{$dev}->{transmit});
        }

    }

    my $ctime = gettimeofday;

    foreach my $vmid (keys %$list) {

        my $d = $res->{$vmid};
        my $pid = $d->{pid};
        next if !$pid;

        my $pstat = PVE::ProcFSTools::read_proc_pid_stat($pid);
        next if !$pstat; # not running

        my $used = $pstat->{utime} + $pstat->{stime};

        $d->{uptime} = int(($uptime - $pstat->{starttime}) / $cpuinfo->{user_hz});

        if ($pstat->{vsize}) {
            $d->{mem} = int(($pstat->{rss} / $pstat->{vsize}) * $d->{maxmem});
        }

        $d->{memhost} = get_vmid_total_cgroup_memory_usage($vmid);

        my $pressures = PVE::ProcFSTools::read_cgroup_pressure("qemu.slice/${vmid}.scope");
        $d->{pressurecpusome} = $pressures->{cpu}->{some}->{avg10} * 1;
        $d->{pressurecpufull} = $pressures->{cpu}->{full}->{avg10} * 1;
        $d->{pressureiosome} = $pressures->{io}->{some}->{avg10} * 1;
        $d->{pressureiofull} = $pressures->{io}->{full}->{avg10} * 1;
        $d->{pressurememorysome} = $pressures->{memory}->{some}->{avg10} * 1;
        $d->{pressurememoryfull} = $pressures->{memory}->{full}->{avg10} * 1;

        my $old = $last_proc_pid_stat->{$pid};
        if (!$old) {
            $last_proc_pid_stat->{$pid} = {
                time => $ctime,
                used => $used,
                cpu => 0,
            };
            next;
        }

        my $dtime = ($ctime - $old->{time}) * $cpucount * $cpuinfo->{user_hz};

        if ($dtime > 1000) {
            my $dutime = $used - $old->{used};

            $d->{cpu} = (($dutime / $dtime) * $cpucount) / $d->{cpus};
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

        $d->{ballooninfo} = $info;
    };

    my $blockstatscb = sub {
        my ($vmid, $resp) = @_;
        my $data = $resp->{'return'} || [];
        my $totalrdbytes = 0;
        my $totalwrbytes = 0;

        for my $blockstat (@$data) {
            $totalrdbytes = $totalrdbytes + $blockstat->{stats}->{rd_bytes};
            $totalwrbytes = $totalwrbytes + $blockstat->{stats}->{wr_bytes};

            # With the switch to -blockdev, the block backend in QEMU has no name, so need to also
            # consider the qdev ID. Note that empty CD-ROM drives do not have a node name, so that
            # cannot be used as a fallback instead of the qdev ID.
            my $drive_id;
            if ($blockstat->{device}) {
                $drive_id = $blockstat->{device} =~ s/drive-//r;
            } elsif ($blockstat->{qdev}) {
                $drive_id = PVE::QemuServer::Blockdev::qdev_id_to_drive_id($blockstat->{qdev});
            } else {
                print "blockstats callback: unexpected missing drive ID\n";
                next;
            }

            $res->{$vmid}->{blockstat}->{$drive_id} = $blockstat->{stats};
        }
        $res->{$vmid}->{diskread} = $totalrdbytes;
        $res->{$vmid}->{diskwrite} = $totalwrbytes;
    };

    my $machinecb = sub {
        my ($vmid, $resp) = @_;
        my $data = $resp->{'return'} || [];

        $res->{$vmid}->{'running-machine'} =
            PVE::QemuServer::Machine::current_from_query_machines($data);
    };

    my $versioncb = sub {
        my ($vmid, $resp) = @_;
        my $data = $resp->{'return'} // {};
        my $version = 'unknown';

        if (my $v = $data->{qemu}) {
            $version = $v->{major} . "." . $v->{minor} . "." . $v->{micro};
        }

        $res->{$vmid}->{'running-qemu'} = $version;
    };

    my $statuscb = sub {
        my ($vmid, $resp) = @_;

        $qmpclient->queue_cmd($vmid, $blockstatscb, 'query-blockstats');
        $qmpclient->queue_cmd($vmid, $machinecb, 'query-machines');
        $qmpclient->queue_cmd($vmid, $versioncb, 'query-version');
        # this fails if ballon driver is not loaded, so this must be
        # the last command (following command are aborted if this fails).
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

    $qmpclient->queue_execute(undef, 2);

    foreach my $vmid (keys %$list) {
        next if $opt_vmid && ($vmid ne $opt_vmid);
        next if !$res->{$vmid}->{pid}; #not running

        # we can't use the $qmpclient since it might have already aborted on
        # 'query-balloon', but this might also fail for older versions...
        my $qemu_support = eval { mon_cmd($vmid, "query-proxmox-support") };
        $res->{$vmid}->{'proxmox-support'} = $qemu_support // {};
    }

    foreach my $vmid (keys %$list) {
        next if $opt_vmid && ($vmid ne $opt_vmid);
        $res->{$vmid}->{qmpstatus} = $res->{$vmid}->{status} if !$res->{$vmid}->{qmpstatus};
    }

    return $res;
}

sub conf_has_serial {
    my ($conf) = @_;

    for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++) {
        if ($conf->{"serial$i"}) {
            return 1;
        }
    }

    return 0;
}

sub conf_has_audio {
    my ($conf, $id) = @_;

    $id //= 0;
    my $audio = $conf->{"audio$id"};
    return if !defined($audio);

    my $audioproperties = parse_property_string($audio_fmt, $audio);
    my $audiodriver = $audioproperties->{driver} // 'spice';

    return {
        dev => $audioproperties->{device},
        dev_id => "audiodev$id",
        backend => $audiodriver,
        backend_id => "$audiodriver-backend${id}",
    };
}

sub audio_devs {
    my ($audio, $audiopciaddr, $machine_version) = @_;

    my $devs = [];

    my $id = $audio->{dev_id};
    my $audiodev = "";
    if (min_version($machine_version, 4, 2)) {
        $audiodev = ",audiodev=$audio->{backend_id}";
    }

    if ($audio->{dev} eq 'AC97') {
        push @$devs, '-device', "AC97,id=${id}${audiopciaddr}$audiodev";
    } elsif ($audio->{dev} =~ /intel\-hda$/) {
        push @$devs, '-device', "$audio->{dev},id=${id}${audiopciaddr}";
        push @$devs, '-device', "hda-micro,id=${id}-codec0,bus=${id}.0,cad=0$audiodev";
        push @$devs, '-device', "hda-duplex,id=${id}-codec1,bus=${id}.0,cad=1$audiodev";
    } else {
        die "unknown audio device '$audio->{dev}', implement me!";
    }

    push @$devs, '-audiodev', "$audio->{backend},id=$audio->{backend_id}";

    return $devs;
}

sub get_tpm_paths {
    my ($vmid) = @_;
    return {
        socket => "/var/run/qemu-server/$vmid.swtpm",
        pid => "/var/run/qemu-server/$vmid.swtpm.pid",
    };
}

sub add_tpm_device {
    my ($vmid, $devices, $conf) = @_;

    return if !$conf->{tpmstate0};

    my $paths = get_tpm_paths($vmid);

    push @$devices, "-chardev", "socket,id=tpmchar,path=$paths->{socket}";
    push @$devices, "-tpmdev", "emulator,id=tpmdev,chardev=tpmchar";
    push @$devices, "-device", "tpm-tis,tpmdev=tpmdev";
}

sub start_swtpm {
    my ($storecfg, $vmid, $tpmdrive, $migration) = @_;

    return if !$tpmdrive;

    my $state;
    my $tpm = parse_drive("tpmstate0", $tpmdrive);
    my ($storeid) = PVE::Storage::parse_volume_id($tpm->{file}, 1);
    if ($storeid) {
        my $format = checked_volume_format($storecfg, $tpm->{file});
        die "swtpm currently only supports 'raw' state volumes\n" if $format ne 'raw';
        $state = PVE::Storage::map_volume($storecfg, $tpm->{file});
    } else {
        $state = $tpm->{file};
    }

    my $paths = get_tpm_paths($vmid);

    # during migration, we will get state from remote
    #
    if (!$migration) {
        # run swtpm_setup to create a new TPM state if it doesn't exist yet
        my $setup_cmd = [
            "swtpm_setup",
            "--tpmstate",
            "file://$state",
            "--createek",
            "--create-ek-cert",
            "--create-platform-cert",
            "--lock-nvram",
            "--config",
            "/etc/swtpm_setup.conf", # do not use XDG configs
            "--runas",
            "0", # force creation as root, error if not possible
            "--not-overwrite", # ignore existing state, do not modify
        ];

        push @$setup_cmd, "--tpm2" if $tpm->{version} && $tpm->{version} eq 'v2.0';
        # TPM 2.0 supports ECC crypto, use if possible
        push @$setup_cmd, "--ecc" if $tpm->{version} && $tpm->{version} eq 'v2.0';

        run_command(
            $setup_cmd,
            outfunc => sub {
                print "swtpm_setup: $1\n";
            },
        );
    }

    # Used to distinguish different invocations in the log.
    my $log_prefix = "[id=" . int(time()) . "] ";

    my $emulator_cmd = [
        "swtpm",
        "socket",
        "--tpmstate",
        "backend-uri=file://$state,mode=0600",
        "--ctrl",
        "type=unixio,path=$paths->{socket},mode=0600",
        "--pid",
        "file=$paths->{pid}",
        "--terminate", # terminate on QEMU disconnect
        "--daemon",
        "--log",
        "file=/run/qemu-server/$vmid-swtpm.log,level=1,prefix=$log_prefix",
    ];
    push @$emulator_cmd, "--tpm2" if $tpm->{version} && $tpm->{version} eq 'v2.0';
    run_command($emulator_cmd, outfunc => sub { print $1; });

    my $tries = 100; # swtpm may take a bit to start before daemonizing, wait up to 5s for pid
    while (!-e $paths->{pid}) {
        die "failed to start swtpm: pid file '$paths->{pid}' wasn't created.\n" if --$tries == 0;
        usleep(50_000);
    }

    # return untainted PID of swtpm daemon so it can be killed on error
    file_read_firstline($paths->{pid}) =~ m/(\d+)/;
    return $1;
}

sub vga_conf_has_spice {
    my ($vga) = @_;

    my $vgaconf = parse_vga($vga);
    my $vgatype = $vgaconf->{type};
    return 0 if !$vgatype || $vgatype !~ m/^qxl([234])?$/;

    return $1 || 1;
}

# To use query_supported_cpu_flags and query_understood_cpu_flags to get flags
# to use in a QEMU command line (-cpu element), first array_intersect the result
# of query_supported_ with query_understood_. This is necessary because:
#
# a) query_understood_ returns flags the host cannot use and
# b) query_supported_ (rather the QMP call) doesn't actually return CPU
#    flags, but CPU settings - with most of them being flags. Those settings
#    (and some flags, curiously) cannot be specified as a "-cpu" argument.
#
# query_supported_ needs to start up to 2 temporary VMs and is therefore rather
# expensive. If you need the value returned from this, you can get it much
# cheaper from pmxcfs using PVE::Cluster::get_node_kv('cpuflags-$accel') with
# $accel being 'kvm' or 'tcg'.
#
# pvestatd calls this function on startup and whenever the QEMU/KVM version
# changes, automatically populating pmxcfs.
#
# Returns: { kvm => [ flagX, flagY, ... ], tcg => [ flag1, flag2, ... ] }
# since kvm and tcg machines support different flags
#
sub query_supported_cpu_flags {
    my ($arch) = @_;

    $arch //= get_host_arch();
    my $default_machine = PVE::QemuServer::Machine::default_machine_for_arch($arch);

    my $flags = {};

    # FIXME: Once this is merged, the code below should work for ARM as well:
    # https://lists.nongnu.org/archive/html/qemu-devel/2019-06/msg04947.html
    die "QEMU/KVM cannot detect CPU flags on ARM (aarch64)\n"
        if $arch eq "aarch64";

    my $kvm_supported = defined(kvm_version());
    my $qemu_cmd = PVE::QemuServer::Helpers::get_command_for_arch($arch);
    my $fakevmid = -1;
    my $pidfile = PVE::QemuServer::Helpers::pidfile_name($fakevmid);

    # Start a temporary (frozen) VM with vmid -1 to allow sending a QMP command
    my $query_supported_run_qemu = sub {
        my ($kvm) = @_;

        my $flags = {};
        my $cmd = [
            $qemu_cmd,
            '-machine',
            $default_machine,
            '-display',
            'none',
            '-chardev',
            "socket,id=qmp,path=/var/run/qemu-server/$fakevmid.qmp,server=on,wait=off",
            '-mon',
            'chardev=qmp,mode=control',
            '-pidfile',
            $pidfile,
            '-S',
            '-daemonize',
        ];

        if (!$kvm) {
            push @$cmd, '-accel', 'tcg';
        }

        my $rc = run_command($cmd, noerr => 1, quiet => 0);
        die "QEMU flag querying VM exited with code " . $rc if $rc;

        eval {
            my $cmd_result = mon_cmd(
                $fakevmid,
                'query-cpu-model-expansion',
                type => 'full',
                model => { name => 'host' },
            );

            my $props = $cmd_result->{model}->{props};
            foreach my $prop (keys %$props) {
                next if $props->{$prop} ne '1';
                # QEMU returns some flags multiple times, with '_', '.' or '-'
                # (e.g. lahf_lm and lahf-lm; sse4.2, sse4-2 and sse4_2; ...).
                # We only keep those with underscores, to match /proc/cpuinfo
                $prop =~ s/\.|-/_/g;
                $flags->{$prop} = 1;
            }
        };
        my $err = $@;

        # force stop with 10 sec timeout and 'nocheck', always stop, even if QMP failed
        vm_stop(undef, $fakevmid, 1, 1, 10, 0, 1);

        die $err if $err;

        return [sort keys %$flags];
    };

    # We need to query QEMU twice, since KVM and TCG have different supported flags
    PVE::QemuConfig->lock_config(
        $fakevmid,
        sub {
            $flags->{tcg} = eval { $query_supported_run_qemu->(0) };
            warn "warning: failed querying supported tcg flags: $@\n" if $@;

            if ($kvm_supported) {
                $flags->{kvm} = eval { $query_supported_run_qemu->(1) };
                warn "warning: failed querying supported kvm flags: $@\n" if $@;
            }
        },
    );

    return $flags;
}

# Understood CPU flags are written to a file at 'pve-qemu' compile time
my $understood_cpu_flag_dir = "/usr/share/kvm";

sub query_understood_cpu_flags {
    my $arch = get_host_arch();
    my $filepath = "$understood_cpu_flag_dir/recognized-CPUID-flags-$arch";

    die "Cannot query understood QEMU CPU flags for architecture: $arch (file not found)\n"
        if !-e $filepath;

    my $raw = file_get_contents($filepath);
    $raw =~ s/^\s+|\s+$//g;
    my @flags = split(/\s+/, $raw);

    return \@flags;
}

# Since commit 277d33454f77ec1d1e0bc04e37621e4dd2424b67 in pve-qemu, smm is not off by default
# anymore. But smm=off seems to be required when using SeaBIOS and serial display.
my sub should_disable_smm {
    my ($conf, $vga, $machine) = @_;

    return if $machine =~ m/^virt/; # there is no smm flag that could be disabled

    return
        (!defined($conf->{bios}) || $conf->{bios} eq 'seabios')
        && $vga->{type}
        && $vga->{type} =~ m/^(serial\d+|none)$/;
}

my sub get_vga_properties {
    my ($conf, $arch, $machine_version, $winversion) = @_;

    my $vga = parse_vga($conf->{vga});

    my $qxlnum = vga_conf_has_spice($conf->{vga});
    $vga->{type} = 'qxl' if $qxlnum;

    if (!$vga->{type}) {
        if ($arch eq 'aarch64') {
            $vga->{type} = 'virtio';
        } elsif (min_version($machine_version, 2, 9)) {
            $vga->{type} = (!$winversion || $winversion >= 6) ? 'std' : 'cirrus';
        } else {
            $vga->{type} = ($winversion >= 6) ? 'std' : 'cirrus';
        }
    }

    return ($vga, $qxlnum);
}

sub config_to_command {
    my ($storecfg, $vmid, $conf, $defaults, $options) = @_;

    my ($forcemachine, $forcecpu, $live_restore_backing, $dry_run) =
        $options->@{qw(force-machine force-cpu live-restore-backing dry-run)};

    # minimize config for templates, they can only start for backup,
    # so most options besides the disks are irrelevant
    if (PVE::QemuConfig->is_template($conf)) {
        my $newconf = {
            template => 1, # in case below code checks that
            kvm => 0, # to prevent an error on hosts without virtualization extensions
            vga => 'none', # to not start a vnc server
            scsihw => $conf->{scsihw}, # so that the scsi disks are correctly added
            bios => $conf->{bios}, # so efidisk gets included if it exists
            name => $conf->{name}, # so it's correct in the process list
        };

        # copy all disks over
        for my $device (PVE::QemuServer::Drive::valid_drive_names()) {
            $newconf->{$device} = $conf->{$device};
        }

        # remaining configs stay default

        # mark config to prevent writing it out
        PVE::QemuConfig::NoWrite->mark_config($newconf);

        $conf = $newconf;
    }

    my ($machineFlags, $rtcFlags) = ([], []);
    my $devices = [];
    my $bridges = {};
    my $ostype = $conf->{ostype};
    my $winversion = windows_version($ostype);
    my $kvm = $conf->{kvm};
    my $nodename = nodename();

    my $machine_conf = PVE::QemuServer::Machine::parse_machine($conf->{machine});

    my $arch = PVE::QemuServer::Helpers::get_vm_arch($conf);
    my $kvm_binary = PVE::QemuServer::Helpers::get_command_for_arch($arch);
    my $kvmver = kvm_user_version($kvm_binary);

    if (!$kvmver || $kvmver !~ m/^(\d+)\.(\d+)/ || $1 < 6) {
        $kvmver //= "undefined";
        die "Detected old QEMU binary ('$kvmver', at least 6.0 is required)\n";
    }

    my $machine_type = PVE::QemuServer::Machine::get_vm_machine($conf, $forcemachine, $arch);
    my $machine_version = extract_version($machine_type, $kvmver);
    $kvm //= 1 if is_native_arch($arch);

    $machine_version =~ m/(\d+)\.(\d+)/;
    my ($machine_major, $machine_minor) = ($1, $2);

    if ($kvmver =~ m/^\d+\.\d+\.(\d+)/ && $1 >= 90) {
        warn
            "warning: Installed QEMU version ($kvmver) is a release candidate, ignoring version checks\n";
    } elsif (!min_version($kvmver, $machine_major, $machine_minor)) {
        die "Installed QEMU version '$kvmver' is too old to run machine type '$machine_type',"
            . " please upgrade node '$nodename'\n";
    } elsif (!PVE::QemuServer::Machine::can_run_pve_machine_version($machine_version, $kvmver)) {
        my $max_pve_version = PVE::QemuServer::Machine::get_pve_version($machine_version);
        die "Installed qemu-server (max feature level for $machine_major.$machine_minor is"
            . " pve$max_pve_version) is too old to run machine type '$machine_type', please upgrade"
            . " node '$nodename'\n";
    }

    # if a specific +pve version is required for a feature, use $version_guard
    # instead of min_version to allow machines to be run with the minimum
    # required version
    my $required_pve_version = 0;
    my $version_guard = sub {
        my ($major, $minor, $pve) = @_;
        return 0 if !min_version($machine_version, $major, $minor, $pve);
        my $max_pve = PVE::QemuServer::Machine::get_pve_version("$major.$minor");
        return 1 if min_version($machine_version, $major, $minor, $max_pve + 1);
        $required_pve_version = $pve if $pve && $pve > $required_pve_version;
        return 1;
    };

    if ($kvm && !defined kvm_version()) {
        die "KVM virtualisation configured, but not available. Either disable in VM configuration"
            . " or enable in BIOS.\n";
    }

    my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);
    my $hotplug_features =
        parse_hotplug_features(defined($conf->{hotplug}) ? $conf->{hotplug} : '1');
    my $use_old_bios_files = undef;
    ($use_old_bios_files, $machine_type) = qemu_use_old_bios_files($machine_type);

    my $cmd = [];
    if ($conf->{affinity}) {
        push @$cmd, '/usr/bin/taskset', '--cpu-list', '--all-tasks', $conf->{affinity};
    }

    push @$cmd, $kvm_binary;

    push @$cmd, '-id', $vmid;

    my $vmname = $conf->{name} || "vm$vmid";

    push @$cmd, '-name', "$vmname,debug-threads=on";

    push @$cmd, '-no-shutdown';

    my $use_virtio = 0;

    my $qmpsocket = PVE::QemuServer::Helpers::qmp_socket($vmid);
    push @$cmd, '-chardev', "socket,id=qmp,path=$qmpsocket,server=on,wait=off";
    push @$cmd, '-mon', "chardev=qmp,mode=control";

    if (min_version($machine_version, 2, 12)) {
        # QEMU 9.2 introduced a new 'reconnect-ms' option while deprecating the 'reconnect' option
        my $reconnect_param = "reconnect=5";
        if (min_version($kvmver, 9, 2)) { # this depends on the binary version
            $reconnect_param = "reconnect-ms=5000";
        }
        push @$cmd, '-chardev', "socket,id=qmp-event,path=/var/run/qmeventd.sock,$reconnect_param";
        push @$cmd, '-mon', "chardev=qmp-event,mode=control";
    }

    push @$cmd, '-pidfile', PVE::QemuServer::Helpers::pidfile_name($vmid);

    push @$cmd, '-daemonize';

    if ($conf->{smbios1}) {
        my $smbios_conf = parse_smbios1($conf->{smbios1});
        if ($smbios_conf->{base64}) {
            # Do not pass base64 flag to qemu
            delete $smbios_conf->{base64};
            my $smbios_string = "";
            foreach my $key (keys %$smbios_conf) {
                my $value;
                if ($key eq "uuid") {
                    $value = $smbios_conf->{uuid};
                } else {
                    $value = decode_base64($smbios_conf->{$key});
                }
                # qemu accepts any binary data, only commas need escaping by double comma
                $value =~ s/,/,,/g;
                $smbios_string .= "," . $key . "=" . $value if $value;
            }
            push @$cmd, '-smbios', "type=1" . $smbios_string;
        } else {
            push @$cmd, '-smbios', "type=1,$conf->{smbios1}";
        }
    }

    if ($conf->{bios} && $conf->{bios} eq 'ovmf') {
        die "OVMF (UEFI) BIOS is not supported on 32-bit CPU types\n"
            if !$forcecpu && get_cpu_bitness($conf->{cpu}, $arch) == 32;

        my $hw_info = {
            'amd-sev-type' => get_amd_sev_type($conf),
            arch => $arch,
            'machine-version' => $machine_version,
            q35 => $q35,
        };
        my ($ovmf_cmd, $ovmf_machine_flags) = PVE::QemuServer::OVMF::print_ovmf_commandline(
            $conf, $storecfg, $vmid, $hw_info, $version_guard,
        );
        push $cmd->@*, $ovmf_cmd->@*;
        push $machineFlags->@*, $ovmf_machine_flags->@*;
    }

    if ($q35) { # tell QEMU to load q35 config early
        # we use different pcie-port hardware for qemu >= 4.0 for passthrough
        if (min_version($machine_version, 4, 0)) {
            push @$devices, '-readconfig', '/usr/share/qemu-server/pve-q35-4.0.cfg';
        } else {
            push @$devices, '-readconfig', '/usr/share/qemu-server/pve-q35.cfg';
        }
    }

    if (defined(my $fixups = qemu_created_version_fixups($conf, $forcemachine, $kvmver))) {
        push @$cmd, $fixups->@*;
    }

    if ($conf->{vmgenid}) {
        push @$devices, '-device', 'vmgenid,guid=' . $conf->{vmgenid};
    }

    # add usb controllers
    my @usbcontrollers =
        PVE::QemuServer::USB::get_usb_controllers($conf, $bridges, $arch, $machine_version);
    push @$devices, @usbcontrollers if @usbcontrollers;

    my ($vga, $qxlnum) = get_vga_properties($conf, $arch, $machine_version, $winversion);

    # enable absolute mouse coordinates (needed by vnc)
    my $tablet = $conf->{tablet};
    if (!defined($tablet)) {
        $tablet = $defaults->{tablet};
        $tablet = 0 if $qxlnum; # disable for spice because it is not needed
        $tablet = 0 if $vga->{type} =~ m/^serial\d+$/; # disable if we use serial terminal (no vga card)
    }

    if ($tablet) {
        push @$devices, '-device', print_tabletdevice_full($conf, $arch) if $tablet;
        my $kbd = print_keyboarddevice_full($conf, $arch);
        push @$devices, '-device', $kbd if defined($kbd);
    }

    my $bootorder = device_bootorder($conf);

    # host pci device passthrough
    my ($kvm_off, $gpu_passthrough, $legacy_igd, $pci_devices) =
        PVE::QemuServer::PCI::print_hostpci_devices(
            $vmid, $conf, $devices, $vga, $winversion, $bridges, $arch, $bootorder, $dry_run,
        );

    # usb devices
    my $usb_dev_features = {};
    $usb_dev_features->{spice_usb3} = 1 if min_version($machine_version, 4, 0);

    my @usbdevices = PVE::QemuServer::USB::get_usb_devices(
        $conf, $usb_dev_features, $bootorder, $machine_version,
    );
    push @$devices, @usbdevices if @usbdevices;

    # serial devices
    for (my $i = 0; $i < $MAX_SERIAL_PORTS; $i++) {
        my $path = $conf->{"serial$i"} or next;
        if ($path eq 'socket') {
            my $socket = "/var/run/qemu-server/${vmid}.serial$i";
            push @$devices, '-chardev', "socket,id=serial$i,path=$socket,server=on,wait=off";
            # On aarch64, serial0 is the UART device. QEMU only allows
            # connecting UART devices via the '-serial' command line, as
            # the device has a fixed slot on the hardware...
            if ($arch eq 'aarch64' && $i == 0) {
                push @$devices, '-serial', "chardev:serial$i";
            } else {
                push @$devices, '-device', "isa-serial,chardev=serial$i";
            }
        } else {
            die "no such serial device\n" if !-c $path;
            push @$devices, '-chardev', "serial,id=serial$i,path=$path";
            push @$devices, '-device', "isa-serial,chardev=serial$i";
        }
    }

    # parallel devices
    for (my $i = 0; $i < $MAX_PARALLEL_PORTS; $i++) {
        if (my $path = $conf->{"parallel$i"}) {
            die "no such parallel device\n" if !-c $path;
            my $devtype = $path =~ m!^/dev/usb/lp! ? 'serial' : 'parallel';
            push @$devices, '-chardev', "$devtype,id=parallel$i,path=$path";
            push @$devices, '-device', "isa-parallel,chardev=parallel$i";
        }
    }

    if (min_version($machine_version, 4, 0) && (my $audio = conf_has_audio($conf))) {
        my $audiopciaddr = print_pci_addr("audio0", $bridges, $arch);
        my $audio_devs = audio_devs($audio, $audiopciaddr, $machine_version);
        push @$devices, @$audio_devs;
    }

    # Add a TPM only if the VM is not a template,
    # to support backing up template VMs even if the TPM disk is write-protected.
    add_tpm_device($vmid, $devices, $conf) if (!PVE::QemuConfig->is_template($conf));

    my $sockets = 1;
    $sockets = $conf->{smp} if $conf->{smp}; # old style - no longer iused
    $sockets = $conf->{sockets} if $conf->{sockets};

    my $cores = $conf->{cores} || 1;

    my $maxcpus = $sockets * $cores;

    my $vcpus = $conf->{vcpus} ? $conf->{vcpus} : $maxcpus;

    my $allowed_vcpus = $cpuinfo->{cpus};

    die "MAX $allowed_vcpus vcpus allowed per VM on this node\n" if ($allowed_vcpus < $maxcpus);

    if ($hotplug_features->{cpu} && min_version($machine_version, 2, 7)) {
        push @$cmd, '-smp', "1,sockets=$sockets,cores=$cores,maxcpus=$maxcpus";
        for (my $i = 2; $i <= $vcpus; $i++) {
            my $cpustr = print_cpu_device($conf, $arch, $i);
            push @$cmd, '-device', $cpustr;
        }

    } else {

        push @$cmd, '-smp', "$vcpus,sockets=$sockets,cores=$cores,maxcpus=$maxcpus";
    }
    push @$cmd, '-nodefaults';

    push @$cmd, '-boot',
        "menu=on,strict=on,reboot-timeout=1000,splash=/usr/share/qemu-server/bootsplash.jpg";

    push $machineFlags->@*, 'acpi=off' if defined($conf->{acpi}) && $conf->{acpi} == 0;

    push @$cmd, '-no-reboot' if defined($conf->{reboot}) && $conf->{reboot} == 0;

    if ($vga->{type} && $vga->{type} !~ m/^serial\d+$/ && $vga->{type} ne 'none') {
        push @$devices, '-device',
            print_vga_device($conf, $vga, $arch, $machine_version, undef, $qxlnum, $bridges);

        push @$cmd, '-display', 'egl-headless,gl=core' if $vga->{type} eq 'virtio-gl'; # VIRGL

        my $socket = PVE::QemuServer::Helpers::vnc_socket($vmid);
        push @$cmd, '-vnc', "unix:$socket,password=on";
    } else {
        push @$cmd, '-vga', 'none' if $vga->{type} eq 'none';
        push @$cmd, '-nographic';
    }

    # time drift fix
    my $tdf = defined($conf->{tdf}) ? $conf->{tdf} : $defaults->{tdf};
    my $useLocaltime = $conf->{localtime};

    if ($winversion >= 5) { # windows
        $useLocaltime = 1 if !defined($conf->{localtime});

        # use time drift fix when acpi is enabled
        if (!(defined($conf->{acpi}) && $conf->{acpi} == 0)) {
            $tdf = 1 if !defined($conf->{tdf});
        }
    }

    if ($winversion >= 6) {
        push $cmd->@*, '-global', 'kvm-pit.lost_tick_policy=discard';
        push @$machineFlags, 'hpet=off';
    }

    push @$rtcFlags, 'driftfix=slew' if $tdf;

    if ($conf->{startdate} && $conf->{startdate} ne 'now') {
        push @$rtcFlags, "base=$conf->{startdate}";
    } elsif ($useLocaltime) {
        push @$rtcFlags, 'base=localtime';
    }

    if ($forcecpu) {
        push @$cmd, '-cpu', $forcecpu;
    } else {
        push @$cmd,
            get_cpu_options(
                $conf, $arch, $kvm, $kvm_off, $machine_version, $winversion, $gpu_passthrough,
            );
    }

    my $virtiofs_enabled = PVE::QemuServer::Virtiofs::virtiofs_enabled($conf);

    PVE::QemuServer::Memory::config(
        $conf,
        $vmid,
        $sockets,
        $cores,
        $hotplug_features->{memory},
        $virtiofs_enabled,
        $cmd,
        $machineFlags,
    );

    push @$cmd, '-S' if $conf->{freeze};

    push @$cmd, '-k', $conf->{keyboard} if defined($conf->{keyboard});

    my $guest_agent = parse_guest_agent($conf);

    if ($guest_agent->{enabled}) {
        my $qgasocket = PVE::QemuServer::Helpers::qmp_socket($vmid, 1);
        push @$devices, '-chardev', "socket,path=$qgasocket,server=on,wait=off,id=qga0";

        if (!$guest_agent->{type} || $guest_agent->{type} eq 'virtio') {
            my $pciaddr = print_pci_addr("qga0", $bridges, $arch);
            push @$devices, '-device', "virtio-serial,id=qga0$pciaddr";
            push @$devices, '-device', 'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0';
        } elsif ($guest_agent->{type} eq 'isa') {
            push @$devices, '-device', "isa-serial,chardev=qga0";
        }
    }

    my $rng = $conf->{rng0} ? parse_rng($conf->{rng0}) : undef;
    if ($rng && $version_guard->(4, 1, 2)) {
        my $rng_object = print_rng_object_commandline('rng0', $rng);
        my $rng_device = print_rng_device_commandline('rng0', $rng, $bridges, $arch);
        push @$devices, '-object', $rng_object;
        push @$devices, '-device', $rng_device;
    }

    my $spice_port;

    assert_clipboard_config($vga);
    my $is_spice = $qxlnum || $vga->{type} =~ /^virtio/;

    if ($is_spice || ($vga->{'clipboard'} && $vga->{'clipboard'} eq 'vnc')) {
        if ($qxlnum > 1) {
            if ($winversion) {
                for (my $i = 1; $i < $qxlnum; $i++) {
                    push @$devices, '-device',
                        print_vga_device(
                            $conf, $vga, $arch, $machine_version, $i, $qxlnum, $bridges,
                        );
                }
            } else {
                # assume other OS works like Linux
                my ($ram, $vram) = ("134217728", "67108864");
                if ($vga->{memory}) {
                    $ram = PVE::Tools::convert_size($qxlnum * 4 * $vga->{memory}, 'mb' => 'b');
                    $vram = PVE::Tools::convert_size($qxlnum * 2 * $vga->{memory}, 'mb' => 'b');
                }
                push @$cmd, '-global', "qxl-vga.ram_size=$ram";
                push @$cmd, '-global', "qxl-vga.vram_size=$vram";
            }
        }

        my $pciaddr = print_pci_addr("spice", $bridges, $arch);

        push @$devices, '-device', "virtio-serial,id=spice$pciaddr";
        if ($vga->{'clipboard'} && $vga->{'clipboard'} eq 'vnc') {
            push @$devices, '-chardev', 'qemu-vdagent,id=vdagent,name=vdagent,clipboard=on';
        } else {
            push @$devices, '-chardev', 'spicevmc,id=vdagent,name=vdagent';
        }
        push @$devices, '-device', "virtserialport,chardev=vdagent,name=com.redhat.spice.0";

        if ($is_spice) {
            my $pfamily = PVE::Tools::get_host_address_family($nodename);
            my @nodeaddrs = PVE::Tools::getaddrinfo_all('localhost', family => $pfamily);
            die "failed to get an ip address of type $pfamily for 'localhost'\n" if !@nodeaddrs;

            my $localhost = PVE::Network::addr_to_ip($nodeaddrs[0]->{addr});
            $spice_port = PVE::Tools::next_spice_port($pfamily, $localhost);

            my $spice_enhancement_str = $conf->{spice_enhancements} // '';
            my $spice_enhancement =
                parse_property_string($spice_enhancements_fmt, $spice_enhancement_str);
            if ($spice_enhancement->{foldersharing}) {
                push @$devices, '-chardev',
                    "spiceport,id=foldershare,name=org.spice-space.webdav.0";
                push @$devices, '-device',
                    "virtserialport,chardev=foldershare,name=org.spice-space.webdav.0";
            }

            my $spice_opts =
                "tls-port=${spice_port},addr=$localhost,tls-ciphers=HIGH,seamless-migration=on";
            $spice_opts .= ",streaming-video=$spice_enhancement->{videostreaming}"
                if $spice_enhancement->{videostreaming};
            push @$devices, '-spice', "$spice_opts";
        }
    }

    # enable balloon by default, unless explicitly disabled
    if (!defined($conf->{balloon}) || $conf->{balloon}) {
        my $pciaddr = print_pci_addr("balloon0", $bridges, $arch);
        my $ballooncmd = "virtio-balloon-pci,id=balloon0$pciaddr";
        $ballooncmd .= ",free-page-reporting=on" if min_version($machine_version, 6, 2);
        push @$devices, '-device', $ballooncmd;
    }

    if ($conf->{watchdog}) {
        my $wdopts = parse_watchdog($conf->{watchdog});
        my $pciaddr = print_pci_addr("watchdog", $bridges, $arch);
        my $watchdog = $wdopts->{model} || 'i6300esb';
        push @$devices, '-device', "$watchdog$pciaddr";
        push @$devices, '-watchdog-action', $wdopts->{action} if $wdopts->{action};
    }

    my $scsicontroller = {};
    my $ahcicontroller = {};
    my $scsihw = defined($conf->{scsihw}) ? $conf->{scsihw} : $defaults->{scsihw};

    # Add iscsi initiator name if available
    if (my $initiator = get_iscsi_initiator_name()) {
        push @$devices, '-iscsi', "initiator-name=$initiator";
    }

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;

            # ignore efidisk here, already added in bios/fw handling code above
            return if $drive->{interface} eq 'efidisk';
            # similar for TPM
            return if $drive->{interface} eq 'tpmstate';

            $use_virtio = 1 if $ds =~ m/^virtio/;

            $drive->{bootindex} = $bootorder->{$ds} if $bootorder->{$ds};

            if ($drive->{interface} eq 'virtio') {
                push @$cmd, '-object', "iothread,id=iothread-$ds" if $drive->{iothread};
            }

            if ($drive->{interface} eq 'scsi') {

                my ($maxdev, $controller, $controller_prefix) = scsihw_infos($conf, $drive);

                die
                    "scsi$drive->{index}: machine version 4.1~pve2 or higher is required to use more than 14 SCSI disks\n"
                    if $drive->{index} > 13 && !&$version_guard(4, 1, 2);

                my $pciaddr = print_pci_addr("$controller_prefix$controller", $bridges, $arch);
                my $scsihw_type =
                    $scsihw =~ m/^virtio-scsi-single/ ? "virtio-scsi-pci" : $scsihw;

                my $iothread = '';
                if (
                    $conf->{scsihw}
                    && $conf->{scsihw} eq "virtio-scsi-single"
                    && $drive->{iothread}
                ) {
                    $iothread .= ",iothread=iothread-$controller_prefix$controller";
                    push @$cmd, '-object', "iothread,id=iothread-$controller_prefix$controller";
                } elsif ($drive->{iothread}) {
                    log_warn(
                        "iothread is only valid with virtio disk or virtio-scsi-single controller, ignoring\n"
                    );
                }

                my $queues = '';
                if (
                    $conf->{scsihw}
                    && $conf->{scsihw} eq "virtio-scsi-single"
                    && $drive->{queues}
                ) {
                    $queues = ",num_queues=$drive->{queues}";
                }

                push @$devices, '-device',
                    "$scsihw_type,id=$controller_prefix$controller$pciaddr$iothread$queues"
                    if !$scsicontroller->{$controller};
                $scsicontroller->{$controller} = 1;
            }

            if ($drive->{interface} eq 'sata') {
                my $controller = int($drive->{index} / $PVE::QemuServer::Drive::MAX_SATA_DISKS);
                my $pciaddr = print_pci_addr("ahci$controller", $bridges, $arch);
                push @$devices, '-device', "ahci,id=ahci$controller,multifunction=on$pciaddr"
                    if !$ahcicontroller->{$controller};
                $ahcicontroller->{$controller} = 1;
            }

            my $live_restore = $live_restore_backing->{$ds};

            if (min_version($machine_version, 10, 0)) { # for the switch to -blockdev
                if ($drive->{file} ne 'none') {
                    my $throttle_group =
                        PVE::QemuServer::Blockdev::generate_throttle_group($drive);
                    push @$cmd, '-object', to_json($throttle_group, { canonical => 1 });

                    my $extra_blockdev_options = {};
                    $extra_blockdev_options->{'live-restore'} = $live_restore if $live_restore;
                    # extra protection for templates, but SATA and IDE don't support it..
                    $extra_blockdev_options->{'read-only'} = 1
                        if drive_is_read_only($conf, $drive);

                    my $blockdev = PVE::QemuServer::Blockdev::generate_drive_blockdev(
                        $storecfg, $drive, $machine_version, $extra_blockdev_options,
                    );
                    push @$devices, '-blockdev', to_json($blockdev, { canonical => 1 });
                }
            } else {
                my $live_blockdev_name = undef;
                if ($live_restore) {
                    $live_blockdev_name = $live_restore->{name};
                    push @$devices, '-blockdev', $live_restore->{blockdev};
                }

                my $drive_cmd =
                    print_drive_commandline_full($storecfg, $vmid, $drive, $live_blockdev_name);

                # extra protection for templates, but SATA and IDE don't support it..
                $drive_cmd .= ',readonly=on' if drive_is_read_only($conf, $drive);

                push @$devices, '-drive', $drive_cmd;
            }

            push @$devices, '-device',
                print_drivedevice_full(
                    $storecfg, $conf, $vmid, $drive, $bridges, $arch, $machine_type,
                );
        },
    );

    for (my $i = 0; $i < $MAX_NETS; $i++) {
        my $netname = "net$i";

        next if !$conf->{$netname};
        my $d = PVE::QemuServer::Network::parse_net($conf->{$netname});
        next if !$d;
        # save the MAC addr here (could be auto-gen. in some odd setups) for FDB registering later?

        $use_virtio = 1 if $d->{model} eq 'virtio';

        $d->{bootindex} = $bootorder->{$netname} if $bootorder->{$netname};

        my $netdevfull = print_netdev_full($vmid, $conf, $arch, $d, $netname);
        push @$devices, '-netdev', $netdevfull;

        my $netdevicefull = print_netdevice_full(
            $vmid,
            $conf,
            $d,
            $netname,
            $bridges,
            $use_old_bios_files,
            $arch,
            $machine_version,
        );

        push @$devices, '-device', $netdevicefull;
    }

    if ($conf->{ivshmem}) {
        my $ivshmem = parse_property_string($ivshmem_fmt, $conf->{ivshmem});

        my $bus;
        if ($q35) {
            $bus = print_pcie_addr("ivshmem");
        } else {
            $bus = print_pci_addr("ivshmem", $bridges, $arch);
        }

        my $ivshmem_name = $ivshmem->{name} // $vmid;
        my $path = '/dev/shm/pve-shm-' . $ivshmem_name;

        push @$devices, '-device', "ivshmem-plain,memdev=ivshmem$bus,";
        push @$devices, '-object',
            "memory-backend-file,id=ivshmem,share=on,mem-path=$path" . ",size=$ivshmem->{size}M";
    }

    # pci.4 is nested in pci.1
    $bridges->{1} = 1 if $bridges->{4};

    if (!$q35) { # add pci bridges
        if (min_version($machine_version, 2, 3)) {
            $bridges->{1} = 1;
            $bridges->{2} = 1;
        }
        $bridges->{3} = 1 if $scsihw =~ m/^virtio-scsi-single/;
    }

    for my $k (sort { $b cmp $a } keys %$bridges) {
        next if $q35 && $k < 4; # q35.cfg already includes bridges up to 3

        my $k_name = $k;
        if ($k == 2 && $legacy_igd) {
            $k_name = "$k-igd";
        }
        my $pciaddr = print_pci_addr("pci.$k_name", undef, $arch);
        my $devstr = "pci-bridge,id=pci.$k,chassis_nr=$k$pciaddr";

        if ($q35) { # add after -readconfig pve-q35.cfg
            splice @$devices, 2, 0, '-device', $devstr;
        } else {
            unshift @$devices, '-device', $devstr if $k > 0;
        }
    }

    if (!$kvm) {
        push @$machineFlags, 'accel=tcg';
    }
    my $power_state_flags =
        PVE::QemuServer::Machine::get_power_state_flags($machine_conf, $version_guard);
    push $cmd->@*, $power_state_flags->@* if defined($power_state_flags);

    push @$machineFlags, 'smm=off' if should_disable_smm($conf, $vga, $machine_type);

    my $machine_type_min = $machine_type;
    $machine_type_min =~ s/\+pve\d+$//;
    $machine_type_min .= "+pve$required_pve_version";
    push @$machineFlags, "type=${machine_type_min}";

    PVE::QemuServer::Machine::assert_valid_machine_property($machine_conf);

    if (my $viommu = $machine_conf->{viommu}) {
        if ($viommu eq 'intel') {
            unshift @$devices, '-device', 'intel-iommu,intremap=on,caching-mode=on';
            push @$machineFlags, 'kernel-irqchip=split';
        } elsif ($viommu eq 'virtio') {
            push @$devices, '-device', 'virtio-iommu-pci';
        }
    }

    if ($conf->{'amd-sev'}) {
        push @$devices, '-object', get_amd_sev_object($conf->{'amd-sev'}, $conf->{bios});
        push @$machineFlags, 'confidential-guest-support=sev0';
    }

    PVE::QemuServer::Virtiofs::config($conf, $vmid, $devices);

    push @$cmd, @$devices;
    push @$cmd, '-rtc', join(',', @$rtcFlags) if scalar(@$rtcFlags);
    push @$cmd, '-machine', join(',', @$machineFlags) if scalar(@$machineFlags);

    if (my $vmstate = $conf->{vmstate}) {
        my $statepath = PVE::Storage::path($storecfg, $vmstate);
        push @$cmd, '-loadstate', $statepath;
        print "activating and using '$vmstate' as vmstate\n";
    }

    if (PVE::QemuConfig->is_template($conf)) {
        # needed to workaround base volumes being read-only
        push @$cmd, '-snapshot';
    }

    # add custom args
    if ($conf->{args}) {
        my $aa = PVE::Tools::split_args($conf->{args});
        push @$cmd, @$aa;
    }

    return wantarray ? ($cmd, $spice_port, $pci_devices, $conf) : $cmd;
}

sub spice_port {
    my ($vmid) = @_;

    my $res = mon_cmd($vmid, 'query-spice');

    return $res->{'tls-port'} || $res->{'port'} || die "no spice port\n";
}

sub vm_devices_list {
    my ($vmid) = @_;

    my $res = mon_cmd($vmid, 'query-pci');
    my $devices_to_check = [];
    my $devices = {};
    foreach my $pcibus (@$res) {
        push @$devices_to_check, @{ $pcibus->{devices} },;
    }

    while (@$devices_to_check) {
        my $to_check = [];
        for my $d (@$devices_to_check) {
            $devices->{ $d->{'qdev_id'} } = 1 if $d->{'qdev_id'};
            next if !$d->{'pci_bridge'} || !$d->{'pci_bridge'}->{devices};

            $devices->{ $d->{'qdev_id'} } += scalar(@{ $d->{'pci_bridge'}->{devices} });
            push @$to_check, @{ $d->{'pci_bridge'}->{devices} };
        }
        $devices_to_check = $to_check;
    }

    # Block device IDs need to be checked at the qdev level, since with '-blockdev', the 'device'
    # property will not be set.
    my $resblock = mon_cmd($vmid, 'query-block');
    for my $block ($resblock->@*) {
        my $qdev_id = $block->{qdev} or next;
        my $drive_id = PVE::QemuServer::Blockdev::qdev_id_to_drive_id($qdev_id);
        $devices->{$drive_id} = 1;
    }

    my $resmice = mon_cmd($vmid, 'query-mice');
    foreach my $mice (@$resmice) {
        if ($mice->{name} eq 'QEMU HID Tablet') {
            $devices->{tablet} = 1;
            last;
        }
    }

    # for usb devices there is no query-usb
    # but we can iterate over the entries in
    # qom-list path=/machine/peripheral
    my $resperipheral = mon_cmd($vmid, 'qom-list', path => '/machine/peripheral');
    foreach my $per (@$resperipheral) {
        if ($per->{name} =~ m/^usb(?:redirdev)?\d+$/) {
            $devices->{ $per->{name} } = 1;
        }
    }

    return $devices;
}

sub vm_deviceplug {
    my ($storecfg, $conf, $vmid, $deviceid, $device, $arch, $machine_type) = @_;

    my $q35 = PVE::QemuServer::Machine::machine_type_is_q35($conf);

    my $devices_list = vm_devices_list($vmid);
    return 1 if defined($devices_list->{$deviceid});

    # add PCI bridge if we need it for the device
    qemu_add_pci_bridge($storecfg, $conf, $vmid, $deviceid, $arch, $machine_type);

    if ($deviceid eq 'tablet') {
        qemu_deviceadd($vmid, print_tabletdevice_full($conf, $arch));
    } elsif ($deviceid eq 'keyboard') {
        qemu_deviceadd($vmid, print_keyboarddevice_full($conf, $arch));
    } elsif ($deviceid =~ m/^usbredirdev(\d+)$/) {
        my $id = $1;
        qemu_spice_usbredir_chardev_add($vmid, "usbredirchardev$id");
        qemu_deviceadd($vmid, PVE::QemuServer::USB::print_spice_usbdevice($id, "xhci", $id + 1));
    } elsif ($deviceid =~ m/^usb(\d+)$/) {
        qemu_deviceadd(
            $vmid,
            PVE::QemuServer::USB::print_usbdevice_full($conf, $deviceid, $device, {}, $1 + 1),
        );
    } elsif ($deviceid =~ m/^(virtio)(\d+)$/) {
        qemu_iothread_add($vmid, $deviceid, $device);

        qemu_driveadd($storecfg, $vmid, $device);
        my $devicefull =
            print_drivedevice_full($storecfg, $conf, $vmid, $device, undef, $arch, $machine_type);

        qemu_deviceadd($vmid, $devicefull);
        eval { qemu_deviceaddverify($vmid, $deviceid); };
        if (my $err = $@) {
            eval { qemu_drivedel($vmid, $deviceid); };
            warn $@ if $@;
            die $err;
        }
    } elsif ($deviceid =~ m/^(virtioscsi|scsihw)(\d+)$/) {
        my $scsihw = defined($conf->{scsihw}) ? $conf->{scsihw} : "lsi";
        my $pciaddr = print_pci_addr($deviceid, undef, $arch);
        my $scsihw_type = $scsihw eq 'virtio-scsi-single' ? "virtio-scsi-pci" : $scsihw;

        my $devicefull = "$scsihw_type,id=$deviceid$pciaddr";

        if ($deviceid =~ m/^virtioscsi(\d+)$/ && $device->{iothread}) {
            qemu_iothread_add($vmid, $deviceid, $device);
            $devicefull .= ",iothread=iothread-$deviceid";
        }

        if ($deviceid =~ m/^virtioscsi(\d+)$/ && $device->{queues}) {
            $devicefull .= ",num_queues=$device->{queues}";
        }

        qemu_deviceadd($vmid, $devicefull);
        qemu_deviceaddverify($vmid, $deviceid);
    } elsif ($deviceid =~ m/^(scsi)(\d+)$/) {
        qemu_findorcreatescsihw($storecfg, $conf, $vmid, $device, $arch, $machine_type);
        qemu_driveadd($storecfg, $vmid, $device);

        my $devicefull =
            print_drivedevice_full($storecfg, $conf, $vmid, $device, undef, $arch, $machine_type);
        eval { qemu_deviceadd($vmid, $devicefull); };
        if (my $err = $@) {
            eval { qemu_drivedel($vmid, $deviceid); };
            warn $@ if $@;
            die $err;
        }
    } elsif ($deviceid =~ m/^(net)(\d+)$/) {
        return if !qemu_netdevadd($vmid, $conf, $arch, $device, $deviceid);

        my $machine_type = PVE::QemuServer::Machine::qemu_machine_pxe($vmid, $conf);
        my $machine_version = PVE::QemuServer::Machine::extract_version($machine_type);
        my $use_old_bios_files = undef;
        ($use_old_bios_files, $machine_type) = qemu_use_old_bios_files($machine_type);

        my $netdevicefull = print_netdevice_full(
            $vmid,
            $conf,
            $device,
            $deviceid,
            undef,
            $use_old_bios_files,
            $arch,
            $machine_version,
        );
        qemu_deviceadd($vmid, $netdevicefull);
        eval {
            qemu_deviceaddverify($vmid, $deviceid);
            qemu_set_link_status($vmid, $deviceid, !$device->{link_down});
        };
        if (my $err = $@) {
            eval { qemu_netdevdel($vmid, $deviceid); };
            warn $@ if $@;
            die $err;
        }
    } elsif (!$q35 && $deviceid =~ m/^(pci\.)(\d+)$/) {
        my $bridgeid = $2;
        my $pciaddr = print_pci_addr($deviceid, undef, $arch);
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

    my $bootdisks = PVE::QemuServer::Drive::get_bootdisks($conf);
    die "can't unplug bootdisk '$deviceid'\n" if grep { $_ eq $deviceid } @$bootdisks;

    if ($deviceid eq 'tablet' || $deviceid eq 'keyboard' || $deviceid eq 'xhci') {
        qemu_devicedel($vmid, $deviceid);
    } elsif ($deviceid =~ m/^usbredirdev\d+$/) {
        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
    } elsif ($deviceid =~ m/^usb\d+$/) {
        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
    } elsif ($deviceid =~ m/^(virtio)(\d+)$/) {
        my $device = parse_drive($deviceid, $conf->{$deviceid});

        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
        qemu_drivedel($vmid, $deviceid);
        qemu_iothread_del($vmid, $deviceid, $device);
    } elsif ($deviceid =~ m/^(virtioscsi|scsihw)(\d+)$/) {
        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid, 15);
    } elsif ($deviceid =~ m/^(scsi)(\d+)$/) {
        my $device = parse_drive($deviceid, $conf->{$deviceid});

        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
        qemu_drivedel($vmid, $deviceid);
        qemu_deletescsihw($conf, $vmid, $deviceid);

        qemu_iothread_del($vmid, "virtioscsi$device->{index}", $device)
            if $conf->{scsihw} && ($conf->{scsihw} eq 'virtio-scsi-single');
    } elsif ($deviceid =~ m/^(net)(\d+)$/) {
        qemu_devicedel($vmid, $deviceid);
        qemu_devicedelverify($vmid, $deviceid);
        qemu_netdevdel($vmid, $deviceid);
    } else {
        die "can't unplug device '$deviceid'\n";
    }

    return 1;
}

sub qemu_spice_usbredir_chardev_add {
    my ($vmid, $id) = @_;

    mon_cmd(
        $vmid,
        "chardev-add",
        (
            id => $id,
            backend => {
                type => 'spicevmc',
                data => {
                    type => "usbredir",
                },
            },
        ),
    );
}

sub qemu_iothread_add {
    my ($vmid, $deviceid, $device) = @_;

    if ($device->{iothread}) {
        my $iothreads = vm_iothreads_list($vmid);
        qemu_objectadd($vmid, "iothread-$deviceid", "iothread")
            if !$iothreads->{"iothread-$deviceid"};
    }
}

sub qemu_iothread_del {
    my ($vmid, $deviceid, $device) = @_;

    if ($device->{iothread}) {
        my $iothreads = vm_iothreads_list($vmid);
        qemu_objectdel($vmid, "iothread-$deviceid") if $iothreads->{"iothread-$deviceid"};
    }
}

sub qemu_driveadd {
    my ($storecfg, $vmid, $device) = @_;

    my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);

    # for the switch to -blockdev
    if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 10, 0)) {
        PVE::QemuServer::Blockdev::attach($storecfg, $vmid, $device, {});
        return 1;
    } else {
        my $drive = print_drive_commandline_full($storecfg, $vmid, $device, undef);
        $drive =~ s/\\/\\\\/g;
        my $ret = PVE::QemuServer::Monitor::hmp_cmd($vmid, "drive_add auto \"$drive\"", 60);

        # If the command succeeds qemu prints: "OK"
        return 1 if $ret =~ m/OK/s;

        die "adding drive failed: $ret\n";
    }
}

sub qemu_drivedel {
    my ($vmid, $deviceid) = @_;

    my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);

    # for the switch to -blockdev
    if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 10, 0)) {
        PVE::QemuServer::Blockdev::detach($vmid, "drive-$deviceid");
        return 1;
    } else {
        my $ret = PVE::QemuServer::Monitor::hmp_cmd($vmid, "drive_del drive-$deviceid", 10 * 60);
        $ret =~ s/^\s+//;

        return 1 if $ret eq "";

        # NB: device not found errors mean the drive was auto-deleted and we ignore the error
        return 1 if $ret =~ m/Device \'.*?\' not found/s;

        die "deleting drive $deviceid failed : $ret\n";
    }
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
    my ($vmid, $deviceid, $timeout) = @_;

    $timeout //= 5;

    # need to verify that the device is correctly removed as device_del
    # is async and empty return is not reliable

    for (my $i = 0; $i <= $timeout; $i++) {
        my $devices_list = vm_devices_list($vmid);
        return 1 if !defined($devices_list->{$deviceid});
        sleep 1;
    }

    die "error on hot-unplugging device '$deviceid'\n";
}

sub qemu_findorcreatescsihw {
    my ($storecfg, $conf, $vmid, $device, $arch, $machine_type) = @_;

    my ($maxdev, $controller, $controller_prefix) = scsihw_infos($conf, $device);

    my $scsihwid = "$controller_prefix$controller";
    my $devices_list = vm_devices_list($vmid);

    if (!defined($devices_list->{$scsihwid})) {
        vm_deviceplug($storecfg, $conf, $vmid, $scsihwid, $device, $arch, $machine_type);
    }

    return 1;
}

sub qemu_deletescsihw {
    my ($conf, $vmid, $opt) = @_;

    my $device = parse_drive($opt, $conf->{$opt});

    if ($conf->{scsihw} && ($conf->{scsihw} eq 'virtio-scsi-single')) {
        vm_deviceunplug($vmid, $conf, "virtioscsi$device->{index}");
        return 1;
    }

    my ($maxdev, $controller, $controller_prefix) = scsihw_infos($conf, $device);

    my $devices_list = vm_devices_list($vmid);
    foreach my $opt (keys %{$devices_list}) {
        if (is_valid_drivename($opt)) {
            my $drive = parse_drive($opt, $conf->{$opt});
            if (
                $drive->{interface} eq 'scsi'
                && $drive->{index} < (($maxdev - 1) * ($controller + 1))
            ) {
                return 1;
            }
        }
    }

    my $scsihwid = "scsihw$controller";

    vm_deviceunplug($vmid, $conf, $scsihwid);

    return 1;
}

sub qemu_add_pci_bridge {
    my ($storecfg, $conf, $vmid, $device, $arch, $machine_type) = @_;

    my $bridges = {};

    my $bridgeid;

    print_pci_addr($device, $bridges, $arch);

    while (my ($k, $v) = each %$bridges) {
        $bridgeid = $k;
    }
    return 1 if !defined($bridgeid) || $bridgeid < 1;

    my $bridge = "pci.$bridgeid";
    my $devices_list = vm_devices_list($vmid);

    if (!defined($devices_list->{$bridge})) {
        vm_deviceplug($storecfg, $conf, $vmid, $bridge, $arch, $machine_type);
    }

    return 1;
}

sub qemu_set_link_status {
    my ($vmid, $device, $up) = @_;

    mon_cmd(
        $vmid, "set_link",
        name => $device,
        up => $up ? JSON::true : JSON::false,
    );
}

sub qemu_netdevadd {
    my ($vmid, $conf, $arch, $device, $deviceid) = @_;

    my $netdev = print_netdev_full($vmid, $conf, $arch, $device, $deviceid, 1);
    my %options = split(/[=,]/, $netdev);

    if (defined(my $vhost = $options{vhost})) {
        $options{vhost} = JSON::boolean(PVE::JSONSchema::parse_boolean($vhost));
    }

    if (defined(my $queues = $options{queues})) {
        $options{queues} = $queues + 0;
    }

    mon_cmd($vmid, "netdev_add", %options);
    return 1;
}

sub qemu_netdevdel {
    my ($vmid, $deviceid) = @_;

    mon_cmd($vmid, "netdev_del", id => $deviceid);
}

sub qemu_usb_hotplug {
    my ($storecfg, $conf, $vmid, $deviceid, $device, $arch, $machine_type) = @_;

    return if !$device;

    # remove the old one first
    vm_deviceunplug($vmid, $conf, $deviceid);

    # check if xhci controller is necessary and available
    my $devicelist = vm_devices_list($vmid);

    if (!$devicelist->{xhci}) {
        my $pciaddr = print_pci_addr("xhci", undef, $arch);
        qemu_deviceadd($vmid, PVE::QemuServer::USB::print_qemu_xhci_controller($pciaddr));
    }

    # add the new one
    vm_deviceplug($storecfg, $conf, $vmid, $deviceid, $device, $arch, $machine_type);
}

sub qemu_cpu_hotplug {
    my ($vmid, $conf, $vcpus) = @_;

    my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);

    my $sockets = 1;
    $sockets = $conf->{smp} if $conf->{smp}; # old style - no longer iused
    $sockets = $conf->{sockets} if $conf->{sockets};
    my $cores = $conf->{cores} || 1;
    my $maxcpus = $sockets * $cores;

    $vcpus = $maxcpus if !$vcpus;

    die "you can't add more vcpus than maxcpus\n"
        if $vcpus > $maxcpus;

    my $currentvcpus = $conf->{vcpus} || $maxcpus;

    if ($vcpus < $currentvcpus) {

        if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 2, 7)) {

            for (my $i = $currentvcpus; $i > $vcpus; $i--) {
                qemu_devicedel($vmid, "cpu$i");
                my $retry = 0;
                my $currentrunningvcpus = undef;
                while (1) {
                    $currentrunningvcpus = mon_cmd($vmid, "query-cpus-fast");
                    last if scalar(@{$currentrunningvcpus}) == $i - 1;
                    raise_param_exc({ vcpus => "error unplugging cpu$i" }) if $retry > 5;
                    $retry++;
                    sleep 1;
                }
                #update conf after each successful cpu unplug
                $conf->{vcpus} = scalar(@{$currentrunningvcpus});
                PVE::QemuConfig->write_config($vmid, $conf);
            }
        } else {
            die "cpu hot-unplugging requires qemu version 2.7 or higher\n";
        }

        return;
    }

    my $currentrunningvcpus = mon_cmd($vmid, "query-cpus-fast");
    die "vcpus in running vm does not match its configuration\n"
        if scalar(@{$currentrunningvcpus}) != $currentvcpus;

    if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 2, 7)) {
        my $arch = PVE::QemuServer::Helpers::get_vm_arch($conf);

        for (my $i = $currentvcpus + 1; $i <= $vcpus; $i++) {
            my $cpustr = print_cpu_device($conf, $arch, $i);
            qemu_deviceadd($vmid, $cpustr);

            my $retry = 0;
            my $currentrunningvcpus = undef;
            while (1) {
                $currentrunningvcpus = mon_cmd($vmid, "query-cpus-fast");
                last if scalar(@{$currentrunningvcpus}) == $i;
                raise_param_exc({ vcpus => "error hotplugging cpu$i" }) if $retry > 10;
                sleep 1;
                $retry++;
            }
            #update conf after each successful cpu hotplug
            $conf->{vcpus} = scalar(@{$currentrunningvcpus});
            PVE::QemuConfig->write_config($vmid, $conf);
        }
    } else {

        for (my $i = $currentvcpus; $i < $vcpus; $i++) {
            mon_cmd($vmid, "cpu-add", id => int($i));
        }
    }
}

sub qemu_volume_snapshot {
    my ($vmid, $deviceid, $storecfg, $drive, $snap) = @_;

    my $volid = $drive->{file};
    my $running = check_running($vmid);

    my $do_snapshots_type = do_snapshots_type($storecfg, $volid, $deviceid, $running);

    if ($do_snapshots_type eq 'internal') {
        print "internal qemu snapshot\n";
        mon_cmd($vmid, 'blockdev-snapshot-internal-sync', device => $deviceid, name => $snap);
    } elsif ($do_snapshots_type eq 'external') {
        my $storeid = (PVE::Storage::parse_volume_id($volid))[0];
        my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
        print "external qemu snapshot\n";
        my $snapshots = PVE::Storage::volume_snapshot_info($storecfg, $volid);
        my $parent_snap = $snapshots->{'current'}->{parent};
        my $machine_version = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
        PVE::QemuServer::Blockdev::blockdev_external_snapshot(
            $storecfg, $vmid, $machine_version, $deviceid, $drive, $snap, $parent_snap,
        );
    } elsif ($do_snapshots_type eq 'storage') {
        PVE::Storage::volume_snapshot($storecfg, $volid, $snap);
    }
}

sub qemu_volume_snapshot_delete {
    my ($vmid, $storecfg, $drive, $snap) = @_;

    my $volid = $drive->{file};
    my $running = check_running($vmid);
    my $attached_deviceid;

    if ($running) {
        my $conf = PVE::QemuConfig->load_config($vmid);
        PVE::QemuConfig->foreach_volume(
            $conf,
            sub {
                my ($ds, $drive) = @_;
                $attached_deviceid = "drive-$ds" if $drive->{file} eq $volid;
            },
        );
    }

    my $do_snapshots_type = do_snapshots_type($storecfg, $volid, $attached_deviceid, $running);

    if ($do_snapshots_type eq 'internal') {
        mon_cmd(
            $vmid,
            'blockdev-snapshot-delete-internal-sync',
            device => $attached_deviceid,
            name => $snap,
        );
    } elsif ($do_snapshots_type eq 'external') {
        print "delete qemu external snapshot\n";

        my $path = PVE::Storage::path($storecfg, $volid);
        my $snapshots = PVE::Storage::volume_snapshot_info($storecfg, $volid);

        die "could not find snapshot '$snap' for volume '$volid'\n"
            if !defined($snapshots->{$snap});

        my $parentsnap = $snapshots->{$snap}->{parent};
        my $childsnap = $snapshots->{$snap}->{child};
        my $machine_version = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);

        # if we delete the first snasphot, we commit because the first snapshot original base image, it should be big.
        # improve-me: if firstsnap > child : commit, if firstsnap < child do a stream.
        if (!$parentsnap) {
            print "delete first snapshot $snap\n";
            PVE::QemuServer::Blockdev::blockdev_commit(
                $storecfg,
                $vmid,
                $machine_version,
                $attached_deviceid,
                $drive,
                $childsnap,
                $snap,
            );

            PVE::Storage::rename_snapshot($storecfg, $volid, $snap, $childsnap);

            PVE::QemuServer::Blockdev::blockdev_replace(
                $storecfg,
                $vmid,
                $machine_version,
                $attached_deviceid,
                $drive,
                $snap,
                $childsnap,
                $snapshots->{$childsnap}->{child},
            );
        } else {
            #intermediate snapshot, we always stream the snapshot to child snapshot
            print "stream intermediate snapshot $snap to $childsnap\n";
            PVE::QemuServer::Blockdev::blockdev_stream(
                $storecfg,
                $vmid,
                $machine_version,
                $attached_deviceid,
                $drive,
                $snap,
                $parentsnap,
                $childsnap,
            );
        }
    } elsif ($do_snapshots_type eq 'storage') {
        PVE::Storage::volume_snapshot_delete(
            $storecfg,
            $volid,
            $snap,
            $attached_deviceid ? 1 : undef,
        );
    }
}

sub foreach_volid {
    my ($conf, $func, @param) = @_;

    my $volhash = {};

    my $test_volid = sub {
        my ($key, $drive, $snapname, $pending) = @_;

        my $volid = $drive->{file};
        return if !$volid;

        $volhash->{$volid}->{cdrom} //= 1;
        $volhash->{$volid}->{cdrom} = 0 if !drive_is_cdrom($drive);

        my $replicate = $drive->{replicate} // 1;
        $volhash->{$volid}->{replicate} //= 0;
        $volhash->{$volid}->{replicate} = 1 if $replicate;

        $volhash->{$volid}->{shared} //= 0;
        $volhash->{$volid}->{shared} = 1 if $drive->{shared};

        $volhash->{$volid}->{is_unused} //= 0;
        $volhash->{$volid}->{is_unused} = 1 if $key =~ /^unused\d+$/;

        $volhash->{$volid}->{is_attached} //= 0;
        $volhash->{$volid}->{is_attached} = 1
            if !$volhash->{$volid}->{is_unused} && !defined($snapname) && !$pending;

        $volhash->{$volid}->{referenced_in_snapshot}->{$snapname} = 1
            if defined($snapname);

        $volhash->{$volid}->{referenced_in_pending} = 1 if $pending;

        my $size = $drive->{size};
        $volhash->{$volid}->{size} //= $size if $size;

        $volhash->{$volid}->{is_vmstate} //= 0;
        $volhash->{$volid}->{is_vmstate} = 1 if $key eq 'vmstate';

        $volhash->{$volid}->{is_tpmstate} //= 0;
        $volhash->{$volid}->{is_tpmstate} = 1 if $key eq 'tpmstate0';

        $volhash->{$volid}->{drivename} = $key if is_valid_drivename($key);
    };

    my $include_opts = {
        extra_keys => ['vmstate'],
        include_unused => 1,
    };

    PVE::QemuConfig->foreach_volume_full($conf, $include_opts, $test_volid);

    PVE::QemuConfig->foreach_volume_full($conf->{pending}, $include_opts, $test_volid, undef, 1)
        if defined($conf->{pending}) && $conf->{pending}->%*;

    foreach my $snapname (keys %{ $conf->{snapshots} }) {
        my $snap = $conf->{snapshots}->{$snapname};
        PVE::QemuConfig->foreach_volume_full($snap, $include_opts, $test_volid, $snapname);
    }

    foreach my $volid (keys %$volhash) {
        &$func($volid, $volhash->{$volid}, @param);
    }
}

my $fast_plug_option = {
    'description' => 1,
    'hookscript' => 1,
    'lock' => 1,
    'migrate_downtime' => 1,
    'migrate_speed' => 1,
    'name' => 1,
    'onboot' => 1,
    'protection' => 1,
    'shares' => 1,
    'startup' => 1,
    'tags' => 1,
    'vmstatestorage' => 1,
};

for my $opt (keys %$confdesc_cloudinit) {
    $fast_plug_option->{$opt} = 1;
}

# hotplug changes in [PENDING]
# $selection hash can be used to only apply specified options, for
# example: { cores => 1 } (only apply changed 'cores')
# $errors ref is used to return error messages
sub vmconfig_hotplug_pending {
    my ($vmid, $conf, $storecfg, $selection, $errors) = @_;

    my $defaults = load_defaults();
    my $arch = PVE::QemuServer::Helpers::get_vm_arch($conf);
    my $machine_type = PVE::QemuServer::Machine::get_vm_machine($conf, undef, $arch);

    # commit values which do not have any impact on running VM first
    # Note: those option cannot raise errors, we we do not care about
    # $selection and always apply them.

    my $add_error = sub {
        my ($opt, $msg) = @_;
        $errors->{$opt} = "hotplug problem - $msg";
    };

    my $cloudinit_pending_properties = PVE::QemuServer::cloudinit_pending_properties();

    my $cloudinit_record_changed = sub {
        my ($conf, $opt, $old, $new) = @_;
        return if !$cloudinit_pending_properties->{$opt};

        my $ci = ($conf->{'special-sections'}->{cloudinit} //= {});

        my $recorded = $ci->{$opt};
        my %added = map { $_ => 1 } PVE::Tools::split_list(delete($ci->{added}) // '');

        if (defined($new)) {
            if (defined($old)) {
                # an existing value is being modified
                if (defined($recorded)) {
                    # the value was already not in sync
                    if ($new eq $recorded) {
                        # a value is being reverted to the cloud-init state:
                        delete $ci->{$opt};
                        delete $added{$opt};
                    } else {
                        # the value was changed multiple times, do nothing
                    }
                } elsif ($added{$opt}) {
                    # the value had been marked as added and is being changed, do nothing
                } else {
                    # the value is new, record it:
                    $ci->{$opt} = $old;
                }
            } else {
                # a new value is being added
                if (defined($recorded)) {
                    # it was already not in sync
                    if ($new eq $recorded) {
                        # a value is being reverted to the cloud-init state:
                        delete $ci->{$opt};
                        delete $added{$opt};
                    } else {
                        # the value had temporarily been removed, do nothing
                    }
                } elsif ($added{$opt}) {
                    # the value had been marked as added already, do nothing
                } else {
                    # the value is new, add it
                    $added{$opt} = 1;
                }
            }
        } elsif (!defined($old)) {
            # a non-existent value is being removed? ignore...
        } else {
            # a value is being deleted
            if (defined($recorded)) {
                # a value was already recorded, just keep it
            } elsif ($added{$opt}) {
                # the value was marked as added, remove it
                delete $added{$opt};
            } else {
                # a previously unrecorded value is being removed, record the old value:
                $ci->{$opt} = $old;
            }
        }

        my $added = join(',', sort keys %added);
        $ci->{added} = $added if length($added);
    };

    my $changes = 0;
    foreach my $opt (keys %{ $conf->{pending} }) { # add/change
        if ($fast_plug_option->{$opt}) {
            my $new = delete $conf->{pending}->{$opt};
            $cloudinit_record_changed->($conf, $opt, $conf->{$opt}, $new);
            $conf->{$opt} = $new;
            $changes = 1;
        }
    }

    if ($changes) {
        PVE::QemuConfig->write_config($vmid, $conf);
    }

    my $ostype = $conf->{ostype};
    my $version = extract_version($machine_type, get_running_qemu_version($vmid));
    my $hotplug_features =
        parse_hotplug_features(defined($conf->{hotplug}) ? $conf->{hotplug} : '1');
    my $usb_hotplug =
        $hotplug_features->{usb}
        && min_version($version, 7, 1)
        && defined($ostype)
        && ($ostype eq 'l26' || windows_version($ostype) > 7);

    my $cgroup = PVE::QemuServer::CGroup->new($vmid);
    my $pending_delete_hash = PVE::QemuConfig->parse_pending_delete($conf->{pending}->{delete});

    foreach my $opt (sort keys %$pending_delete_hash) {
        next if $selection && !$selection->{$opt};
        my $force = $pending_delete_hash->{$opt}->{force};
        eval {
            if ($opt eq 'hotplug') {
                die "skip\n" if ($conf->{hotplug} =~ /(cpu|memory)/);
            } elsif ($opt eq 'tablet') {
                die "skip\n" if !$hotplug_features->{usb};
                if ($defaults->{tablet}) {
                    vm_deviceplug($storecfg, $conf, $vmid, 'tablet', $arch, $machine_type);
                    vm_deviceplug($storecfg, $conf, $vmid, 'keyboard', $arch, $machine_type)
                        if $arch eq 'aarch64';
                } else {
                    vm_deviceunplug($vmid, $conf, 'tablet');
                    vm_deviceunplug($vmid, $conf, 'keyboard') if $arch eq 'aarch64';
                }
            } elsif ($opt =~ m/^usb(\d+)$/) {
                my $index = $1;
                die "skip\n" if !$usb_hotplug;
                vm_deviceunplug($vmid, $conf, "usbredirdev$index"); # if it's a spice port
                vm_deviceunplug($vmid, $conf, $opt);
            } elsif ($opt eq 'vcpus') {
                die "skip\n" if !$hotplug_features->{cpu};
                qemu_cpu_hotplug($vmid, $conf, undef);
            } elsif ($opt eq 'balloon') {
                # enable balloon device is not hotpluggable
                die "skip\n" if defined($conf->{balloon}) && $conf->{balloon} == 0;
                # here we reset the ballooning value to memory
                my $balloon = get_current_memory($conf->{memory});
                mon_cmd($vmid, "balloon", value => $balloon * 1024 * 1024);
            } elsif ($fast_plug_option->{$opt}) {
                # do nothing
            } elsif ($opt =~ m/^net(\d+)$/) {
                die "skip\n" if !$hotplug_features->{network};
                vm_deviceunplug($vmid, $conf, $opt);
                my $net = PVE::QemuServer::Network::parse_net($conf->{$opt});
                PVE::Network::SDN::Vnets::del_ips_from_mac(
                    $net->{bridge},
                    $net->{macaddr},
                    $conf->{name},
                );
            } elsif (is_valid_drivename($opt)) {
                die "skip\n"
                    if !$hotplug_features->{disk} || $opt =~ m/(efidisk|ide|sata|tpmstate)(\d+)/;
                vm_deviceunplug($vmid, $conf, $opt);
                vmconfig_delete_or_detach_drive($vmid, $storecfg, $conf, $opt, $force);
            } elsif ($opt =~ m/^memory$/) {
                die "skip\n" if !$hotplug_features->{memory};
                PVE::QemuServer::Memory::qemu_memory_hotplug($vmid, $conf);
            } elsif ($opt eq 'cpuunits') {
                $cgroup->change_cpu_shares(undef);
            } elsif ($opt eq 'cpulimit') {
                $cgroup->change_cpu_quota(undef, undef); # reset, cgroup module can better decide values
            } else {
                die "skip\n";
            }
        };
        if (my $err = $@) {
            &$add_error($opt, $err) if $err ne "skip\n";
        } else {
            my $old = delete $conf->{$opt};
            $cloudinit_record_changed->($conf, $opt, $old, undef);
            PVE::QemuConfig->remove_from_pending_delete($conf, $opt);
        }
    }

    my $cloudinit_opt;
    foreach my $opt (keys %{ $conf->{pending} }) {
        next if $selection && !$selection->{$opt};
        my $value = $conf->{pending}->{$opt};
        eval {
            if ($opt eq 'hotplug') {
                die "skip\n"
                    if ($value =~ /memory/) || ($value !~ /memory/ && $conf->{hotplug} =~ /memory/);
                die "skip\n"
                    if ($value =~ /cpu/) || ($value !~ /cpu/ && $conf->{hotplug} =~ /cpu/);
            } elsif ($opt eq 'tablet') {
                die "skip\n" if !$hotplug_features->{usb};
                if ($value == 1) {
                    vm_deviceplug($storecfg, $conf, $vmid, 'tablet', $arch, $machine_type);
                    vm_deviceplug($storecfg, $conf, $vmid, 'keyboard', $arch, $machine_type)
                        if $arch eq 'aarch64';
                } elsif ($value == 0) {
                    vm_deviceunplug($vmid, $conf, 'tablet');
                    vm_deviceunplug($vmid, $conf, 'keyboard') if $arch eq 'aarch64';
                }
            } elsif ($opt =~ m/^usb(\d+)$/) {
                my $index = $1;
                die "skip\n" if !$usb_hotplug;
                my $d = eval { parse_property_string('pve-qm-usb', $value) };
                my $id = $opt;
                if ($d->{host} =~ m/^spice$/i) {
                    $id = "usbredirdev$index";
                }
                qemu_usb_hotplug($storecfg, $conf, $vmid, $id, $d, $arch, $machine_type);
            } elsif ($opt eq 'vcpus') {
                die "skip\n" if !$hotplug_features->{cpu};
                qemu_cpu_hotplug($vmid, $conf, $value);
            } elsif ($opt eq 'balloon') {
                # enable/disable balloning device is not hotpluggable
                my $old_balloon_enabled = !!(!defined($conf->{balloon}) || $conf->{balloon});
                my $new_balloon_enabled =
                    !!(!defined($conf->{pending}->{balloon}) || $conf->{pending}->{balloon});
                die "skip\n" if $old_balloon_enabled != $new_balloon_enabled;

                # allow manual ballooning if shares is set to zero
                if ((defined($conf->{shares}) && ($conf->{shares} == 0))) {
                    my $memory = get_current_memory($conf->{memory});
                    my $balloon = $conf->{pending}->{balloon} || $memory;
                    mon_cmd($vmid, "balloon", value => $balloon * 1024 * 1024);
                }
            } elsif ($opt =~ m/^net(\d+)$/) {
                # some changes can be done without hotplug
                vmconfig_update_net(
                    $storecfg,
                    $conf,
                    $hotplug_features->{network},
                    $vmid,
                    $opt,
                    $value,
                    $arch,
                    $machine_type,
                );
            } elsif (is_valid_drivename($opt)) {
                die "skip\n" if $opt eq 'efidisk0' || $opt eq 'tpmstate0';
                # some changes can be done without hotplug
                my $drive = parse_drive($opt, $value);
                if (drive_is_cloudinit($drive)) {
                    $cloudinit_opt = [$opt, $drive];
                    # apply all the other changes first, then generate the cloudinit disk
                    die "skip\n";
                }
                vmconfig_update_disk(
                    $storecfg,
                    $conf,
                    $hotplug_features->{disk},
                    $vmid,
                    $opt,
                    $value,
                    $arch,
                    $machine_type,
                );
            } elsif ($opt =~ m/^memory$/) { #dimms
                die "skip\n" if !$hotplug_features->{memory};
                $value = PVE::QemuServer::Memory::qemu_memory_hotplug($vmid, $conf, $value);
            } elsif ($opt eq 'cpuunits') {
                my $new_cpuunits = PVE::CGroup::clamp_cpu_shares($conf->{pending}->{$opt}); #clamp
                $cgroup->change_cpu_shares($new_cpuunits);
            } elsif ($opt eq 'cpulimit') {
                my $cpulimit =
                    $conf->{pending}->{$opt} == 0 ? undef : int($conf->{pending}->{$opt} * 100);
                $cgroup->change_cpu_quota($cpulimit, undef);
            } elsif ($opt eq 'agent') {
                vmconfig_update_agent($conf, $opt, $value);
            } else {
                die "skip\n"; # skip non-hot-pluggable options
            }
        };
        if (my $err = $@) {
            &$add_error($opt, $err) if $err ne "skip\n";
        } else {
            $cloudinit_record_changed->($conf, $opt, $conf->{$opt}, $value);
            $conf->{$opt} = $value;
            delete $conf->{pending}->{$opt};
        }
    }

    if (defined($cloudinit_opt)) {
        my ($opt, $drive) = @$cloudinit_opt;
        my $value = $conf->{pending}->{$opt};
        eval {
            my $temp = { %$conf, $opt => $value };
            PVE::QemuServer::Cloudinit::apply_cloudinit_config($temp, $vmid);
            vmconfig_update_disk(
                $storecfg,
                $conf,
                $hotplug_features->{disk},
                $vmid,
                $opt,
                $value,
                $arch,
                $machine_type,
            );
        };
        if (my $err = $@) {
            &$add_error($opt, $err) if $err ne "skip\n";
        } else {
            $conf->{$opt} = $value;
            delete $conf->{pending}->{$opt};
        }
    }

    # unplug xhci controller if no usb device is left
    if ($usb_hotplug) {
        my $has_usb = 0;
        for (my $i = 0; $i < $PVE::QemuServer::USB::MAX_USB_DEVICES; $i++) {
            next if !defined($conf->{"usb$i"});
            $has_usb = 1;
            last;
        }
        if (!$has_usb) {
            vm_deviceunplug($vmid, $conf, 'xhci');
        }
    }

    PVE::QemuConfig->write_config($vmid, $conf);

    if ($hotplug_features->{cloudinit} && PVE::QemuServer::Cloudinit::has_changes($conf)) {
        PVE::QemuServer::vmconfig_update_cloudinit_drive($storecfg, $conf, $vmid);
    }
}

sub try_deallocate_drive {
    my ($storecfg, $vmid, $conf, $key, $drive, $rpcenv, $authuser, $force) = @_;

    if (($force || $key =~ /^unused/) && !drive_is_cdrom($drive, 1)) {
        my $volid = $drive->{file};
        if (vm_is_volid_owner($storecfg, $vmid, $volid)) {
            my $sid = PVE::Storage::parse_volume_id($volid);
            $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);

            # check if the disk is really unused
            die "unable to delete '$volid' - volume is still in use (snapshot?)\n"
                if PVE::QemuServer::Drive::is_volume_in_use($storecfg, $conf, $key, $volid);
            PVE::Storage::vdisk_free($storecfg, $volid);
            return 1;
        } else {
            # If vm is not owner of this disk remove from config
            return 1;
        }
    }

    return;
}

sub vmconfig_delete_or_detach_drive {
    my ($vmid, $storecfg, $conf, $opt, $force) = @_;

    my $drive = parse_drive($opt, $conf->{$opt});

    my $rpcenv = PVE::RPCEnvironment::get();
    my $authuser = $rpcenv->get_user();

    if ($force) {
        $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
        try_deallocate_drive($storecfg, $vmid, $conf, $opt, $drive, $rpcenv, $authuser, $force);
    } else {
        vmconfig_register_unused_drive($storecfg, $vmid, $conf, $drive);
    }
}

sub vmconfig_apply_pending {
    my ($vmid, $conf, $storecfg, $errors, $skip_cloud_init) = @_;

    return if !scalar(keys %{ $conf->{pending} });

    my $add_apply_error = sub {
        my ($opt, $msg) = @_;
        my $err_msg = "unable to apply pending change $opt : $msg";
        $errors->{$opt} = $err_msg;
        warn $err_msg;
    };

    # cold plug

    my $pending_delete_hash = PVE::QemuConfig->parse_pending_delete($conf->{pending}->{delete});
    foreach my $opt (sort keys %$pending_delete_hash) {
        my $force = $pending_delete_hash->{$opt}->{force};
        eval {
            if ($opt =~ m/^unused/) {
                die "internal error";
            } elsif (defined($conf->{$opt}) && is_valid_drivename($opt)) {
                vmconfig_delete_or_detach_drive($vmid, $storecfg, $conf, $opt, $force);
            } elsif (defined($conf->{$opt}) && $opt =~ m/^net\d+$/) {
                my $net = PVE::QemuServer::Network::parse_net($conf->{$opt});
                eval {
                    PVE::Network::SDN::Vnets::del_ips_from_mac(
                        $net->{bridge},
                        $net->{macaddr},
                        $conf->{name},
                    );
                };
                warn if $@;
            }
        };
        if (my $err = $@) {
            $add_apply_error->($opt, $err);
        } else {
            PVE::QemuConfig->remove_from_pending_delete($conf, $opt);
            delete $conf->{$opt};
        }
    }

    PVE::QemuConfig->cleanup_pending($conf);

    my $generate_cloudinit = $skip_cloud_init ? 0 : undef;

    foreach my $opt (keys %{ $conf->{pending} }) { # add/change
        next if $opt eq 'delete'; # just to be sure
        eval {
            if (defined($conf->{$opt}) && is_valid_drivename($opt)) {
                vmconfig_register_unused_drive(
                    $storecfg,
                    $vmid,
                    $conf,
                    parse_drive($opt, $conf->{$opt}),
                );
            } elsif (defined($conf->{pending}->{$opt}) && $opt =~ m/^net\d+$/) {
                my $new_net = PVE::QemuServer::Network::parse_net($conf->{pending}->{$opt});
                if ($conf->{$opt}) {
                    my $old_net = PVE::QemuServer::Network::parse_net($conf->{$opt});

                    if (
                        defined($old_net->{bridge})
                        && defined($old_net->{macaddr})
                        && (safe_string_ne($old_net->{bridge}, $new_net->{bridge})
                            || safe_string_ne($old_net->{macaddr}, $new_net->{macaddr}))
                    ) {
                        PVE::Network::SDN::Vnets::del_ips_from_mac(
                            $old_net->{bridge},
                            $old_net->{macaddr},
                            $conf->{name},
                        );
                        PVE::Network::SDN::Vnets::add_next_free_cidr(
                            $new_net->{bridge},
                            $conf->{name},
                            $new_net->{macaddr},
                            $vmid,
                            undef,
                            1,
                        );
                    }
                } else {
                    PVE::Network::SDN::Vnets::add_next_free_cidr(
                        $new_net->{bridge},
                        $conf->{name},
                        $new_net->{macaddr},
                        $vmid,
                        undef,
                        1,
                    );
                }
            }
        };
        if (my $err = $@) {
            $add_apply_error->($opt, $err);
        } else {

            if (is_valid_drivename($opt)) {
                my $drive = parse_drive($opt, $conf->{pending}->{$opt});
                $generate_cloudinit //= 1 if drive_is_cloudinit($drive);
            }

            $conf->{$opt} = delete $conf->{pending}->{$opt};
        }
    }

    # write all changes at once to avoid unnecessary i/o
    PVE::QemuConfig->write_config($vmid, $conf);
    if ($generate_cloudinit) {
        if (PVE::QemuServer::Cloudinit::apply_cloudinit_config($conf, $vmid)) {
            # After successful generation and if there were changes to be applied, update the
            # config to drop the 'cloudinit' special section.
            PVE::QemuConfig->write_config($vmid, $conf);
        }
    }
}

sub vmconfig_update_net {
    my ($storecfg, $conf, $hotplug, $vmid, $opt, $value, $arch, $machine_type) = @_;

    my $newnet = PVE::QemuServer::Network::parse_net($value);

    if ($conf->{$opt}) {
        my $oldnet = PVE::QemuServer::Network::parse_net($conf->{$opt});

        if (
            safe_string_ne($oldnet->{model}, $newnet->{model})
            || safe_string_ne($oldnet->{macaddr}, $newnet->{macaddr})
            || safe_num_ne($oldnet->{queues}, $newnet->{queues})
            || safe_num_ne($oldnet->{mtu}, $newnet->{mtu})
            || !($newnet->{bridge} && $oldnet->{bridge})
        ) { # bridge/nat mode change

            # for non online change, we try to hot-unplug
            die "skip\n" if !$hotplug;
            vm_deviceunplug($vmid, $conf, $opt);

            PVE::Network::SDN::Vnets::del_ips_from_mac(
                $oldnet->{bridge},
                $oldnet->{macaddr},
                $conf->{name},
            );
        } else {

            die "internal error" if $opt !~ m/net(\d+)/;
            my $iface = "tap${vmid}i$1";

            if (
                safe_string_ne($oldnet->{bridge}, $newnet->{bridge})
                || safe_num_ne($oldnet->{tag}, $newnet->{tag})
                || safe_string_ne($oldnet->{trunks}, $newnet->{trunks})
                || safe_num_ne($oldnet->{firewall}, $newnet->{firewall})
            ) {
                PVE::Network::tap_unplug($iface);

                #set link_down in guest if bridge or vlan change to notify guest (dhcp renew for example)
                if (
                    safe_string_ne($oldnet->{bridge}, $newnet->{bridge})
                    || safe_num_ne($oldnet->{tag}, $newnet->{tag})
                ) {
                    qemu_set_link_status($vmid, $opt, 0);
                }

                if (safe_string_ne($oldnet->{bridge}, $newnet->{bridge})) {
                    PVE::Network::SDN::Vnets::del_ips_from_mac(
                        $oldnet->{bridge},
                        $oldnet->{macaddr},
                        $conf->{name},
                    );
                    PVE::Network::SDN::Vnets::add_next_free_cidr(
                        $newnet->{bridge},
                        $conf->{name},
                        $newnet->{macaddr},
                        $vmid,
                        undef,
                        1,
                    );
                }

                PVE::QemuServer::Network::tap_plug(
                    $iface,
                    $newnet->{bridge},
                    $newnet->{tag},
                    $newnet->{firewall},
                    $newnet->{trunks},
                    $newnet->{rate},
                );

            } elsif (safe_num_ne($oldnet->{rate}, $newnet->{rate})) {
                # Rate can be applied on its own but any change above needs to
                # include the rate in tap_plug since OVS resets everything.
                PVE::Network::tap_rate_limit($iface, $newnet->{rate});
            }

            # set link_down on changed bridge/tag as well, because we detach the
            # network device in the section above if the bridge or tag changed
            if (
                safe_string_ne($oldnet->{link_down}, $newnet->{link_down})
                || safe_string_ne($oldnet->{bridge}, $newnet->{bridge})
                || safe_num_ne($oldnet->{tag}, $newnet->{tag})
            ) {
                qemu_set_link_status($vmid, $opt, !$newnet->{link_down});
            }

            return 1;
        }
    }

    if ($hotplug) {
        PVE::Network::SDN::Vnets::add_next_free_cidr(
            $newnet->{bridge}, $conf->{name}, $newnet->{macaddr}, $vmid, undef, 1,
        );
        PVE::Network::SDN::Vnets::add_dhcp_mapping(
            $newnet->{bridge}, $newnet->{macaddr}, $vmid, $conf->{name},
        );
        vm_deviceplug($storecfg, $conf, $vmid, $opt, $newnet, $arch, $machine_type);
    } else {
        die "skip\n";
    }
}

sub vmconfig_update_agent {
    my ($conf, $opt, $value) = @_;

    die "skip\n" if !$conf->{$opt};

    my $hotplug_options = { fstrim_cloned_disks => 1 };

    my $old_agent = parse_guest_agent($conf);
    my $agent = parse_guest_agent({ $opt => $value });

    for my $option (keys %$agent) { # added/changed options
        next if defined($hotplug_options->{$option});
        die "skip\n" if safe_string_ne($agent->{$option}, $old_agent->{$option});
    }

    for my $option (keys %$old_agent) { # removed options
        next if defined($hotplug_options->{$option});
        die "skip\n" if safe_string_ne($old_agent->{$option}, $agent->{$option});
    }

    return; # either no actual change (e.g., format string reordered) or just hotpluggable changes
}

sub vmconfig_update_disk {
    my ($storecfg, $conf, $hotplug, $vmid, $opt, $value, $arch, $machine_type) = @_;

    my $drive = parse_drive($opt, $value);

    if ($conf->{$opt} && (my $old_drive = parse_drive($opt, $conf->{$opt}))) {
        my $media = $drive->{media} || 'disk';
        my $oldmedia = $old_drive->{media} || 'disk';
        die "unable to change media type\n" if $media ne $oldmedia;

        if (!drive_is_cdrom($old_drive)) {

            if ($drive->{file} ne $old_drive->{file}) {

                die "skip\n" if !$hotplug;

                # unplug and register as unused
                vm_deviceunplug($vmid, $conf, $opt);
                vmconfig_register_unused_drive($storecfg, $vmid, $conf, $old_drive);

            } else {
                # update existing disk

                # skip non hotpluggable value
                if (
                    safe_string_ne($drive->{aio}, $old_drive->{aio})
                    || safe_string_ne($drive->{discard}, $old_drive->{discard})
                    || safe_string_ne($drive->{iothread}, $old_drive->{iothread})
                    || safe_string_ne($drive->{queues}, $old_drive->{queues})
                    || safe_string_ne($drive->{product}, $old_drive->{product})
                    || safe_string_ne($drive->{cache}, $old_drive->{cache})
                    || safe_string_ne($drive->{ssd}, $old_drive->{ssd})
                    || safe_string_ne($drive->{vendor}, $old_drive->{vendor})
                    || safe_string_ne($drive->{ro}, $old_drive->{ro})
                ) {
                    die "skip\n";
                }

                # apply throttle
                if (
                    safe_num_ne($drive->{mbps}, $old_drive->{mbps})
                    || safe_num_ne($drive->{mbps_rd}, $old_drive->{mbps_rd})
                    || safe_num_ne($drive->{mbps_wr}, $old_drive->{mbps_wr})
                    || safe_num_ne($drive->{iops}, $old_drive->{iops})
                    || safe_num_ne($drive->{iops_rd}, $old_drive->{iops_rd})
                    || safe_num_ne($drive->{iops_wr}, $old_drive->{iops_wr})
                    || safe_num_ne($drive->{mbps_max}, $old_drive->{mbps_max})
                    || safe_num_ne($drive->{mbps_rd_max}, $old_drive->{mbps_rd_max})
                    || safe_num_ne($drive->{mbps_wr_max}, $old_drive->{mbps_wr_max})
                    || safe_num_ne($drive->{iops_max}, $old_drive->{iops_max})
                    || safe_num_ne($drive->{iops_rd_max}, $old_drive->{iops_rd_max})
                    || safe_num_ne($drive->{iops_wr_max}, $old_drive->{iops_wr_max})
                    || safe_num_ne($drive->{bps_max_length}, $old_drive->{bps_max_length})
                    || safe_num_ne($drive->{bps_rd_max_length}, $old_drive->{bps_rd_max_length})
                    || safe_num_ne($drive->{bps_wr_max_length}, $old_drive->{bps_wr_max_length})
                    || safe_num_ne($drive->{iops_max_length}, $old_drive->{iops_max_length})
                    || safe_num_ne($drive->{iops_rd_max_length},
                        $old_drive->{iops_rd_max_length})
                    || safe_num_ne($drive->{iops_wr_max_length},
                        $old_drive->{iops_wr_max_length})
                ) {

                    PVE::QemuServer::Blockdev::set_io_throttle(
                        $vmid,
                        "drive-$opt",
                        ($drive->{mbps} || 0) * 1024 * 1024,
                        ($drive->{mbps_rd} || 0) * 1024 * 1024,
                        ($drive->{mbps_wr} || 0) * 1024 * 1024,
                        $drive->{iops} || 0,
                        $drive->{iops_rd} || 0,
                        $drive->{iops_wr} || 0,
                        ($drive->{mbps_max} || 0) * 1024 * 1024,
                        ($drive->{mbps_rd_max} || 0) * 1024 * 1024,
                        ($drive->{mbps_wr_max} || 0) * 1024 * 1024,
                        $drive->{iops_max} || 0,
                        $drive->{iops_rd_max} || 0,
                        $drive->{iops_wr_max} || 0,
                        $drive->{bps_max_length} || 1,
                        $drive->{bps_rd_max_length} || 1,
                        $drive->{bps_wr_max_length} || 1,
                        $drive->{iops_max_length} || 1,
                        $drive->{iops_rd_max_length} || 1,
                        $drive->{iops_wr_max_length} || 1,
                    );

                }

                return 1;
            }

        } else { # cdrom
            eval { PVE::QemuServer::Blockdev::change_medium($storecfg, $vmid, $opt, $drive); };
            my $err = $@;

            if ($drive->{file} eq 'none' && drive_is_cloudinit($old_drive)) {
                vmconfig_register_unused_drive($storecfg, $vmid, $conf, $old_drive);
            }

            die $err if $err;

            return 1;
        }
    }

    die "skip\n" if !$hotplug || $opt =~ m/(ide|sata)(\d+)/;
    # hotplug new disks
    PVE::Storage::activate_volumes($storecfg, [$drive->{file}]) if $drive->{file} !~ m|^/dev/.+|;
    vm_deviceplug($storecfg, $conf, $vmid, $opt, $drive, $arch, $machine_type);
}

sub vmconfig_update_cloudinit_drive {
    my ($storecfg, $conf, $vmid) = @_;

    my $cloudinit_ds = undef;
    my $cloudinit_drive = undef;

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;
            if (PVE::QemuServer::drive_is_cloudinit($drive)) {
                $cloudinit_ds = $ds;
                $cloudinit_drive = $drive;
            }
        },
    );

    return if !$cloudinit_drive;

    if (PVE::QemuServer::Cloudinit::apply_cloudinit_config($conf, $vmid)) {
        PVE::QemuConfig->write_config($vmid, $conf);
    }

    my $running = PVE::QemuServer::check_running($vmid);

    if ($running) {
        PVE::QemuServer::Blockdev::change_medium($storecfg, $vmid, $cloudinit_ds, $cloudinit_drive);
    }
}

# called in locked context by incoming migration
sub vm_migrate_get_nbd_disks {
    my ($storecfg, $conf, $replicated_volumes) = @_;

    my $local_volumes = {};
    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;

            return if drive_is_cdrom($drive);
            return if $ds eq 'tpmstate0';

            my $volid = $drive->{file};

            return if !$volid;

            my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

            my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
            return if $scfg->{shared};

            my $format = checked_volume_format($storecfg, $volid);

            # replicated disks re-use existing state via bitmap
            my $use_existing = $replicated_volumes->{$volid} ? 1 : 0;
            $local_volumes->{$ds} = [$volid, $storeid, $drive, $use_existing, $format];
        },
    );
    return $local_volumes;
}

# called in locked context by incoming migration
sub vm_migrate_alloc_nbd_disks {
    my ($storecfg, $vmid, $source_volumes, $storagemap) = @_;

    my $nbd = {};
    foreach my $opt (sort keys %$source_volumes) {
        my ($volid, $storeid, $drive, $use_existing, $format) = @{ $source_volumes->{$opt} };

        if ($use_existing) {
            $nbd->{$opt}->{drivestr} = print_drive($drive);
            $nbd->{$opt}->{volid} = $volid;
            $nbd->{$opt}->{replicated} = 1;
            next;
        }

        $storeid = PVE::JSONSchema::map_id($storagemap, $storeid);

        # order of precedence, filtered by whether storage supports it:
        # 1. explicit requested format
        # 2. default format of storage
        $format = PVE::Storage::resolve_format_hint($storecfg, $storeid, $format);

        my $size = $drive->{size} / 1024;
        my $newvolid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $format, undef, $size);
        my $newdrive = $drive;
        $newdrive->{format} = $format;
        $newdrive->{file} = $newvolid;
        my $drivestr = print_drive($newdrive);
        $nbd->{$opt}->{drivestr} = $drivestr;
        $nbd->{$opt}->{volid} = $newvolid;
    }

    return $nbd;
}

# see vm_start_nolock for parameters, additionally:
# migrate_opts:
#   storagemap = parsed storage map for allocating NBD disks
sub vm_start {
    my ($storecfg, $vmid, $params, $migrate_opts) = @_;

    return PVE::QemuConfig->lock_config(
        $vmid,
        sub {
            my $conf = PVE::QemuConfig->load_config($vmid, $migrate_opts->{migratedfrom});

            die "you can't start a vm if it's a template\n"
                if !$params->{skiptemplate} && PVE::QemuConfig->is_template($conf);

            my $has_suspended_lock = PVE::QemuConfig->has_lock($conf, 'suspended');
            my $has_backup_lock = PVE::QemuConfig->has_lock($conf, 'backup');

            my $running = check_running($vmid, undef, $migrate_opts->{migratedfrom});

            if ($has_backup_lock && $running) {
                # a backup is currently running, attempt to start the guest in the
                # existing QEMU instance
                return PVE::QemuServer::RunState::vm_resume($vmid);
            }

            PVE::QemuConfig->check_lock($conf)
                if !($params->{skiplock} || $has_suspended_lock);

            $params->{resume} = $has_suspended_lock || defined($conf->{vmstate});

            die "VM $vmid already running\n" if $running;

            if (my $storagemap = $migrate_opts->{storagemap}) {
                my $replicated = $migrate_opts->{replicated_volumes};
                my $disks = vm_migrate_get_nbd_disks($storecfg, $conf, $replicated);
                $migrate_opts->{nbd} =
                    vm_migrate_alloc_nbd_disks($storecfg, $vmid, $disks, $storagemap);

                foreach my $opt (keys %{ $migrate_opts->{nbd} }) {
                    $conf->{$opt} = $migrate_opts->{nbd}->{$opt}->{drivestr};
                }
            }

            return vm_start_nolock($storecfg, $vmid, $conf, $params, $migrate_opts);
        },
    );
}

# params:
#   statefile => 'tcp', 'unix' for migration or path/volid for RAM state
#   skiplock => 0/1, skip checking for config lock
#   skiptemplate => 0/1, skip checking whether VM is template
#   forcemachine => to force QEMU machine (rollback/migration)
#   forcecpu => a QEMU '-cpu' argument string to override get_cpu_options
#   timeout => in seconds
#   paused => start VM in paused state (backup)
#   resume => resume from hibernation
#   live-restore-backing => {
#      sata0 => {
#          name => blockdev-name,
#          blockdev => "arg to the -blockdev command instantiating device named 'name'",
#      },
#      virtio2 => ...
#   }
# migrate_opts:
#   nbd => volumes for NBD exports (vm_migrate_alloc_nbd_disks)
#   migratedfrom => source node
#   spice_ticket => used for spice migration, passed via tunnel/stdin
#   network => CIDR of migration network
#   type => secure/insecure - tunnel over encrypted connection or plain-text
#   nbd_proto_version => int, 0 for TCP, 1 for UNIX
#   replicated_volumes => which volids should be re-used with bitmaps for nbd migration
#   offline_volumes => new volids of offline migrated disks like tpmstate and cloudinit, not yet
#       contained in config
#   with_conntrack_state => whether to start the dbus-vmstate helper for conntrack state migration
sub vm_start_nolock {
    my ($storecfg, $vmid, $conf, $params, $migrate_opts) = @_;

    my $statefile = $params->{statefile};
    my $resume = $params->{resume};

    my $migratedfrom = $migrate_opts->{migratedfrom};
    my $migration_type = $migrate_opts->{type};
    my $nbd_protocol_version = $migrate_opts->{nbd_proto_version} // 0;

    # clean up leftover reboot request files
    eval { clear_reboot_request($vmid); };
    warn $@ if $@;

    if (!$statefile && scalar(keys %{ $conf->{pending} })) {
        vmconfig_apply_pending($vmid, $conf, $storecfg);
        $conf = PVE::QemuConfig->load_config($vmid); # update/reload
    }

    # don't regenerate the ISO if the VM is started as part of a live migration
    # this way we can reuse the old ISO with the correct config
    if (!$migratedfrom) {
        if (PVE::QemuServer::Cloudinit::apply_cloudinit_config($conf, $vmid)) {
            # FIXME: apply_cloudinit_config updates $conf in this case, and it would only drop
            # $conf->{'special-sections'}->{cloudinit}, so we could just not do this?
            # But we do it above, so for now let's be consistent.
            $conf = PVE::QemuConfig->load_config($vmid); # update/reload
        }
    }

    # override offline migrated volumes, conf is out of date still
    if (my $offline_volumes = $migrate_opts->{offline_volumes}) {
        for my $key (sort keys $offline_volumes->%*) {
            my $parsed = parse_drive($key, $conf->{$key});
            $parsed->{file} = $offline_volumes->{$key};
            $conf->{$key} = print_drive($parsed);
        }
    }

    my $defaults = load_defaults();

    # set environment variable useful inside network script
    # for remote migration the config is available on the target node!
    if (!$migrate_opts->{remote_node}) {
        $ENV{PVE_MIGRATED_FROM} = $migratedfrom;
    }

    PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'pre-start', 1);

    my $forcemachine = $params->{forcemachine};
    my $forcecpu = $params->{forcecpu};
    if ($resume) {
        # enforce machine and CPU type on suspended vm to ensure HW compatibility
        $forcemachine = $conf->{runningmachine};
        $forcecpu = $conf->{runningcpu};
        print "Resuming suspended VM\n";
    }

    my $migration_ip;
    if (
        ($statefile && $statefile eq 'tcp' && $migration_type eq 'insecure')
        || ($migrate_opts->{nbd}
            && ($nbd_protocol_version == 0 || $migration_type eq 'insecure'))
    ) {
        my $nodename = nodename();
        $migration_ip =
            PVE::QemuServer::StateFile::get_migration_ip($nodename, $migrate_opts->{network});
    }

    my $res = {};
    my $statefile_is_a_volume;
    my $state_cmdline = [];
    if ($statefile) {
        ($state_cmdline, $res->{migrate}, $statefile_is_a_volume) =
            PVE::QemuServer::StateFile::statefile_cmdline_option(
                $storecfg, $vmid, $statefile, $migration_type, $migration_ip,
            );
    } elsif ($params->{paused}) {
        $state_cmdline = ['-S'];
    }

    my $vollist = get_current_vm_volumes($storecfg, $conf);
    push $vollist->@*, $statefile if $statefile_is_a_volume;

    my ($cmd, $spice_port, $start_timeout);
    my $pci_reserve_list = [];
    eval {
        # With -blockdev, it is necessary to activate the volumes before generating the command line
        PVE::Storage::activate_volumes($storecfg, $vollist);

        # Note that for certain cases like templates, the configuration is minimized, so need to ensure
        # the rest of the function here uses the same configuration that was used to build the command
        ($cmd, $spice_port, my $pci_devices, $conf) = config_to_command(
            $storecfg,
            $vmid,
            $conf,
            $defaults,
            {
                'force-machine' => $forcemachine,
                'force-cpu' => $forcecpu,
                'live-restore-backing' => $params->{'live-restore-backing'},
            },
        );

        my $memory = get_current_memory($conf->{memory});
        $start_timeout = $params->{timeout} // config_aware_timeout($conf, $memory, $resume);

        push $cmd->@*, $state_cmdline->@*;

        for my $device (values $pci_devices->%*) {
            next if $device->{mdev}; # we don't reserve for mdev devices
            push $pci_reserve_list->@*, map { $_->{id} } $device->{ids}->@*;
        }

        # reserve all PCI IDs before actually doing anything with them
        PVE::QemuServer::PCI::reserve_pci_usage($pci_reserve_list, $vmid, $start_timeout);

        my $uuid;
        for my $id (sort keys %$pci_devices) {
            my $d = $pci_devices->{$id};
            my ($index) = ($id =~ m/^hostpci(\d+)$/);

            my $chosen_mdev;
            for my $dev ($d->{ids}->@*) {
                my $info =
                    eval { PVE::QemuServer::PCI::prepare_pci_device($vmid, $dev->{id}, $index, $d) };
                if ($d->{mdev} || $d->{nvidia}) {
                    warn $@ if $@;
                    $chosen_mdev = $info;
                    last if $chosen_mdev; # if successful, we're done
                } else {
                    die $@ if $@;
                }
            }

            next if !$d->{mdev} && !$d->{nvidia};
            die "could not create mediated device\n" if !defined($chosen_mdev);

            # nvidia grid needs the uuid of the mdev as qemu parameter
            if (!defined($uuid) && $chosen_mdev->{vendor} =~ m/^(0x)?10de$/) {
                if (defined($conf->{smbios1})) {
                    my $smbios_conf = parse_smbios1($conf->{smbios1});
                    $uuid = $smbios_conf->{uuid} if defined($smbios_conf->{uuid});
                }
                $uuid = PVE::QemuServer::PCI::generate_mdev_uuid($vmid, $index)
                    if !defined($uuid);
            }
        }
        push @$cmd, '-uuid', $uuid if defined($uuid);
    };
    if (my $err = $@) {
        eval { PVE::Storage::deactivate_volumes($storecfg, $vollist); };
        warn $@ if $@;
        eval { cleanup_pci_devices($vmid, $conf) };
        warn $@ if $@;
        die $err;
    }

    my %silence_std_outs = (outfunc => sub { }, errfunc => sub { });
    eval { run_command(['/bin/systemctl', 'reset-failed', "$vmid.scope"], %silence_std_outs) };
    eval { run_command(['/bin/systemctl', 'stop', "$vmid.scope"], %silence_std_outs) };
    # Issues with the above 'stop' not being fully completed are extremely rare, a very low
    # timeout should be more than enough here...
    PVE::Systemd::wait_for_unit_removed("$vmid.scope", 20);

    my $cpuunits = PVE::CGroup::clamp_cpu_shares($conf->{cpuunits});

    my %run_params = (
        timeout => $statefile ? undef : $start_timeout,
        umask => 0077,
        noerr => 1,
    );

    # when migrating, prefix QEMU output so other side can pick up any
    # errors that might occur and show the user
    if ($migratedfrom) {
        $run_params{quiet} = 1;
        $run_params{logfunc} = sub { print "QEMU: $_[0]\n" };
    }

    my %systemd_properties = (
        Slice => 'qemu.slice',
        KillMode => 'process',
        SendSIGKILL => 0,
        TimeoutStopUSec => ULONG_MAX, # infinity
    );

    if (PVE::CGroup::cgroup_mode() == 2) {
        $systemd_properties{CPUWeight} = $cpuunits;
    } else {
        $systemd_properties{CPUShares} = $cpuunits;
    }

    if (my $cpulimit = $conf->{cpulimit}) {
        $systemd_properties{CPUQuota} = int($cpulimit * 100);
    }
    $systemd_properties{timeout} = 10 if $statefile; # setting up the scope should be quick

    my $run_qemu = sub {
        PVE::Tools::run_fork sub {
            PVE::Systemd::enter_systemd_scope($vmid, "Proxmox VE VM $vmid",
                %systemd_properties);

            my $virtiofs_sockets = start_all_virtiofsd($conf, $vmid);

            my $tpmpid;
            if ((my $tpm = $conf->{tpmstate0}) && !PVE::QemuConfig->is_template($conf)) {
                # start the TPM emulator so QEMU can connect on start
                $tpmpid = start_swtpm($storecfg, $vmid, $tpm, $migratedfrom);
            }

            my $exitcode = run_command($cmd, %run_params);
            eval { PVE::QemuServer::Virtiofs::close_sockets(@$virtiofs_sockets); };
            log_warn("closing virtiofs sockets failed - $@") if $@;
            if ($exitcode) {
                if ($tpmpid) {
                    warn "stopping swtpm instance (pid $tpmpid) due to QEMU startup error\n";
                    kill 'TERM', $tpmpid;
                }
                die "QEMU exited with code $exitcode\n";
            }
        };
    };

    if ($conf->{hugepages}) {

        my $code = sub {
            my $hotplug_features =
                parse_hotplug_features(defined($conf->{hotplug}) ? $conf->{hotplug} : '1');
            my $hugepages_topology =
                PVE::QemuServer::Memory::hugepages_topology($conf, $hotplug_features->{memory});

            my $hugepages_host_topology = PVE::QemuServer::Memory::hugepages_host_topology();

            PVE::QemuServer::Memory::hugepages_mount();
            PVE::QemuServer::Memory::hugepages_allocate(
                $hugepages_topology, $hugepages_host_topology,
            );

            eval { $run_qemu->() };
            if (my $err = $@) {
                PVE::QemuServer::Memory::hugepages_reset($hugepages_host_topology)
                    if !$conf->{keephugepages};
                die $err;
            }

            PVE::QemuServer::Memory::hugepages_pre_deallocate($hugepages_topology)
                if !$conf->{keephugepages};
        };
        eval { PVE::QemuServer::Memory::hugepages_update_locked($code); };

    } else {
        eval { $run_qemu->() };
    }

    if (my $err = $@) {
        # deactivate volumes if start fails
        eval { PVE::Storage::deactivate_volumes($storecfg, $vollist); };
        warn $@ if $@;
        eval { cleanup_pci_devices($vmid, $conf) };
        warn $@ if $@;

        die "start failed: $err";
    }

    # re-reserve all PCI IDs now that we can know the actual VM PID
    my $pid = PVE::QemuServer::Helpers::vm_running_locally($vmid);
    eval { PVE::QemuServer::PCI::reserve_pci_usage($pci_reserve_list, $vmid, undef, $pid) };
    warn $@ if $@;

    syslog("info", "VM $vmid started with PID $pid.");

    if (defined(my $migrate = $res->{migrate})) {
        if ($migrate->{proto} eq 'tcp') {
            my $nodename = nodename();
            my $pfamily = PVE::Tools::get_host_address_family($nodename);
            $migrate->{port} = PVE::Tools::next_migrate_port($pfamily);
            $migrate->{uri} = "tcp:$migrate->{addr}:$migrate->{port}";
            mon_cmd($vmid, "migrate-incoming", uri => $migrate->{uri});
        }
        print "migration listens on $migrate->{uri}\n";
    } elsif ($statefile) {
        eval { mon_cmd($vmid, "cont"); };
        warn $@ if $@;
    }

    #start nbd server for storage migration
    if (my $nbd = $migrate_opts->{nbd}) {

        my $migrate_storage_uri;
        # nbd_protocol_version > 0 for unix socket support
        if (
            $nbd_protocol_version > 0
            && ($migration_type eq 'secure' || $migration_type eq 'websocket')
        ) {
            my $socket_path = "/run/qemu-server/$vmid\_nbd.migrate";
            mon_cmd(
                $vmid,
                "nbd-server-start",
                addr => { type => 'unix', data => { path => $socket_path } },
            );
            $migrate_storage_uri = "nbd:unix:$socket_path";
            $res->{migrate}->{unix_sockets} = [$socket_path];
        } else {
            my $nodename = nodename();
            my $localip = $migration_ip // die "internal error - no migration IP";
            my $pfamily = PVE::Tools::get_host_address_family($nodename);
            my $storage_migrate_port = PVE::Tools::next_migrate_port($pfamily);

            mon_cmd(
                $vmid,
                "nbd-server-start",
                addr => {
                    type => 'inet',
                    data => {
                        host => "${localip}",
                        port => "${storage_migrate_port}",
                    },
                },
            );
            $localip = "[$localip]" if Net::IP::ip_is_ipv6($localip);
            $migrate_storage_uri = "nbd:${localip}:${storage_migrate_port}";
        }

        my $block_info = PVE::QemuServer::Blockdev::get_block_info($vmid);

        foreach my $opt (sort keys %$nbd) {
            my $drivestr = $nbd->{$opt}->{drivestr};
            my $volid = $nbd->{$opt}->{volid};

            my $block_node = $block_info->{$opt}->{inserted}->{'node-name'};

            mon_cmd(
                $vmid,
                "block-export-add",
                id => "drive-$opt",
                'node-name' => $block_node,
                writable => JSON::true,
                type => "nbd",
                name => "drive-$opt", # NBD export name
            );

            my $nbd_uri = "$migrate_storage_uri:exportname=drive-$opt";
            print "storage migration listens on $nbd_uri volume:$drivestr\n";
            print "re-using replicated volume: $opt - $volid\n"
                if $nbd->{$opt}->{replicated};

            $res->{drives}->{$opt} = $nbd->{$opt};
            $res->{drives}->{$opt}->{nbd_uri} = $nbd_uri;
        }
    }

    if ($migratedfrom) {
        eval { PVE::QemuMigrate::Helpers::set_migration_caps($vmid); };
        warn $@ if $@;

        if ($spice_port) {
            print "spice listens on port $spice_port\n";
            $res->{spice_port} = $spice_port;
            if ($migrate_opts->{spice_ticket}) {
                mon_cmd(
                    $vmid, "set_password",
                    protocol => 'spice',
                    password => $migrate_opts->{spice_ticket},
                );
                mon_cmd($vmid, "expire_password", protocol => 'spice', time => "+30");
            }
        }

        # conntrack migration is only supported for intra-cluster migrations
        if ($migrate_opts->{with_conntrack_state} && !$migrate_opts->{remote_node}) {
            PVE::QemuServer::DBusVMState::qemu_add_dbus_vmstate($vmid);
        }
    } else {
        mon_cmd($vmid, "balloon", value => $conf->{balloon} * 1024 * 1024)
            if !$statefile && $conf->{balloon};

        foreach my $opt (keys %$conf) {
            next if $opt !~ m/^net\d+$/;
            my $nicconf = PVE::QemuServer::Network::parse_net($conf->{$opt});
            qemu_set_link_status($vmid, $opt, 0) if $nicconf->{link_down};
        }
        PVE::QemuServer::Network::add_nets_bridge_fdb($conf, $vmid);
    }

    if (!defined($conf->{balloon}) || $conf->{balloon}) {
        eval {
            mon_cmd(
                $vmid,
                'qom-set',
                path => "machine/peripheral/balloon0",
                property => "guest-stats-polling-interval",
                value => 2,
            );
        };
        log_warn("could not set polling interval for ballooning - $@") if $@;
    }

    if ($resume) {
        print "Resumed VM, removing state\n";
        if (my $vmstate = $conf->{vmstate}) {
            PVE::Storage::deactivate_volumes($storecfg, [$vmstate]);
            PVE::Storage::vdisk_free($storecfg, $vmstate);
        }
        delete $conf->@{qw(lock vmstate runningmachine runningcpu)};
        PVE::QemuConfig->write_config($vmid, $conf);
    }

    PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'post-start');

    my ($current_machine, $is_deprecated) =
        PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
    if ($is_deprecated) {
        log_warn(
            "current machine version '$current_machine' is deprecated - see the documentation and "
                . "change to a newer one",
        );
    }

    return $res;
}

sub vm_commandline {
    my ($storecfg, $vmid, $snapname) = @_;

    my $conf = PVE::QemuConfig->load_config($vmid);

    my $options = { 'dry-run' => 1 };
    if ($snapname) {
        my $snapshot = $conf->{snapshots}->{$snapname};
        die "snapshot '$snapname' does not exist\n" if !defined($snapshot);

        # check for machine or CPU overrides in snapshot
        $options->{'force-machine'} = $snapshot->{runningmachine};
        $options->{'force-cpu'} = $snapshot->{runningcpu};

        $snapshot->{digest} = $conf->{digest}; # keep file digest for API

        $conf = $snapshot;
    }

    my $defaults = load_defaults();

    my $running = PVE::QemuServer::Helpers::vm_running_locally($vmid);
    my $volumes = [];

    # With -blockdev, it is necessary to activate the volumes before generating the command line
    if (!$running) {
        $volumes = get_current_vm_volumes($storecfg, $conf);
        PVE::Storage::activate_volumes($storecfg, $volumes);
    }

    # There might be concurrent operations on the volumes, so do not deactivate.

    my $cmd = config_to_command($storecfg, $vmid, $conf, $defaults, $options);

    return PVE::Tools::cmd2string($cmd);
}

sub vm_reset {
    my ($vmid, $skiplock) = @_;

    PVE::QemuConfig->lock_config(
        $vmid,
        sub {

            my $conf = PVE::QemuConfig->load_config($vmid);

            PVE::QemuConfig->check_lock($conf) if !$skiplock;

            mon_cmd($vmid, "system_reset");
        },
    );
}

sub get_vm_volumes {
    my ($conf) = @_;

    my $vollist = [];
    foreach_volid(
        $conf,
        sub {
            my ($volid, $attr) = @_;

            return if $volid =~ m|^/|;

            my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
            return if !$sid;

            push @$vollist, $volid;
        },
    );

    return $vollist;
}

# Get volumes defined in the current VM configuration, including the VM state file.
sub get_current_vm_volumes {
    my ($storecfg, $conf) = @_;

    my $volumes = [];

    PVE::QemuConfig->foreach_volume_full(
        $conf,
        { extra_keys => ['vmstate'] },
        sub {
            my ($ds, $drive) = @_;

            if (PVE::Storage::parse_volume_id($drive->{file}, 1)) {
                check_volume_storage_type($storecfg, $drive->{file});
                push $volumes->@*, $drive->{file};
            }
        },
    );

    return $volumes;
}

sub cleanup_pci_devices {
    my ($vmid, $conf) = @_;

    # templates don't use pci devices
    return if $conf->{template};

    my $reservations = PVE::QemuServer::PCI::get_reservations($vmid);
    # clean up nvidia devices
    for my $id ($reservations->@*) {
        $id = PVE::SysFSTools::normalize_pci_id($id);

        my $create_path = "/sys/bus/pci/devices/$id/nvidia/current_vgpu_type";

        next if !-f $create_path;

        for (my $i = 0; $i < 10; $i++) {
            last if file_read_firstline($create_path) eq "0";
            sleep 1;
            PVE::SysFSTools::file_write($create_path, "0");
        }
        if (file_read_firstline($create_path) ne "0") {
            warn "could not cleanup nvidia vgpu for '$id'\n";
        }
    }

    foreach my $key (keys %$conf) {
        next if $key !~ m/^hostpci(\d+)$/;
        my $hostpciindex = $1;
        my $uuid = PVE::SysFSTools::generate_mdev_uuid($vmid, $hostpciindex);
        my $d = parse_hostpci($conf->{$key});
        if ($d->{mdev}) {
            # NOTE: avoid PVE::SysFSTools::pci_cleanup_mdev_device as it requires PCI ID and we
            # don't want to break ABI just for this two liner
            my $dev_sysfs_dir = "/sys/bus/mdev/devices/$uuid";

            # some nvidia vgpu driver versions want to clean the mdevs up themselves, and error
            # out when we do it first. so wait for up to 10 seconds and then try it manually
            if ($d->{ids}->[0]->[0]->{vendor} =~ m/^(0x)?10de$/ && -e $dev_sysfs_dir) {
                my $count = 0;
                while (-e $dev_sysfs_dir && $count < 10) {
                    sleep 1;
                    $count++;
                }
                print "waited $count seconds for mediated device driver finishing clean up\n";
            }

            if (-e $dev_sysfs_dir) {
                print "actively clean up mediated device with UUID $uuid\n";
                PVE::SysFSTools::file_write("$dev_sysfs_dir/remove", "1");
            }
        }
    }
    PVE::QemuServer::PCI::remove_pci_reservation($vmid);
}

sub vm_stop_cleanup {
    my ($storecfg, $vmid, $conf, $keepActive, $apply_pending_changes, $noerr) = @_;

    eval {

        if (!$keepActive) {
            my $vollist = get_vm_volumes($conf);
            PVE::Storage::deactivate_volumes($storecfg, $vollist);
        }

        foreach my $ext (qw(mon qmp pid vnc qga)) {
            unlink "/var/run/qemu-server/${vmid}.$ext";
        }

        if ($conf->{ivshmem}) {
            my $ivshmem = parse_property_string($ivshmem_fmt, $conf->{ivshmem});
            # just delete it for now, VMs which have this already open do not
            # are affected, but new VMs will get a separated one. If this
            # becomes an issue we either add some sort of ref-counting or just
            # add a "don't delete on stop" flag to the ivshmem format.
            unlink '/dev/shm/pve-shm-' . ($ivshmem->{name} // $vmid);
        }

        cleanup_pci_devices($vmid, $conf);

        vmconfig_apply_pending($vmid, $conf, $storecfg) if $apply_pending_changes;
    };
    if (my $err = $@) {
        die $err if !$noerr;
        warn $err;
    }
}

# call only in locked context
sub _do_vm_stop {
    my ($storecfg, $vmid, $skiplock, $nocheck, $timeout, $shutdown, $force, $keepActive) = @_;

    my $pid = check_running($vmid, $nocheck);
    return if !$pid;

    my $conf;
    if (!$nocheck) {
        $conf = PVE::QemuConfig->load_config($vmid);
        PVE::QemuConfig->check_lock($conf) if !$skiplock;
        if (!defined($timeout) && $shutdown && $conf->{startup}) {
            my $opts = PVE::JSONSchema::pve_parse_startup_order($conf->{startup});
            $timeout = $opts->{down} if $opts->{down};
        }
        PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'pre-stop');
    }

    eval {
        if ($shutdown) {
            if (defined($conf) && get_qga_key($conf, 'enabled') && qga_check_running($vmid)) {
                mon_cmd($vmid, "guest-shutdown", timeout => $timeout);
            } else {
                mon_cmd($vmid, "system_powerdown");
            }
        } else {
            mon_cmd($vmid, "quit");
        }
    };
    my $err = $@;

    if (!$err) {
        $timeout = 60 if !defined($timeout);

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
            vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive, 1, 1) if $conf;
            return;
        }
    } else {
        if (!check_running($vmid, $nocheck)) {
            warn "Unexpected: VM shutdown command failed, but VM not running anymore..\n";
            return;
        }
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

    vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive, 1, 1) if $conf;
}

# Note: use $nocheck to skip tests if VM configuration file exists.
# We need that when migration VMs to other nodes (files already moved)
# Note: we set $keepActive in vzdump stop mode - volumes need to stay active
sub vm_stop {
    my (
        $storecfg,
        $vmid,
        $skiplock,
        $nocheck,
        $timeout,
        $shutdown,
        $force,
        $keepActive,
        $migratedfrom,
    ) = @_;

    $force = 1 if !defined($force) && !$shutdown;

    if ($migratedfrom) {
        my $pid = check_running($vmid, $nocheck, $migratedfrom);
        kill 15, $pid if $pid;
        my $conf = PVE::QemuConfig->load_config($vmid, $migratedfrom);
        vm_stop_cleanup($storecfg, $vmid, $conf, $keepActive, 0, 1);
        return;
    }

    PVE::QemuConfig->lock_config(
        $vmid,
        sub {
            _do_vm_stop(
                $storecfg,
                $vmid,
                $skiplock,
                $nocheck,
                $timeout,
                $shutdown,
                $force,
                $keepActive,
            );
        },
    );
}

sub vm_reboot {
    my ($vmid, $timeout) = @_;

    PVE::QemuConfig->lock_config(
        $vmid,
        sub {
            eval {

                # only reboot if running, as qmeventd starts it again on a stop event
                return if !check_running($vmid);

                create_reboot_request($vmid);

                my $storecfg = PVE::Storage::config();
                _do_vm_stop($storecfg, $vmid, undef, undef, $timeout, 1);

            };
            if (my $err = $@) {
                # avoid that the next normal shutdown will be confused for a reboot
                clear_reboot_request($vmid);
                die $err;
            }
        },
    );
}

sub vm_sendkey {
    my ($vmid, $skiplock, $key) = @_;

    PVE::QemuConfig->lock_config(
        $vmid,
        sub {

            my $conf = PVE::QemuConfig->load_config($vmid);

            # there is no qmp command, so we use the human monitor command
            my $res = PVE::QemuServer::Monitor::hmp_cmd($vmid, "sendkey $key");
            die $res if $res ne '';
        },
    );
}

sub check_bridge_access {
    my ($rpcenv, $authuser, $conf) = @_;

    return 1 if $authuser eq 'root@pam';

    for my $opt (sort keys $conf->%*) {
        next if $opt !~ m/^net\d+$/;
        my $net = PVE::QemuServer::Network::parse_net($conf->{$opt});
        my ($bridge, $tag, $trunks) = $net->@{ 'bridge', 'tag', 'trunks' };
        PVE::GuestHelpers::check_vnet_access($rpcenv, $authuser, $bridge, $tag, $trunks);
    }
    return 1;
}

sub check_mapping_access {
    my ($rpcenv, $user, $conf) = @_;

    return 1 if $user eq 'root@pam';

    for my $opt (keys $conf->%*) {
        if ($opt =~ m/^usb\d+$/) {
            my $device = PVE::JSONSchema::parse_property_string('pve-qm-usb', $conf->{$opt});
            if (my $host = $device->{host}) {
                die "only root can set '$opt' config for real devices\n"
                    if $host !~ m/^spice$/i;
            } elsif ($device->{mapping}) {
                $rpcenv->check_full($user, "/mapping/usb/$device->{mapping}", ['Mapping.Use']);
            } else {
                die "either 'host' or 'mapping' must be set.\n";
            }
        } elsif ($opt =~ m/^hostpci\d+$/) {
            my $device = PVE::JSONSchema::parse_property_string('pve-qm-hostpci', $conf->{$opt});
            if ($device->{host}) {
                die "only root can set '$opt' config for non-mapped devices\n";
            } elsif ($device->{mapping}) {
                $rpcenv->check_full($user, "/mapping/pci/$device->{mapping}", ['Mapping.Use']);
            } else {
                die "either 'host' or 'mapping' must be set.\n";
            }
        } elsif ($opt =~ m/^rng\d+$/) {
            my $device = PVE::JSONSchema::parse_property_string('pve-qm-rng', $conf->{$opt});

            if ($device->{source} && $device->{source} eq '/dev/hwrng') {
                $rpcenv->check_full($user, "/mapping/hwrng", ['Mapping.Use']);
            }
        } elsif ($opt =~ m/^virtiofs\d$/) {
            my $virtiofs = PVE::JSONSchema::parse_property_string('pve-qm-virtiofs', $conf->{$opt});
            $rpcenv->check_full($user, "/mapping/dir/$virtiofs->{dirid}", ['Mapping.Use']);
        }
    }
}

sub check_restore_permissions {
    my ($rpcenv, $user, $conf) = @_;

    check_bridge_access($rpcenv, $user, $conf);
    check_mapping_access($rpcenv, $user, $conf);
}
# vzdump restore implementation

sub tar_archive_read_firstfile {
    my $archive = shift;

    die "ERROR: file '$archive' does not exist\n" if !-f $archive;

    # try to detect archive type first
    my $pid = open(my $fh, '-|', 'tar', 'tf', $archive)
        || die "unable to open file '$archive'\n";
    my $firstfile = <$fh>;
    kill 15, $pid;
    close $fh;

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
                    print STDERR "temporary volume '$volid' successfully removed\n";
                };
                print STDERR "unable to cleanup '$volid' - $@" if $@;
            } else {
                print STDERR "unable to parse line in statfile - $line";
            }
        }
        $fd->close();
    }
}

sub restore_file_archive {
    my ($archive, $vmid, $user, $opts) = @_;

    return restore_vma_archive($archive, $vmid, $user, $opts)
        if $archive eq '-';

    my $info = PVE::Storage::archive_info($archive);
    my $format = $opts->{format} // $info->{format};
    my $comp = $info->{compression};

    # try to detect archive format
    if ($format eq 'tar') {
        return restore_tar_archive($archive, $vmid, $user, $opts);
    } else {
        return restore_vma_archive($archive, $vmid, $user, $opts, $comp);
    }
}

# helper to remove disks that will not be used after restore
my $restore_cleanup_oldconf = sub {
    my ($storecfg, $vmid, $oldconf, $virtdev_hash) = @_;

    my $kept_disks = {};

    PVE::QemuConfig->foreach_volume(
        $oldconf,
        sub {
            my ($ds, $drive) = @_;

            return if drive_is_cdrom($drive, 1);

            my $volid = $drive->{file};
            return if !$volid || $volid =~ m|^/|;

            my ($path, $owner) = PVE::Storage::path($storecfg, $volid);
            return if !$path || !$owner || ($owner != $vmid);

            # Note: only delete disk we want to restore
            # other volumes will become unused
            if ($virtdev_hash->{$ds}) {
                eval { PVE::Storage::vdisk_free($storecfg, $volid); };
                if (my $err = $@) {
                    warn $err;
                }
            } else {
                $kept_disks->{$volid} = 1;
            }
        },
    );

    # after the restore we have no snapshots anymore
    for my $snapname (keys $oldconf->{snapshots}->%*) {
        my $snap = $oldconf->{snapshots}->{$snapname};
        if ($snap->{vmstate}) {
            eval { PVE::Storage::vdisk_free($storecfg, $snap->{vmstate}); };
            if (my $err = $@) {
                warn $err;
            }
        }

        for my $volid (keys $kept_disks->%*) {
            eval { PVE::Storage::volume_snapshot_delete($storecfg, $volid, $snapname); };
            warn $@ if $@;
        }
    }
};

# Helper to parse vzdump backup device hints
#
# $rpcenv: Environment, used to ckeck storage permissions
# $user: User ID, to check storage permissions
# $storecfg: Storage configuration
# $fh: the file handle for reading the configuration
# $devinfo: should contain device sizes for all backu-up'ed devices
# $options: backup options (pool, default storage)
#
# Return: $virtdev_hash, updates $devinfo (add devname, virtdev, format, storeid)
my $parse_backup_hints = sub {
    my ($rpcenv, $user, $storecfg, $fh, $devinfo, $options) = @_;

    my $check_storage = sub { # assert if an image can be allocate
        my ($storeid, $scfg) = @_;
        die "Content type 'images' is not available on storage '$storeid'\n"
            if !$scfg->{content}->{images};
        $rpcenv->check($user, "/storage/$storeid", ['Datastore.AllocateSpace'])
            if $user ne 'root@pam';
    };

    my $virtdev_hash = {};
    while (defined(my $line = <$fh>)) {
        if ($line =~ m/^\#qmdump\#map:(\S+):(\S+):(\S*):(\S*):$/) {
            my ($virtdev, $devname, $storeid, $format) = ($1, $2, $3, $4);
            die "archive does not contain data for drive '$virtdev'\n"
                if !$devinfo->{$devname};

            if (defined($options->{storage})) {
                $storeid = $options->{storage} || 'local';
            } elsif (!$storeid) {
                $storeid = 'local';
            }
            $format = 'raw' if !$format;
            $devinfo->{$devname}->{devname} = $devname;
            $devinfo->{$devname}->{virtdev} = $virtdev;
            $devinfo->{$devname}->{format} = $format;
            $devinfo->{$devname}->{storeid} = $storeid;

            my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
            $check_storage->($storeid, $scfg); # permission and content type check

            $virtdev_hash->{$virtdev} = $devinfo->{$devname};
        } elsif ($line =~ m/^((?:ide|sata|scsi)\d+):\s*(.*)\s*$/) {
            my $virtdev = $1;
            my $drive = parse_drive($virtdev, $2);

            if (drive_is_cloudinit($drive)) {
                my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file});
                $storeid = $options->{storage} if defined($options->{storage});
                my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
                my $format = eval { checked_volume_format($storecfg, $drive->{file}) } // 'raw';

                $check_storage->($storeid, $scfg); # permission and content type check

                $virtdev_hash->{$virtdev} = {
                    format => $format,
                    storeid => $storeid,
                    size => PVE::QemuServer::Cloudinit::CLOUDINIT_DISK_SIZE,
                    is_cloudinit => 1,
                };
            }
        }
    }

    return $virtdev_hash;
};

# Helper to allocate and activate all volumes required for a restore
#
# $storecfg: Storage configuration
# $virtdev_hash: as returned by parse_backup_hints()
#
# Returns: { $virtdev => $volid }
my $restore_allocate_devices = sub {
    my ($storecfg, $virtdev_hash, $vmid) = @_;

    my $map = {};
    foreach my $virtdev (sort keys %$virtdev_hash) {
        my $d = $virtdev_hash->{$virtdev};
        die "got no size for '$virtdev'\n" if !defined($d->{size});
        my $alloc_size = int(($d->{size} + 1024 - 1) / 1024);
        my $storeid = $d->{storeid};
        my $scfg = PVE::Storage::storage_config($storecfg, $storeid);

        # falls back to default format if requested format is not supported
        $d->{format} = PVE::Storage::resolve_format_hint($storecfg, $storeid, $d->{format});

        my $name;
        if ($d->{is_cloudinit}) {
            $name = "vm-$vmid-cloudinit";
            my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
            if ($scfg->{path}) {
                $name .= ".$d->{format}";
            }
        }

        my $volid =
            PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $d->{format}, $name, $alloc_size);

        print STDERR "new volume ID is '$volid'\n";
        $d->{volid} = $volid;

        PVE::Storage::activate_volumes($storecfg, [$volid]);

        $map->{$virtdev} = $volid;
    }

    return $map;
};

sub restore_update_config_line {
    my ($cookie, $map, $line, $unique) = @_;

    return '' if $line =~ m/^\#qmdump\#/;
    return '' if $line =~ m/^\#vzdump\#/;
    return '' if $line =~ m/^lock:/;
    return '' if $line =~ m/^unused\d+:/;
    return '' if $line =~ m/^parent:/;

    my $res = '';

    my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
    if (($line =~ m/^(vlan(\d+)):\s*(\S+)\s*$/)) {
        # try to convert old 1.X settings
        my ($id, $ind, $ethcfg) = ($1, $2, $3);
        foreach my $devconfig (PVE::Tools::split_list($ethcfg)) {
            my ($model, $macaddr) = split(/\=/, $devconfig);
            $macaddr = PVE::Tools::random_ether_addr($dc->{mac_prefix}) if !$macaddr || $unique;
            my $net = {
                model => $model,
                bridge => "vmbr$ind",
                macaddr => $macaddr,
            };
            my $netstr = PVE::QemuServer::Network::print_net($net);

            $res .= "net$cookie->{netcount}: $netstr\n";
            $cookie->{netcount}++;
        }
    } elsif (($line =~ m/^(net\d+):\s*(\S+)\s*$/) && $unique) {
        my ($id, $netstr) = ($1, $2);
        my $net = PVE::QemuServer::Network::parse_net($netstr);
        $net->{macaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix}) if $net->{macaddr};
        $netstr = PVE::QemuServer::Network::print_net($net);
        $res .= "$id: $netstr\n";
    } elsif ($line =~ m/^((ide|scsi|virtio|sata|efidisk|tpmstate)\d+):\s*(\S+)\s*$/) {
        my $virtdev = $1;
        my $value = $3;
        my $di = parse_drive($virtdev, $value);
        if (defined($di->{backup}) && !$di->{backup}) {
            $res .= "#$line";
        } elsif ($map->{$virtdev}) {
            delete $di->{format}; # format can change on restore
            $di->{file} = $map->{$virtdev};
            $value = print_drive($di);
            $res .= "$virtdev: $value\n";
        } else {
            $res .= $line;
        }
    } elsif (($line =~ m/^vmgenid: (.*)/)) {
        my $vmgenid = $1;
        if ($vmgenid ne '0') {
            # always generate a new vmgenid if there was a valid one setup
            $vmgenid = generate_uuid();
        }
        $res .= "vmgenid: $vmgenid\n";
    } elsif (($line =~ m/^(smbios1: )(.*)/) && $unique) {
        my ($uuid, $uuid_str);
        UUID::generate($uuid);
        UUID::unparse($uuid, $uuid_str);
        my $smbios1 = parse_smbios1($2);
        $smbios1->{uuid} = $uuid_str;
        $res .= $1 . print_smbios1($smbios1) . "\n";
    } else {
        $res .= $line;
    }

    return $res;
}

my $restore_deactivate_volumes = sub {
    my ($storecfg, $virtdev_hash) = @_;

    my $vollist = [];
    for my $dev (values $virtdev_hash->%*) {
        push $vollist->@*, $dev->{volid} if $dev->{volid};
    }

    eval { PVE::Storage::deactivate_volumes($storecfg, $vollist); };
    print STDERR $@ if $@;
};

my $restore_destroy_volumes = sub {
    my ($storecfg, $virtdev_hash) = @_;

    for my $dev (values $virtdev_hash->%*) {
        my $volid = $dev->{volid} or next;
        eval {
            PVE::Storage::vdisk_free($storecfg, $volid);
            print STDERR "temporary volume '$volid' successfully removed\n";
        };
        print STDERR "unable to cleanup '$volid' - $@" if $@;
    }
};

sub restore_merge_config {
    my ($filename, $backup_conf_raw, $override_conf) = @_;

    my $backup_conf = parse_vm_config($filename, $backup_conf_raw);
    for my $key (keys $override_conf->%*) {
        $backup_conf->{$key} = $override_conf->{$key};
    }

    return $backup_conf;
}

sub scan_volids {
    my ($cfg, $vmid) = @_;

    my $info = PVE::Storage::vdisk_list($cfg, undef, $vmid, undef, 'images');

    my $volid_hash = {};
    foreach my $storeid (keys %$info) {
        foreach my $item (@{ $info->{$storeid} }) {
            next if !($item->{volid} && $item->{size});
            $item->{path} = PVE::Storage::path($cfg, $item->{volid});
            $volid_hash->{ $item->{volid} } = $item;
        }
    }

    return $volid_hash;
}

sub update_disk_config {
    my ($vmid, $conf, $volid_hash) = @_;

    my $changes;
    my $prefix = "VM $vmid";

    # used and unused disks
    my $referenced = {};

    # Note: it is allowed to define multiple storages with same path (alias), so
    # we need to check both 'volid' and real 'path' (two different volid can point
    # to the same path).

    my $referencedpath = {};

    # update size info
    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($opt, $drive) = @_;

            my $volid = $drive->{file};
            return if !$volid;
            my $volume = $volid_hash->{$volid};

            # mark volid as "in-use" for next step
            $referenced->{$volid} = 1;
            if ($volume && (my $path = $volume->{path})) {
                $referencedpath->{$path} = 1;
            }

            return if drive_is_cdrom($drive);
            return if !$volume;

            my ($updated, $msg) =
                PVE::QemuServer::Drive::update_disksize($drive, $volume->{size});
            if (defined($updated)) {
                $changes = 1;
                $conf->{$opt} = print_drive($updated);
                print "$prefix ($opt): $msg\n";
            }
        },
    );

    # remove 'unusedX' entry if volume is used
    PVE::QemuConfig->foreach_unused_volume(
        $conf,
        sub {
            my ($opt, $drive) = @_;

            my $volid = $drive->{file};
            return if !$volid;

            my $path;
            $path = $volid_hash->{$volid}->{path} if $volid_hash->{$volid};
            if ($referenced->{$volid} || ($path && $referencedpath->{$path})) {
                print "$prefix remove entry '$opt', its volume '$volid' is in use\n";
                $changes = 1;
                delete $conf->{$opt};
            }

            $referenced->{$volid} = 1;
            $referencedpath->{$path} = 1 if $path;
        },
    );

    if (my $fleecing = $conf->{'special-sections'}->{fleecing}) {
        $referenced->{$_} = 1 for PVE::Tools::split_list($fleecing->{'fleecing-images'});
    }

    foreach my $volid (sort keys %$volid_hash) {
        next if $volid =~ m/vm-$vmid-state-/;
        next if $referenced->{$volid};
        my $path = $volid_hash->{$volid}->{path};
        next if !$path; # just to be sure
        next if $referencedpath->{$path};
        $changes = 1;
        my $key = PVE::QemuConfig->add_unused_volume($conf, $volid);
        print "$prefix add unreferenced volume '$volid' as '$key' to config\n";
        $referencedpath->{$path} = 1; # avoid to add more than once (aliases)
    }

    return $changes;
}

sub rescan {
    my ($vmid, $nolock, $dryrun) = @_;

    my $cfg = PVE::Storage::config();

    print "rescan volumes...\n";
    my $volid_hash = scan_volids($cfg, $vmid);

    my $updatefn = sub {
        my ($vmid) = @_;

        my $conf = PVE::QemuConfig->load_config($vmid);

        PVE::QemuConfig->check_lock($conf);

        my $vm_volids = {};
        foreach my $volid (keys %$volid_hash) {
            my $info = $volid_hash->{$volid};
            $vm_volids->{$volid} = $info if $info->{vmid} && $info->{vmid} == $vmid;
        }

        my $changes = update_disk_config($vmid, $conf, $vm_volids);

        PVE::QemuConfig->write_config($vmid, $conf) if $changes && !$dryrun;
    };

    if (defined($vmid)) {
        if ($nolock) {
            &$updatefn($vmid);
        } else {
            PVE::QemuConfig->lock_config($vmid, $updatefn, $vmid);
        }
    } else {
        my $vmlist = config_list();
        foreach my $vmid (keys %$vmlist) {
            if ($nolock) {
                &$updatefn($vmid);
            } else {
                PVE::QemuConfig->lock_config($vmid, $updatefn, $vmid);
            }
        }
    }
}

sub restore_proxmox_backup_archive {
    my ($archive, $vmid, $user, $options) = @_;

    my $storecfg = PVE::Storage::config();

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($archive);
    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);

    my $fingerprint = $scfg->{fingerprint};
    my $keyfile = PVE::Storage::PBSPlugin::pbs_encryption_key_file_name($storecfg, $storeid);

    my $repo = PVE::PBSClient::get_repository($scfg);
    my $namespace = $scfg->{namespace};

    # This is only used for `pbs-restore` and the QEMU PBS driver (live-restore)
    my $password = PVE::Storage::PBSPlugin::pbs_get_password($scfg, $storeid);
    local $ENV{PBS_PASSWORD} = $password;
    local $ENV{PBS_FINGERPRINT} = $fingerprint if defined($fingerprint);

    my ($vtype, $pbs_backup_name, undef, undef, undef, undef, $format) =
        PVE::Storage::parse_volname($storecfg, $archive);

    die "got unexpected vtype '$vtype'\n" if $vtype ne 'backup';

    die "got unexpected backup format '$format'\n" if $format ne 'pbs-vm';

    my $tmpdir = "/var/tmp/vzdumptmp$$";
    rmtree $tmpdir;
    mkpath $tmpdir;

    my $conffile = PVE::QemuConfig->config_file($vmid);
    # disable interrupts (always do cleanups)
    local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
        sub { print STDERR "got interrupt - ignored\n"; };

    # Note: $oldconf is undef if VM does not exists
    my $cfs_path = PVE::QemuConfig->cfs_config_path($vmid);
    my $oldconf = PVE::Cluster::cfs_read_file($cfs_path);
    my $new_conf_raw = '';

    my $rpcenv = PVE::RPCEnvironment::get();
    my $devinfo = {}; # info about drives included in backup
    my $virtdev_hash = {}; # info about allocated drives

    eval {
        # enable interrupts
        local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
            local $SIG{PIPE} = sub { die "interrupted by signal\n"; };

        my $cfgfn = "$tmpdir/qemu-server.conf";
        my $firewall_config_fn = "$tmpdir/fw.conf";
        my $index_fn = "$tmpdir/index.json";

        my $cmd = "restore";

        my $param = [$pbs_backup_name, "index.json", $index_fn];
        PVE::Storage::PBSPlugin::run_raw_client_cmd($scfg, $storeid, $cmd, $param);
        my $index = PVE::Tools::file_get_contents($index_fn);
        $index = decode_json($index);

        foreach my $info (@{ $index->{files} }) {
            if ($info->{filename} =~ m/^(drive-\S+).img.fidx$/) {
                my $devname = $1;
                if ($info->{size} =~ m/^(\d+)$/) { # untaint size
                    $devinfo->{$devname}->{size} = $1;
                } else {
                    die "unable to parse file size in 'index.json' - got '$info->{size}'\n";
                }
            }
        }

        my $is_qemu_server_backup =
            scalar(grep { $_->{filename} eq 'qemu-server.conf.blob' } @{ $index->{files} });
        if (!$is_qemu_server_backup) {
            die
                "backup does not look like a qemu-server backup (missing 'qemu-server.conf' file)\n";
        }
        my $has_firewall_config =
            scalar(grep { $_->{filename} eq 'fw.conf.blob' } @{ $index->{files} });

        $param = [$pbs_backup_name, "qemu-server.conf", $cfgfn];
        PVE::Storage::PBSPlugin::run_raw_client_cmd($scfg, $storeid, $cmd, $param);

        if ($has_firewall_config) {
            $param = [$pbs_backup_name, "fw.conf", $firewall_config_fn];
            PVE::Storage::PBSPlugin::run_raw_client_cmd($scfg, $storeid, $cmd, $param);

            my $pve_firewall_dir = '/etc/pve/firewall';
            mkdir $pve_firewall_dir; # make sure the dir exists
            PVE::Tools::file_copy($firewall_config_fn, "${pve_firewall_dir}/$vmid.fw");
        }

        my $fh = IO::File->new($cfgfn, "r")
            || die "unable to read qemu-server.conf - $!\n";

        $virtdev_hash =
            $parse_backup_hints->($rpcenv, $user, $storecfg, $fh, $devinfo, $options);

        # fixme: rate limit?

        # create empty/temp config
        PVE::Tools::file_set_contents($conffile, "memory: 128\nlock: create");

        $restore_cleanup_oldconf->($storecfg, $vmid, $oldconf, $virtdev_hash) if $oldconf;

        # allocate volumes
        my $map = $restore_allocate_devices->($storecfg, $virtdev_hash, $vmid);

        foreach my $virtdev (sort keys %$virtdev_hash) {
            my $d = $virtdev_hash->{$virtdev};
            next if $d->{is_cloudinit}; # no need to restore cloudinit

            # this fails if storage is unavailable
            my $volid = $d->{volid};
            my $path = PVE::Storage::path($storecfg, $volid);

            # for live-restore we only want to preload the efidisk and TPM state
            next if $options->{live} && $virtdev ne 'efidisk0' && $virtdev ne 'tpmstate0';

            my @ns_arg;
            if (defined(my $ns = $scfg->{namespace})) {
                @ns_arg = ('--ns', $ns);
            }

            my $pbs_restore_cmd = [
                '/usr/bin/pbs-restore',
                '--repository',
                $repo,
                @ns_arg,
                $pbs_backup_name,
                "$d->{devname}.img.fidx",
                $path,
                '--verbose',
            ];

            push @$pbs_restore_cmd, '--format', $d->{format} if $d->{format};
            push @$pbs_restore_cmd, '--keyfile', $keyfile if -e $keyfile;

            if (PVE::Storage::volume_has_feature($storecfg, 'sparseinit', $volid)) {
                push @$pbs_restore_cmd, '--skip-zero';
            }

            my $dbg_cmdstring = PVE::Tools::cmd2string($pbs_restore_cmd);
            print "restore proxmox backup image: $dbg_cmdstring\n";
            run_command($pbs_restore_cmd);
        }

        $fh->seek(0, 0) || die "seek failed - $!\n";

        my $cookie = { netcount => 0 };
        while (defined(my $line = <$fh>)) {
            $new_conf_raw .= restore_update_config_line(
                $cookie, $map, $line, $options->{unique},
            );
        }

        $fh->close();
    };
    my $err = $@;

    if ($err || !$options->{live}) {
        $restore_deactivate_volumes->($storecfg, $virtdev_hash);
    }

    rmtree $tmpdir;

    if ($err) {
        $restore_destroy_volumes->($storecfg, $virtdev_hash);
        die $err;
    }

    if ($options->{live}) {
        # keep lock during live-restore
        $new_conf_raw .= "\nlock: create";
    }

    my $new_conf = restore_merge_config($conffile, $new_conf_raw, $options->{override_conf});
    check_restore_permissions($rpcenv, $user, $new_conf);
    PVE::QemuConfig->write_config($vmid, $new_conf);

    eval { rescan($vmid, 1); };
    warn $@ if $@;

    PVE::AccessControl::add_vm_to_pool($vmid, $options->{pool}) if $options->{pool};

    if ($options->{live}) {
        # enable interrupts
        local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
            local $SIG{PIPE} = sub { die "got signal ($!) - abort\n"; };

        my $conf = PVE::QemuConfig->load_config($vmid);
        die "cannot do live-restore for template\n" if PVE::QemuConfig->is_template($conf);

        # these special drives are already restored before start
        delete $devinfo->{'drive-efidisk0'};
        delete $devinfo->{'drive-tpmstate0-backup'};

        my $pbs_opts = {
            repo => $repo,
            keyfile => $keyfile,
            snapshot => $pbs_backup_name,
            namespace => $namespace,
        };
        pbs_live_restore($vmid, $conf, $storecfg, $devinfo, $pbs_opts);

        PVE::QemuConfig->remove_lock($vmid, "create");
    }
}

sub restore_external_archive {
    my ($backup_provider, $archive, $vmid, $user, $options) = @_;

    die "live restore from backup provider is not implemented\n" if $options->{live};

    my $storecfg = PVE::Storage::config();

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($archive);
    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);

    my $tmpdir = "/run/qemu-server/vzdumptmp$$";
    rmtree($tmpdir);
    mkpath($tmpdir) or die "unable to create $tmpdir\n";

    my $conffile = PVE::QemuConfig->config_file($vmid);
    # disable interrupts (always do cleanups)
    local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
        sub { print STDERR "got interrupt - ignored\n"; };

    # Note: $oldconf is undef if VM does not exists
    my $cfs_path = PVE::QemuConfig->cfs_config_path($vmid);
    my $oldconf = PVE::Cluster::cfs_read_file($cfs_path);
    my $new_conf_raw = '';

    my $rpcenv = PVE::RPCEnvironment::get();
    my $devinfo = {}; # info about drives included in backup
    my $virtdev_hash = {}; # info about allocated drives

    eval {
        # enable interrupts
        local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
            local $SIG{PIPE} = sub { die "interrupted by signal\n"; };

        my $cfgfn = "$tmpdir/qemu-server.conf";
        my $firewall_config_fn = "$tmpdir/fw.conf";

        my $cmd = "restore";

        my ($mechanism, $vmtype) = $backup_provider->restore_get_mechanism($volname);
        die "mechanism '$mechanism' requested by backup provider is not supported for VMs\n"
            if $mechanism ne 'qemu-img';
        die "cannot restore non-VM guest of type '$vmtype'\n" if $vmtype ne 'qemu';

        $devinfo = $backup_provider->restore_vm_init($volname);

        my $data = $backup_provider->archive_get_guest_config($volname)
            or die "backup provider failed to extract guest configuration\n";
        PVE::Tools::file_set_contents($cfgfn, $data);

        if ($data = $backup_provider->archive_get_firewall_config($volname)) {
            PVE::Tools::file_set_contents($firewall_config_fn, $data);
            my $pve_firewall_dir = '/etc/pve/firewall';
            mkdir $pve_firewall_dir; # make sure the dir exists
            PVE::Tools::file_copy($firewall_config_fn, "${pve_firewall_dir}/$vmid.fw");
        }

        my $fh = IO::File->new($cfgfn, "r") or die "unable to read qemu-server.conf - $!\n";

        $virtdev_hash =
            $parse_backup_hints->($rpcenv, $user, $storecfg, $fh, $devinfo, $options);

        # create empty/temp config
        PVE::Tools::file_set_contents($conffile, "memory: 128\nlock: create");

        $restore_cleanup_oldconf->($storecfg, $vmid, $oldconf, $virtdev_hash) if $oldconf;

        # allocate volumes
        my $map = $restore_allocate_devices->($storecfg, $virtdev_hash, $vmid);

        for my $virtdev (sort keys $virtdev_hash->%*) {
            my $d = $virtdev_hash->{$virtdev};
            next if $d->{is_cloudinit}; # no need to restore cloudinit

            my $sparseinit =
                PVE::Storage::volume_has_feature($storecfg, 'sparseinit', $d->{volid});
            my $source_format = 'raw';

            my $info = $backup_provider->restore_vm_volume_init($volname, $d->{devname}, {});
            my $source_path = $info->{'qemu-img-path'}
                or die "did not get source image path from backup provider\n";

            print "importing drive '$d->{devname}' from '$source_path'\n";

            # safety check for untrusted source image
            PVE::Storage::file_size_info($source_path, undef, $source_format, 1);

            eval {
                my $convert_opts = {
                    bwlimit => $options->{bwlimit},
                    'is-zero-initialized' => $sparseinit,
                    'source-path-format' => $source_format,
                };
                PVE::QemuServer::QemuImage::convert(
                    $source_path,
                    $d->{volid},
                    $d->{size},
                    $convert_opts,
                );
            };
            my $err = $@;
            eval { $backup_provider->restore_vm_volume_cleanup($volname, $d->{devname}, {}); };
            if (my $cleanup_err = $@) {
                die $cleanup_err if !$err;
                warn $cleanup_err;
            }
            die $err if $err;
        }

        $fh->seek(0, 0) || die "seek failed - $!\n";

        my $cookie = { netcount => 0 };
        while (defined(my $line = <$fh>)) {
            $new_conf_raw .= restore_update_config_line(
                $cookie, $map, $line, $options->{unique},
            );
        }

        $fh->close();
    };
    my $err = $@;

    eval { $backup_provider->restore_vm_cleanup($volname); };
    warn "backup provider cleanup after restore failed - $@" if $@;

    if ($err) {
        $restore_deactivate_volumes->($storecfg, $virtdev_hash);
    }

    rmtree($tmpdir);

    if ($err) {
        $restore_destroy_volumes->($storecfg, $virtdev_hash);
        die $err;
    }

    my $new_conf = restore_merge_config($conffile, $new_conf_raw, $options->{override_conf});
    check_restore_permissions($rpcenv, $user, $new_conf);
    PVE::QemuConfig->write_config($vmid, $new_conf);

    eval { rescan($vmid, 1); };
    warn $@ if $@;

    PVE::AccessControl::add_vm_to_pool($vmid, $options->{pool}) if $options->{pool};

    return;
}

sub pbs_live_restore {
    my ($vmid, $conf, $storecfg, $restored_disks, $opts) = @_;

    print "starting VM for live-restore\n";
    print "repository: '$opts->{repo}', snapshot: '$opts->{snapshot}'\n";

    my $live_restore_backing = {};
    for my $ds (keys %$restored_disks) {
        $ds =~ m/^drive-(.*)$/;
        my $confname = $1;
        my $pbs_conf = {};
        $pbs_conf = {
            repository => $opts->{repo},
            snapshot => $opts->{snapshot},
            archive => "$ds.img.fidx",
        };
        $pbs_conf->{keyfile} = $opts->{keyfile} if -e $opts->{keyfile};
        $pbs_conf->{namespace} = $opts->{namespace} if defined($opts->{namespace});

        my $drive = parse_drive($confname, $conf->{$confname});
        print "restoring '$ds' to '$drive->{file}'\n";

        my $pbs_name = "drive-${confname}-pbs";

        $live_restore_backing->{$confname} = { name => $pbs_name };

        # add blockdev information
        my $machine_type = PVE::QemuServer::Machine::get_vm_machine($conf, undef, $conf->{arch});
        my $machine_version = PVE::QemuServer::Machine::extract_version(
            $machine_type,
            PVE::QemuServer::Helpers::kvm_user_version(),
        );
        if (min_version($machine_version, 10, 0)) { # for the switch to -blockdev
            $live_restore_backing->{$confname}->{blockdev} =
                PVE::QemuServer::Blockdev::generate_pbs_blockdev($pbs_conf, $pbs_name);
        } else {
            $live_restore_backing->{$confname}->{blockdev} =
                print_pbs_blockdev($pbs_conf, $pbs_name);
        }
    }

    my $drives_streamed = 0;
    eval {
        # make sure HA doesn't interrupt our restore by stopping the VM
        if (vm_is_ha_managed($vmid)) {
            run_command(['ha-manager', 'set', "vm:$vmid", '--state', 'started']);
        }

        # start VM with backing chain pointing to PBS backup, environment vars for PBS driver
        # in QEMU (PBS_PASSWORD and PBS_FINGERPRINT) are already set by our caller
        vm_start_nolock(
            $storecfg,
            $vmid,
            $conf,
            { paused => 1, 'live-restore-backing' => $live_restore_backing },
            {},
        );

        my $qmeventd_fd = register_qmeventd_handle($vmid);

        # begin streaming, i.e. data copy from PBS to target disk for every vol,
        # this will effectively collapse the backing image chain consisting of
        # [target <- alloc-track -> PBS snapshot] to just [target] (alloc-track
        # removes itself once all backing images vanish with 'auto-remove=on')
        my $jobs = {};
        for my $ds (sort keys %$restored_disks) {
            my $node_name = PVE::QemuServer::Blockdev::get_node_name_below_throttle($vmid, $ds);
            my $job_id = "restore-$ds";
            mon_cmd(
                $vmid, 'block-stream',
                'job-id' => $job_id,
                device => "$node_name",
                'auto-dismiss' => JSON::false,
            );
            $jobs->{$job_id} = {};
        }

        mon_cmd($vmid, 'cont');
        PVE::QemuServer::BlockJob::qemu_drive_mirror_monitor(
            $vmid, undef, $jobs, 'auto', 0, 'stream',
        );

        print "restore-drive jobs finished successfully, removing all tracking block devices"
            . " to disconnect from Proxmox Backup Server\n";

        for my $ds (sort keys %$restored_disks) {
            PVE::QemuServer::Blockdev::detach($vmid, "$ds-pbs");
        }

        close($qmeventd_fd);
    };

    my $err = $@;

    if ($err) {
        warn "An error occurred during live-restore: $err\n";
        _do_vm_stop($storecfg, $vmid, 1, 1, 10, 0, 1);
        die "live-restore failed\n";
    }
}

# Inspired by pbs live-restore, this restores with the disks being available as files.
# Theoretically this can also be used to quick-start a full-clone vm if the
# disks are all available as files.
#
# The mapping should provide a path by config entry, such as
# `{ scsi0 => { format => <qcow2|raw|...>, path => "/path/to/file", sata1 => ... } }`
#
# This is used when doing a `create` call with the `--live-import` parameter,
# where the disks get an `import-from=` property. The non-live part is
# therefore already handled in the `$create_disks()` call happening in the
# `create` api call
sub live_import_from_files {
    my ($mapping, $vmid, $conf, $restore_options) = @_;

    my $storecfg = PVE::Storage::config();

    my $live_restore_backing = {};
    my $sources_to_remove = [];
    for my $dev (keys %$mapping) {
        die "disk not support for live-restoring: '$dev'\n"
            if !is_valid_drivename($dev) || $dev =~ /^(?:efidisk|tpmstate)/;

        die "mapping contains disk '$dev' which does not exist in the config\n"
            if !exists($conf->{$dev});

        my $info = $mapping->{$dev};
        my ($format, $path, $volid) = $info->@{qw(format path volid)};
        die "missing path for '$dev' mapping\n" if !$path;
        die "missing volid for '$dev' mapping\n" if !$volid;
        die "missing format for '$dev' mapping\n" if !$format;
        die "invalid format '$format' for '$dev' mapping\n"
            if !grep { $format eq $_ } qw(raw qcow2 vmdk);

        $live_restore_backing->{$dev} = { name => "drive-$dev-restore" };

        my $machine_type = PVE::QemuServer::Machine::get_vm_machine($conf, undef, $conf->{arch});
        my $machine_version = PVE::QemuServer::Machine::extract_version(
            $machine_type,
            PVE::QemuServer::Helpers::kvm_user_version(),
        );
        if (min_version($machine_version, 10, 0)) { # for the switch to -blockdev
            my ($interface, $index) = PVE::QemuServer::Drive::parse_drive_interface($dev);
            my $drive = { file => $volid, interface => $interface, index => $index };
            my $blockdev = PVE::QemuServer::Blockdev::generate_drive_blockdev(
                $storecfg, $drive, $machine_version, {},
            );
            $live_restore_backing->{$dev}->{blockdev} = $blockdev;
        } else {
            $live_restore_backing->{$dev}->{blockdev} =
                "driver=$format,node-name=drive-$dev-restore"
                . ",read-only=on"
                . ",file.driver=file,file.filename=$path";
        }

        my $source_volid = $info->{'delete-after-finish'};
        push $sources_to_remove->@*, $source_volid if defined($source_volid);
    }

    eval {

        # make sure HA doesn't interrupt our restore by stopping the VM
        if (vm_is_ha_managed($vmid)) {
            run_command(['ha-manager', 'set', "vm:$vmid", '--state', 'started']);
        }

        vm_start_nolock(
            $storecfg,
            $vmid,
            $conf,
            { paused => 1, 'live-restore-backing' => $live_restore_backing },
            {},
        );

        # prevent shutdowns from qmeventd when the VM powers off from the inside
        my $qmeventd_fd = register_qmeventd_handle($vmid);

        # begin streaming, i.e. data copy from PBS to target disk for every vol,
        # this will effectively collapse the backing image chain consisting of
        # [target <- alloc-track -> PBS snapshot] to just [target] (alloc-track
        # removes itself once all backing images vanish with 'auto-remove=on')
        my $jobs = {};
        for my $ds (sort keys %$live_restore_backing) {
            my $node_name =
                PVE::QemuServer::Blockdev::get_node_name_below_throttle($vmid, "drive-$ds");
            my $job_id = "restore-$ds";
            mon_cmd(
                $vmid, 'block-stream',
                'job-id' => $job_id,
                device => "$node_name",
                'auto-dismiss' => JSON::false,
            );
            $jobs->{$job_id} = {};
        }

        mon_cmd($vmid, 'cont');
        PVE::QemuServer::BlockJob::qemu_drive_mirror_monitor(
            $vmid, undef, $jobs, 'auto', 0, 'stream',
        );

        print "restore-drive jobs finished successfully, removing all tracking block devices\n";

        for my $ds (sort keys %$live_restore_backing) {
            PVE::QemuServer::Blockdev::detach($vmid, "drive-$ds-restore");
        }

        close($qmeventd_fd);
    };

    my $err = $@;

    for my $volid ($sources_to_remove->@*) {
        eval {
            PVE::Storage::vdisk_free($storecfg, $volid);
            print "cleaned up extracted image $volid\n";
        };
        warn "An error occurred while cleaning up source images: $@\n" if $@;
    }

    if ($err) {
        warn "An error occurred during live-restore: $err\n";
        _do_vm_stop($storecfg, $vmid, 1, 1, 10, 0, 1);
        die "live-restore failed\n";
    }

    PVE::QemuConfig->remove_lock($vmid, "import");
}

sub restore_vma_archive {
    my ($archive, $vmid, $user, $opts, $comp) = @_;

    my $readfrom = $archive;

    my $cfg = PVE::Storage::config();
    my $commands = [];
    my $bwlimit = $opts->{bwlimit};

    my $dbg_cmdstring = '';
    my $add_pipe = sub {
        my ($cmd) = @_;
        push @$commands, $cmd;
        $dbg_cmdstring .= ' | ' if length($dbg_cmdstring);
        $dbg_cmdstring .= PVE::Tools::cmd2string($cmd);
        $readfrom = '-';
    };

    my $input = undef;
    if ($archive eq '-') {
        $input = '<&STDIN';
    } else {
        # If we use a backup from a PVE defined storage we also consider that
        # storage's rate limit:
        my (undef, $volid) = PVE::Storage::path_to_volume_id($cfg, $archive);
        if (defined($volid)) {
            my ($sid, undef) = PVE::Storage::parse_volume_id($volid);
            my $readlimit = PVE::Storage::get_bandwidth_limit('restore', [$sid], $bwlimit);
            if ($readlimit) {
                print STDERR "applying read rate limit: $readlimit\n";
                my $cstream = ['cstream', '-t', $readlimit * 1024, '--', $readfrom];
                $add_pipe->($cstream);
            }
        }
    }

    if ($comp) {
        my $info = PVE::Storage::decompressor_info('vma', $comp);
        my $cmd = $info->{decompressor};
        push @$cmd, $readfrom;
        $add_pipe->($cmd);
    }

    my $tmpdir = "/var/tmp/vzdumptmp$$";
    rmtree $tmpdir;

    # disable interrupts (always do cleanups)
    local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
        sub { warn "got interrupt - ignored\n"; };

    my $mapfifo = "/var/tmp/vzdumptmp$$.fifo";
    POSIX::mkfifo($mapfifo, 0600);
    my $fifofh;
    my $openfifo = sub { open($fifofh, '>', $mapfifo) or die $! };

    $add_pipe->(['vma', 'extract', '-v', '-r', $mapfifo, $readfrom, $tmpdir]);

    my $devinfo = {}; # info about drives included in backup
    my $virtdev_hash = {}; # info about allocated drives

    my $rpcenv = PVE::RPCEnvironment::get();

    my $conffile = PVE::QemuConfig->config_file($vmid);

    # Note: $oldconf is undef if VM does not exist
    my $cfs_path = PVE::QemuConfig->cfs_config_path($vmid);
    my $oldconf = PVE::Cluster::cfs_read_file($cfs_path);
    my $new_conf_raw = '';

    my %storage_limits;

    my $print_devmap = sub {
        my $cfgfn = "$tmpdir/qemu-server.conf";

        # we can read the config - that is already extracted
        my $fh = IO::File->new($cfgfn, "r")
            || die "unable to read qemu-server.conf - $!\n";

        my $fwcfgfn = "$tmpdir/qemu-server.fw";
        if (-f $fwcfgfn) {
            my $pve_firewall_dir = '/etc/pve/firewall';
            mkdir $pve_firewall_dir; # make sure the dir exists
            PVE::Tools::file_copy($fwcfgfn, "${pve_firewall_dir}/$vmid.fw");
        }

        $virtdev_hash = $parse_backup_hints->($rpcenv, $user, $cfg, $fh, $devinfo, $opts);

        foreach my $info (values %{$virtdev_hash}) {
            my $storeid = $info->{storeid};
            next if defined($storage_limits{$storeid});

            my $limit = PVE::Storage::get_bandwidth_limit('restore', [$storeid], $bwlimit) // 0;
            print STDERR "rate limit for storage $storeid: $limit KiB/s\n" if $limit;
            $storage_limits{$storeid} = $limit * 1024;
        }

        foreach my $devname (keys %$devinfo) {
            die "found no device mapping information for device '$devname'\n"
                if !$devinfo->{$devname}->{virtdev};
        }

        # create empty/temp config
        if ($oldconf) {
            PVE::Tools::file_set_contents($conffile, "memory: 128\n");
            $restore_cleanup_oldconf->($cfg, $vmid, $oldconf, $virtdev_hash);
        }

        # allocate volumes
        my $map = $restore_allocate_devices->($cfg, $virtdev_hash, $vmid);

        # print restore information to $fifofh
        foreach my $virtdev (sort keys %$virtdev_hash) {
            my $d = $virtdev_hash->{$virtdev};
            next if $d->{is_cloudinit}; # no need to restore cloudinit

            my $storeid = $d->{storeid};
            my $volid = $d->{volid};

            my $map_opts = '';
            if (my $limit = $storage_limits{$storeid}) {
                $map_opts .= "throttling.bps=$limit:throttling.group=$storeid:";
            }

            my $write_zeros = 1;
            if (PVE::Storage::volume_has_feature($cfg, 'sparseinit', $volid)) {
                $write_zeros = 0;
            }

            my $path = PVE::Storage::path($cfg, $volid);

            print $fifofh "${map_opts}format=$d->{format}:${write_zeros}:$d->{devname}=$path\n";

            print "map '$d->{devname}' to '$path' (write zeros = ${write_zeros})\n";
        }

        $fh->seek(0, 0) || die "seek failed - $!\n";

        my $cookie = { netcount => 0 };
        while (defined(my $line = <$fh>)) {
            $new_conf_raw .= restore_update_config_line(
                $cookie, $map, $line, $opts->{unique},
            );
        }

        $fh->close();
    };

    my $oldtimeout;

    eval {
        my $timeout_message = "got timeout preparing VMA restore\n";
        # enable interrupts
        local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
            local $SIG{PIPE} = sub { die "interrupted by signal\n"; };
        local $SIG{ALRM} = sub { die $timeout_message; };

        $oldtimeout = alarm(60); # for reading the VMA header - might hang with a corrupted one
        $timeout_message = "got timeout reading VMA header - corrupted?\n";

        my $parser = sub {
            my $line = shift;

            print "$line\n";

            if ($line =~ m/^DEV:\sdev_id=(\d+)\ssize:\s(\d+)\sdevname:\s(\S+)$/) {
                my ($dev_id, $size, $devname) = ($1, $2, $3);
                $devinfo->{$devname} = { size => $size, dev_id => $dev_id };
            } elsif ($line =~ m/^CTIME: /) {
                $timeout_message = "got timeout during VMA restore\n";
                # we correctly received the vma config, so we can disable
                # the timeout now for disk allocation
                alarm($oldtimeout || 0);
                $oldtimeout = undef;
                &$print_devmap();
                print $fifofh "done\n";
                close($fifofh);
                $fifofh = undef;
            }
        };

        print "restore vma archive: $dbg_cmdstring\n";
        run_command($commands, input => $input, outfunc => $parser, afterfork => $openfifo);
    };
    my $err = $@;

    alarm($oldtimeout) if $oldtimeout;

    $restore_deactivate_volumes->($cfg, $virtdev_hash);

    close($fifofh) if $fifofh;
    unlink $mapfifo;
    rmtree $tmpdir;

    if ($err) {
        $restore_destroy_volumes->($cfg, $virtdev_hash);
        die $err;
    }

    my $new_conf = restore_merge_config($conffile, $new_conf_raw, $opts->{override_conf});
    check_restore_permissions($rpcenv, $user, $new_conf);
    PVE::QemuConfig->write_config($vmid, $new_conf);

    eval { rescan($vmid, 1); };
    warn $@ if $@;

    PVE::AccessControl::add_vm_to_pool($vmid, $opts->{pool}) if $opts->{pool};
}

sub restore_tar_archive {
    my ($archive, $vmid, $user, $opts) = @_;

    if (scalar(keys $opts->{override_conf}->%*) > 0) {
        my $keystring = join(' ', keys $opts->{override_conf}->%*);
        die "cannot pass along options ($keystring) when restoring from tar archive\n";
    }

    if ($archive ne '-') {
        my $firstfile = tar_archive_read_firstfile($archive);
        die "ERROR: file '$archive' does not look like a QemuServer vzdump backup\n"
            if $firstfile ne 'qemu-server.conf';
    }

    my $storecfg = PVE::Storage::config();

    # avoid zombie disks when restoring over an existing VM -> cleanup first
    # pass keep_empty_config=1 to keep the config (thus VMID) reserved for us
    # skiplock=1 because qmrestore has set the 'create' lock itself already
    my $vmcfgfn = PVE::QemuConfig->config_file($vmid);
    destroy_vm($storecfg, $vmid, 1, { lock => 'restore' }) if -f $vmcfgfn;

    my $tocmd = "/usr/lib/qemu-server/qmextract";

    $tocmd .= " --storage " . PVE::Tools::shellquote($opts->{storage}) if $opts->{storage};
    $tocmd .= " --pool " . PVE::Tools::shellquote($opts->{pool}) if $opts->{pool};
    $tocmd .= ' --prealloc' if $opts->{prealloc};
    $tocmd .= ' --info' if $opts->{info};

    # tar option "xf" does not autodetect compression when read from STDIN,
    # so we pipe to zcat
    my $cmd =
        "zcat -f|tar xf "
        . PVE::Tools::shellquote($archive) . " "
        . PVE::Tools::shellquote("--to-command=$tocmd");

    my $tmpdir = "/var/tmp/vzdumptmp$$";
    mkpath $tmpdir;

    local $ENV{VZDUMP_TMPDIR} = $tmpdir;
    local $ENV{VZDUMP_VMID} = $vmid;
    local $ENV{VZDUMP_USER} = $user;

    my $conffile = PVE::QemuConfig->config_file($vmid);
    my $new_conf_raw = '';

    # disable interrupts (always do cleanups)
    local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
        sub { print STDERR "got interrupt - ignored\n"; };

    eval {
        # enable interrupts
        local $SIG{INT} = local $SIG{TERM} = local $SIG{QUIT} = local $SIG{HUP} =
            local $SIG{PIPE} = sub { die "interrupted by signal\n"; };

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
            while (defined(my $line = <$fd>)) {
                if ($line =~ m/vzdump:([^\s:]*):(\S+)$/) {
                    $map->{$1} = $2 if $1;
                } else {
                    print STDERR "unable to parse line in statfile - $line\n";
                }
            }
            $fd->close();
        }

        my $confsrc = "$tmpdir/qemu-server.conf";

        my $srcfd = IO::File->new($confsrc, "r") || die "unable to open file '$confsrc'\n";

        my $cookie = { netcount => 0 };
        while (defined(my $line = <$srcfd>)) {
            $new_conf_raw .= restore_update_config_line(
                $cookie, $map, $line, $opts->{unique},
            );
        }

        $srcfd->close();
    };
    if (my $err = $@) {
        tar_restore_cleanup($storecfg, "$tmpdir/qmrestore.stat") if !$opts->{info};
        die $err;
    }

    rmtree $tmpdir;

    PVE::Tools::file_set_contents($conffile, $new_conf_raw);

    PVE::Cluster::cfs_update(); # make sure we read new file

    eval { rescan($vmid, 1); };
    warn $@ if $@;
}

sub do_snapshots_type {
    my ($storecfg, $volid, $deviceid, $running) = @_;

    #always use storage snapshot for tpmstate
    return 'storage' if $deviceid && $deviceid =~ m/tpmstate0/;

    #we use storage snapshot if vm is not running or if disk is unused;
    return 'storage' if !$running || !$deviceid;

    if (my $method = PVE::Storage::volume_qemu_snapshot_method($storecfg, $volid)) {
        return 'internal' if $method eq 'qemu';
        return 'external' if $method eq 'mixed';
    }
    return 'storage';
}

=head3 template_create($vmid, $conf [, $disk])

Converts all used disk volumes for the VM with the identifier C<$vmid> and
configuration C<$conf> to base images (e.g. for VM templates).

If the optional C<$disk> parameter is set, it will only convert the disk
volume at the specified drive name (e.g. "scsi0").

=cut

sub template_create : prototype($$;$) {
    my ($vmid, $conf, $disk) = @_;

    my $storecfg = PVE::Storage::config();

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;

            return if drive_is_cdrom($drive);
            return if $disk && $ds ne $disk;

            my $volid = $drive->{file};
            return if !PVE::Storage::volume_has_feature($storecfg, 'template', $volid);

            my $voliddst = PVE::Storage::vdisk_create_base($storecfg, $volid);
            $drive->{file} = $voliddst;
            $conf->{$ds} = print_drive($drive);

            # write vm config on every change in case this fails on subsequent iterations
            PVE::QemuConfig->write_config($vmid, $conf);
        },
    );
}

# Check for bug #4525: drive-mirror will open the target drive with the same aio setting as the
# source, but some storages have problems with io_uring, sometimes even leading to crashes.
my sub clone_disk_check_io_uring {
    my ($vmid, $src_drive, $storecfg, $src_storeid, $dst_storeid, $use_drive_mirror) = @_;

    return if !$use_drive_mirror;

    # Don't complain when not changing storage.
    # Assume if it works for the source, it'll work for the target too.
    return if $src_storeid eq $dst_storeid;

    my $src_scfg = PVE::Storage::storage_config($storecfg, $src_storeid);
    my $dst_scfg = PVE::Storage::storage_config($storecfg, $dst_storeid);

    my $cache_direct = PVE::QemuServer::Drive::drive_uses_cache_direct($src_drive, $src_scfg);

    my $src_uses_io_uring;
    if ($src_drive->{aio}) {
        $src_uses_io_uring = $src_drive->{aio} eq 'io_uring';
    } else {
        # With the switch to -blockdev and blockdev-mirror, the aio setting will be changed on the
        # fly if not explicitly set.
        my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($vmid);
        return if PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 10, 0);

        $src_uses_io_uring = storage_allows_io_uring_default($src_scfg, $cache_direct);
    }

    die "target storage is known to cause issues with aio=io_uring (used by current drive)\n"
        if $src_uses_io_uring && !storage_allows_io_uring_default($dst_scfg, $cache_direct);
}

sub clone_disk {
    my ($storecfg, $source, $dest, $full, $newvollist, $jobs, $completion, $qga, $bwlimit) = @_;

    my ($vmid, $running) = $source->@{qw(vmid running)};
    my ($src_drivename, $drive, $snapname) = $source->@{qw(drivename drive snapname)};

    my ($newvmid, $dst_drivename, $efisize) = $dest->@{qw(vmid drivename efisize)};
    my ($storage, $format) = $dest->@{qw(storage format)};

    my $unused = defined($src_drivename) && $src_drivename =~ /^unused/;
    my $use_drive_mirror = $full && $running && $src_drivename && !$snapname && !$unused;

    if ($src_drivename && $dst_drivename && $src_drivename ne $dst_drivename) {
        die "cloning from/to EFI disk requires EFI disk\n"
            if $src_drivename eq 'efidisk0' || $dst_drivename eq 'efidisk0';
        die "cloning from/to TPM state requires TPM state\n"
            if $src_drivename eq 'tpmstate0' || $dst_drivename eq 'tpmstate0';

        # This would lead to two device nodes in QEMU pointing to the same backing image!
        die "cannot change drive name when cloning disk from/to the same VM\n"
            if $use_drive_mirror && $vmid == $newvmid;
    }

    die "cannot move TPM state while VM is running\n"
        if $use_drive_mirror && $src_drivename eq 'tpmstate0';

    my $newvolid;

    print "create " . ($full ? 'full' : 'linked') . " clone of drive ";
    print "$src_drivename " if $src_drivename;
    print "($drive->{file})\n";

    if (!$full) {
        $newvolid = PVE::Storage::vdisk_clone($storecfg, $drive->{file}, $newvmid, $snapname);
        push @$newvollist, $newvolid;
    } else {
        my ($src_storeid) = PVE::Storage::parse_volume_id($drive->{file});
        my $storeid = $storage || $src_storeid;

        my $dst_format = resolve_dst_disk_format($storecfg, $storeid, $drive->{file}, $format);

        my $name = undef;
        my $size = undef;
        if (drive_is_cloudinit($drive)) {
            $name = "vm-$newvmid-cloudinit";
            my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
            if ($scfg->{path}) {
                $name .= ".$dst_format";
            }
            $snapname = undef;
            $size = PVE::QemuServer::Cloudinit::CLOUDINIT_DISK_SIZE;
        } elsif ($dst_drivename eq 'efidisk0') {
            $size = $efisize or die "internal error - need to specify EFI disk size\n";
        } elsif ($dst_drivename eq 'tpmstate0') {
            $dst_format = 'raw';
            $size = PVE::QemuServer::Drive::TPMSTATE_DISK_SIZE;
        } else {
            clone_disk_check_io_uring(
                $vmid, $drive, $storecfg, $src_storeid, $storeid, $use_drive_mirror,
            );

            $size = PVE::Storage::volume_size_info($storecfg, $drive->{file}, 10);
        }
        $newvolid = PVE::Storage::vdisk_alloc(
            $storecfg,
            $storeid,
            $newvmid,
            $dst_format,
            $name,
            ($size / 1024),
        );
        push @$newvollist, $newvolid;

        PVE::Storage::activate_volumes($storecfg, [$newvolid]);

        if (drive_is_cloudinit($drive)) {
            # when cloning multiple disks (e.g. during clone_vm) it might be the last disk
            # if this is the case, we have to complete any block-jobs still there from
            # previous drive-mirrors
            if (($completion && $completion eq 'complete') && (scalar(keys %$jobs) > 0)) {
                PVE::QemuServer::BlockJob::qemu_drive_mirror_monitor(
                    $vmid, $newvmid, $jobs, $completion, $qga,
                );
            }
            goto no_data_clone;
        }

        my $sparseinit = PVE::Storage::volume_has_feature($storecfg, 'sparseinit', $newvolid);
        if ($use_drive_mirror) {
            my $source_info = { vmid => $vmid, drive => $drive };
            my $dest_info = { volid => $newvolid };
            $dest_info->{'zero-initialized'} = 1 if $sparseinit;
            $dest_info->{vmid} = $newvmid if defined($newvmid);
            my $mirror_opts = {};
            $mirror_opts->{'guest-agent'} = 1 if $qga;
            $mirror_opts->{bwlimit} = $bwlimit if defined($bwlimit);
            PVE::QemuServer::BlockJob::mirror(
                $source_info,
                $dest_info,
                $jobs,
                $completion,
                $mirror_opts,
            );
        } else {
            if ($dst_drivename eq 'efidisk0') {
                # the relevant data on the efidisk may be smaller than the source
                # e.g. on RBD/ZFS, so we use dd to copy only the amount
                # that is given by the OVMF_VARS.fd
                my $src_path = PVE::Storage::path($storecfg, $drive->{file}, $snapname);
                my $dst_path = PVE::Storage::path($storecfg, $newvolid);

                my $src_format = (PVE::Storage::parse_volname($storecfg, $drive->{file}))[6];

                # better for Ceph if block size is not too small, see bug #3324
                my $bs = 1024 * 1024;

                my $cmd = ['qemu-img', 'dd', '-n', '-f', $src_format, '-O', $dst_format];

                if ($src_format eq 'qcow2' && $snapname) {
                    die "cannot clone qcow2 EFI disk snapshot - requires QEMU >= 6.2\n"
                        if !min_version(kvm_user_version(), 6, 2);
                    push $cmd->@*, '-l', $snapname;
                }
                push $cmd->@*, "bs=$bs", "osize=$size", "if=$src_path", "of=$dst_path";
                run_command($cmd);
            } else {
                my $opts = {
                    bwlimit => $bwlimit,
                    'is-zero-initialized' => $sparseinit,
                    snapname => $snapname,
                };
                PVE::QemuServer::QemuImage::convert($drive->{file}, $newvolid, $size, $opts);
            }
        }
    }

no_data_clone:
    my $size = eval { PVE::Storage::volume_size_info($storecfg, $newvolid, 10) };

    my $disk = dclone($drive);
    delete $disk->{format};
    $disk->{file} = $newvolid;
    $disk->{size} = $size if defined($size) && !$unused;

    return $disk;
}

sub get_running_qemu_version {
    my ($vmid) = @_;
    my $res = mon_cmd($vmid, "query-version");
    return "$res->{qemu}->{major}.$res->{qemu}->{minor}";
}

sub qemu_use_old_bios_files {
    my ($machine_type) = @_;

    return if !$machine_type;

    my $use_old_bios_files = undef;

    if ($machine_type =~ m/^(\S+)\.pxe$/) {
        $machine_type = $1;
        $use_old_bios_files = 1;
    } else {
        my $version = extract_version($machine_type, kvm_user_version());
        # Note: kvm version < 2.4 use non-efi pxe files, and have problems when we
        # load new efi bios files on migration. So this hack is required to allow
        # live migration from qemu-2.2 to qemu-2.4, which is sometimes used when
        # updrading from proxmox-ve-3.X to proxmox-ve 4.0
        $use_old_bios_files = !min_version($version, 2, 4);
    }

    return ($use_old_bios_files, $machine_type);
}

sub get_efivars_size {
    my ($conf, $efidisk) = @_;

    my $arch = PVE::QemuServer::Helpers::get_vm_arch($conf);
    $efidisk //= $conf->{efidisk0} ? parse_drive('efidisk0', $conf->{efidisk0}) : undef;
    my $smm = PVE::QemuServer::Machine::machine_type_is_q35($conf);
    my $amd_sev_type = get_amd_sev_type($conf);

    return PVE::QemuServer::OVMF::get_efivars_size($arch, $efidisk, $smm, $amd_sev_type);
}

sub update_efidisk_size {
    my ($conf) = @_;

    return if !defined($conf->{efidisk0});

    my $disk = PVE::QemuServer::parse_drive('efidisk0', $conf->{efidisk0});
    $disk->{size} = get_efivars_size($conf);
    $conf->{efidisk0} = print_drive($disk);

    return;
}

sub update_tpmstate_size {
    my ($conf) = @_;

    my $disk = PVE::QemuServer::parse_drive('tpmstate0', $conf->{tpmstate0});
    $disk->{size} = PVE::QemuServer::Drive::TPMSTATE_DISK_SIZE;
    $conf->{tpmstate0} = print_drive($disk);
}

sub vm_iothreads_list {
    my ($vmid) = @_;

    my $res = mon_cmd($vmid, 'query-iothreads');

    my $iothreads = {};
    foreach my $iothread (@$res) {
        $iothreads->{ $iothread->{id} } = $iothread->{"thread-id"};
    }

    return $iothreads;
}

sub scsihw_infos {
    my ($conf, $drive) = @_;

    my $maxdev = 0;

    if (!$conf->{scsihw} || ($conf->{scsihw} =~ m/^lsi/)) {
        $maxdev = 7;
    } elsif ($conf->{scsihw} && ($conf->{scsihw} eq 'virtio-scsi-single')) {
        $maxdev = 1;
    } else {
        $maxdev = 256;
    }

    my $controller = int($drive->{index} / $maxdev);
    my $controller_prefix =
        ($conf->{scsihw} && $conf->{scsihw} eq 'virtio-scsi-single')
        ? "virtioscsi"
        : "scsihw";

    return ($maxdev, $controller, $controller_prefix);
}

sub resolve_dst_disk_format {
    my ($storecfg, $storeid, $src_volid, $format) = @_;

    # if no target format is specified, use the source disk format as hint
    if (!$format && $src_volid) {
        $format = checked_volume_format($storecfg, $src_volid);
    }

    # falls back to default format if requested format is not supported
    return PVE::Storage::resolve_format_hint($storecfg, $storeid, $format);
}

sub generate_uuid {
    my ($uuid, $uuid_str);
    UUID::generate($uuid);
    UUID::unparse($uuid, $uuid_str);
    return $uuid_str;
}

sub generate_smbios1_uuid {
    return "uuid=" . generate_uuid();
}

sub create_reboot_request {
    my ($vmid) = @_;
    open(my $fh, '>', "/run/qemu-server/$vmid.reboot")
        or die "failed to create reboot trigger file: $!\n";
    close($fh);
}

sub clear_reboot_request {
    my ($vmid) = @_;
    my $path = "/run/qemu-server/$vmid.reboot";
    my $res = 0;

    $res = unlink($path);
    die "could not remove reboot request for $vmid: $!"
        if !$res && $! != POSIX::ENOENT;

    return $res;
}

sub bootorder_from_legacy {
    my ($conf, $bootcfg) = @_;

    my $boot = $bootcfg->{legacy} || $boot_fmt->{legacy}->{default};
    my $bootindex_hash = {};
    my $i = 1;
    foreach my $o (split(//, $boot)) {
        $bootindex_hash->{$o} = $i * 100;
        $i++;
    }

    my $bootorder = {};

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($ds, $drive) = @_;

            if (drive_is_cdrom($drive, 1)) {
                if ($bootindex_hash->{d}) {
                    $bootorder->{$ds} = $bootindex_hash->{d};
                    $bootindex_hash->{d} += 1;
                }
            } elsif ($bootindex_hash->{c}) {
                $bootorder->{$ds} = $bootindex_hash->{c}
                    if $conf->{bootdisk} && $conf->{bootdisk} eq $ds;
                $bootindex_hash->{c} += 1;
            }
        },
    );

    if ($bootindex_hash->{n}) {
        for (my $i = 0; $i < $MAX_NETS; $i++) {
            my $netname = "net$i";
            next if !$conf->{$netname};
            $bootorder->{$netname} = $bootindex_hash->{n};
            $bootindex_hash->{n} += 1;
        }
    }

    return $bootorder;
}

# Generate default device list for 'boot: order=' property. Matches legacy
# default boot order, but with explicit device names. This is important, since
# the fallback for when neither 'order' nor the old format is specified relies
# on 'bootorder_from_legacy' above, and it would be confusing if this diverges.
sub get_default_bootdevices {
    my ($conf) = @_;

    my @ret = ();

    # harddisk
    my $first = PVE::QemuServer::Drive::resolve_first_disk($conf, 0);
    push @ret, $first if $first;

    # cdrom
    $first = PVE::QemuServer::Drive::resolve_first_disk($conf, 1);
    push @ret, $first if $first;

    # network
    for (my $i = 0; $i < $MAX_NETS; $i++) {
        my $netname = "net$i";
        next if !$conf->{$netname};
        push @ret, $netname;
        last;
    }

    return \@ret;
}

sub device_bootorder {
    my ($conf) = @_;

    return bootorder_from_legacy($conf) if !defined($conf->{boot});

    my $boot = parse_property_string($boot_fmt, $conf->{boot});

    my $bootorder = {};
    if (!defined($boot) || $boot->{legacy}) {
        $bootorder = bootorder_from_legacy($conf, $boot);
    } elsif ($boot->{order}) {
        my $i = 100; # start at 100 to allow user to insert devices before us with -args
        for my $dev (PVE::Tools::split_list($boot->{order})) {
            $bootorder->{$dev} = $i++;
        }
    }

    return $bootorder;
}

sub register_qmeventd_handle {
    my ($vmid) = @_;

    my $fh;
    my $peer = "/var/run/qmeventd.sock";
    my $count = 0;

    for (;;) {
        $count++;
        $fh = IO::Socket::UNIX->new(Peer => $peer, Blocking => 0, Timeout => 1);
        last if $fh;
        if ($! != EINTR && $! != EAGAIN) {
            die "unable to connect to qmeventd socket (vmid: $vmid) - $!\n";
        }
        if ($count > 4) {
            die "unable to connect to qmeventd socket (vmid: $vmid) - timeout "
                . "after $count retries\n";
        }
        usleep(25000);
    }

    # send handshake to mark VM as backing up
    print $fh to_json({ vzdump => { vmid => "$vmid" } });

    # return handle to be closed later when inhibit is no longer required
    return $fh;
}

# bash completion helper

sub complete_backup_archives {
    my ($cmdname, $pname, $cvalue) = @_;

    my $cfg = PVE::Storage::config();

    my $storeid;

    if ($cvalue =~ m/^([^:]+):/) {
        $storeid = $1;
    }

    my $data = PVE::Storage::template_list($cfg, $storeid, 'backup');

    my $res = [];
    foreach my $id (keys %$data) {
        foreach my $item (@{ $data->{$id} }) {
            next if ($item->{subtype} // '') ne 'qemu';
            push @$res, $item->{volid} if defined($item->{volid});
        }
    }

    return $res;
}

my $complete_vmid_full = sub {
    my ($running) = @_;

    my $idlist = vmstatus();

    my $res = [];

    foreach my $id (keys %$idlist) {
        my $d = $idlist->{$id};
        if (defined($running)) {
            next if $d->{template};
            next if $running && $d->{status} ne 'running';
            next if !$running && $d->{status} eq 'running';
        }
        push @$res, $id;

    }
    return $res;
};

sub complete_vmid {
    return &$complete_vmid_full();
}

sub complete_vmid_stopped {
    return &$complete_vmid_full(0);
}

sub complete_vmid_running {
    return &$complete_vmid_full(1);
}

sub complete_storage {

    my $cfg = PVE::Storage::config();
    my $ids = $cfg->{ids};

    my $res = [];
    foreach my $sid (keys %$ids) {
        next if !PVE::Storage::storage_check_enabled($cfg, $sid, undef, 1);
        next if !$ids->{$sid}->{content}->{images};
        push @$res, $sid;
    }

    return $res;
}

sub complete_migration_storage {
    my ($cmd, $param, $current_value, $all_args) = @_;

    my $targetnode = @$all_args[1];

    my $cfg = PVE::Storage::config();
    my $ids = $cfg->{ids};

    my $res = [];
    foreach my $sid (keys %$ids) {
        next if !PVE::Storage::storage_check_enabled($cfg, $sid, $targetnode, 1);
        next if !$ids->{$sid}->{content}->{images};
        push @$res, $sid;
    }

    return $res;
}

sub vm_is_paused {
    my ($vmid, $include_suspended) = @_;
    my $qmpstatus = eval {
        PVE::QemuConfig::assert_config_exists_on_node($vmid);
        mon_cmd($vmid, "query-status");
    };
    warn "$@\n" if $@;
    return $qmpstatus
        && ($qmpstatus->{status} eq "paused"
            || $qmpstatus->{status} eq "prelaunch"
            || ($include_suspended && $qmpstatus->{status} eq "suspended"));
}

sub check_volume_storage_type {
    my ($storecfg, $vol) = @_;

    my ($storeid, $volname) = PVE::Storage::parse_volume_id($vol);
    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
    my ($vtype) = PVE::Storage::parse_volname($storecfg, $vol);

    die "storage '$storeid' does not support content-type '$vtype'\n"
        if !$scfg->{content}->{$vtype};

    return 1;
}

1;
