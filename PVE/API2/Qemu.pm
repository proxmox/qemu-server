package PVE::API2::Qemu;

use strict;
use warnings;
use Cwd 'abs_path';
use Net::SSLeay;
use POSIX;
use IO::Socket::IP;
use URI::Escape;
use Crypt::OpenSSL::Random;

use PVE::Cluster qw (cfs_read_file cfs_write_file);;
use PVE::RRD;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::Storage;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::ReplicationConfig;
use PVE::GuestHelpers;
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Drive;
use PVE::QemuServer::CPUConfig;
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::Machine;
use PVE::QemuMigrate;
use PVE::RPCEnvironment;
use PVE::AccessControl;
use PVE::INotify;
use PVE::Network;
use PVE::Firewall;
use PVE::API2::Firewall::VM;
use PVE::API2::Qemu::Agent;
use PVE::VZDump::Plugin;
use PVE::DataCenterConfig;
use PVE::SSHInfo;
use PVE::Replication;

BEGIN {
    if (!$ENV{PVE_GENERATING_DOCS}) {
	require PVE::HA::Env::PVE2;
	import PVE::HA::Env::PVE2;
	require PVE::HA::Config;
	import PVE::HA::Config;
    }
}

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

my $opt_force_description = "Force physical removal. Without this, we simple remove the disk from the config file and create an additional configuration entry called 'unused[n]', which contains the volume ID. Unlink of unused[n] always cause physical removal.";

my $resolve_cdrom_alias = sub {
    my $param = shift;

    if (my $value = $param->{cdrom}) {
	$value .= ",media=cdrom" if $value !~ m/media=/;
	$param->{ide2} = $value;
	delete $param->{cdrom};
    }
};

my $NEW_DISK_RE = qr!^(([^/:\s]+):)?(\d+(\.\d+)?)$!;
my $check_storage_access = sub {
   my ($rpcenv, $authuser, $storecfg, $vmid, $settings, $default_storage) = @_;

   PVE::QemuConfig->foreach_volume($settings, sub {
	my ($ds, $drive) = @_;

	my $isCDROM = PVE::QemuServer::drive_is_cdrom($drive);

	my $volid = $drive->{file};
	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	if (!$volid || ($volid eq 'none' || $volid eq 'cloudinit' || (defined($volname) && $volname eq 'cloudinit'))) {
	    # nothing to check
	} elsif ($isCDROM && ($volid eq 'cdrom')) {
	    $rpcenv->check($authuser, "/", ['Sys.Console']);
	} elsif (!$isCDROM && ($volid =~ $NEW_DISK_RE)) {
	    my ($storeid, $size) = ($2 || $default_storage, $3);
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);
	    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	    raise_param_exc({ storage => "storage '$storeid' does not support vm images"})
		if !$scfg->{content}->{images};
	} else {
	    PVE::Storage::check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $volid);
	}
    });

   $rpcenv->check($authuser, "/storage/$settings->{vmstatestorage}", ['Datastore.AllocateSpace'])
       if defined($settings->{vmstatestorage});
};

my $check_storage_access_clone = sub {
   my ($rpcenv, $authuser, $storecfg, $conf, $storage) = @_;

   my $sharedvm = 1;

   PVE::QemuConfig->foreach_volume($conf, sub {
	my ($ds, $drive) = @_;

	my $isCDROM = PVE::QemuServer::drive_is_cdrom($drive);

	my $volid = $drive->{file};

	return if !$volid || $volid eq 'none';

	if ($isCDROM) {
	    if ($volid eq 'cdrom') {
		$rpcenv->check($authuser, "/", ['Sys.Console']);
	    } else {
		# we simply allow access
		my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
		my $scfg = PVE::Storage::storage_config($storecfg, $sid);
		$sharedvm = 0 if !$scfg->{shared};

	    }
	} else {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    my $scfg = PVE::Storage::storage_config($storecfg, $sid);
	    $sharedvm = 0 if !$scfg->{shared};

	    $sid = $storage if $storage;
	    $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);
	}
    });

   $rpcenv->check($authuser, "/storage/$conf->{vmstatestorage}", ['Datastore.AllocateSpace'])
       if defined($conf->{vmstatestorage});

   return $sharedvm;
};

my $check_storage_access_migrate = sub {
    my ($rpcenv, $authuser, $storecfg, $storage, $node) = @_;

    PVE::Storage::storage_check_enabled($storecfg, $storage, $node);

    $rpcenv->check($authuser, "/storage/$storage", ['Datastore.AllocateSpace']);

    my $scfg = PVE::Storage::storage_config($storecfg, $storage);
    die "storage '$storage' does not support vm images\n"
	if !$scfg->{content}->{images};
};

# Note: $pool is only needed when creating a VM, because pool permissions
# are automatically inherited if VM already exists inside a pool.
my $create_disks = sub {
    my ($rpcenv, $authuser, $conf, $arch, $storecfg, $vmid, $pool, $settings, $default_storage) = @_;

    my $vollist = [];

    my $res = {};

    my $code = sub {
	my ($ds, $disk) = @_;

	my $volid = $disk->{file};
	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	if (!$volid || $volid eq 'none' || $volid eq 'cdrom') {
	    delete $disk->{size};
	    $res->{$ds} = PVE::QemuServer::print_drive($disk);
	} elsif (defined($volname) && $volname eq 'cloudinit') {
	    $storeid = $storeid // $default_storage;
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	    my $name = "vm-$vmid-cloudinit";

	    my $fmt = undef;
	    if ($scfg->{path}) {
		$fmt = $disk->{format} // "qcow2";
		$name .= ".$fmt";
	    } else {
		$fmt = $disk->{format} // "raw";
	    }

	    # Initial disk created with 4 MB and aligned to 4MB on regeneration
	    my $ci_size = PVE::QemuServer::Cloudinit::CLOUDINIT_DISK_SIZE;
	    my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $fmt, $name, $ci_size/1024);
	    $disk->{file} = $volid;
	    $disk->{media} = 'cdrom';
	    push @$vollist, $volid;
	    delete $disk->{format}; # no longer needed
	    $res->{$ds} = PVE::QemuServer::print_drive($disk);
	} elsif ($volid =~ $NEW_DISK_RE) {
	    my ($storeid, $size) = ($2 || $default_storage, $3);
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    my $defformat = PVE::Storage::storage_default_format($storecfg, $storeid);
	    my $fmt = $disk->{format} || $defformat;

	    $size = PVE::Tools::convert_size($size, 'gb' => 'kb'); # vdisk_alloc uses kb

	    my $volid;
	    if ($ds eq 'efidisk0') {
		my $smm = PVE::QemuServer::Machine::machine_type_is_q35($conf);
		($volid, $size) = PVE::QemuServer::create_efidisk(
		    $storecfg, $storeid, $vmid, $fmt, $arch, $disk, $smm);
	    } elsif ($ds eq 'tpmstate0') {
		# swtpm can only use raw volumes, and uses a fixed size
		$size = PVE::Tools::convert_size(PVE::QemuServer::Drive::TPMSTATE_DISK_SIZE, 'b' => 'kb');
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, "raw", undef, $size);
	    } else {
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $fmt, undef, $size);
	    }
	    push @$vollist, $volid;
	    $disk->{file} = $volid;
	    $disk->{size} = PVE::Tools::convert_size($size, 'kb' => 'b');
	    delete $disk->{format}; # no longer needed
	    $res->{$ds} = PVE::QemuServer::print_drive($disk);
	} else {

	    PVE::Storage::check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $volid);

	    my $volid_is_new = 1;

	    if ($conf->{$ds}) {
		my $olddrive = PVE::QemuServer::parse_drive($ds, $conf->{$ds});
		$volid_is_new = undef if $olddrive->{file} && $olddrive->{file} eq $volid;
	    }

	    if ($volid_is_new) {

		PVE::Storage::activate_volumes($storecfg, [ $volid ]) if $storeid;

		my $size = PVE::Storage::volume_size_info($storecfg, $volid);

		die "volume $volid does not exist\n" if !$size;

		$disk->{size} = $size;
	    }

	    $res->{$ds} = PVE::QemuServer::print_drive($disk);
	}
    };

    eval { PVE::QemuConfig->foreach_volume($settings, $code); };

    # free allocated images on error
    if (my $err = $@) {
	syslog('err', "VM $vmid creating disks failed");
	foreach my $volid (@$vollist) {
	    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	    warn $@ if $@;
	}
	die $err;
    }

    # modify vm config if everything went well
    foreach my $ds (keys %$res) {
	$conf->{$ds} = $res->{$ds};
    }

    return $vollist;
};

my $check_cpu_model_access = sub {
    my ($rpcenv, $authuser, $new, $existing) = @_;

    return if !defined($new->{cpu});

    my $cpu = PVE::JSONSchema::check_format('pve-vm-cpu-conf', $new->{cpu});
    return if !$cpu || !$cpu->{cputype}; # always allow default
    my $cputype = $cpu->{cputype};

    if ($existing && $existing->{cpu}) {
	# changing only other settings doesn't require permissions for CPU model
	my $existingCpu = PVE::JSONSchema::check_format('pve-vm-cpu-conf', $existing->{cpu});
	return if $existingCpu->{cputype} eq $cputype;
    }

    if (PVE::QemuServer::CPUConfig::is_custom_model($cputype)) {
	$rpcenv->check($authuser, "/nodes", ['Sys.Audit']);
    }
};

my $cpuoptions = {
    'cores' => 1,
    'cpu' => 1,
    'cpulimit' => 1,
    'cpuunits' => 1,
    'numa' => 1,
    'smp' => 1,
    'sockets' => 1,
    'vcpus' => 1,
};

my $memoryoptions = {
    'memory' => 1,
    'balloon' => 1,
    'shares' => 1,
};

my $hwtypeoptions = {
    'acpi' => 1,
    'hotplug' => 1,
    'kvm' => 1,
    'machine' => 1,
    'scsihw' => 1,
    'smbios1' => 1,
    'tablet' => 1,
    'vga' => 1,
    'watchdog' => 1,
    'audio0' => 1,
};

my $generaloptions = {
    'agent' => 1,
    'autostart' => 1,
    'bios' => 1,
    'description' => 1,
    'keyboard' => 1,
    'localtime' => 1,
    'migrate_downtime' => 1,
    'migrate_speed' => 1,
    'name' => 1,
    'onboot' => 1,
    'ostype' => 1,
    'protection' => 1,
    'reboot' => 1,
    'startdate' => 1,
    'startup' => 1,
    'tdf' => 1,
    'template' => 1,
    'tags' => 1,
};

my $vmpoweroptions = {
    'freeze' => 1,
};

my $diskoptions = {
    'boot' => 1,
    'bootdisk' => 1,
    'vmstatestorage' => 1,
};

my $cloudinitoptions = {
    cicustom => 1,
    cipassword => 1,
    citype => 1,
    ciuser => 1,
    nameserver => 1,
    searchdomain => 1,
    sshkeys => 1,
};

my $check_vm_create_serial_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $param) = @_;

    return 1 if $authuser eq 'root@pam';

    foreach my $opt (keys %{$param}) {
	next if $opt !~ m/^serial\d+$/;

	if ($param->{$opt} eq 'socket') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.HWType']);
	} else {
	    die "only root can set '$opt' config for real devices\n";
	}
    }

    return 1;
};

my $check_vm_create_usb_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $param) = @_;

    return 1 if $authuser eq 'root@pam';

    foreach my $opt (keys %{$param}) {
	next if $opt !~ m/^usb\d+$/;

	if ($param->{$opt} =~ m/spice/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.HWType']);
	} else {
	    die "only root can set '$opt' config for real devices\n";
	}
    }

    return 1;
};

my $check_vm_modify_config_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $key_list) = @_;

    return 1 if $authuser eq 'root@pam';

    foreach my $opt (@$key_list) {
	# some checks (e.g., disk, serial port, usb) need to be done somewhere
	# else, as there the permission can be value dependend
	next if PVE::QemuServer::is_valid_drivename($opt);
	next if $opt eq 'cdrom';
	next if $opt =~ m/^(?:unused|serial|usb)\d+$/;


	if ($cpuoptions->{$opt} || $opt =~ m/^numa\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($memoryoptions->{$opt}) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($hwtypeoptions->{$opt}) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.HWType']);
	} elsif ($generaloptions->{$opt}) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Options']);
	    # special case for startup since it changes host behaviour
	    if ($opt eq 'startup') {
		$rpcenv->check_full($authuser, "/", ['Sys.Modify']);
	    }
	} elsif ($vmpoweroptions->{$opt}) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.PowerMgmt']);
	} elsif ($diskoptions->{$opt}) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	} elsif ($opt =~ m/^(?:net|ipconfig)\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	} elsif ($cloudinitoptions->{$opt}) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Cloudinit', 'VM.Config.Network'], 1);
	} elsif ($opt eq 'vmstate') {
	    # the user needs Disk and PowerMgmt privileges to change the vmstate
	    # also needs privileges on the storage, that will be checked later
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk', 'VM.PowerMgmt' ]);
	} else {
	    # catches hostpci\d+, args, lock, etc.
	    # new options will be checked here
	    die "only root can set '$opt' config\n";
	}
    }

    return 1;
};

__PACKAGE__->register_method({
    name => 'vmlist',
    path => '',
    method => 'GET',
    description => "Virtual machine index (per node).",
    permissions => {
	description => "Only list VMs where you have VM.Audit permissons on /vms/<vmid>.",
	user => 'all',
    },
    proxyto => 'node',
    protected => 1, # qemu pid files are only readable by root
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    full => {
		type => 'boolean',
		optional => 1,
		description => "Determine the full status of active VMs.",
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => $PVE::QemuServer::vmstatus_return_properties,
	},
	links => [ { rel => 'child', href => "{vmid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $vmstatus = PVE::QemuServer::vmstatus(undef, $param->{full});

	my $res = [];
	foreach my $vmid (keys %$vmstatus) {
	    next if !$rpcenv->check($authuser, "/vms/$vmid", [ 'VM.Audit' ], 1);

	    my $data = $vmstatus->{$vmid};
	    push @$res, $data;
	}

	return $res;
    }});

my $parse_restore_archive = sub {
    my ($storecfg, $archive) = @_;

    my ($archive_storeid, $archive_volname) = PVE::Storage::parse_volume_id($archive, 1);

    if (defined($archive_storeid)) {
	my $scfg =  PVE::Storage::storage_config($storecfg, $archive_storeid);
	if ($scfg->{type} eq 'pbs') {
	    return {
		type => 'pbs',
		volid => $archive,
	    };
	}
    }
    my $path = PVE::Storage::abs_filesystem_path($storecfg, $archive);
    return {
	type => 'file',
	path => $path,
    };
};


__PACKAGE__->register_method({
    name => 'create_vm',
    path => '',
    method => 'POST',
    description => "Create or restore a virtual machine.",
    permissions => {
	description => "You need 'VM.Allocate' permissions on /vms/{vmid} or on the VM pool /pool/{pool}. " .
	    "For restore (option 'archive'), it is enough if the user has 'VM.Backup' permission and the VM already exists. " .
	    "If you create disks you need 'Datastore.AllocateSpace' on any used storage.",
        user => 'all', # check inside
    },
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => PVE::QemuServer::json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid', { completion => \&PVE::Cluster::complete_next_vmid }),
		archive => {
		    description => "The backup archive. Either the file system path to a .tar or .vma file (use '-' to pipe data from stdin) or a proxmox storage backup volume identifier.",
		    type => 'string',
		    optional => 1,
		    maxLength => 255,
		    completion => \&PVE::QemuServer::complete_backup_archives,
		},
		storage => get_standard_option('pve-storage-id', {
		    description => "Default storage.",
		    optional => 1,
		    completion => \&PVE::QemuServer::complete_storage,
		}),
		force => {
		    optional => 1,
		    type => 'boolean',
		    description => "Allow to overwrite existing VM.",
		    requires => 'archive',
		},
		unique => {
		    optional => 1,
		    type => 'boolean',
		    description => "Assign a unique random ethernet address.",
		    requires => 'archive',
		},
		'live-restore' => {
		    optional => 1,
		    type => 'boolean',
		    description => "Start the VM immediately from the backup and restore in background. PBS only.",
		    requires => 'archive',
		},
		pool => {
		    optional => 1,
		    type => 'string', format => 'pve-poolid',
		    description => "Add the VM to the specified pool.",
		},
		bwlimit => {
		    description => "Override I/O bandwidth limit (in KiB/s).",
		    optional => 1,
		    type => 'integer',
		    minimum => '0',
		    default => 'restore limit from datacenter or storage config',
		},
		start => {
		    optional => 1,
		    type => 'boolean',
		    default => 0,
		    description => "Start VM after it was created successfully.",
		},
	    }),
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');

	my $archive = extract_param($param, 'archive');
	my $is_restore = !!$archive;

	my $bwlimit = extract_param($param, 'bwlimit');
	my $force = extract_param($param, 'force');
	my $pool = extract_param($param, 'pool');
	my $start_after_create = extract_param($param, 'start');
	my $storage = extract_param($param, 'storage');
	my $unique = extract_param($param, 'unique');
	my $live_restore = extract_param($param, 'live-restore');

	if (defined(my $ssh_keys = $param->{sshkeys})) {
		$ssh_keys = URI::Escape::uri_unescape($ssh_keys);
		PVE::Tools::validate_ssh_public_keys($ssh_keys);
	}

	PVE::Cluster::check_cfs_quorum();

	my $filename = PVE::QemuConfig->config_file($vmid);
	my $storecfg = PVE::Storage::config();

	if (defined($pool)) {
	    $rpcenv->check_pool_exist($pool);
	}

	$rpcenv->check($authuser, "/storage/$storage", ['Datastore.AllocateSpace'])
	    if defined($storage);

	if ($rpcenv->check($authuser, "/vms/$vmid", ['VM.Allocate'], 1)) {
	    # OK
	} elsif ($pool && $rpcenv->check($authuser, "/pool/$pool", ['VM.Allocate'], 1)) {
	    # OK
	} elsif ($archive && $force && (-f $filename) &&
		 $rpcenv->check($authuser, "/vms/$vmid", ['VM.Backup'], 1)) {
	    # OK: user has VM.Backup permissions, and want to restore an existing VM
	} else {
	    raise_perm_exc();
	}

	if (!$archive) {
	    &$resolve_cdrom_alias($param);

	    &$check_storage_access($rpcenv, $authuser, $storecfg, $vmid, $param, $storage);

	    &$check_vm_modify_config_perm($rpcenv, $authuser, $vmid, $pool, [ keys %$param]);

	    &$check_vm_create_serial_perm($rpcenv, $authuser, $vmid, $pool, $param);
	    &$check_vm_create_usb_perm($rpcenv, $authuser, $vmid, $pool, $param);

	    &$check_cpu_model_access($rpcenv, $authuser, $param);

	    foreach my $opt (keys %$param) {
		if (PVE::QemuServer::is_valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
		    raise_param_exc({ $opt => "unable to parse drive options" }) if !$drive;

		    PVE::QemuServer::cleanup_drive_path($opt, $storecfg, $drive);
		    $param->{$opt} = PVE::QemuServer::print_drive($drive);
		}
	    }

	    PVE::QemuServer::add_random_macs($param);
	} else {
	    my $keystr = join(' ', keys %$param);
	    raise_param_exc({ archive => "option conflicts with other options ($keystr)"}) if $keystr;

	    if ($archive eq '-') {
		die "pipe requires cli environment\n" if $rpcenv->{type} ne 'cli';
		$archive = { type => 'pipe' };
	    } else {
		PVE::Storage::check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $archive);

		$archive = $parse_restore_archive->($storecfg, $archive);
	    }
	}

	my $emsg = $is_restore ? "unable to restore VM $vmid -" : "unable to create VM $vmid -";

	eval { PVE::QemuConfig->create_and_lock_config($vmid, $force) };
	die "$emsg $@" if $@;

	my $restored_data = 0;
	my $restorefn = sub {
	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_protection($conf, $emsg);

	    die "$emsg vm is running\n" if PVE::QemuServer::check_running($vmid);

	    my $realcmd = sub {
		my $restore_options = {
		    storage => $storage,
		    pool => $pool,
		    unique => $unique,
		    bwlimit => $bwlimit,
		    live => $live_restore,
		};
		if ($archive->{type} eq 'file' || $archive->{type} eq 'pipe') {
		    die "live-restore is only compatible with backup images from a Proxmox Backup Server\n"
			if $live_restore;
		    PVE::QemuServer::restore_file_archive($archive->{path} // '-', $vmid, $authuser, $restore_options);
		} elsif ($archive->{type} eq 'pbs') {
		    PVE::QemuServer::restore_proxmox_backup_archive($archive->{volid}, $vmid, $authuser, $restore_options);
		} else {
		    die "unknown backup archive type\n";
		}
		$restored_data = 1;

		my $restored_conf = PVE::QemuConfig->load_config($vmid);
		# Convert restored VM to template if backup was VM template
		if (PVE::QemuConfig->is_template($restored_conf)) {
		    warn "Convert to template.\n";
		    eval { PVE::QemuServer::template_create($vmid, $restored_conf) };
		    warn $@ if $@;
		}
	    };

	    # ensure no old replication state are exists
	    PVE::ReplicationState::delete_guest_states($vmid);

	    PVE::QemuConfig->lock_config_full($vmid, 1, $realcmd);

	    if ($start_after_create && !$live_restore) {
		print "Execute autostart\n";
		eval { PVE::API2::Qemu->vm_start({ vmid => $vmid, node => $node }) };
		warn $@ if $@;
	    }
	};

	my $createfn = sub {
	    # ensure no old replication state are exists
	    PVE::ReplicationState::delete_guest_states($vmid);

	    my $realcmd = sub {
		my $conf = $param;
		my $arch = PVE::QemuServer::get_vm_arch($conf);

		$conf->{meta} = PVE::QemuServer::new_meta_info_string();

		my $vollist = [];
		eval {
		    $vollist = &$create_disks($rpcenv, $authuser, $conf, $arch, $storecfg, $vmid, $pool, $param, $storage);

		    if (!$conf->{boot}) {
			my $devs = PVE::QemuServer::get_default_bootdevices($conf);
			$conf->{boot} = PVE::QemuServer::print_bootorder($devs);
		    }

		    # auto generate uuid if user did not specify smbios1 option
		    if (!$conf->{smbios1}) {
			$conf->{smbios1} = PVE::QemuServer::generate_smbios1_uuid();
		    }

		    if ((!defined($conf->{vmgenid}) || $conf->{vmgenid} eq '1') && $arch ne 'aarch64') {
			$conf->{vmgenid} = PVE::QemuServer::generate_uuid();
		    }

		    my $machine = $conf->{machine};
		    if (!$machine || $machine =~ m/^(?:pc|q35|virt)$/) {
			# always pin Windows' machine version on create, they get to easily confused
			if (PVE::QemuServer::windows_version($conf->{ostype})) {
			    $conf->{machine} = PVE::QemuServer::windows_get_pinned_machine_version($machine);
			}
		    }

		    PVE::QemuConfig->write_config($vmid, $conf);

		};
		my $err = $@;

		if ($err) {
		    foreach my $volid (@$vollist) {
			eval { PVE::Storage::vdisk_free($storecfg, $volid); };
			warn $@ if $@;
		    }
		    die "$emsg $err";
		}

		PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
	    };

	    PVE::QemuConfig->lock_config_full($vmid, 1, $realcmd);

	    if ($start_after_create) {
		print "Execute autostart\n";
		eval { PVE::API2::Qemu->vm_start({vmid => $vmid, node => $node}) };
		warn $@ if $@;
	    }
	};

	my ($code, $worker_name);
	if ($is_restore) {
	    $worker_name = 'qmrestore';
	    $code = sub {
		eval { $restorefn->() };
		if (my $err = $@) {
		    eval { PVE::QemuConfig->remove_lock($vmid, 'create') };
		    warn $@ if $@;
		    if ($restored_data) {
			warn "error after data was restored, VM disks should be OK but config may "
			    ."require adaptions. VM $vmid state is NOT cleaned up.\n";
		    } else {
			warn "error before or during data restore, some or all disks were not "
			    ."completely restored. VM $vmid state is NOT cleaned up.\n";
		    }
		    die $err;
		}
	    };
	} else {
	    $worker_name = 'qmcreate';
	    $code = sub {
		eval { $createfn->() };
		if (my $err = $@) {
		    eval {
			my $conffile = PVE::QemuConfig->config_file($vmid);
			unlink($conffile) or die "failed to remove config file: $!\n";
		    };
		    warn $@ if $@;
		    die $err;
		}
	    };
	}

	return $rpcenv->fork_worker($worker_name, $vmid, $authuser, $code);
    }});

__PACKAGE__->register_method({
    name => 'vmdiridx',
    path => '{vmid}',
    method => 'GET',
    proxyto => 'node',
    description => "Directory index",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [
	    { subdir => 'config' },
	    { subdir => 'pending' },
	    { subdir => 'status' },
	    { subdir => 'unlink' },
	    { subdir => 'vncproxy' },
	    { subdir => 'termproxy' },
	    { subdir => 'migrate' },
	    { subdir => 'resize' },
	    { subdir => 'move' },
	    { subdir => 'rrd' },
	    { subdir => 'rrddata' },
	    { subdir => 'monitor' },
	    { subdir => 'agent' },
	    { subdir => 'snapshot' },
	    { subdir => 'spiceproxy' },
	    { subdir => 'sendkey' },
	    { subdir => 'firewall' },
	    ];

	return $res;
    }});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::VM",
    path => '{vmid}/firewall',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Qemu::Agent",
    path => '{vmid}/agent',
});

__PACKAGE__->register_method({
    name => 'rrd',
    path => '{vmid}/rrd',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    description => "Read VM RRD statistics (returns PNG)",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    timeframe => {
		description => "Specify the time frame you are interested in.",
		type => 'string',
		enum => [ 'hour', 'day', 'week', 'month', 'year' ],
	    },
	    ds => {
		description => "The list of datasources you want to display.",
 		type => 'string', format => 'pve-configid-list',
	    },
	    cf => {
		description => "The RRD consolidation function",
 		type => 'string',
		enum => [ 'AVERAGE', 'MAX' ],
		optional => 1,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    filename => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	return PVE::RRD::create_rrd_graph(
	    "pve2-vm/$param->{vmid}", $param->{timeframe},
	    $param->{ds}, $param->{cf});

    }});

__PACKAGE__->register_method({
    name => 'rrddata',
    path => '{vmid}/rrddata',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    description => "Read VM RRD statistics",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    timeframe => {
		description => "Specify the time frame you are interested in.",
		type => 'string',
		enum => [ 'hour', 'day', 'week', 'month', 'year' ],
	    },
	    cf => {
		description => "The RRD consolidation function",
 		type => 'string',
		enum => [ 'AVERAGE', 'MAX' ],
		optional => 1,
	    },
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	return PVE::RRD::create_rrd_data(
	    "pve2-vm/$param->{vmid}", $param->{timeframe}, $param->{cf});
    }});


__PACKAGE__->register_method({
    name => 'vm_config',
    path => '{vmid}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get the virtual machine configuration with pending configuration " .
	"changes applied. Set the 'current' parameter to get the current configuration instead.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    current => {
		description => "Get current values (instead of pending values).",
		optional => 1,
		default => 0,
		type => 'boolean',
	    },
	    snapshot => get_standard_option('pve-snapshot-name', {
		description => "Fetch config values from given snapshot.",
		optional => 1,
		completion => sub {
		    my ($cmd, $pname, $cur, $args) = @_;
		    PVE::QemuConfig->snapshot_list($args->[0]);
		},
	    }),
	},
    },
    returns => {
	description => "The VM configuration.",
	type => "object",
	properties => PVE::QemuServer::json_config_properties({
	    digest => {
		type => 'string',
		description => 'SHA1 digest of configuration file. This can be used to prevent concurrent modifications.',
	    }
	}),
    },
    code => sub {
	my ($param) = @_;

	raise_param_exc({ snapshot => "cannot use 'snapshot' parameter with 'current'",
	                  current => "cannot use 'snapshot' parameter with 'current'"})
	    if ($param->{snapshot} && $param->{current});

	my $conf;
	if ($param->{snapshot}) {
	    $conf = PVE::QemuConfig->load_snapshot_config($param->{vmid}, $param->{snapshot});
	} else {
	    $conf = PVE::QemuConfig->load_current_config($param->{vmid}, $param->{current});
	}
	$conf->{cipassword} = '**********' if $conf->{cipassword};
	return $conf;

    }});

__PACKAGE__->register_method({
    name => 'vm_pending',
    path => '{vmid}/pending',
    method => 'GET',
    proxyto => 'node',
    description => "Get the virtual machine configuration with both current and pending values.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {
		key => {
		    description => "Configuration option name.",
		    type => 'string',
		},
		value => {
		    description => "Current value.",
		    type => 'string',
		    optional => 1,
		},
		pending => {
		    description => "Pending value.",
		    type => 'string',
		    optional => 1,
		},
		delete => {
		    description => "Indicates a pending delete request if present and not 0. " .
		                   "The value 2 indicates a force-delete request.",
		    type => 'integer',
		    minimum => 0,
		    maximum => 2,
		    optional => 1,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $conf = PVE::QemuConfig->load_config($param->{vmid});

	my $pending_delete_hash = PVE::QemuConfig->parse_pending_delete($conf->{pending}->{delete});

	$conf->{cipassword} = '**********' if defined($conf->{cipassword});
	$conf->{pending}->{cipassword} = '********** ' if defined($conf->{pending}->{cipassword});

	return PVE::GuestHelpers::config_with_pending_array($conf, $pending_delete_hash);
   }});

# POST/PUT {vmid}/config implementation
#
# The original API used PUT (idempotent) an we assumed that all operations
# are fast. But it turned out that almost any configuration change can
# involve hot-plug actions, or disk alloc/free. Such actions can take long
# time to complete and have side effects (not idempotent).
#
# The new implementation uses POST and forks a worker process. We added
# a new option 'background_delay'. If specified we wait up to
# 'background_delay' second for the worker task to complete. It returns null
# if the task is finished within that time, else we return the UPID.

my $update_vm_api  = sub {
    my ($param, $sync) = @_;

    my $rpcenv = PVE::RPCEnvironment::get();

    my $authuser = $rpcenv->get_user();

    my $node = extract_param($param, 'node');

    my $vmid = extract_param($param, 'vmid');

    my $digest = extract_param($param, 'digest');

    my $background_delay = extract_param($param, 'background_delay');

    if (defined(my $cipassword = $param->{cipassword})) {
	# Same logic as in cloud-init (but with the regex fixed...)
	$param->{cipassword} = PVE::Tools::encrypt_pw($cipassword)
	    if $cipassword !~ /^\$(?:[156]|2[ay])(\$.+){2}/;
    }

    my @paramarr = (); # used for log message
    foreach my $key (sort keys %$param) {
	my $value = $key eq 'cipassword' ? '<hidden>' : $param->{$key};
	push @paramarr, "-$key", $value;
    }

    my $skiplock = extract_param($param, 'skiplock');
    raise_param_exc({ skiplock => "Only root may use this option." })
	if $skiplock && $authuser ne 'root@pam';

    my $delete_str = extract_param($param, 'delete');

    my $revert_str = extract_param($param, 'revert');

    my $force = extract_param($param, 'force');

    if (defined(my $ssh_keys = $param->{sshkeys})) {
	$ssh_keys = URI::Escape::uri_unescape($ssh_keys);
	PVE::Tools::validate_ssh_public_keys($ssh_keys);
    }

    die "no options specified\n" if !$delete_str && !$revert_str && !scalar(keys %$param);

    my $storecfg = PVE::Storage::config();

    my $defaults = PVE::QemuServer::load_defaults();

    &$resolve_cdrom_alias($param);

    # now try to verify all parameters

    my $revert = {};
    foreach my $opt (PVE::Tools::split_list($revert_str)) {
	if (!PVE::QemuServer::option_exists($opt)) {
	    raise_param_exc({ revert => "unknown option '$opt'" });
	}

	raise_param_exc({ delete => "you can't use '-$opt' and " .
			      "-revert $opt' at the same time" })
	    if defined($param->{$opt});

	$revert->{$opt} = 1;
    }

    my @delete = ();
    foreach my $opt (PVE::Tools::split_list($delete_str)) {
	$opt = 'ide2' if $opt eq 'cdrom';

	raise_param_exc({ delete => "you can't use '-$opt' and " .
			      "-delete $opt' at the same time" })
	    if defined($param->{$opt});

	raise_param_exc({ revert => "you can't use '-delete $opt' and " .
			      "-revert $opt' at the same time" })
	    if $revert->{$opt};

	if (!PVE::QemuServer::option_exists($opt)) {
	    raise_param_exc({ delete => "unknown option '$opt'" });
	}

	push @delete, $opt;
    }

    my $repl_conf = PVE::ReplicationConfig->new();
    my $is_replicated = $repl_conf->check_for_existing_jobs($vmid, 1);
    my $check_replication = sub {
	my ($drive) = @_;
	return if !$is_replicated;
	my $volid = $drive->{file};
	return if !$volid || !($drive->{replicate}//1);
	return if PVE::QemuServer::drive_is_cdrom($drive);

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	die "cannot add non-managed/pass-through volume to a replicated VM\n"
	    if !defined($storeid);

	return if defined($volname) && $volname eq 'cloudinit';

	my $format;
	if ($volid =~ $NEW_DISK_RE) {
	    $storeid = $2;
	    $format = $drive->{format} || PVE::Storage::storage_default_format($storecfg, $storeid);
	} else {
	    $format = (PVE::Storage::parse_volname($storecfg, $volid))[6];
	}
	return if PVE::Storage::storage_can_replicate($storecfg, $storeid, $format);
	my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	return if $scfg->{shared};
	die "cannot add non-replicatable volume to a replicated VM\n";
    };

    foreach my $opt (keys %$param) {
	if (PVE::QemuServer::is_valid_drivename($opt)) {
	    # cleanup drive path
	    my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
	    raise_param_exc({ $opt => "unable to parse drive options" }) if !$drive;
	    PVE::QemuServer::cleanup_drive_path($opt, $storecfg, $drive);
	    $check_replication->($drive);
	    $param->{$opt} = PVE::QemuServer::print_drive($drive);
	} elsif ($opt =~ m/^net(\d+)$/) {
	    # add macaddr
	    my $net = PVE::QemuServer::parse_net($param->{$opt});
	    $param->{$opt} = PVE::QemuServer::print_net($net);
	} elsif ($opt eq 'vmgenid') {
	    if ($param->{$opt} eq '1') {
		$param->{$opt} = PVE::QemuServer::generate_uuid();
	    }
	} elsif ($opt eq 'hookscript') {
	    eval { PVE::GuestHelpers::check_hookscript($param->{$opt}, $storecfg); };
	    raise_param_exc({ $opt => $@ }) if $@;
	}
    }

    &$check_vm_modify_config_perm($rpcenv, $authuser, $vmid, undef, [@delete]);

    &$check_vm_modify_config_perm($rpcenv, $authuser, $vmid, undef, [keys %$param]);

    &$check_storage_access($rpcenv, $authuser, $storecfg, $vmid, $param);

    my $updatefn =  sub {

	my $conf = PVE::QemuConfig->load_config($vmid);

	die "checksum missmatch (file change by other user?)\n"
	    if $digest && $digest ne $conf->{digest};

	&$check_cpu_model_access($rpcenv, $authuser, $param, $conf);

	# FIXME: 'suspended' lock should probabyl be a state or "weak" lock?!
	if (scalar(@delete) && grep { $_ eq 'vmstate'} @delete) {
	    if (defined($conf->{lock}) && $conf->{lock} eq 'suspended') {
		delete $conf->{lock}; # for check lock check, not written out
		push @delete, 'lock'; # this is the real deal to write it out
	    }
	    push @delete, 'runningmachine' if $conf->{runningmachine};
	    push @delete, 'runningcpu' if $conf->{runningcpu};
	}

	PVE::QemuConfig->check_lock($conf) if !$skiplock;

	foreach my $opt (keys %$revert) {
	    if (defined($conf->{$opt})) {
		$param->{$opt} = $conf->{$opt};
	    } elsif (defined($conf->{pending}->{$opt})) {
		push @delete, $opt;
	    }
	}

	if ($param->{memory} || defined($param->{balloon})) {
	    my $maxmem = $param->{memory} || $conf->{pending}->{memory} || $conf->{memory} || $defaults->{memory};
	    my $balloon = defined($param->{balloon}) ? $param->{balloon} : $conf->{pending}->{balloon} || $conf->{balloon};

	    die "balloon value too large (must be smaller than assigned memory)\n"
		if $balloon && $balloon > $maxmem;
	}

	PVE::Cluster::log_msg('info', $authuser, "update VM $vmid: " . join (' ', @paramarr));

	my $worker = sub {

	    print "update VM $vmid: " . join (' ', @paramarr) . "\n";

	    # write updates to pending section

	    my $modified = {}; # record what $option we modify

	    my @bootorder;
	    if (my $boot = $conf->{boot}) {
		my $bootcfg = PVE::JSONSchema::parse_property_string('pve-qm-boot', $boot);
		@bootorder = PVE::Tools::split_list($bootcfg->{order}) if $bootcfg && $bootcfg->{order};
	    }
	    my $bootorder_deleted = grep {$_ eq 'bootorder'} @delete;

	    my $check_drive_perms = sub {
		my ($opt, $val) = @_;
		my $drive = PVE::QemuServer::parse_drive($opt, $val);
		# FIXME: cloudinit: CDROM or Disk?
		if (PVE::QemuServer::drive_is_cdrom($drive)) { # CDROM
		    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.CDROM']);
		} else {
		    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
		}
	    };

	    foreach my $opt (@delete) {
		$modified->{$opt} = 1;
		$conf = PVE::QemuConfig->load_config($vmid); # update/reload

		# value of what we want to delete, independent if pending or not
		my $val = $conf->{$opt} // $conf->{pending}->{$opt};
		if (!defined($val)) {
		    warn "cannot delete '$opt' - not set in current configuration!\n";
		    $modified->{$opt} = 0;
		    next;
		}
		my $is_pending_val = defined($conf->{pending}->{$opt});
		delete $conf->{pending}->{$opt};

		# remove from bootorder if necessary
		if (!$bootorder_deleted && @bootorder && grep {$_ eq $opt} @bootorder) {
		    @bootorder = grep {$_ ne $opt} @bootorder;
		    $conf->{pending}->{boot} = PVE::QemuServer::print_bootorder(\@bootorder);
		    $modified->{boot} = 1;
		}

		if ($opt =~ m/^unused/) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $val);
		    PVE::QemuConfig->check_protection($conf, "can't remove unused disk '$drive->{file}'");
		    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
		    if (PVE::QemuServer::try_deallocate_drive($storecfg, $vmid, $conf, $opt, $drive, $rpcenv, $authuser)) {
			delete $conf->{$opt};
			PVE::QemuConfig->write_config($vmid, $conf);
		    }
		} elsif ($opt eq 'vmstate') {
		    PVE::QemuConfig->check_protection($conf, "can't remove vmstate '$val'");
		    if (PVE::QemuServer::try_deallocate_drive($storecfg, $vmid, $conf, $opt, { file => $val }, $rpcenv, $authuser, 1)) {
			delete $conf->{$opt};
			PVE::QemuConfig->write_config($vmid, $conf);
		    }
		} elsif (PVE::QemuServer::is_valid_drivename($opt)) {
		    PVE::QemuConfig->check_protection($conf, "can't remove drive '$opt'");
		    $check_drive_perms->($opt, $val);
		    PVE::QemuServer::vmconfig_register_unused_drive($storecfg, $vmid, $conf, PVE::QemuServer::parse_drive($opt, $val))
			if $is_pending_val;
		    PVE::QemuConfig->add_to_pending_delete($conf, $opt, $force);
		    PVE::QemuConfig->write_config($vmid, $conf);
		} elsif ($opt =~ m/^serial\d+$/) {
		    if ($val eq 'socket') {
			$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.HWType']);
		    } elsif ($authuser ne 'root@pam') {
			die "only root can delete '$opt' config for real devices\n";
		    }
		    PVE::QemuConfig->add_to_pending_delete($conf, $opt, $force);
		    PVE::QemuConfig->write_config($vmid, $conf);
		} elsif ($opt =~ m/^usb\d+$/) {
		    if ($val =~ m/spice/) {
			$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.HWType']);
		    } elsif ($authuser ne 'root@pam') {
			die "only root can delete '$opt' config for real devices\n";
		    }
		    PVE::QemuConfig->add_to_pending_delete($conf, $opt, $force);
		    PVE::QemuConfig->write_config($vmid, $conf);
		} else {
		    PVE::QemuConfig->add_to_pending_delete($conf, $opt, $force);
		    PVE::QemuConfig->write_config($vmid, $conf);
		}
	    }

	    foreach my $opt (keys %$param) { # add/change
		$modified->{$opt} = 1;
		$conf = PVE::QemuConfig->load_config($vmid); # update/reload
		next if defined($conf->{pending}->{$opt}) && ($param->{$opt} eq $conf->{pending}->{$opt}); # skip if nothing changed

		my $arch = PVE::QemuServer::get_vm_arch($conf);

		if (PVE::QemuServer::is_valid_drivename($opt)) {
		    # old drive
		    if ($conf->{$opt}) {
			$check_drive_perms->($opt, $conf->{$opt});
		    }

		    # new drive
		    $check_drive_perms->($opt, $param->{$opt});
		    PVE::QemuServer::vmconfig_register_unused_drive($storecfg, $vmid, $conf, PVE::QemuServer::parse_drive($opt, $conf->{pending}->{$opt}))
			if defined($conf->{pending}->{$opt});

		    &$create_disks($rpcenv, $authuser, $conf->{pending}, $arch, $storecfg, $vmid, undef, {$opt => $param->{$opt}});

		    # default legacy boot order implies all cdroms anyway
		    if (@bootorder) {
			# append new CD drives to bootorder to mark them bootable
			my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
			if (PVE::QemuServer::drive_is_cdrom($drive, 1) && !grep(/^$opt$/, @bootorder)) {
			    push @bootorder, $opt;
			    $conf->{pending}->{boot} = PVE::QemuServer::print_bootorder(\@bootorder);
			    $modified->{boot} = 1;
			}
		    }
		} elsif ($opt =~ m/^serial\d+/) {
		    if ((!defined($conf->{$opt}) || $conf->{$opt} eq 'socket') && $param->{$opt} eq 'socket') {
			$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.HWType']);
		    } elsif ($authuser ne 'root@pam') {
			die "only root can modify '$opt' config for real devices\n";
		    }
		    $conf->{pending}->{$opt} = $param->{$opt};
		} elsif ($opt =~ m/^usb\d+/) {
		    if ((!defined($conf->{$opt}) || $conf->{$opt} =~ m/spice/) && $param->{$opt} =~ m/spice/) {
			$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.HWType']);
		    } elsif ($authuser ne 'root@pam') {
			die "only root can modify '$opt' config for real devices\n";
		    }
		    $conf->{pending}->{$opt} = $param->{$opt};
		} else {
		    $conf->{pending}->{$opt} = $param->{$opt};

		    if ($opt eq 'boot') {
			my $new_bootcfg = PVE::JSONSchema::parse_property_string('pve-qm-boot', $param->{$opt});
			if ($new_bootcfg->{order}) {
			    my @devs = PVE::Tools::split_list($new_bootcfg->{order});
			    for my $dev (@devs) {
				my $exists = $conf->{$dev} || $conf->{pending}->{$dev} || $param->{$dev};
				my $deleted = grep {$_ eq $dev} @delete;
				die "invalid bootorder: device '$dev' does not exist'\n"
				    if !$exists || $deleted;
			    }

			    # remove legacy boot order settings if new one set
			    $conf->{pending}->{$opt} = PVE::QemuServer::print_bootorder(\@devs);
			    PVE::QemuConfig->add_to_pending_delete($conf, "bootdisk")
				if $conf->{bootdisk};
			}
		    }
		}
		PVE::QemuConfig->remove_from_pending_delete($conf, $opt);
		PVE::QemuConfig->write_config($vmid, $conf);
	    }

	    # remove pending changes when nothing changed
	    $conf = PVE::QemuConfig->load_config($vmid); # update/reload
	    my $changes = PVE::QemuConfig->cleanup_pending($conf);
	    PVE::QemuConfig->write_config($vmid, $conf) if $changes;

	    return if !scalar(keys %{$conf->{pending}});

	    my $running = PVE::QemuServer::check_running($vmid);

	    # apply pending changes

	    $conf = PVE::QemuConfig->load_config($vmid); # update/reload

	    my $errors = {};
	    if ($running) {
		PVE::QemuServer::vmconfig_hotplug_pending($vmid, $conf, $storecfg, $modified, $errors);
	    } else {
		PVE::QemuServer::vmconfig_apply_pending($vmid, $conf, $storecfg, $errors);
	    }
	    raise_param_exc($errors) if scalar(keys %$errors);

	    return;
	};

	if ($sync) {
	    &$worker();
	    return;
	} else {
	    my $upid = $rpcenv->fork_worker('qmconfig', $vmid, $authuser, $worker);

	    if ($background_delay) {

		# Note: It would be better to do that in the Event based HTTPServer
		# to avoid blocking call to sleep.

		my $end_time = time() + $background_delay;

		my $task = PVE::Tools::upid_decode($upid);

		my $running = 1;
		while (time() < $end_time) {
		    $running = PVE::ProcFSTools::check_process_running($task->{pid}, $task->{pstart});
		    last if !$running;
		    sleep(1); # this gets interrupted when child process ends
		}

		if (!$running) {
		    my $status = PVE::Tools::upid_read_status($upid);
		    return if !PVE::Tools::upid_status_is_error($status);
		    die "failed to update VM $vmid: $status\n";
		}
	    }

	    return $upid;
	}
    };

    return PVE::QemuConfig->lock_config($vmid, $updatefn);
};

my $vm_config_perm_list = [
	    'VM.Config.Disk',
	    'VM.Config.CDROM',
	    'VM.Config.CPU',
	    'VM.Config.Memory',
	    'VM.Config.Network',
	    'VM.Config.HWType',
	    'VM.Config.Options',
	    'VM.Config.Cloudinit',
    ];

__PACKAGE__->register_method({
    name => 'update_vm_async',
    path => '{vmid}/config',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Set virtual machine options (asynchrounous API).",
    permissions => {
	check => ['perm', '/vms/{vmid}', $vm_config_perm_list, any => 1],
    },
    parameters => {
	additionalProperties => 0,
	properties => PVE::QemuServer::json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
		skiplock => get_standard_option('skiplock'),
		delete => {
		    type => 'string', format => 'pve-configid-list',
		    description => "A list of settings you want to delete.",
		    optional => 1,
		},
		revert => {
		    type => 'string', format => 'pve-configid-list',
		    description => "Revert a pending change.",
		    optional => 1,
		},
		force => {
		    type => 'boolean',
		    description => $opt_force_description,
		    optional => 1,
		    requires => 'delete',
		},
		digest => {
		    type => 'string',
		    description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
		    maxLength => 40,
		    optional => 1,
		},
		background_delay => {
		    type => 'integer',
		    description => "Time to wait for the task to finish. We return 'null' if the task finish within that time.",
		    minimum => 1,
		    maximum => 30,
		    optional => 1,
		},
	    }),
    },
    returns => {
	type => 'string',
	optional => 1,
    },
    code => $update_vm_api,
});

__PACKAGE__->register_method({
    name => 'update_vm',
    path => '{vmid}/config',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Set virtual machine options (synchrounous API) - You should consider using the POST method instead for any actions involving hotplug or storage allocation.",
    permissions => {
	check => ['perm', '/vms/{vmid}', $vm_config_perm_list, any => 1],
    },
    parameters => {
	additionalProperties => 0,
	properties => PVE::QemuServer::json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
		skiplock => get_standard_option('skiplock'),
		delete => {
		    type => 'string', format => 'pve-configid-list',
		    description => "A list of settings you want to delete.",
		    optional => 1,
		},
		revert => {
		    type => 'string', format => 'pve-configid-list',
		    description => "Revert a pending change.",
		    optional => 1,
		},
		force => {
		    type => 'boolean',
		    description => $opt_force_description,
		    optional => 1,
		    requires => 'delete',
		},
		digest => {
		    type => 'string',
		    description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
		    maxLength => 40,
		    optional => 1,
		},
	    }),
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	&$update_vm_api($param, 1);
	return;
    }
});

__PACKAGE__->register_method({
    name => 'destroy_vm',
    path => '{vmid}',
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Destroy the VM and  all used/owned volumes. Removes any VM specific permissions"
	." and firewall rules",
    permissions => {
	check => [ 'perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_stopped }),
	    skiplock => get_standard_option('skiplock'),
	    purge => {
		type => 'boolean',
		description => "Remove VMID from configurations, like backup & replication jobs and HA.",
		optional => 1,
	    },
	    'destroy-unreferenced-disks' => {
		type => 'boolean',
		description => "If set, destroy additionally all disks not referenced in the config"
		 ." but with a matching VMID from all enabled storages.",
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();
	my $vmid = $param->{vmid};

	my $skiplock = $param->{skiplock};
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $early_checks = sub {
	    # test if VM exists
	    my $conf = PVE::QemuConfig->load_config($vmid);
	    PVE::QemuConfig->check_protection($conf, "can't remove VM $vmid");

	    my $ha_managed = PVE::HA::Config::service_is_configured("vm:$vmid");

	    if (!$param->{purge}) {
		die "unable to remove VM $vmid - used in HA resources and purge parameter not set.\n"
		    if $ha_managed;
		# don't allow destroy if with replication jobs but no purge param
		my $repl_conf = PVE::ReplicationConfig->new();
		$repl_conf->check_for_existing_jobs($vmid);
	    }

	    die "VM $vmid is running - destroy failed\n"
		if PVE::QemuServer::check_running($vmid);

	    return $ha_managed;
	};

	$early_checks->();

	my $realcmd = sub {
	    my $upid = shift;

	    my $storecfg = PVE::Storage::config();

	    syslog('info', "destroy VM $vmid: $upid\n");
	    PVE::QemuConfig->lock_config($vmid, sub {
		# repeat, config might have changed
		my $ha_managed = $early_checks->();

		my $purge_unreferenced = $param->{'destroy-unreferenced-disks'};

		PVE::QemuServer::destroy_vm(
		    $storecfg,
		    $vmid,
		    $skiplock, { lock => 'destroyed' },
		    $purge_unreferenced,
		);

		PVE::AccessControl::remove_vm_access($vmid);
		PVE::Firewall::remove_vmfw_conf($vmid);
		if ($param->{purge}) {
		    print "purging VM $vmid from related configurations..\n";
		    PVE::ReplicationConfig::remove_vmid_jobs($vmid);
		    PVE::VZDump::Plugin::remove_vmid_from_backup_jobs($vmid);

		    if ($ha_managed) {
			PVE::HA::Config::delete_service_from_config("vm:$vmid");
			print "NOTE: removed VM $vmid from HA resource configuration.\n";
		    }
		}

		# only now remove the zombie config, else we can have reuse race
		PVE::QemuConfig->destroy_config($vmid);
	    });
	};

	return $rpcenv->fork_worker('qmdestroy', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'unlink',
    path => '{vmid}/unlink',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Unlink/delete disk images.",
    permissions => {
	check => [ 'perm', '/vms/{vmid}', ['VM.Config.Disk']],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    idlist => {
		type => 'string', format => 'pve-configid-list',
		description => "A list of disk IDs you want to delete.",
	    },
	    force => {
		type => 'boolean',
		description => $opt_force_description,
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	$param->{delete} = extract_param($param, 'idlist');

	__PACKAGE__->update_vm($param);

	return;
    }});

# uses good entropy, each char is limited to 6 bit to get printable chars simply
my $gen_rand_chars = sub {
    my ($length) = @_;

    die "invalid length $length" if $length < 1;

    my $min = ord('!'); # first printable ascii

    my $rand_bytes = Crypt::OpenSSL::Random::random_bytes($length);
    die "failed to generate random bytes!\n"
      if !$rand_bytes;

    my $str = join('', map { chr((ord($_) & 0x3F) + $min) } split('', $rand_bytes));

    return $str;
};

my $sslcert;

__PACKAGE__->register_method({
    name => 'vncproxy',
    path => '{vmid}/vncproxy',
    method => 'POST',
    protected => 1,
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Creates a TCP VNC proxy connections.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    websocket => {
		optional => 1,
		type => 'boolean',
		description => "starts websockify instead of vncproxy",
	    },
	    'generate-password' => {
		optional => 1,
		type => 'boolean',
		default => 0,
		description => "Generates a random password to be used as ticket instead of the API ticket.",
	    },
	},
    },
    returns => {
	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
	    password => {
		optional => 1,
		description => "Returned if requested with 'generate-password' param."
		    ." Consists of printable ASCII characters ('!' .. '~').",
		type => 'string',
	    },
	    cert => { type => 'string' },
	    port => { type => 'integer' },
	    upid => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = $param->{vmid};
	my $node = $param->{node};
	my $websocket = $param->{websocket};

	my $conf = PVE::QemuConfig->load_config($vmid, $node); # check if VM exists

	my $serial;
	if ($conf->{vga}) {
	    my $vga = PVE::QemuServer::parse_vga($conf->{vga});
	    $serial = $vga->{type} if $vga->{type} =~ m/^serial\d+$/;
	}

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);
	my $password = $ticket;
	if ($param->{'generate-password'}) {
	    $password = $gen_rand_chars->(8);
	}

	$sslcert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192)
	    if !$sslcert;

	my $family;
	my $remcmd = [];

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    (undef, $family) = PVE::Cluster::remote_node_ip($node);
	    my $sshinfo = PVE::SSHInfo::get_ssh_info($node);
	    # NOTE: kvm VNC traffic is already TLS encrypted or is known unsecure
	    $remcmd = PVE::SSHInfo::ssh_info_to_command($sshinfo, defined($serial) ? '-t' : '-T');
	} else {
	    $family = PVE::Tools::get_host_address_family($node);
	}

	my $port = PVE::Tools::next_vnc_port($family);

	my $timeout = 10;

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "starting vnc proxy $upid\n");

	    my $cmd;

	    if (defined($serial)) {

		my $termcmd = [ '/usr/sbin/qm', 'terminal', $vmid, '-iface', $serial, '-escape', '0' ];

		$cmd = ['/usr/bin/vncterm', '-rfbport', $port,
			'-timeout', $timeout, '-authpath', $authpath,
			'-perm', 'Sys.Console'];

		if ($param->{websocket}) {
		    $ENV{PVE_VNC_TICKET} = $password; # pass ticket to vncterm
		    push @$cmd, '-notls', '-listen', 'localhost';
		}

		push @$cmd, '-c', @$remcmd, @$termcmd;

		PVE::Tools::run_command($cmd);

	    } else {

		$ENV{LC_PVE_TICKET} = $password if $websocket; # set ticket with "qm vncproxy"

		$cmd = [@$remcmd, "/usr/sbin/qm", 'vncproxy', $vmid];

		my $sock = IO::Socket::IP->new(
		    ReuseAddr => 1,
		    Listen => 1,
		    LocalPort => $port,
		    Proto => 'tcp',
		    GetAddrInfoFlags => 0,
		) or die "failed to create socket: $!\n";
		# Inside the worker we shouldn't have any previous alarms
		# running anyway...:
		alarm(0);
		local $SIG{ALRM} = sub { die "connection timed out\n" };
		alarm $timeout;
		accept(my $cli, $sock) or die "connection failed: $!\n";
		alarm(0);
		close($sock);
		if (PVE::Tools::run_command($cmd,
		    output => '>&'.fileno($cli),
		    input => '<&'.fileno($cli),
		    noerr => 1) != 0)
		{
		    die "Failed to run vncproxy.\n";
		}
	    }

	    return;
	};

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd, 1);

	PVE::Tools::wait_for_vnc_port($port);

	my $res = {
	    user => $authuser,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	    cert => $sslcert,
	};
	$res->{password} = $password if $param->{'generate-password'};

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'termproxy',
    path => '{vmid}/termproxy',
    method => 'POST',
    protected => 1,
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Creates a TCP proxy connections.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    serial=> {
		optional => 1,
		type => 'string',
		enum => [qw(serial0 serial1 serial2 serial3)],
		description => "opens a serial terminal (defaults to display)",
	    },
	},
    },
    returns => {
	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
	    port => { type => 'integer' },
	    upid => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = $param->{vmid};
	my $node = $param->{node};
	my $serial = $param->{serial};

	my $conf = PVE::QemuConfig->load_config($vmid, $node); # check if VM exists

	if (!defined($serial)) {
	    if ($conf->{vga}) {
		my $vga = PVE::QemuServer::parse_vga($conf->{vga});
		$serial = $vga->{type} if $vga->{type} =~ m/^serial\d+$/;
	    }
	}

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

	my $family;
	my $remcmd = [];

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    (undef, $family) = PVE::Cluster::remote_node_ip($node);
	    my $sshinfo = PVE::SSHInfo::get_ssh_info($node);
	    $remcmd = PVE::SSHInfo::ssh_info_to_command($sshinfo, '-t');
	    push @$remcmd, '--';
	} else {
	    $family = PVE::Tools::get_host_address_family($node);
	}

	my $port = PVE::Tools::next_vnc_port($family);

	my $termcmd = [ '/usr/sbin/qm', 'terminal', $vmid, '-escape', '0'];
	push @$termcmd, '-iface', $serial if $serial;

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "starting qemu termproxy $upid\n");

	    my $cmd = ['/usr/bin/termproxy', $port, '--path', $authpath,
		       '--perm', 'VM.Console', '--'];
	    push @$cmd, @$remcmd, @$termcmd;

	    PVE::Tools::run_command($cmd);
	};

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd, 1);

	PVE::Tools::wait_for_vnc_port($port);

	return {
	    user => $authuser,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	};
    }});

__PACKAGE__->register_method({
    name => 'vncwebsocket',
    path => '{vmid}/vncwebsocket',
    method => 'GET',
    permissions => {
	description => "You also need to pass a valid ticket (vncticket).",
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Opens a weksocket for VNC traffic.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    vncticket => {
		description => "Ticket from previous call to vncproxy.",
		type => 'string',
		maxLength => 512,
	    },
	    port => {
		description => "Port number returned by previous vncproxy call.",
		type => 'integer',
		minimum => 5900,
		maximum => 5999,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    port => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = $param->{vmid};
	my $node = $param->{node};

	my $authpath = "/vms/$vmid";

	PVE::AccessControl::verify_vnc_ticket($param->{vncticket}, $authuser, $authpath);

	my $conf = PVE::QemuConfig->load_config($vmid, $node); # VM exists ?

	# Note: VNC ports are acessible from outside, so we do not gain any
	# security if we verify that $param->{port} belongs to VM $vmid. This
	# check is done by verifying the VNC ticket (inside VNC protocol).

	my $port = $param->{port};

	return { port => $port };
    }});

__PACKAGE__->register_method({
    name => 'spiceproxy',
    path => '{vmid}/spiceproxy',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Returns a SPICE configuration to connect to the VM.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    proxy => get_standard_option('spice-proxy', { optional => 1 }),
	},
    },
    returns => get_standard_option('remote-viewer-config'),
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = $param->{vmid};
	my $node = $param->{node};
	my $proxy = $param->{proxy};

	my $conf = PVE::QemuConfig->load_config($vmid, $node);
	my $title = "VM $vmid";
	$title .= " - ". $conf->{name} if $conf->{name};

	my $port = PVE::QemuServer::spice_port($vmid);

	my ($ticket, undef, $remote_viewer_config) =
	    PVE::AccessControl::remote_viewer_config($authuser, $vmid, $node, $proxy, $title, $port);

	mon_cmd($vmid, "set_password", protocol => 'spice', password => $ticket);
	mon_cmd($vmid, "expire_password", protocol => 'spice', time => "+30");

	return $remote_viewer_config;
    }});

__PACKAGE__->register_method({
    name => 'vmcmdidx',
    path => '{vmid}/status',
    method => 'GET',
    proxyto => 'node',
    description => "Directory index",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::QemuConfig->load_config($param->{vmid});

	my $res = [
	    { subdir => 'current' },
	    { subdir => 'start' },
	    { subdir => 'stop' },
	    { subdir => 'reset' },
	    { subdir => 'shutdown' },
	    { subdir => 'suspend' },
	    { subdir => 'reboot' },
	    ];

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'vm_status',
    path => '{vmid}/status/current',
    method => 'GET',
    proxyto => 'node',
    protected => 1, # qemu pid files are only readable by root
    description => "Get virtual machine status.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	},
    },
    returns => {
	type => 'object',
	properties => {
	    %$PVE::QemuServer::vmstatus_return_properties,
	    ha => {
		description => "HA manager service status.",
		type => 'object',
	    },
	    spice => {
		description => "Qemu VGA configuration supports spice.",
		type => 'boolean',
		optional => 1,
	    },
	    agent => {
		description => "Qemu GuestAgent enabled in config.",
		type => 'boolean',
		optional => 1,
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::QemuConfig->load_config($param->{vmid});

	my $vmstatus = PVE::QemuServer::vmstatus($param->{vmid}, 1);
	my $status = $vmstatus->{$param->{vmid}};

	$status->{ha} = PVE::HA::Config::get_service_status("vm:$param->{vmid}");

	$status->{spice} = 1 if PVE::QemuServer::vga_conf_has_spice($conf->{vga});
	$status->{agent} = 1 if PVE::QemuServer::get_qga_key($conf, 'enabled');

	return $status;
    }});

__PACKAGE__->register_method({
    name => 'vm_start',
    path => '{vmid}/status/start',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Start virtual machine.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_stopped }),
	    skiplock => get_standard_option('skiplock'),
	    stateuri => get_standard_option('pve-qm-stateuri'),
	    migratedfrom => get_standard_option('pve-node',{ optional => 1 }),
	    migration_type => {
		type => 'string',
		enum => ['secure', 'insecure'],
		description => "Migration traffic is encrypted using an SSH " .
		  "tunnel by default. On secure, completely private networks " .
		  "this can be disabled to increase performance.",
		optional => 1,
	    },
	    migration_network => {
		type => 'string', format => 'CIDR',
		description => "CIDR of the (sub) network that is used for migration.",
		optional => 1,
	    },
	    machine => get_standard_option('pve-qemu-machine'),
	    'force-cpu' => {
		description => "Override QEMU's -cpu argument with the given string.",
		type => 'string',
		optional => 1,
	    },
	    targetstorage => get_standard_option('pve-targetstorage'),
	    timeout => {
		description => "Wait maximal timeout seconds.",
		type => 'integer',
		minimum => 0,
		default => 'max(30, vm memory in GiB)',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');
	my $timeout = extract_param($param, 'timeout');

	my $machine = extract_param($param, 'machine');
	my $force_cpu = extract_param($param, 'force-cpu');

	my $get_root_param = sub {
	    my $value = extract_param($param, $_[0]);
	    raise_param_exc({ "$_[0]" => "Only root may use this option." })
		if $value && $authuser ne 'root@pam';
	    return $value;
	};

	my $stateuri = $get_root_param->('stateuri');
	my $skiplock = $get_root_param->('skiplock');
	my $migratedfrom = $get_root_param->('migratedfrom');
	my $migration_type = $get_root_param->('migration_type');
	my $migration_network = $get_root_param->('migration_network');
	my $targetstorage = $get_root_param->('targetstorage');

	my $storagemap;

	if ($targetstorage) {
	    raise_param_exc({ targetstorage => "targetstorage can only by used with migratedfrom." })
		if !$migratedfrom;
	    $storagemap = eval { PVE::JSONSchema::parse_idmap($targetstorage, 'pve-storage-id') };
	    raise_param_exc({ targetstorage => "failed to parse storage map: $@" })
		if $@;
	}

	# read spice ticket from STDIN
	my $spice_ticket;
	my $nbd_protocol_version = 0;
	my $replicated_volumes = {};
	my $tpmstate_vol;
	if ($stateuri && ($stateuri eq 'tcp' || $stateuri eq 'unix') && $migratedfrom && ($rpcenv->{type} eq 'cli')) {
	    while (defined(my $line = <STDIN>)) {
		chomp $line;
		if ($line =~ m/^spice_ticket: (.+)$/) {
		    $spice_ticket = $1;
		} elsif ($line =~ m/^nbd_protocol_version: (\d+)$/) {
		    $nbd_protocol_version = $1;
		} elsif ($line =~ m/^replicated_volume: (.*)$/) {
		    $replicated_volumes->{$1} = 1;
		} elsif ($line =~ m/^tpmstate0: (.*)$/) {
		    $tpmstate_vol = $1;
		} elsif (!$spice_ticket) {
		    # fallback for old source node
		    $spice_ticket = $line;
		} else {
		    warn "unknown 'start' parameter on STDIN: '$line'\n";
		}
	    }
	}

	PVE::Cluster::check_cfs_quorum();

	my $storecfg = PVE::Storage::config();

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && !$stateuri &&  $rpcenv->{type} ne 'ha') {
	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA start for VM $vmid\n";

		my $cmd = ['ha-manager', 'set',  "vm:$vmid", '--state', 'started'];
		PVE::Tools::run_command($cmd);
		return;
	    };

	    return $rpcenv->fork_worker('hastart', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "start VM $vmid: $upid\n");

		my $migrate_opts = {
		    migratedfrom => $migratedfrom,
		    spice_ticket => $spice_ticket,
		    network => $migration_network,
		    type => $migration_type,
		    storagemap => $storagemap,
		    nbd_proto_version => $nbd_protocol_version,
		    replicated_volumes => $replicated_volumes,
		    tpmstate_vol => $tpmstate_vol,
		};

		my $params = {
		    statefile => $stateuri,
		    skiplock => $skiplock,
		    forcemachine => $machine,
		    timeout => $timeout,
		    forcecpu => $force_cpu,
		};

		PVE::QemuServer::vm_start($storecfg, $vmid, $params, $migrate_opts);
		return;
	    };

	    return $rpcenv->fork_worker('qmstart', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_stop',
    path => '{vmid}/status/stop',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Stop virtual machine. The qemu process will exit immediately. This" .
	"is akin to pulling the power plug of a running computer and may damage the VM data",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    skiplock => get_standard_option('skiplock'),
	    migratedfrom => get_standard_option('pve-node', { optional => 1 }),
	    timeout => {
		description => "Wait maximal timeout seconds.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    keepActive => {
		description => "Do not deactivate storage volumes.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $keepActive = extract_param($param, 'keepActive');
	raise_param_exc({ keepActive => "Only root may use this option." })
	    if $keepActive && $authuser ne 'root@pam';

	my $migratedfrom = extract_param($param, 'migratedfrom');
	raise_param_exc({ migratedfrom => "Only root may use this option." })
	    if $migratedfrom && $authuser ne 'root@pam';


	my $storecfg = PVE::Storage::config();

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && ($rpcenv->{type} ne 'ha') && !defined($migratedfrom)) {

	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA stop for VM $vmid\n";

		my $cmd = ['ha-manager', 'crm-command', 'stop',  "vm:$vmid", '0'];
		PVE::Tools::run_command($cmd);
		return;
	    };

	    return $rpcenv->fork_worker('hastop', $vmid, $authuser, $hacmd);

	} else {
	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "stop VM $vmid: $upid\n");

		PVE::QemuServer::vm_stop($storecfg, $vmid, $skiplock, 0,
					 $param->{timeout}, 0, 1, $keepActive, $migratedfrom);
		return;
	    };

	    return $rpcenv->fork_worker('qmstop', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_reset',
    path => '{vmid}/status/reset',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Reset virtual machine.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    skiplock => get_standard_option('skiplock'),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    PVE::QemuServer::vm_reset($vmid, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmreset', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_shutdown',
    path => '{vmid}/status/shutdown',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Shutdown virtual machine. This is similar to pressing the power button on a physical machine." .
	"This will send an ACPI event for the guest OS, which should then proceed to a clean shutdown.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    skiplock => get_standard_option('skiplock'),
	    timeout => {
		description => "Wait maximal timeout seconds.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    forceStop => {
		description => "Make sure the VM stops.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    keepActive => {
		description => "Do not deactivate storage volumes.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $keepActive = extract_param($param, 'keepActive');
	raise_param_exc({ keepActive => "Only root may use this option." })
	    if $keepActive && $authuser ne 'root@pam';

	my $storecfg = PVE::Storage::config();

	my $shutdown = 1;

	# if vm is paused, do not shutdown (but stop if forceStop = 1)
	# otherwise, we will infer a shutdown command, but run into the timeout,
	# then when the vm is resumed, it will instantly shutdown
	#
	# checking the qmp status here to get feedback to the gui/cli/api
	# and the status query should not take too long
	if (PVE::QemuServer::vm_is_paused($vmid)) {
	    if ($param->{forceStop}) {
		warn "VM is paused - stop instead of shutdown\n";
		$shutdown = 0;
	    } else {
		die "VM is paused - cannot shutdown\n";
	    }
	}

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $timeout = $param->{timeout} // 60;
	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA stop for VM $vmid\n";

		my $cmd = ['ha-manager', 'crm-command', 'stop', "vm:$vmid", "$timeout"];
		PVE::Tools::run_command($cmd);
		return;
	    };

	    return $rpcenv->fork_worker('hastop', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "shutdown VM $vmid: $upid\n");

		PVE::QemuServer::vm_stop($storecfg, $vmid, $skiplock, 0, $param->{timeout},
					 $shutdown, $param->{forceStop}, $keepActive);
		return;
	    };

	    return $rpcenv->fork_worker('qmshutdown', $vmid, $authuser, $realcmd);
	}
    }});

__PACKAGE__->register_method({
    name => 'vm_reboot',
    path => '{vmid}/status/reboot',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Reboot the VM by shutting it down, and starting it again. Applies pending changes.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    timeout => {
		description => "Wait maximal timeout seconds for the shutdown.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');

	die "VM is paused - cannot shutdown\n" if PVE::QemuServer::vm_is_paused($vmid);

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "requesting reboot of VM $vmid: $upid\n");
	    PVE::QemuServer::vm_reboot($vmid, $param->{timeout});
	    return;
	};

	return $rpcenv->fork_worker('qmreboot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_suspend',
    path => '{vmid}/status/suspend',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Suspend virtual machine.",
    permissions => {
	description => "You need 'VM.PowerMgmt' on /vms/{vmid}, and if you have set 'todisk',".
	    " you need also 'VM.Config.Disk' on /vms/{vmid} and 'Datastore.AllocateSpace'".
	    " on the storage for the vmstate.",
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    skiplock => get_standard_option('skiplock'),
	    todisk => {
		type => 'boolean',
		default => 0,
		optional => 1,
		description => 'If set, suspends the VM to disk. Will be resumed on next VM start.',
	    },
	    statestorage => get_standard_option('pve-storage-id', {
		description => "The storage for the VM state",
		requires => 'todisk',
		optional => 1,
		completion => \&PVE::Storage::complete_storage_enabled,
	    }),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');

	my $todisk = extract_param($param, 'todisk') // 0;

	my $statestorage = extract_param($param, 'statestorage');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	die "Cannot suspend HA managed VM to disk\n"
	    if $todisk && PVE::HA::Config::vm_is_ha_managed($vmid);

	# early check for storage permission, for better user feedback
	if ($todisk) {
	    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);

	    if (!$statestorage) {
		# get statestorage from config if none is given
		my $conf = PVE::QemuConfig->load_config($vmid);
		my $storecfg = PVE::Storage::config();
		$statestorage = PVE::QemuServer::find_vmstate_storage($conf, $storecfg);
	    }

	    $rpcenv->check($authuser, "/storage/$statestorage", ['Datastore.AllocateSpace']);
	}

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "suspend VM $vmid: $upid\n");

	    PVE::QemuServer::vm_suspend($vmid, $skiplock, $todisk, $statestorage);

	    return;
	};

	my $taskname = $todisk ? 'qmsuspend' : 'qmpause';
	return $rpcenv->fork_worker($taskname, $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_resume',
    path => '{vmid}/status/resume',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Resume virtual machine.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    skiplock => get_standard_option('skiplock'),
	    nocheck => { type => 'boolean', optional => 1 },

	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $nocheck = extract_param($param, 'nocheck');
	raise_param_exc({ nocheck => "Only root may use this option." })
	    if $nocheck && $authuser ne 'root@pam';

	my $to_disk_suspended;
	eval {
	    PVE::QemuConfig->lock_config($vmid, sub {
		my $conf = PVE::QemuConfig->load_config($vmid);
		$to_disk_suspended = PVE::QemuConfig->has_lock($conf, 'suspended');
	    });
	};

	die "VM $vmid not running\n"
	    if !$to_disk_suspended && !PVE::QemuServer::check_running($vmid, $nocheck);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "resume VM $vmid: $upid\n");

	    if (!$to_disk_suspended) {
		PVE::QemuServer::vm_resume($vmid, $skiplock, $nocheck);
	    } else {
		my $storecfg = PVE::Storage::config();
		PVE::QemuServer::vm_start($storecfg, $vmid, { skiplock => $skiplock });
	    }

	    return;
	};

	return $rpcenv->fork_worker('qmresume', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_sendkey',
    path => '{vmid}/sendkey',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Send key event to virtual machine.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid',
					{ completion => \&PVE::QemuServer::complete_vmid_running }),
	    skiplock => get_standard_option('skiplock'),
	    key => {
		description => "The key (qemu monitor encoding).",
		type => 'string'
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	PVE::QemuServer::vm_sendkey($vmid, $skiplock, $param->{key});

	return;
    }});

__PACKAGE__->register_method({
    name => 'vm_feature',
    path => '{vmid}/feature',
    method => 'GET',
    proxyto => 'node',
    protected => 1,
    description => "Check if feature for virtual machine is available.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
            feature => {
                description => "Feature to check.",
                type => 'string',
                enum => [ 'snapshot', 'clone', 'copy' ],
            },
            snapname => get_standard_option('pve-snapshot-name', {
                optional => 1,
            }),
	},
    },
    returns => {
	type => "object",
	properties => {
	    hasFeature => { type => 'boolean' },
	    nodes => {
		type => 'array',
		items => { type => 'string' },
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $feature = extract_param($param, 'feature');

	my $running = PVE::QemuServer::check_running($vmid);

	my $conf = PVE::QemuConfig->load_config($vmid);

	if($snapname){
	    my $snap = $conf->{snapshots}->{$snapname};
            die "snapshot '$snapname' does not exist\n" if !defined($snap);
	    $conf = $snap;
	}
	my $storecfg = PVE::Storage::config();

	my $nodelist = PVE::QemuServer::shared_nodes($conf, $storecfg);
	my $hasFeature = PVE::QemuConfig->has_feature($feature, $conf, $storecfg, $snapname, $running);

	return {
	    hasFeature => $hasFeature,
	    nodes => [ keys %$nodelist ],
	};
    }});

__PACKAGE__->register_method({
    name => 'clone_vm',
    path => '{vmid}/clone',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Create a copy of virtual machine/template.",
    permissions => {
	description => "You need 'VM.Clone' permissions on /vms/{vmid}, and 'VM.Allocate' permissions " .
	    "on /vms/{newid} (or on the VM pool /pool/{pool}). You also need " .
	    "'Datastore.AllocateSpace' on any used storage.",
	check =>
	[ 'and',
	  ['perm', '/vms/{vmid}', [ 'VM.Clone' ]],
	  [ 'or',
	    [ 'perm', '/vms/{newid}', ['VM.Allocate']],
	    [ 'perm', '/pool/{pool}', ['VM.Allocate'], require_param => 'pool'],
	  ],
	]
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    newid => get_standard_option('pve-vmid', {
		completion => \&PVE::Cluster::complete_next_vmid,
		description => 'VMID for the clone.' }),
	    name => {
		optional => 1,
		type => 'string', format => 'dns-name',
		description => "Set a name for the new VM.",
	    },
	    description => {
		optional => 1,
		type => 'string',
		description => "Description for the new VM.",
	    },
	    pool => {
		optional => 1,
		type => 'string', format => 'pve-poolid',
		description => "Add the new VM to the specified pool.",
	    },
            snapname => get_standard_option('pve-snapshot-name', {
		optional => 1,
            }),
	    storage => get_standard_option('pve-storage-id', {
		description => "Target storage for full clone.",
		optional => 1,
	    }),
	    'format' => {
		description => "Target format for file storage. Only valid for full clone.",
		type => 'string',
		optional => 1,
	        enum => [ 'raw', 'qcow2', 'vmdk'],
	    },
	    full => {
		optional => 1,
	        type => 'boolean',
	        description => "Create a full copy of all disks. This is always done when " .
		    "you clone a normal VM. For VM templates, we try to create a linked clone by default.",
	    },
	    target => get_standard_option('pve-node', {
		description => "Target node. Only allowed if the original VM is on shared storage.",
		optional => 1,
	    }),
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'integer',
		minimum => '0',
		default => 'clone limit from datacenter or storage config',
	    },
        },
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');
	my $newid = extract_param($param, 'newid');
	my $pool = extract_param($param, 'pool');

        my $snapname = extract_param($param, 'snapname');
	my $storage = extract_param($param, 'storage');
	my $format = extract_param($param, 'format');
	my $target = extract_param($param, 'target');

        my $localnode = PVE::INotify::nodename();

	if ($target && ($target eq $localnode || $target eq 'localhost')) {
	    undef $target;
	}

	my $running = PVE::QemuServer::check_running($vmid) || 0;

	my $load_and_check = sub {
	    $rpcenv->check_pool_exist($pool) if defined($pool);
	    PVE::Cluster::check_node_exists($target) if $target;

	    my $storecfg = PVE::Storage::config();

	    if ($storage) {
		# check if storage is enabled on local node
		PVE::Storage::storage_check_enabled($storecfg, $storage);
		if ($target) {
		    # check if storage is available on target node
		    PVE::Storage::storage_check_enabled($storecfg, $storage, $target);
		    # clone only works if target storage is shared
		    my $scfg = PVE::Storage::storage_config($storecfg, $storage);
		    die "can't clone to non-shared storage '$storage'\n"
			if !$scfg->{shared};
		}
	    }

	    PVE::Cluster::check_cfs_quorum();

	    my $conf = PVE::QemuConfig->load_config($vmid);
	    PVE::QemuConfig->check_lock($conf);

	    my $verify_running = PVE::QemuServer::check_running($vmid) || 0;
	    die "unexpected state change\n" if $verify_running != $running;

	    die "snapshot '$snapname' does not exist\n"
		if $snapname && !defined( $conf->{snapshots}->{$snapname});

	    my $full = $param->{full} // !PVE::QemuConfig->is_template($conf);

	    die "parameter 'storage' not allowed for linked clones\n"
		if defined($storage) && !$full;

	    die "parameter 'format' not allowed for linked clones\n"
		if defined($format) && !$full;

	    my $oldconf = $snapname ? $conf->{snapshots}->{$snapname} : $conf;

	    my $sharedvm = &$check_storage_access_clone($rpcenv, $authuser, $storecfg, $oldconf, $storage);

	    die "can't clone VM to node '$target' (VM uses local storage)\n"
		if $target && !$sharedvm;

	    my $conffile = PVE::QemuConfig->config_file($newid);
	    die "unable to create VM $newid: config file already exists\n"
		if -f $conffile;

	    my $newconf = { lock => 'clone' };
	    my $drives = {};
	    my $fullclone = {};
	    my $vollist = [];

	    foreach my $opt (keys %$oldconf) {
		my $value = $oldconf->{$opt};

		# do not copy snapshot related info
		next if $opt eq 'snapshots' ||  $opt eq 'parent' || $opt eq 'snaptime' ||
		    $opt eq 'vmstate' || $opt eq 'snapstate';

		# no need to copy unused images, because VMID(owner) changes anyways
		next if $opt =~ m/^unused\d+$/;

		# always change MAC! address
		if ($opt =~ m/^net(\d+)$/) {
		    my $net = PVE::QemuServer::parse_net($value);
		    my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
		    $net->{macaddr} =  PVE::Tools::random_ether_addr($dc->{mac_prefix});
		    $newconf->{$opt} = PVE::QemuServer::print_net($net);
		} elsif (PVE::QemuServer::is_valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $value);
		    die "unable to parse drive options for '$opt'\n" if !$drive;
		    if (PVE::QemuServer::drive_is_cdrom($drive, 1)) {
			$newconf->{$opt} = $value; # simply copy configuration
		    } else {
			if ($full || PVE::QemuServer::drive_is_cloudinit($drive)) {
			    die "Full clone feature is not supported for drive '$opt'\n"
				if !PVE::Storage::volume_has_feature($storecfg, 'copy', $drive->{file}, $snapname, $running);
			    $fullclone->{$opt} = 1;
			} else {
			    # not full means clone instead of copy
			    die "Linked clone feature is not supported for drive '$opt'\n"
				if !PVE::Storage::volume_has_feature($storecfg, 'clone', $drive->{file}, $snapname, $running);
			}
			$drives->{$opt} = $drive;
			next if PVE::QemuServer::drive_is_cloudinit($drive);
			push @$vollist, $drive->{file};
		    }
		} else {
		    # copy everything else
		    $newconf->{$opt} = $value;
		}
	    }

	    return ($conffile, $newconf, $oldconf, $vollist, $drives, $fullclone);
	};

	my $clonefn = sub {
	    my ($conffile, $newconf, $oldconf, $vollist, $drives, $fullclone) = $load_and_check->();
	    my $storecfg = PVE::Storage::config();

	    # auto generate a new uuid
	    my $smbios1 = PVE::QemuServer::parse_smbios1($newconf->{smbios1} || '');
	    $smbios1->{uuid} = PVE::QemuServer::generate_uuid();
	    $newconf->{smbios1} = PVE::QemuServer::print_smbios1($smbios1);
	    # auto generate a new vmgenid only if the option was set for template
	    if ($newconf->{vmgenid}) {
		$newconf->{vmgenid} = PVE::QemuServer::generate_uuid();
	    }

	    delete $newconf->{template};

	    if ($param->{name}) {
		$newconf->{name} = $param->{name};
	    } else {
		$newconf->{name} = "Copy-of-VM-" . ($oldconf->{name} // $vmid);
	    }

	    if ($param->{description}) {
		$newconf->{description} = $param->{description};
	    }

	    # create empty/temp config - this fails if VM already exists on other node
	    # FIXME use PVE::QemuConfig->create_and_lock_config and adapt code
	    PVE::Tools::file_set_contents($conffile, "# qmclone temporary file\nlock: clone\n");

	    PVE::Firewall::clone_vmfw_conf($vmid, $newid);

	    my $newvollist = [];
	    my $jobs = {};

	    eval {
		local $SIG{INT} =
		    local $SIG{TERM} =
		    local $SIG{QUIT} =
		    local $SIG{HUP} = sub { die "interrupted by signal\n"; };

		PVE::Storage::activate_volumes($storecfg, $vollist, $snapname);

		my $bwlimit = extract_param($param, 'bwlimit');

		my $total_jobs = scalar(keys %{$drives});
		my $i = 1;

		foreach my $opt (sort keys %$drives) {
		    my $drive = $drives->{$opt};
		    my $skipcomplete = ($total_jobs != $i); # finish after last drive
		    my $completion = $skipcomplete ? 'skip' : 'complete';

		    my $src_sid = PVE::Storage::parse_volume_id($drive->{file});
		    my $storage_list = [ $src_sid ];
		    push @$storage_list, $storage if defined($storage);
		    my $clonelimit = PVE::Storage::get_bandwidth_limit('clone', $storage_list, $bwlimit);

		    my $newdrive = PVE::QemuServer::clone_disk(
			$storecfg,
			$vmid,
			$running,
			$opt,
			$drive,
			$snapname,
			$newid,
			$storage,
			$format,
			$fullclone->{$opt},
			$newvollist,
			$jobs,
			$completion,
			$oldconf->{agent},
			$clonelimit,
			$oldconf
		    );

		    $newconf->{$opt} = PVE::QemuServer::print_drive($newdrive);

		    PVE::QemuConfig->write_config($newid, $newconf);
		    $i++;
		}

		delete $newconf->{lock};

		# do not write pending changes
		if (my @changes = keys %{$newconf->{pending}}) {
		    my $pending = join(',', @changes);
		    warn "found pending changes for '$pending', discarding for clone\n";
		    delete $newconf->{pending};
		}

		PVE::QemuConfig->write_config($newid, $newconf);

		if ($target) {
		    # always deactivate volumes - avoid lvm LVs to be active on several nodes
		    PVE::Storage::deactivate_volumes($storecfg, $vollist, $snapname) if !$running;
		    PVE::Storage::deactivate_volumes($storecfg, $newvollist);

		    my $newconffile = PVE::QemuConfig->config_file($newid, $target);
		    die "Failed to move config to node '$target' - rename failed: $!\n"
			if !rename($conffile, $newconffile);
		}

		PVE::AccessControl::add_vm_to_pool($newid, $pool) if $pool;
	    };
	    if (my $err = $@) {
		eval { PVE::QemuServer::qemu_blockjobs_cancel($vmid, $jobs) };
		sleep 1; # some storage like rbd need to wait before release volume - really?

		foreach my $volid (@$newvollist) {
		    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
		    warn $@ if $@;
		}

		PVE::Firewall::remove_vmfw_conf($newid);

		unlink $conffile; # avoid races -> last thing before die

		die "clone failed: $err";
	    }

	    return;
	};

	# Aquire exclusive lock lock for $newid
	my $lock_target_vm = sub {
	    return PVE::QemuConfig->lock_config_full($newid, 1, $clonefn);
	};

	my $lock_source_vm = sub {
	    # exclusive lock if VM is running - else shared lock is enough;
	    if ($running) {
		return PVE::QemuConfig->lock_config_full($vmid, 1, $lock_target_vm);
	    } else {
		return PVE::QemuConfig->lock_config_shared($vmid, 1, $lock_target_vm);
	    }
	};

	$load_and_check->(); # early checks before forking/locking

	return $rpcenv->fork_worker('qmclone', $vmid, $authuser, $lock_source_vm);
    }});

__PACKAGE__->register_method({
    name => 'move_vm_disk',
    path => '{vmid}/move_disk',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Move volume to different storage or to a different VM.",
    permissions => {
	description => "You need 'VM.Config.Disk' permissions on /vms/{vmid}, " .
	    "and 'Datastore.AllocateSpace' permissions on the storage. To move ".
	    "a disk to another VM, you need the permissions on the target VM as well.",
	check => ['perm', '/vms/{vmid}', [ 'VM.Config.Disk' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    'target-vmid' => get_standard_option('pve-vmid', {
		completion => \&PVE::QemuServer::complete_vmid,
		optional => 1,
	    }),
	    disk => {
	        type => 'string',
		description => "The disk you want to move.",
		enum => [PVE::QemuServer::Drive::valid_drive_names_with_unused()],
	    },
            storage => get_standard_option('pve-storage-id', {
		description => "Target storage.",
		completion => \&PVE::QemuServer::complete_storage,
		optional => 1,
            }),
	    'format' => {
		type => 'string',
		description => "Target Format.",
		enum => [ 'raw', 'qcow2', 'vmdk' ],
		optional => 1,
	    },
	    delete => {
		type => 'boolean',
		description => "Delete the original disk after successful copy. By default the"
		    ." original disk is kept as unused disk.",
		optional => 1,
		default => 0,
	    },
	    digest => {
		type => 'string',
		description => 'Prevent changes if current configuration file has different SHA1"
		    ." digest. This can be used to prevent concurrent modifications.',
		maxLength => 40,
		optional => 1,
	    },
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'integer',
		minimum => '0',
		default => 'move limit from datacenter or storage config',
	    },
	    'target-disk' => {
	        type => 'string',
		description => "The config key the disk will be moved to on the target VM"
		    ." (for example, ide0 or scsi1). Default is the source disk key.",
		enum => [PVE::QemuServer::Drive::valid_drive_names_with_unused()],
		optional => 1,
	    },
	    'target-digest' => {
		type => 'string',
		description => 'Prevent changes if the current config file of the target VM has a"
		    ." different SHA1 digest. This can be used to detect concurrent modifications.',
		maxLength => 40,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');
	my $vmid = extract_param($param, 'vmid');
	my $target_vmid = extract_param($param, 'target-vmid');
	my $digest = extract_param($param, 'digest');
	my $target_digest = extract_param($param, 'target-digest');
	my $disk = extract_param($param, 'disk');
	my $target_disk = extract_param($param, 'target-disk') // $disk;
	my $storeid = extract_param($param, 'storage');
	my $format = extract_param($param, 'format');

	my $storecfg = PVE::Storage::config();

	my $load_and_check_move = sub {
	    my $conf = PVE::QemuConfig->load_config($vmid);
	    PVE::QemuConfig->check_lock($conf);

	    PVE::Tools::assert_if_modified($digest, $conf->{digest});

	    die "disk '$disk' does not exist\n" if !$conf->{$disk};

	    my $drive = PVE::QemuServer::parse_drive($disk, $conf->{$disk});

	    die "disk '$disk' has no associated volume\n" if !$drive->{file};
	    die "you can't move a cdrom\n" if PVE::QemuServer::drive_is_cdrom($drive, 1);

	    my $old_volid = $drive->{file};
	    my $oldfmt;
	    my ($oldstoreid, $oldvolname) = PVE::Storage::parse_volume_id($old_volid);
	    if ($oldvolname =~ m/\.(raw|qcow2|vmdk)$/){
		$oldfmt = $1;
	    }

	    die "you can't move to the same storage with same format\n"
		if $oldstoreid eq $storeid && (!$format || !$oldfmt || $oldfmt eq $format);

	    # this only checks snapshots because $disk is passed!
	    my $snapshotted = PVE::QemuServer::Drive::is_volume_in_use(
		$storecfg,
		$conf,
		$disk,
		$old_volid
	    );
	    die "you can't move a disk with snapshots and delete the source\n"
		if $snapshotted && $param->{delete};

	    return ($conf, $drive, $oldstoreid, $snapshotted);
	};

	my $move_updatefn = sub {
	    my ($conf, $drive, $oldstoreid, $snapshotted) = $load_and_check_move->();
	    my $old_volid = $drive->{file};

	    PVE::Cluster::log_msg(
		'info',
		$authuser,
		"move disk VM $vmid: move --disk $disk --storage $storeid"
	    );

	    my $running = PVE::QemuServer::check_running($vmid);

	    PVE::Storage::activate_volumes($storecfg, [ $drive->{file} ]);

	    my $newvollist = [];

	    eval {
		local $SIG{INT} =
		    local $SIG{TERM} =
		    local $SIG{QUIT} =
		    local $SIG{HUP} = sub { die "interrupted by signal\n"; };

		warn "moving disk with snapshots, snapshots will not be moved!\n"
		    if $snapshotted;

		my $bwlimit = extract_param($param, 'bwlimit');
		my $movelimit = PVE::Storage::get_bandwidth_limit(
		    'move',
		    [$oldstoreid, $storeid],
		    $bwlimit
		);

		my $newdrive = PVE::QemuServer::clone_disk(
		    $storecfg,
		    $vmid,
		    $running,
		    $disk,
		    $drive,
		    undef,
		    $vmid,
		    $storeid,
		    $format,
		    1,
		    $newvollist,
		    undef,
		    undef,
		    undef,
		    $movelimit,
		    $conf,
		);
		$conf->{$disk} = PVE::QemuServer::print_drive($newdrive);

		PVE::QemuConfig->add_unused_volume($conf, $old_volid) if !$param->{delete};

		# convert moved disk to base if part of template
		PVE::QemuServer::template_create($vmid, $conf, $disk)
		    if PVE::QemuConfig->is_template($conf);

		PVE::QemuConfig->write_config($vmid, $conf);

		my $do_trim = PVE::QemuServer::get_qga_key($conf, 'fstrim_cloned_disks');
		if ($running && $do_trim && PVE::QemuServer::qga_check_running($vmid)) {
		    eval { mon_cmd($vmid, "guest-fstrim") };
		}

		eval {
		    # try to deactivate volumes - avoid lvm LVs to be active on several nodes
		    PVE::Storage::deactivate_volumes($storecfg, [ $newdrive->{file} ])
			if !$running;
		};
		warn $@ if $@;
	    };
	    if (my $err = $@) {
		foreach my $volid (@$newvollist) {
		    eval { PVE::Storage::vdisk_free($storecfg, $volid) };
		    warn $@ if $@;
		}
		die "storage migration failed: $err";
	    }

	    if ($param->{delete}) {
		eval {
		    PVE::Storage::deactivate_volumes($storecfg, [$old_volid]);
		    PVE::Storage::vdisk_free($storecfg, $old_volid);
		};
		warn $@ if $@;
	    }
	};

	my $load_and_check_reassign_configs = sub {
	    my $vmlist = PVE::Cluster::get_vmlist()->{ids};

	    die "could not find VM ${vmid}\n" if !exists($vmlist->{$vmid});
	    die "could not find target VM ${target_vmid}\n" if !exists($vmlist->{$target_vmid});

	    my $source_node = $vmlist->{$vmid}->{node};
	    my $target_node = $vmlist->{$target_vmid}->{node};

	    die "Both VMs need to be on the same node ($source_node != $target_node)\n"
		if $source_node ne $target_node;

	    my $source_conf = PVE::QemuConfig->load_config($vmid);
	    PVE::QemuConfig->check_lock($source_conf);
	    my $target_conf = PVE::QemuConfig->load_config($target_vmid);
	    PVE::QemuConfig->check_lock($target_conf);

	    die "Can't move disks from or to template VMs\n"
		if ($source_conf->{template} || $target_conf->{template});

	    if ($digest) {
		eval { PVE::Tools::assert_if_modified($digest, $source_conf->{digest}) };
		die "VM ${vmid}: $@" if $@;
	    }

	    if ($target_digest) {
		eval { PVE::Tools::assert_if_modified($target_digest, $target_conf->{digest}) };
		die "VM ${target_vmid}: $@" if $@;
	    }

	    die "Disk '${disk}' for VM '$vmid' does not exist\n" if !defined($source_conf->{$disk});

	    die "Target disk key '${target_disk}' is already in use for VM '$target_vmid'\n"
		if $target_conf->{$target_disk};

	    my $drive = PVE::QemuServer::parse_drive(
		$disk,
		$source_conf->{$disk},
	    );
	    die "failed to parse source disk - $@\n" if !$drive;

	    my $source_volid = $drive->{file};

	    die "disk '${disk}' has no associated volume\n" if !$source_volid;
	    die "CD drive contents can't be moved to another VM\n"
		if PVE::QemuServer::drive_is_cdrom($drive, 1);

	    my $storeid = PVE::Storage::parse_volume_id($source_volid, 1);
	    die "Volume '$source_volid' not managed by PVE\n" if !defined($storeid);

	    die "Can't move disk used by a snapshot to another VM\n"
		if PVE::QemuServer::Drive::is_volume_in_use($storecfg, $source_conf, $disk, $source_volid);
	    die "Storage does not support moving of this disk to another VM\n"
		if (!PVE::Storage::volume_has_feature($storecfg, 'rename', $source_volid));
	    die "Cannot move disk to another VM while the source VM is running - detach first\n"
		if PVE::QemuServer::check_running($vmid) && $disk !~ m/^unused\d+$/;

	    # now re-parse using target disk slot format
	    if ($target_disk =~ /^unused\d+$/) {
		$drive = PVE::QemuServer::parse_drive(
		    $target_disk,
		    $source_volid,
		);
	    } else {
		$drive = PVE::QemuServer::parse_drive(
		    $target_disk,
		    $source_conf->{$disk},
		);
	    }
	    die "failed to parse source disk for target disk format - $@\n" if !$drive;

	    my $repl_conf = PVE::ReplicationConfig->new();
	    if ($repl_conf->check_for_existing_jobs($target_vmid, 1)) {
		my $format = (PVE::Storage::parse_volname($storecfg, $source_volid))[6];
		die "Cannot move disk to a replicated VM. Storage does not support replication!\n"
		    if !PVE::Storage::storage_can_replicate($storecfg, $storeid, $format);
	    }

	    return ($source_conf, $target_conf, $drive);
	};

	my $logfunc = sub {
	    my ($msg) = @_;
	    print STDERR "$msg\n";
	};

	my $disk_reassignfn = sub {
	    return PVE::QemuConfig->lock_config($vmid, sub {
		return PVE::QemuConfig->lock_config($target_vmid, sub {
		    my ($source_conf, $target_conf, $drive) = &$load_and_check_reassign_configs();

		    my $source_volid = $drive->{file};

		    print "moving disk '$disk' from VM '$vmid' to '$target_vmid'\n";
		    my ($storeid, $source_volname) = PVE::Storage::parse_volume_id($source_volid);

		    my $fmt = (PVE::Storage::parse_volname($storecfg, $source_volid))[6];

		    my $new_volid = PVE::Storage::rename_volume(
			$storecfg,
			$source_volid,
			$target_vmid,
		    );

		    $drive->{file} = $new_volid;

		    delete $source_conf->{$disk};
		    print "removing disk '${disk}' from VM '${vmid}' config\n";
		    PVE::QemuConfig->write_config($vmid, $source_conf);

		    my $drive_string = PVE::QemuServer::print_drive($drive);

		    if ($target_disk =~ /^unused\d+$/) {
			$target_conf->{$target_disk} = $drive_string;
			PVE::QemuConfig->write_config($target_vmid, $target_conf);
		    } else {
			&$update_vm_api(
			    {
				node => $node,
				vmid => $target_vmid,
				digest => $target_digest,
				$target_disk => $drive_string,
			    },
			    1,
			);
		    }

		    # remove possible replication snapshots
		    if (PVE::Storage::volume_has_feature(
			    $storecfg,
			    'replicate',
			    $source_volid),
		    ) {
			eval {
			    PVE::Replication::prepare(
				$storecfg,
				[$new_volid],
				undef,
				1,
				undef,
				$logfunc,
			    )
			};
			if (my $err = $@) {
			    print "Failed to remove replication snapshots on moved disk " .
				"'$target_disk'. Manual cleanup could be necessary.\n";
			}
		    }
		});
	    });
	};

	if ($target_vmid && $storeid) {
	    my $msg = "either set 'storage' or 'target-vmid', but not both";
	    raise_param_exc({ 'target-vmid' => $msg, 'storage' => $msg });
	} elsif ($target_vmid) {
	    $rpcenv->check_vm_perm($authuser, $target_vmid, undef, ['VM.Config.Disk'])
		if $authuser ne 'root@pam';

	    raise_param_exc({ 'target-vmid' => "must be different than source VMID to reassign disk" })
		if $vmid eq $target_vmid;

	    my (undef, undef, $drive) = &$load_and_check_reassign_configs();
	    my $storage = PVE::Storage::parse_volume_id($drive->{file});
	    $rpcenv->check($authuser, "/storage/$storage", ['Datastore.AllocateSpace']);

	    return $rpcenv->fork_worker(
		'qmmove',
		"${vmid}-${disk}>${target_vmid}-${target_disk}",
		$authuser,
		$disk_reassignfn
	    );
	} elsif ($storeid) {
	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

	    die "cannot move disk '$disk', only configured disks can be moved to another storage\n"
		if $disk =~ m/^unused\d+$/;

	    $load_and_check_move->(); # early checks before forking/locking

	    my $realcmd = sub {
		PVE::QemuConfig->lock_config($vmid, $move_updatefn);
	    };

	    return $rpcenv->fork_worker('qmmove', $vmid, $authuser, $realcmd);
	} else {
	    my $msg = "both 'storage' and 'target-vmid' missing, either needs to be set";
	    raise_param_exc({ 'target-vmid' => $msg, 'storage' => $msg });
	}
    }});

my $check_vm_disks_local = sub {
    my ($storecfg, $vmconf, $vmid) = @_;

    my $local_disks = {};

    # add some more information to the disks e.g. cdrom
    PVE::QemuServer::foreach_volid($vmconf, sub {
	my ($volid, $attr) = @_;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);
	if ($storeid) {
	    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	    return if $scfg->{shared};
	}
	# The shared attr here is just a special case where the vdisk
	# is marked as shared manually
	return if $attr->{shared};
	return if $attr->{cdrom} and $volid eq "none";

	if (exists $local_disks->{$volid}) {
	    @{$local_disks->{$volid}}{keys %$attr} = values %$attr
	} else {
	    $local_disks->{$volid} = $attr;
	    # ensure volid is present in case it's needed
	    $local_disks->{$volid}->{volid} = $volid;
	}
    });

    return $local_disks;
};

__PACKAGE__->register_method({
    name => 'migrate_vm_precondition',
    path => '{vmid}/migrate',
    method => 'GET',
    protected => 1,
    proxyto => 'node',
    description => "Get preconditions for migration.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Migrate' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    target => get_standard_option('pve-node', {
		description => "Target node.",
		completion =>  \&PVE::Cluster::complete_migration_target,
		optional => 1,
	    }),
	},
    },
    returns => {
	type => "object",
	properties => {
	    running => { type => 'boolean' },
	    allowed_nodes => {
		type => 'array',
		optional => 1,
		description => "List nodes allowed for offline migration, only passed if VM is offline"
	    },
	    not_allowed_nodes => {
		type => 'object',
		optional => 1,
		description => "List not allowed nodes with additional informations, only passed if VM is offline"
	    },
	    local_disks => {
		type => 'array',
		description => "List local disks including CD-Rom, unsused and not referenced disks"
	    },
	    local_resources => {
		type => 'array',
		description => "List local resources e.g. pci, usb"
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	PVE::Cluster::check_cfs_quorum();

	my $res = {};

	my $vmid = extract_param($param, 'vmid');
	my $target = extract_param($param, 'target');
	my $localnode = PVE::INotify::nodename();


	# test if VM exists
	my $vmconf = PVE::QemuConfig->load_config($vmid);
	my $storecfg = PVE::Storage::config();


	# try to detect errors early
	PVE::QemuConfig->check_lock($vmconf);

	$res->{running} = PVE::QemuServer::check_running($vmid) ? 1:0;

	# if vm is not running, return target nodes where local storage is available
	# for offline migration
	if (!$res->{running}) {
	    $res->{allowed_nodes} = [];
	    my $checked_nodes = PVE::QemuServer::check_local_storage_availability($vmconf, $storecfg);
	    delete $checked_nodes->{$localnode};

	    foreach my $node (keys %$checked_nodes) {
		if (!defined $checked_nodes->{$node}->{unavailable_storages}) {
		    push @{$res->{allowed_nodes}}, $node;
		}

	    }
	    $res->{not_allowed_nodes} = $checked_nodes;
	}


	my $local_disks = &$check_vm_disks_local($storecfg, $vmconf, $vmid);
	$res->{local_disks} = [ values %$local_disks ];;

	my $local_resources =  PVE::QemuServer::check_local_resources($vmconf, 1);

	$res->{local_resources} = $local_resources;

	return $res;


    }});

__PACKAGE__->register_method({
    name => 'migrate_vm',
    path => '{vmid}/migrate',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Migrate virtual machine. Creates a new migration task.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Migrate' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    target => get_standard_option('pve-node', {
		description => "Target node.",
		completion =>  \&PVE::Cluster::complete_migration_target,
            }),
	    online => {
		type => 'boolean',
		description => "Use online/live migration if VM is running. Ignored if VM is stopped.",
		optional => 1,
	    },
	    force => {
		type => 'boolean',
		description => "Allow to migrate VMs which use local devices. Only root may use this option.",
		optional => 1,
	    },
	    migration_type => {
		type => 'string',
		enum => ['secure', 'insecure'],
		description => "Migration traffic is encrypted using an SSH tunnel by default. On secure, completely private networks this can be disabled to increase performance.",
		optional => 1,
	    },
	    migration_network => {
		type => 'string', format => 'CIDR',
		description => "CIDR of the (sub) network that is used for migration.",
		optional => 1,
	    },
	    "with-local-disks" => {
		type => 'boolean',
		description => "Enable live storage migration for local disk",
		optional => 1,
	    },
            targetstorage => get_standard_option('pve-targetstorage', {
		completion => \&PVE::QemuServer::complete_migration_storage,
            }),
	    bwlimit => {
		description => "Override I/O bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'integer',
		minimum => '0',
		default => 'migrate limit from datacenter or storage config',
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $target = extract_param($param, 'target');

	my $localnode = PVE::INotify::nodename();
	raise_param_exc({ target => "target is local node."}) if $target eq $localnode;

	PVE::Cluster::check_cfs_quorum();

	PVE::Cluster::check_node_exists($target);

	my $targetip = PVE::Cluster::remote_node_ip($target);

	my $vmid = extract_param($param, 'vmid');

	raise_param_exc({ force => "Only root may use this option." })
	    if $param->{force} && $authuser ne 'root@pam';

	raise_param_exc({ migration_type => "Only root may use this option." })
	    if $param->{migration_type} && $authuser ne 'root@pam';

	# allow root only until better network permissions are available
	raise_param_exc({ migration_network => "Only root may use this option." })
	    if $param->{migration_network} && $authuser ne 'root@pam';

	# test if VM exists
	my $conf = PVE::QemuConfig->load_config($vmid);

	# try to detect errors early

	PVE::QemuConfig->check_lock($conf);

	if (PVE::QemuServer::check_running($vmid)) {
	    die "can't migrate running VM without --online\n" if !$param->{online};

	    my $repl_conf = PVE::ReplicationConfig->new();
	    my $is_replicated = $repl_conf->check_for_existing_jobs($vmid, 1);
	    my $is_replicated_to_target = defined($repl_conf->find_local_replication_job($vmid, $target));
	    if (!$param->{force} && $is_replicated && !$is_replicated_to_target) {
		die "Cannot live-migrate replicated VM to node '$target' - not a replication " .
		    "target. Use 'force' to override.\n";
	    }
	} else {
	    warn "VM isn't running. Doing offline migration instead.\n" if $param->{online};
	    $param->{online} = 0;
	}

	my $storecfg = PVE::Storage::config();
	if (my $targetstorage = $param->{targetstorage}) {
	    my $storagemap = eval { PVE::JSONSchema::parse_idmap($targetstorage, 'pve-storage-id') };
	    raise_param_exc({ targetstorage => "failed to parse storage map: $@" })
		if $@;

	    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk'])
		if !defined($storagemap->{identity});

	    foreach my $target_sid (values %{$storagemap->{entries}}) {
		$check_storage_access_migrate->($rpcenv, $authuser, $storecfg, $target_sid, $target);
	    }

	    $check_storage_access_migrate->($rpcenv, $authuser, $storecfg, $storagemap->{default}, $target)
		if $storagemap->{default};

	    PVE::QemuServer::check_storage_availability($storecfg, $conf, $target)
		if $storagemap->{identity};

	    $param->{storagemap} = $storagemap;
        } else {
	    PVE::QemuServer::check_storage_availability($storecfg, $conf, $target);
	}

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		print "Requesting HA migration for VM $vmid to node $target\n";

		my $cmd = ['ha-manager', 'migrate', "vm:$vmid", $target];
		PVE::Tools::run_command($cmd);
		return;
	    };

	    return $rpcenv->fork_worker('hamigrate', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		PVE::QemuMigrate->migrate($target, $targetip, $vmid, $param);
	    };

	    my $worker = sub {
		return PVE::GuestHelpers::guest_migration_lock($vmid, 10, $realcmd);
	    };

	    return $rpcenv->fork_worker('qmigrate', $vmid, $authuser, $worker);
	}

    }});

__PACKAGE__->register_method({
    name => 'monitor',
    path => '{vmid}/monitor',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Execute Qemu monitor commands.",
    permissions => {
	description => "Sys.Modify is required for (sub)commands which are not read-only ('info *' and 'help')",
        check => ['perm', '/vms/{vmid}', [ 'VM.Monitor' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    command => {
		type => 'string',
		description => "The monitor command.",
	    }
	},
    },
    returns => { type => 'string'},
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $is_ro = sub {
	    my $command = shift;
	    return $command =~ m/^\s*info(\s+|$)/
	        || $command =~ m/^\s*help\s*$/;
	};

	$rpcenv->check_full($authuser, "/", ['Sys.Modify'])
	    if !&$is_ro($param->{command});

	my $vmid = $param->{vmid};

	my $conf = PVE::QemuConfig->load_config ($vmid); # check if VM exists

	my $res = '';
	eval {
	    $res = PVE::QemuServer::Monitor::hmp_cmd($vmid, $param->{command});
	};
	$res = "ERROR: $@" if $@;

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'resize_vm',
    path => '{vmid}/resize',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Extend volume size.",
    permissions => {
        check => ['perm', '/vms/{vmid}', [ 'VM.Config.Disk' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    skiplock => get_standard_option('skiplock'),
	    disk => {
		type => 'string',
		description => "The disk you want to resize.",
		enum => [PVE::QemuServer::Drive::valid_drive_names()],
	    },
	    size => {
		type => 'string',
		pattern => '\+?\d+(\.\d+)?[KMGT]?',
		description => "The new size. With the `+` sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.",
	    },
	    digest => {
		type => 'string',
		description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
		maxLength => 40,
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();

        my $authuser = $rpcenv->get_user();

        my $node = extract_param($param, 'node');

        my $vmid = extract_param($param, 'vmid');

        my $digest = extract_param($param, 'digest');

        my $disk = extract_param($param, 'disk');

	my $sizestr = extract_param($param, 'size');

	my $skiplock = extract_param($param, 'skiplock');
        raise_param_exc({ skiplock => "Only root may use this option." })
            if $skiplock && $authuser ne 'root@pam';

        my $storecfg = PVE::Storage::config();

        my $updatefn =  sub {

            my $conf = PVE::QemuConfig->load_config($vmid);

            die "checksum missmatch (file change by other user?)\n"
                if $digest && $digest ne $conf->{digest};
            PVE::QemuConfig->check_lock($conf) if !$skiplock;

	    die "disk '$disk' does not exist\n" if !$conf->{$disk};

	    my $drive = PVE::QemuServer::parse_drive($disk, $conf->{$disk});

	    my (undef, undef, undef, undef, undef, undef, $format) =
		PVE::Storage::parse_volname($storecfg, $drive->{file});

	    die "can't resize volume: $disk if snapshot exists\n"
		if %{$conf->{snapshots}} && $format eq 'qcow2';

	    my $volid = $drive->{file};

	    die "disk '$disk' has no associated volume\n" if !$volid;

	    die "you can't resize a cdrom\n" if PVE::QemuServer::drive_is_cdrom($drive);

	    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

	    PVE::Storage::activate_volumes($storecfg, [$volid]);
	    my $size = PVE::Storage::volume_size_info($storecfg, $volid, 5);

	    die "Could not determine current size of volume '$volid'\n" if !defined($size);

	    die "internal error" if $sizestr !~ m/^(\+)?(\d+(\.\d+)?)([KMGT])?$/;
	    my ($ext, $newsize, $unit) = ($1, $2, $4);
	    if ($unit) {
		if ($unit eq 'K') {
		    $newsize = $newsize * 1024;
		} elsif ($unit eq 'M') {
		    $newsize = $newsize * 1024 * 1024;
		} elsif ($unit eq 'G') {
		    $newsize = $newsize * 1024 * 1024 * 1024;
		} elsif ($unit eq 'T') {
		    $newsize = $newsize * 1024 * 1024 * 1024 * 1024;
		}
	    }
	    $newsize += $size if $ext;
	    $newsize = int($newsize);

	    die "shrinking disks is not supported\n" if $newsize < $size;

	    return if $size == $newsize;

            PVE::Cluster::log_msg('info', $authuser, "update VM $vmid: resize --disk $disk --size $sizestr");

	    PVE::QemuServer::qemu_block_resize($vmid, "drive-$disk", $storecfg, $volid, $newsize);

	    $drive->{size} = $newsize;
	    $conf->{$disk} = PVE::QemuServer::print_drive($drive);

	    PVE::QemuConfig->write_config($vmid, $conf);
	};

        PVE::QemuConfig->lock_config($vmid, $updatefn);
        return;
    }});

__PACKAGE__->register_method({
    name => 'snapshot_list',
    path => '{vmid}/snapshot',
    method => 'GET',
    description => "List all snapshots.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    proxyto => 'node',
    protected => 1, # qemu pid files are only readable by root
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		name => {
		    description => "Snapshot identifier. Value 'current' identifies the current VM.",
		    type => 'string',
		},
		vmstate => {
		    description => "Snapshot includes RAM.",
		    type => 'boolean',
		    optional => 1,
		},
		description => {
		    description => "Snapshot description.",
		    type => 'string',
		},
		snaptime => {
		    description => "Snapshot creation time",
		    type => 'integer',
		    renderer => 'timestamp',
		    optional => 1,
		},
		parent => {
		    description => "Parent snapshot identifier.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	my $conf = PVE::QemuConfig->load_config($vmid);
	my $snaphash = $conf->{snapshots} || {};

	my $res = [];

	foreach my $name (keys %$snaphash) {
	    my $d = $snaphash->{$name};
	    my $item = {
		name => $name,
		snaptime => $d->{snaptime} || 0,
		vmstate => $d->{vmstate} ? 1 : 0,
		description => $d->{description} || '',
	    };
	    $item->{parent} = $d->{parent} if $d->{parent};
	    $item->{snapstate} = $d->{snapstate} if $d->{snapstate};
	    push @$res, $item;
	}

	my $running = PVE::QemuServer::check_running($vmid, 1) ? 1 : 0;
	my $current = {
	    name => 'current',
	    digest => $conf->{digest},
	    running => $running,
	    description => "You are here!",
	};
	$current->{parent} = $conf->{parent} if $conf->{parent};

	push @$res, $current;

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'snapshot',
    path => '{vmid}/snapshot',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Snapshot a VM.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    snapname => get_standard_option('pve-snapshot-name'),
	    vmstate => {
		optional => 1,
		type => 'boolean',
		description => "Save the vmstate",
	    },
	    description => {
		optional => 1,
		type => 'string',
		description => "A textual description or comment.",
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	die "unable to use snapshot name 'current' (reserved name)\n"
	    if $snapname eq 'current';

	die "unable to use snapshot name 'pending' (reserved name)\n"
	    if lc($snapname) eq 'pending';

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "snapshot VM $vmid: $snapname");
	    PVE::QemuConfig->snapshot_create($vmid, $snapname, $param->{vmstate},
					     $param->{description});
	};

	return $rpcenv->fork_worker('qmsnapshot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'snapshot_cmd_idx',
    path => '{vmid}/snapshot/{snapname}',
    description => '',
    method => 'GET',
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid'),
	    node => get_standard_option('pve-node'),
	    snapname => get_standard_option('pve-snapshot-name'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{cmd}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	push @$res, { cmd => 'rollback' };
	push @$res, { cmd => 'config' };

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'update_snapshot_config',
    path => '{vmid}/snapshot/{snapname}/config',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Update snapshot metadata.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-snapshot-name'),
	    description => {
		optional => 1,
		type => 'string',
		description => "A textual description or comment.",
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	return if !defined($param->{description});

	my $updatefn =  sub {

	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_lock($conf);

	    my $snap = $conf->{snapshots}->{$snapname};

	    die "snapshot '$snapname' does not exist\n" if !defined($snap);

	    $snap->{description} = $param->{description} if defined($param->{description});

	     PVE::QemuConfig->write_config($vmid, $conf);
	};

	PVE::QemuConfig->lock_config($vmid, $updatefn);

	return;
    }});

__PACKAGE__->register_method({
    name => 'get_snapshot_config',
    path => '{vmid}/snapshot/{snapname}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get snapshot configuration",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot', 'VM.Snapshot.Rollback', 'VM.Audit' ], any => 1],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-snapshot-name'),
	},
    },
    returns => { type => "object" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $conf = PVE::QemuConfig->load_config($vmid);

	my $snap = $conf->{snapshots}->{$snapname};

	die "snapshot '$snapname' does not exist\n" if !defined($snap);

	return $snap;
    }});

__PACKAGE__->register_method({
    name => 'rollback',
    path => '{vmid}/snapshot/{snapname}/rollback',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Rollback VM state to specified snapshot.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot', 'VM.Snapshot.Rollback' ], any => 1],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    snapname => get_standard_option('pve-snapshot-name'),
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "rollback snapshot VM $vmid: $snapname");
	    PVE::QemuConfig->snapshot_rollback($vmid, $snapname);
	};

	my $worker = sub {
	    # hold migration lock, this makes sure that nobody create replication snapshots
	    return PVE::GuestHelpers::guest_migration_lock($vmid, 10, $realcmd);
	};

	return $rpcenv->fork_worker('qmrollback', $vmid, $authuser, $worker);
    }});

__PACKAGE__->register_method({
    name => 'delsnapshot',
    path => '{vmid}/snapshot/{snapname}',
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Delete a VM snapshot.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    snapname => get_standard_option('pve-snapshot-name'),
	    force => {
		optional => 1,
		type => 'boolean',
		description => "For removal from config file, even if removing disk snapshots fails.",
	    },
	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $snapname = extract_param($param, 'snapname');

	my $realcmd = sub {
	    PVE::Cluster::log_msg('info', $authuser, "delete snapshot VM $vmid: $snapname");
	    PVE::QemuConfig->snapshot_delete($vmid, $snapname, $param->{force});
	};

	return $rpcenv->fork_worker('qmdelsnapshot', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'template',
    path => '{vmid}/template',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Create a Template.",
    permissions => {
	description => "You need 'VM.Allocate' permissions on /vms/{vmid}",
	check => [ 'perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_stopped }),
	    disk => {
		optional => 1,
		type => 'string',
		description => "If you want to convert only 1 disk to base image.",
		enum => [PVE::QemuServer::Drive::valid_drive_names()],
	    },

	},
    },
    returns => {
	type => 'string',
	description => "the task ID.",
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $disk = extract_param($param, 'disk');

	my $load_and_check = sub {
	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_lock($conf);

	    die "unable to create template, because VM contains snapshots\n"
		if $conf->{snapshots} && scalar(keys %{$conf->{snapshots}});

	    die "you can't convert a template to a template\n"
		if PVE::QemuConfig->is_template($conf) && !$disk;

	    die "you can't convert a VM to template if VM is running\n"
		if PVE::QemuServer::check_running($vmid);

	    return $conf;
	};

	$load_and_check->();

	my $realcmd = sub {
	    PVE::QemuConfig->lock_config($vmid, sub {
		my $conf = $load_and_check->();

		$conf->{template} = 1;
		PVE::QemuConfig->write_config($vmid, $conf);

		PVE::QemuServer::template_create($vmid, $conf, $disk);
	    });
	};

	return $rpcenv->fork_worker('qmtemplate', $vmid, $authuser, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'cloudinit_generated_config_dump',
    path => '{vmid}/cloudinit/dump',
    method => 'GET',
    proxyto => 'node',
    description => "Get automatically generated cloudinit config.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    type => {
		description => 'Config type.',
		type => 'string',
		enum => ['user', 'network', 'meta'],
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $conf = PVE::QemuConfig->load_config($param->{vmid});

	return PVE::QemuServer::Cloudinit::dump_cloudinit_config($conf, $param->{vmid}, $param->{type});
    }});

1;
