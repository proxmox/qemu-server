package PVE::API2::Qemu;

use strict;
use warnings;
use Cwd 'abs_path';
use Net::SSLeay;
use UUID;
use POSIX;
use IO::Socket::IP;
use URI::Escape;

use PVE::Cluster qw (cfs_read_file cfs_write_file);;
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
use PVE::QemuMigrate;
use PVE::RPCEnvironment;
use PVE::AccessControl;
use PVE::INotify;
use PVE::Network;
use PVE::Firewall;
use PVE::API2::Firewall::VM;
use PVE::API2::Qemu::Agent;

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

   PVE::QemuServer::foreach_drive($settings, sub {
	my ($ds, $drive) = @_;

	my $isCDROM = PVE::QemuServer::drive_is_cdrom($drive);

	my $volid = $drive->{file};

	if (!$volid || ($volid eq 'none' || $volid eq 'cloudinit')) {
	    # nothing to check
	} elsif ($volid =~ m/^(([^:\s]+):)?(cloudinit)$/) {
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

   PVE::QemuServer::foreach_drive($conf, sub {
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

# Note: $pool is only needed when creating a VM, because pool permissions
# are automatically inherited if VM already exists inside a pool.
my $create_disks = sub {
    my ($rpcenv, $authuser, $conf, $storecfg, $vmid, $pool, $settings, $default_storage) = @_;

    my $vollist = [];

    my $res = {};

    my $code = sub {
	my ($ds, $disk) = @_;

	my $volid = $disk->{file};

	if (!$volid || $volid eq 'none' || $volid eq 'cdrom') {
	    delete $disk->{size};
	    $res->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	} elsif ($volid =~ m!^(?:([^/:\s]+):)?cloudinit$!) {
	    my $storeid = $1 || $default_storage;
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	    my $name = "vm-$vmid-cloudinit";
	    my $fmt = undef;
	    if ($scfg->{path}) {
		$name .= ".qcow2";
		$fmt = 'qcow2';
	    }else{
		$fmt = 'raw';
	    }
	    # FIXME: Reasonable size? qcow2 shouldn't grow if the space isn't used anyway?
	    my $cloudinit_iso_size = 5; # in MB
	    my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, 
						  $fmt, $name, $cloudinit_iso_size*1024);
	    $disk->{file} = $volid;
	    $disk->{media} = 'cdrom';
	    push @$vollist, $volid;
	    delete $disk->{format}; # no longer needed
	    $res->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	} elsif ($volid =~ $NEW_DISK_RE) {
	    my ($storeid, $size) = ($2 || $default_storage, $3);
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    my $defformat = PVE::Storage::storage_default_format($storecfg, $storeid);
	    my $fmt = $disk->{format} || $defformat;

	    $size = PVE::Tools::convert_size($size, 'gb' => 'kb'); # vdisk_alloc uses kb

	    my $volid;
	    if ($ds eq 'efidisk0') {
		($volid, $size) = PVE::QemuServer::create_efidisk($storecfg, $storeid, $vmid, $fmt);
	    } else {
		$volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $fmt, undef, $size);
	    }
	    push @$vollist, $volid;
	    $disk->{file} = $volid;
	    $disk->{size} = PVE::Tools::convert_size($size, 'kb' => 'b');
	    delete $disk->{format}; # no longer needed
	    $res->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	} else {

	    PVE::Storage::check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $volid);

	    my $volid_is_new = 1;

	    if ($conf->{$ds}) {
		my $olddrive = PVE::QemuServer::parse_drive($ds, $conf->{$ds});
		$volid_is_new = undef if $olddrive->{file} && $olddrive->{file} eq $volid;
	    }

	    if ($volid_is_new) {

		my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

		PVE::Storage::activate_volumes($storecfg, [ $volid ]) if $storeid;

		my $size = PVE::Storage::volume_size_info($storecfg, $volid);

		die "volume $volid does not exists\n" if !$size;

		$disk->{size} = $size;
	    }

	    $res->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	}
    };

    eval { PVE::QemuServer::foreach_drive($settings, $code); };

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
    cipassword => 1,
    citype => 1,
    ciuser => 1,
    nameserver => 1,
    searchdomain => 1,
    sshkeys => 1,
};

my $check_vm_modify_config_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $key_list) = @_;

    return 1 if $authuser eq 'root@pam';

    foreach my $opt (@$key_list) {
	# disk checks need to be done somewhere else
	next if PVE::QemuServer::is_valid_drivename($opt);
	next if $opt eq 'cdrom';
	next if $opt =~ m/^unused\d+$/;

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
	} elsif ($cloudinitoptions->{$opt} || ($opt =~ m/^(?:net|ipconfig)\d+$/)) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	} else {
	    # catches usb\d+, hostpci\d+, args, lock, etc.
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
	    properties => {},
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
	    $data->{vmid} = int($vmid);
	    push @$res, $data;
	}

	return $res;
    }});



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
		    description => "The backup file.",
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
		pool => {
		    optional => 1,
		    type => 'string', format => 'pve-poolid',
		    description => "Add the VM to the specified pool.",
		},
		bwlimit => {
		    description => "Override i/o bandwidth limit (in KiB/s).",
		    optional => 1,
		    type => 'integer',
		    minimum => '0',
		}
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

	my $storage = extract_param($param, 'storage');

	my $force = extract_param($param, 'force');

	my $unique = extract_param($param, 'unique');

	my $pool = extract_param($param, 'pool');

	my $bwlimit = extract_param($param, 'bwlimit');

	my $filename = PVE::QemuConfig->config_file($vmid);

	my $storecfg = PVE::Storage::config();

	if (defined(my $ssh_keys = $param->{sshkeys})) {
		$ssh_keys = URI::Escape::uri_unescape($ssh_keys);
		PVE::Tools::validate_ssh_public_keys($ssh_keys);
	}

	PVE::Cluster::check_cfs_quorum();

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

	    foreach my $opt (keys %$param) {
		if (PVE::QemuServer::is_valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
		    raise_param_exc({ $opt => "unable to parse drive options" }) if !$drive;

		    PVE::QemuServer::cleanup_drive_path($opt, $storecfg, $drive);
		    $param->{$opt} = PVE::QemuServer::print_drive($vmid, $drive);
		}
	    }

	    PVE::QemuServer::add_random_macs($param);
	} else {
	    my $keystr = join(' ', keys %$param);
	    raise_param_exc({ archive => "option conflicts with other options ($keystr)"}) if $keystr;

	    if ($archive eq '-') {
		die "pipe requires cli environment\n"
		    if $rpcenv->{type} ne 'cli';
	    } else {
		PVE::Storage::check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $archive);
		$archive = PVE::Storage::abs_filesystem_path($storecfg, $archive);
	    }
	}

	my $restorefn = sub {
	    my $vmlist = PVE::Cluster::get_vmlist();
	    if ($vmlist->{ids}->{$vmid}) {
		my $current_node = $vmlist->{ids}->{$vmid}->{node};
		if ($current_node eq $node) {
		    my $conf = PVE::QemuConfig->load_config($vmid);

		    PVE::QemuConfig->check_protection($conf, "unable to restore VM $vmid");

		    die "unable to restore vm $vmid - config file already exists\n"
			if !$force;

		    die "unable to restore vm $vmid - vm is running\n"
			if PVE::QemuServer::check_running($vmid);

		    die "unable to restore vm $vmid - vm is a template\n"
			if PVE::QemuConfig->is_template($conf);

		} else {
		    die "unable to restore vm $vmid - already existing on cluster node '$current_node'\n";
		}
	    }

	    my $realcmd = sub {
		PVE::QemuServer::restore_archive($archive, $vmid, $authuser, {
		    storage => $storage,
		    pool => $pool,
		    unique => $unique,
		    bwlimit => $bwlimit, });

		PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
	    };

	    # ensure no old replication state are exists
	    PVE::ReplicationState::delete_guest_states($vmid);

	    return $rpcenv->fork_worker('qmrestore', $vmid, $authuser, $realcmd);
	};

	my $createfn = sub {

	    # test after locking
	    PVE::Cluster::check_vmid_unused($vmid);

	    # ensure no old replication state are exists
	    PVE::ReplicationState::delete_guest_states($vmid);

	    my $realcmd = sub {

		my $vollist = [];

		my $conf = $param;

		eval {

		    $vollist = &$create_disks($rpcenv, $authuser, $conf, $storecfg, $vmid, $pool, $param, $storage);

		    if (!$conf->{bootdisk}) {
			my $firstdisk = PVE::QemuServer::resolve_first_disk($conf);
			$conf->{bootdisk} = $firstdisk if $firstdisk;
		    }

		    # auto generate uuid if user did not specify smbios1 option
		    if (!$conf->{smbios1}) {
			$conf->{smbios1} = PVE::QemuServer::generate_smbios1_uuid();
		    }

		    PVE::QemuConfig->write_config($vmid, $conf);

		};
		my $err = $@;

		if ($err) {
		    foreach my $volid (@$vollist) {
			eval { PVE::Storage::vdisk_free($storecfg, $volid); };
			warn $@ if $@;
		    }
		    die "create failed - $err";
		}

		PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
	    };

	    return $rpcenv->fork_worker('qmcreate', $vmid, $authuser, $realcmd);
	};

	return PVE::QemuConfig->lock_config_full($vmid, 1, $archive ? $restorefn : $createfn);
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

	return PVE::Cluster::create_rrd_graph(
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

	return PVE::Cluster::create_rrd_data(
	    "pve2-vm/$param->{vmid}", $param->{timeframe}, $param->{cf});
    }});


__PACKAGE__->register_method({
    name => 'vm_config',
    path => '{vmid}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get current virtual machine configuration. This does not include pending configuration changes (see 'pending' API).",
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
	},
    },
    returns => {
	type => "object",
	properties => {
	    digest => {
		type => 'string',
		description => 'SHA1 digest of configuration file. This can be used to prevent concurrent modifications.',
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	my $conf = PVE::QemuConfig->load_config($param->{vmid});

	delete $conf->{snapshots};

	if (!$param->{current}) {
	    foreach my $opt (keys %{$conf->{pending}}) {
		next if $opt eq 'delete';
		my $value = $conf->{pending}->{$opt};
		next if ref($value); # just to be sure
		$conf->{$opt} = $value;
	    }
	    my $pending_delete_hash = PVE::QemuServer::split_flagged_list($conf->{pending}->{delete});
	    foreach my $opt (keys %$pending_delete_hash) {
		delete $conf->{$opt} if $conf->{$opt};
	    }
	}

	delete $conf->{pending};

	# hide cloudinit password
	if ($conf->{cipassword}) {
	    $conf->{cipassword} = '**********';
	}

	return $conf;
    }});

__PACKAGE__->register_method({
    name => 'vm_pending',
    path => '{vmid}/pending',
    method => 'GET',
    proxyto => 'node',
    description => "Get virtual machine configuration, including pending changes.",
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

	my $pending_delete_hash = PVE::QemuServer::split_flagged_list($conf->{pending}->{delete});

	my $res = [];

	foreach my $opt (keys %$conf) {
	    next if ref($conf->{$opt});
	    my $item = { key => $opt };
	    $item->{value} = $conf->{$opt} if defined($conf->{$opt});
	    $item->{pending} = $conf->{pending}->{$opt} if defined($conf->{pending}->{$opt});
	    $item->{delete} = ($pending_delete_hash->{$opt} ? 2 : 1) if exists $pending_delete_hash->{$opt};

	    # hide cloudinit password
	    if ($opt eq 'cipassword') {
		$item->{value} = '**********' if defined($item->{value});
		# the trailing space so that the pending string is different
		$item->{pending} = '********** ' if defined($item->{pending});
	    }
	    push @$res, $item;
	}

	foreach my $opt (keys %{$conf->{pending}}) {
	    next if $opt eq 'delete';
	    next if ref($conf->{pending}->{$opt}); # just to be sure
	    next if defined($conf->{$opt});
	    my $item = { key => $opt };
	    $item->{pending} = $conf->{pending}->{$opt};

	    # hide cloudinit password
	    if ($opt eq 'cipassword') {
		$item->{pending} = '**********' if defined($item->{pending});
	    }
	    push @$res, $item;
	}

	while (my ($opt, $force) = each %$pending_delete_hash) {
	    next if $conf->{pending}->{$opt}; # just to be sure
	    next if $conf->{$opt};
	    my $item = { key => $opt, delete => ($force ? 2 : 1)};
	    push @$res, $item;
	}

	return $res;
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
	my ($storeid, $format);
	if ($volid =~ $NEW_DISK_RE) {
	    $storeid = $2;
	    $format = $drive->{format} || PVE::Storage::storage_default_format($storecfg, $storeid);
	} else {
	    ($storeid, undef) = PVE::Storage::parse_volume_id($volid, 1);
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
	    $param->{$opt} = PVE::QemuServer::print_drive($vmid, $drive);
	} elsif ($opt =~ m/^net(\d+)$/) {
	    # add macaddr
	    my $net = PVE::QemuServer::parse_net($param->{$opt});
	    $param->{$opt} = PVE::QemuServer::print_net($net);
	}
    }

    &$check_vm_modify_config_perm($rpcenv, $authuser, $vmid, undef, [@delete]);

    &$check_vm_modify_config_perm($rpcenv, $authuser, $vmid, undef, [keys %$param]);

    &$check_storage_access($rpcenv, $authuser, $storecfg, $vmid, $param);

    my $updatefn =  sub {

	my $conf = PVE::QemuConfig->load_config($vmid);

	die "checksum missmatch (file change by other user?)\n"
	    if $digest && $digest ne $conf->{digest};

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

	    foreach my $opt (@delete) {
		$modified->{$opt} = 1;
		$conf = PVE::QemuConfig->load_config($vmid); # update/reload
		if (!defined($conf->{$opt}) && !defined($conf->{pending}->{$opt})) {
		    warn "cannot delete '$opt' - not set in current configuration!\n";
		    $modified->{$opt} = 0;
		    next;
		}

		if ($opt =~ m/^unused/) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
		    PVE::QemuConfig->check_protection($conf, "can't remove unused disk '$drive->{file}'");
		    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
		    if (PVE::QemuServer::try_deallocate_drive($storecfg, $vmid, $conf, $opt, $drive, $rpcenv, $authuser)) {
			delete $conf->{$opt};
			PVE::QemuConfig->write_config($vmid, $conf);
		    }
		} elsif (PVE::QemuServer::is_valid_drivename($opt)) {
		    PVE::QemuConfig->check_protection($conf, "can't remove drive '$opt'");
		    $rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
		    PVE::QemuServer::vmconfig_register_unused_drive($storecfg, $vmid, $conf, PVE::QemuServer::parse_drive($opt, $conf->{pending}->{$opt}))
			if defined($conf->{pending}->{$opt});
		    PVE::QemuServer::vmconfig_delete_pending_option($conf, $opt, $force);
		    PVE::QemuConfig->write_config($vmid, $conf);
		} else {
		    PVE::QemuServer::vmconfig_delete_pending_option($conf, $opt, $force);
		    PVE::QemuConfig->write_config($vmid, $conf);
		}
	    }

	    foreach my $opt (keys %$param) { # add/change
		$modified->{$opt} = 1;
		$conf = PVE::QemuConfig->load_config($vmid); # update/reload
		next if defined($conf->{pending}->{$opt}) && ($param->{$opt} eq $conf->{pending}->{$opt}); # skip if nothing changed

		if (PVE::QemuServer::is_valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
		    # FIXME: cloudinit: CDROM or Disk?
		    if (PVE::QemuServer::drive_is_cdrom($drive)) { # CDROM
			$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.CDROM']);
		    } else {
			$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
		    }
		    PVE::QemuServer::vmconfig_register_unused_drive($storecfg, $vmid, $conf, PVE::QemuServer::parse_drive($opt, $conf->{pending}->{$opt}))
			if defined($conf->{pending}->{$opt});

		    &$create_disks($rpcenv, $authuser, $conf->{pending}, $storecfg, $vmid, undef, {$opt => $param->{$opt}});
		} else {
		    $conf->{pending}->{$opt} = $param->{$opt};
		}
		PVE::QemuServer::vmconfig_undelete_pending_option($conf, $opt);
		PVE::QemuConfig->write_config($vmid, $conf);
	    }

	    # remove pending changes when nothing changed
	    $conf = PVE::QemuConfig->load_config($vmid); # update/reload
	    my $changes = PVE::QemuServer::vmconfig_cleanup_pending($conf);
	    PVE::QemuConfig->write_config($vmid, $conf) if $changes;

	    return if !scalar(keys %{$conf->{pending}});

	    my $running = PVE::QemuServer::check_running($vmid);

	    # apply pending changes

	    $conf = PVE::QemuConfig->load_config($vmid); # update/reload

	    if ($running) {
		my $errors = {};
		PVE::QemuServer::vmconfig_hotplug_pending($vmid, $conf, $storecfg, $modified, $errors);
		raise_param_exc($errors) if scalar(keys %$errors);
	    } else {
		PVE::QemuServer::vmconfig_apply_pending($vmid, $conf, $storecfg, $running);
	    }

	    return;
	};

	if ($sync) {
	    &$worker();
	    return undef;
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
		    return undef if $status eq 'OK';
		    die $status;
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
	return undef;
    }
});


__PACKAGE__->register_method({
    name => 'destroy_vm',
    path => '{vmid}',
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Destroy the vm (also delete all used/owned volumes).",
    permissions => {
	check => [ 'perm', '/vms/{vmid}', ['VM.Allocate']],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_stopped }),
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

	my $vmid = $param->{vmid};

	my $skiplock = $param->{skiplock};
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	# test if VM exists
	my $conf = PVE::QemuConfig->load_config($vmid);

	my $storecfg = PVE::Storage::config();

	PVE::QemuConfig->check_protection($conf, "can't remove VM $vmid");

	die "unable to remove VM $vmid - used in HA resources\n"
	    if PVE::HA::Config::vm_is_ha_managed($vmid);

	# do not allow destroy if there are replication jobs
	my $repl_conf = PVE::ReplicationConfig->new();
	$repl_conf->check_for_existing_jobs($vmid);

	# early tests (repeat after locking)
	die "VM $vmid is running - destroy failed\n"
	    if PVE::QemuServer::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "destroy VM $vmid: $upid\n");

	    PVE::QemuServer::vm_destroy($storecfg, $vmid, $skiplock);

	    PVE::AccessControl::remove_vm_access($vmid);

            PVE::Firewall::remove_vmfw_conf($vmid);
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

	return undef;
    }});

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
	},
    },
    returns => {
    	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
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

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

	$sslcert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192)
	    if !$sslcert;

	my ($remip, $family);
	my $remcmd = [];

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    ($remip, $family) = PVE::Cluster::remote_node_ip($node);
	    # NOTE: kvm VNC traffic is already TLS encrypted or is known unsecure
	    $remcmd = ['/usr/bin/ssh', '-e', 'none', '-T', '-o', 'BatchMode=yes', $remip];
	} else {
	    $family = PVE::Tools::get_host_address_family($node);
	}

	my $port = PVE::Tools::next_vnc_port($family);

	my $timeout = 10;

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "starting vnc proxy $upid\n");

	    my $cmd;

	    if ($conf->{vga} && ($conf->{vga} =~ m/^serial\d+$/)) {


		my $termcmd = [ '/usr/sbin/qm', 'terminal', $vmid, '-iface', $conf->{vga}, '-escape', '0' ];

		$cmd = ['/usr/bin/vncterm', '-rfbport', $port,
			'-timeout', $timeout, '-authpath', $authpath,
			'-perm', 'Sys.Console'];

		if ($param->{websocket}) {
		    $ENV{PVE_VNC_TICKET} = $ticket; # pass ticket to vncterm
		    push @$cmd, '-notls', '-listen', 'localhost';
		}

		push @$cmd, '-c', @$remcmd, @$termcmd;

		PVE::Tools::run_command($cmd);

	    } else {

		$ENV{LC_PVE_TICKET} = $ticket if $websocket; # set ticket with "qm vncproxy"

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

	return {
	    user => $authuser,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	    cert => $sslcert,
	};
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
	    if ($conf->{vga} && $conf->{vga} =~ m/^serial\d+$/) {
		$serial = $conf->{vga};
	    }
	}

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

	my ($remip, $family);

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    ($remip, $family) = PVE::Cluster::remote_node_ip($node);
	} else {
	    $family = PVE::Tools::get_host_address_family($node);
	}

	my $port = PVE::Tools::next_vnc_port($family);

	my $remcmd = $remip ?
	    ['/usr/bin/ssh', '-e', 'none', '-t', $remip, '--'] : [];

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

	PVE::QemuServer::vm_mon_cmd($vmid, "set_password", protocol => 'spice', password => $ticket);
	PVE::QemuServer::vm_mon_cmd($vmid, "expire_password", protocol => 'spice', time => "+30");

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
    returns => { type => 'object' },
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::QemuConfig->load_config($param->{vmid});

	my $vmstatus = PVE::QemuServer::vmstatus($param->{vmid}, 1);
	my $status = $vmstatus->{$param->{vmid}};

	$status->{ha} = PVE::HA::Config::get_service_status("vm:$param->{vmid}");

	$status->{spice} = 1 if PVE::QemuServer::vga_conf_has_spice($conf->{vga});

	$status->{agent} = 1 if $conf->{agent};

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
	    machine => get_standard_option('pve-qm-machine'),
	    targetstorage => {
		description => "Target storage for the migration. (Can be '1' to use the same storage id as on the source node.)",
		type => 'string',
		optional => 1
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

	my $machine = extract_param($param, 'machine');

	my $stateuri = extract_param($param, 'stateuri');
	raise_param_exc({ stateuri => "Only root may use this option." })
	    if $stateuri && $authuser ne 'root@pam';

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $migratedfrom = extract_param($param, 'migratedfrom');
	raise_param_exc({ migratedfrom => "Only root may use this option." })
	    if $migratedfrom && $authuser ne 'root@pam';

	my $migration_type = extract_param($param, 'migration_type');
	raise_param_exc({ migration_type => "Only root may use this option." })
	    if $migration_type && $authuser ne 'root@pam';

	my $migration_network = extract_param($param, 'migration_network');
	raise_param_exc({ migration_network => "Only root may use this option." })
	    if $migration_network && $authuser ne 'root@pam';

	my $targetstorage = extract_param($param, 'targetstorage');
	raise_param_exc({ targetstorage => "Only root may use this option." })
	    if $targetstorage && $authuser ne 'root@pam';

	raise_param_exc({ targetstorage => "targetstorage can only by used with migratedfrom." })
	    if $targetstorage && !$migratedfrom;

	# read spice ticket from STDIN
	my $spice_ticket;
	if ($stateuri && ($stateuri eq 'tcp') && $migratedfrom && ($rpcenv->{type} eq 'cli')) {
	    if (defined(my $line = <STDIN>)) {
		chomp $line;
		$spice_ticket = $line;
	    }
	}

	PVE::Cluster::check_cfs_quorum();

	my $storecfg = PVE::Storage::config();

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && !$stateuri &&
	    $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "vm:$vmid";

		my $cmd = ['ha-manager', 'set', $service, '--state', 'started'];

		print "Requesting HA start for VM $vmid\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hastart', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "start VM $vmid: $upid\n");

		PVE::QemuServer::vm_start($storecfg, $vmid, $stateuri, $skiplock, $migratedfrom, undef,
					  $machine, $spice_ticket, $migration_network, $migration_type, $targetstorage);

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

		my $service = "vm:$vmid";

		my $cmd = ['ha-manager', 'set', $service, '--state', 'stopped'];

		print "Requesting HA stop for VM $vmid\n";

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
	my $qmpstatus;
	eval {
	    $qmpstatus = PVE::QemuServer::vm_qmp_command($vmid, { execute => "query-status" }, 0);
	};
	my $err = $@ if $@;

	if (!$err && $qmpstatus->{status} eq "paused") {
	    if ($param->{forceStop}) {
		warn "VM is paused - stop instead of shutdown\n";
		$shutdown = 0;
	    } else {
		die "VM is paused - cannot shutdown\n";
	    }
	}

	if (PVE::HA::Config::vm_is_ha_managed($vmid) &&
	    ($rpcenv->{type} ne 'ha')) {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "vm:$vmid";

		my $cmd = ['ha-manager', 'set', $service, '--state', 'stopped'];

		print "Requesting HA stop for VM $vmid\n";

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
    name => 'vm_suspend',
    path => '{vmid}/status/suspend',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Suspend virtual machine.",
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

	    syslog('info', "suspend VM $vmid: $upid\n");

	    PVE::QemuServer::vm_suspend($vmid, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmsuspend', $vmid, $authuser, $realcmd);
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

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid, $nocheck);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "resume VM $vmid: $upid\n");

	    PVE::QemuServer::vm_resume($vmid, $skiplock, $nocheck);

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

	if (defined($pool)) {
	    $rpcenv->check_pool_exist($pool);
	}

        my $snapname = extract_param($param, 'snapname');

	my $storage = extract_param($param, 'storage');

	my $format = extract_param($param, 'format');

	my $target = extract_param($param, 'target');

        my $localnode = PVE::INotify::nodename();

        undef $target if $target && ($target eq $localnode || $target eq 'localhost');

	PVE::Cluster::check_node_exists($target) if $target;

	my $storecfg = PVE::Storage::config();

	if ($storage) {
	    # check if storage is enabled on local node
	    PVE::Storage::storage_check_enabled($storecfg, $storage);
	    if ($target) {
		# check if storage is available on target node
		PVE::Storage::storage_check_node($storecfg, $storage, $target);
		# clone only works if target storage is shared
		my $scfg = PVE::Storage::storage_config($storecfg, $storage);
		die "can't clone to non-shared storage '$storage'\n" if !$scfg->{shared};
	    }
	}

        PVE::Cluster::check_cfs_quorum();

	my $running = PVE::QemuServer::check_running($vmid) || 0;

	# exclusive lock if VM is running - else shared lock is enough;
	my $shared_lock = $running ? 0 : 1;

	my $clonefn = sub {

	    # do all tests after lock
	    # we also try to do all tests before we fork the worker

	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_lock($conf);

	    my $verify_running = PVE::QemuServer::check_running($vmid) || 0;

	    die "unexpected state change\n" if $verify_running != $running;

	    die "snapshot '$snapname' does not exist\n"
		if $snapname && !defined( $conf->{snapshots}->{$snapname});

	    my $full = extract_param($param, 'full');
	    if (!defined($full)) {
		$full = !PVE::QemuConfig->is_template($conf);
	    }

	    die "parameter 'storage' not allowed for linked clones\n"
		if defined($storage) && !$full;

	    die "parameter 'format' not allowed for linked clones\n"
		if defined($format) && !$full;

	    my $oldconf = $snapname ? $conf->{snapshots}->{$snapname} : $conf;

	    my $sharedvm = &$check_storage_access_clone($rpcenv, $authuser, $storecfg, $oldconf, $storage);

	    die "can't clone VM to node '$target' (VM uses local storage)\n" if $target && !$sharedvm;

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
			push @$vollist, $drive->{file};
		    }
		} else {
		    # copy everything else
		    $newconf->{$opt} = $value;
		}
	    }

            # auto generate a new uuid
            my ($uuid, $uuid_str);
            UUID::generate($uuid);
            UUID::unparse($uuid, $uuid_str);
	    my $smbios1 = PVE::QemuServer::parse_smbios1($newconf->{smbios1} || '');
	    $smbios1->{uuid} = $uuid_str;
	    $newconf->{smbios1} = PVE::QemuServer::print_smbios1($smbios1);

	    delete $newconf->{template};

	    if ($param->{name}) {
		$newconf->{name} = $param->{name};
	    } else {
		if ($oldconf->{name}) {
		    $newconf->{name} = "Copy-of-$oldconf->{name}";
		} else {
		    $newconf->{name} = "Copy-of-VM-$vmid";
		}
	    }

	    if ($param->{description}) {
		$newconf->{description} = $param->{description};
	    }

	    # create empty/temp config - this fails if VM already exists on other node
	    PVE::Tools::file_set_contents($conffile, "# qmclone temporary file\nlock: clone\n");

	    my $realcmd = sub {
		my $upid = shift;

		my $newvollist = [];
		my $jobs = {};

		eval {
		    local $SIG{INT} =
			local $SIG{TERM} =
			local $SIG{QUIT} =
			local $SIG{HUP} = sub { die "interrupted by signal\n"; };

		    PVE::Storage::activate_volumes($storecfg, $vollist, $snapname);

		    my $total_jobs = scalar(keys %{$drives});
		    my $i = 1;

		    foreach my $opt (keys %$drives) {
			my $drive = $drives->{$opt};
			my $skipcomplete = ($total_jobs != $i); # finish after last drive

			my $newdrive = PVE::QemuServer::clone_disk($storecfg, $vmid, $running, $opt, $drive, $snapname,
								   $newid, $storage, $format, $fullclone->{$opt}, $newvollist,
								   $jobs, $skipcomplete, $oldconf->{agent});

			$newconf->{$opt} = PVE::QemuServer::print_drive($vmid, $newdrive);

			PVE::QemuConfig->write_config($newid, $newconf);
			$i++;
		    }

		    delete $newconf->{lock};

		    # do not write pending changes
		    if ($newconf->{pending}) {
			warn "found pending changes, discarding for clone\n";
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
		    unlink $conffile;

		    eval { PVE::QemuServer::qemu_blockjobs_cancel($vmid, $jobs) };

		    sleep 1; # some storage like rbd need to wait before release volume - really?

		    foreach my $volid (@$newvollist) {
			eval { PVE::Storage::vdisk_free($storecfg, $volid); };
			warn $@ if $@;
		    }
		    die "clone failed: $err";
		}

		return;
	    };

	    PVE::Firewall::clone_vmfw_conf($vmid, $newid);

	    return $rpcenv->fork_worker('qmclone', $vmid, $authuser, $realcmd);
	};

	return PVE::QemuConfig->lock_config_mode($vmid, 1, $shared_lock, sub {
	    # Aquire exclusive lock lock for $newid
	    return PVE::QemuConfig->lock_config_full($newid, 1, $clonefn);
	});

    }});

__PACKAGE__->register_method({
    name => 'move_vm_disk',
    path => '{vmid}/move_disk',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Move volume to different storage.",
    permissions => {
	description => "You need 'VM.Config.Disk' permissions on /vms/{vmid}, and 'Datastore.AllocateSpace' permissions on the storage.",
	check => [ 'and',
		   ['perm', '/vms/{vmid}', [ 'VM.Config.Disk' ]],
		   ['perm', '/storage/{storage}', [ 'Datastore.AllocateSpace' ]],
	    ],
    },
    parameters => {
        additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    disk => {
	        type => 'string',
		description => "The disk you want to move.",
		enum => [ PVE::QemuServer::valid_drive_names() ],
	    },
            storage => get_standard_option('pve-storage-id', {
		description => "Target storage.",
		completion => \&PVE::QemuServer::complete_storage,
            }),
            'format' => {
                type => 'string',
                description => "Target Format.",
                enum => [ 'raw', 'qcow2', 'vmdk' ],
                optional => 1,
            },
	    delete => {
		type => 'boolean',
		description => "Delete the original disk after successful copy. By default the original disk is kept as unused disk.",
		optional => 1,
		default => 0,
	    },
	    digest => {
		type => 'string',
		description => 'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
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

	my $digest = extract_param($param, 'digest');

	my $disk = extract_param($param, 'disk');

	my $storeid = extract_param($param, 'storage');

	my $format = extract_param($param, 'format');

	my $storecfg = PVE::Storage::config();

	my $updatefn =  sub {

	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_lock($conf);

	    die "checksum missmatch (file change by other user?)\n"
		if $digest && $digest ne $conf->{digest};

	    die "disk '$disk' does not exist\n" if !$conf->{$disk};

	    my $drive = PVE::QemuServer::parse_drive($disk, $conf->{$disk});

	    my $old_volid = $drive->{file} || die "disk '$disk' has no associated volume\n";

	    die "you can't move a cdrom\n" if PVE::QemuServer::drive_is_cdrom($drive, 1);

	    my $oldfmt;
	    my ($oldstoreid, $oldvolname) = PVE::Storage::parse_volume_id($old_volid);
	    if ($oldvolname =~ m/\.(raw|qcow2|vmdk)$/){
		$oldfmt = $1;
	    }

	    die "you can't move on the same storage with same format\n" if $oldstoreid eq $storeid &&
                (!$format || !$oldfmt || $oldfmt eq $format);

	    # this only checks snapshots because $disk is passed!
	    my $snapshotted = PVE::QemuServer::is_volume_in_use($storecfg, $conf, $disk, $old_volid);
	    die "you can't move a disk with snapshots and delete the source\n"
		if $snapshotted && $param->{delete};

	    PVE::Cluster::log_msg('info', $authuser, "move disk VM $vmid: move --disk $disk --storage $storeid");

	    my $running = PVE::QemuServer::check_running($vmid);

	    PVE::Storage::activate_volumes($storecfg, [ $drive->{file} ]);

	    my $realcmd = sub {

		my $newvollist = [];

		eval {
		    local $SIG{INT} =
			local $SIG{TERM} =
			local $SIG{QUIT} =
			local $SIG{HUP} = sub { die "interrupted by signal\n"; };

		    warn "moving disk with snapshots, snapshots will not be moved!\n"
			if $snapshotted;

		    my $newdrive = PVE::QemuServer::clone_disk($storecfg, $vmid, $running, $disk, $drive, undef,
							       $vmid, $storeid, $format, 1, $newvollist);

		    $conf->{$disk} = PVE::QemuServer::print_drive($vmid, $newdrive);

		    PVE::QemuConfig->add_unused_volume($conf, $old_volid) if !$param->{delete};

		    # convert moved disk to base if part of template
		    PVE::QemuServer::template_create($vmid, $conf, $disk)
			if PVE::QemuConfig->is_template($conf);

		    PVE::QemuConfig->write_config($vmid, $conf);

		    eval {
			# try to deactivate volumes - avoid lvm LVs to be active on several nodes
			PVE::Storage::deactivate_volumes($storecfg, [ $newdrive->{file} ])
			    if !$running;
		    };
		    warn $@ if $@;
		};
		if (my $err = $@) {

                   foreach my $volid (@$newvollist) {
                        eval { PVE::Storage::vdisk_free($storecfg, $volid); };
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

            return $rpcenv->fork_worker('qmmove', $vmid, $authuser, $realcmd);
	};

	return PVE::QemuConfig->lock_config($vmid, $updatefn);
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
		description => "Use online/live migration.",
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
            targetstorage => get_standard_option('pve-storage-id', {
		description => "Default target storage.",
		optional => 1,
		completion => \&PVE::QemuServer::complete_storage,
            }),
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

	raise_param_exc({ targetstorage => "Live storage migration can only be done online." })
	    if !$param->{online} && $param->{targetstorage};

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
	    die "cant migrate running VM without --online\n"
		if !$param->{online};
	}

	my $storecfg = PVE::Storage::config();

	if( $param->{targetstorage}) {
	    PVE::Storage::storage_check_node($storecfg, $param->{targetstorage}, $target);
        } else {
	    PVE::QemuServer::check_storage_availability($storecfg, $conf, $target);
	}

	if (PVE::HA::Config::vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "vm:$vmid";

		my $cmd = ['ha-manager', 'migrate', $service, $target];

		print "Requesting HA migration for VM $vmid to node $target\n";

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
	    $res = PVE::QemuServer::vm_human_monitor_command($vmid, $param->{command});
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
		enum => [PVE::QemuServer::valid_drive_names()],
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
	    $conf->{$disk} = PVE::QemuServer::print_drive($vmid, $drive);

	    PVE::QemuConfig->write_config($vmid, $conf);
	};

        PVE::QemuConfig->lock_config($vmid, $updatefn);
        return undef;
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
	    properties => {},
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
	my $current = { name => 'current', digest => $conf->{digest}, running => $running };
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

	return undef if !defined($param->{description});

	my $updatefn =  sub {

	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_lock($conf);

	    my $snap = $conf->{snapshots}->{$snapname};

	    die "snapshot '$snapname' does not exist\n" if !defined($snap);

	    $snap->{description} = $param->{description} if defined($param->{description});

	     PVE::QemuConfig->write_config($vmid, $conf);
	};

	PVE::QemuConfig->lock_config($vmid, $updatefn);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'get_snapshot_config',
    path => '{vmid}/snapshot/{snapname}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get snapshot configuration",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot', 'VM.Snapshot.Rollback' ], any => 1],
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
		enum => [PVE::QemuServer::valid_drive_names()],
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

	my $disk = extract_param($param, 'disk');

	my $updatefn =  sub {

	    my $conf = PVE::QemuConfig->load_config($vmid);

	    PVE::QemuConfig->check_lock($conf);

	    die "unable to create template, because VM contains snapshots\n"
		if $conf->{snapshots} && scalar(keys %{$conf->{snapshots}});

	    die "you can't convert a template to a template\n"
		if PVE::QemuConfig->is_template($conf) && !$disk;

	    die "you can't convert a VM to template if VM is running\n"
		if PVE::QemuServer::check_running($vmid);

	    my $realcmd = sub {
		PVE::QemuServer::template_create($vmid, $conf, $disk);
	    };

	    $conf->{template} = 1;
	    PVE::QemuConfig->write_config($vmid, $conf);

	    return $rpcenv->fork_worker('qmtemplate', $vmid, $authuser, $realcmd);
	};

	PVE::QemuConfig->lock_config($vmid, $updatefn);
	return undef;
    }});

1;
