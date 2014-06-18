package PVE::API2::Qemu;

use strict;
use warnings;
use Cwd 'abs_path';
use Net::SSLeay;

use PVE::Cluster qw (cfs_read_file cfs_write_file);;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::Storage;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::QemuServer;
use PVE::QemuMigrate;
use PVE::RPCEnvironment;
use PVE::AccessControl;
use PVE::INotify;
use PVE::Network;
use PVE::API2::Firewall::VM;

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


my $check_storage_access = sub {
   my ($rpcenv, $authuser, $storecfg, $vmid, $settings, $default_storage) = @_;

   PVE::QemuServer::foreach_drive($settings, sub {
	my ($ds, $drive) = @_;

	my $isCDROM = PVE::QemuServer::drive_is_cdrom($drive);

	my $volid = $drive->{file};

	if (!$volid || $volid eq 'none') {
	    # nothing to check
	} elsif ($isCDROM && ($volid eq 'cdrom')) {
	    $rpcenv->check($authuser, "/", ['Sys.Console']);
	} elsif (!$isCDROM && ($volid =~ m/^(([^:\s]+):)?(\d+(\.\d+)?)$/)) {
	    my ($storeid, $size) = ($2 || $default_storage, $3);
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);
	} else {
	    $rpcenv->check_volume_access($authuser, $storecfg, $vmid, $volid);
	}
    });
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

   return $sharedvm;
};

# Note: $pool is only needed when creating a VM, because pool permissions
# are automatically inherited if VM already exists inside a pool.
my $create_disks = sub {
    my ($rpcenv, $authuser, $conf, $storecfg, $vmid, $pool, $settings, $default_storage) = @_;

    my $vollist = [];

    my $res = {};
    PVE::QemuServer::foreach_drive($settings, sub {
	my ($ds, $disk) = @_;

	my $volid = $disk->{file};

	if (!$volid || $volid eq 'none' || $volid eq 'cdrom') {
	    delete $disk->{size};
	    $res->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	} elsif ($volid =~ m/^(([^:\s]+):)?(\d+(\.\d+)?)$/) {
	    my ($storeid, $size) = ($2 || $default_storage, $3);
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    my $defformat = PVE::Storage::storage_default_format($storecfg, $storeid);
	    my $fmt = $disk->{format} || $defformat;
	    my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid,
						  $fmt, undef, $size*1024*1024);
	    $disk->{file} = $volid;
	    $disk->{size} = $size*1024*1024*1024;
	    push @$vollist, $volid;
	    delete $disk->{format}; # no longer needed
	    $res->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
	} else {

	    $rpcenv->check_volume_access($authuser, $storecfg, $vmid, $volid);

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
    });

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

my $check_vm_modify_config_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $key_list) = @_;

    return 1 if $authuser eq 'root@pam';

    foreach my $opt (@$key_list) {
	# disk checks need to be done somewhere else
	next if PVE::QemuServer::valid_drivename($opt);

	if ($opt eq 'sockets' || $opt eq 'cores' ||
	    $opt eq 'cpu' || $opt eq 'smp' ||
	    $opt eq 'cpulimit' || $opt eq 'cpuunits') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'boot' || $opt eq 'bootdisk') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	} elsif ($opt eq 'memory' || $opt eq 'balloon' || $opt eq 'shares') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($opt eq 'args' || $opt eq 'lock') {
	    die "only root can set '$opt' config\n";
	} elsif ($opt eq 'cpu' || $opt eq 'kvm' || $opt eq 'acpi' || $opt eq 'machine' ||
		 $opt eq 'vga' || $opt eq 'watchdog' || $opt eq 'tablet') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.HWType']);
	} elsif ($opt =~ m/^net\d+$/) {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Network']);
	} else {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Options']);
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

	my $vmstatus = PVE::QemuServer::vmstatus();

	my $res = [];
	foreach my $vmid (keys %$vmstatus) {
	    next if !$rpcenv->check($authuser, "/vms/$vmid", [ 'VM.Audit' ], 1);

	    my $data = $vmstatus->{$vmid};
	    $data->{vmid} = $vmid;
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
		vmid => get_standard_option('pve-vmid'),
		archive => {
		    description => "The backup file.",
		    type => 'string',
		    optional => 1,
		    maxLength => 255,
		},
		storage => get_standard_option('pve-storage-id', {
		    description => "Default storage.",
		    optional => 1,
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

	my $filename = PVE::QemuServer::config_file($vmid);

	my $storecfg = PVE::Storage::config();

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
		if (PVE::QemuServer::valid_drivename($opt)) {
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
		$rpcenv->check_volume_access($authuser, $storecfg, $vmid, $archive);
		$archive = PVE::Storage::abs_filesystem_path($storecfg, $archive);
	    }
	}

	my $restorefn = sub {

	    # fixme: this test does not work if VM exists on other node!
	    if (-f $filename) {
		die "unable to restore vm $vmid: config file already exists\n"
		    if !$force;

		die "unable to restore vm $vmid: vm is running\n"
		    if PVE::QemuServer::check_running($vmid);
	    }

	    my $realcmd = sub {
		PVE::QemuServer::restore_archive($archive, $vmid, $authuser, {
		    storage => $storage,
		    pool => $pool,
		    unique => $unique });

		PVE::AccessControl::add_vm_to_pool($vmid, $pool) if $pool;
	    };

	    return $rpcenv->fork_worker('qmrestore', $vmid, $authuser, $realcmd);
	};

	my $createfn = sub {

	    # test after locking
	    die "unable to create vm $vmid: config file already exists\n"
		if -f $filename;

	    my $realcmd = sub {

		my $vollist = [];

		my $conf = $param;

		eval {

		    $vollist = &$create_disks($rpcenv, $authuser, $conf, $storecfg, $vmid, $pool, $param, $storage);

		    # try to be smart about bootdisk
		    my @disks = PVE::QemuServer::disknames();
		    my $firstdisk;
		    foreach my $ds (reverse @disks) {
			next if !$conf->{$ds};
			my $disk = PVE::QemuServer::parse_drive($ds, $conf->{$ds});
			next if PVE::QemuServer::drive_is_cdrom($disk);
			$firstdisk = $ds;
		    }

		    if (!$conf->{bootdisk} && $firstdisk) {
			$conf->{bootdisk} = $firstdisk;
		    }

		    PVE::QemuServer::update_config_nolock($vmid, $conf);

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

	return PVE::QemuServer::lock_config_full($vmid, 1, $archive ? $restorefn : $createfn);
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
	    { subdir => 'status' },
	    { subdir => 'unlink' },
	    { subdir => 'vncproxy' },
	    { subdir => 'migrate' },
	    { subdir => 'resize' },
	    { subdir => 'move' },
	    { subdir => 'rrd' },
	    { subdir => 'rrddata' },
	    { subdir => 'monitor' },
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
    description => "Get virtual machine configuration.",
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

	my $conf = PVE::QemuServer::load_config($param->{vmid});

	delete $conf->{snapshots};

	return $conf;
    }});

my $vm_is_volid_owner = sub {
    my ($storecfg, $vmid, $volid) =@_;

    if ($volid !~  m|^/|) {
	my ($path, $owner);
	eval { ($path, $owner) = PVE::Storage::path($storecfg, $volid); };
	if ($owner && ($owner == $vmid)) {
	    return 1;
	}
    }

    return undef;
};

my $test_deallocate_drive = sub {
    my ($storecfg, $vmid, $key, $drive, $force) = @_;

    if (!PVE::QemuServer::drive_is_cdrom($drive)) {
	my $volid = $drive->{file};
	if (&$vm_is_volid_owner($storecfg, $vmid, $volid)) {
	    if ($force || $key =~ m/^unused/) {
		my $sid = PVE::Storage::parse_volume_id($volid);
		return $sid;
	    }
	}
    }

    return undef;
};

my $delete_drive = sub {
    my ($conf, $storecfg, $vmid, $key, $drive, $force) = @_;

    if (!PVE::QemuServer::drive_is_cdrom($drive)) {
	my $volid = $drive->{file};

	if (&$vm_is_volid_owner($storecfg, $vmid, $volid)) {
	    if ($force || $key =~ m/^unused/) {
		eval {
		    # check if the disk is really unused
		    my $used_paths = PVE::QemuServer::get_used_paths($vmid, $storecfg, $conf, 1, $key);
		    my $path = PVE::Storage::path($storecfg, $volid);

		    die "unable to delete '$volid' - volume is still in use (snapshot?)\n"
			if $used_paths->{$path};

		    PVE::Storage::vdisk_free($storecfg, $volid);
		};
		die $@ if $@;
	    } else {
		PVE::QemuServer::add_unused_volume($conf, $volid, $vmid);
	    }
	}
    }

    delete $conf->{$key};
};

my $vmconfig_delete_option = sub {
    my ($rpcenv, $authuser, $conf, $storecfg, $vmid, $opt, $force) = @_;

    return if !defined($conf->{$opt});

    my $isDisk = PVE::QemuServer::valid_drivename($opt)|| ($opt =~ m/^unused/);

    if ($isDisk) {
	$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);

	my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
	if (my $sid = &$test_deallocate_drive($storecfg, $vmid, $opt, $drive, $force)) {
	    $rpcenv->check($authuser, "/storage/$sid", ['Datastore.AllocateSpace']);
	}
    }

    my $unplugwarning = "";
    if ($conf->{ostype} && $conf->{ostype} eq 'l26') {
	$unplugwarning = "<br>verify that you have acpiphp && pci_hotplug modules loaded in your guest VM";
    } elsif ($conf->{ostype} && $conf->{ostype} eq 'l24') {
	$unplugwarning = "<br>kernel 2.4 don't support hotplug, please disable hotplug in options";
    } elsif (!$conf->{ostype} || ($conf->{ostype} && $conf->{ostype} eq 'other')) {
	$unplugwarning = "<br>verify that your guest support acpi hotplug";
    }

    if ($opt eq 'tablet') {
	PVE::QemuServer::vm_deviceplug(undef, $conf, $vmid, $opt);
    } else {
        die "error hot-unplug $opt $unplugwarning" if !PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);
    }

    if ($isDisk) {
	my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
	&$delete_drive($conf, $storecfg, $vmid, $opt, $drive, $force);
    } else {
	delete $conf->{$opt};
    }

    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);
};

my $safe_num_ne = sub {
    my ($a, $b) = @_;

    return 0 if !defined($a) && !defined($b);
    return 1 if !defined($a);
    return 1 if !defined($b);

    return $a != $b;
};

my $vmconfig_update_disk = sub {
    my ($rpcenv, $authuser, $conf, $storecfg, $vmid, $opt, $value, $force) = @_;

    my $drive = PVE::QemuServer::parse_drive($opt, $value);

    if (PVE::QemuServer::drive_is_cdrom($drive)) { #cdrom
	$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.CDROM']);
    } else {
	$rpcenv->check_vm_perm($authuser, $vmid, undef, ['VM.Config.Disk']);
    }

    if ($conf->{$opt}) {

	if (my $old_drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt}))  {

	    my $media = $drive->{media} || 'disk';
	    my $oldmedia = $old_drive->{media} || 'disk';
	    die "unable to change media type\n" if $media ne $oldmedia;

	    if (!PVE::QemuServer::drive_is_cdrom($old_drive) &&
		($drive->{file} ne $old_drive->{file})) {  # delete old disks

		&$vmconfig_delete_option($rpcenv, $authuser, $conf, $storecfg, $vmid, $opt, $force);
		$conf = PVE::QemuServer::load_config($vmid); # update/reload
	    }

            if(&$safe_num_ne($drive->{mbps}, $old_drive->{mbps}) ||
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
               PVE::QemuServer::qemu_block_set_io_throttle($vmid,"drive-$opt",
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
							   $drive->{iops_wr_max} || 0)
		   if !PVE::QemuServer::drive_is_cdrom($drive);
            }
	}
    }

    &$create_disks($rpcenv, $authuser, $conf, $storecfg, $vmid, undef, {$opt => $value});
    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);

    $conf = PVE::QemuServer::load_config($vmid); # update/reload
    $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});

    if (PVE::QemuServer::drive_is_cdrom($drive)) { # cdrom

	if (PVE::QemuServer::check_running($vmid)) {
	    if ($drive->{file} eq 'none') {
		PVE::QemuServer::vm_mon_cmd($vmid, "eject",force => JSON::true,device => "drive-$opt");
	    } else {
		my $path = PVE::QemuServer::get_iso_path($storecfg, $vmid, $drive->{file});
		PVE::QemuServer::vm_mon_cmd($vmid, "eject",force => JSON::true,device => "drive-$opt"); #force eject if locked
		PVE::QemuServer::vm_mon_cmd($vmid, "change",device => "drive-$opt",target => "$path") if $path;
	    }
	}

    } else { # hotplug new disks

	die "error hotplug $opt" if !PVE::QemuServer::vm_deviceplug($storecfg, $conf, $vmid, $opt, $drive);
    }
};

my $vmconfig_update_net = sub {
    my ($rpcenv, $authuser, $conf, $storecfg, $vmid, $opt, $value) = @_;

    if ($conf->{$opt} && PVE::QemuServer::check_running($vmid)) {
	my $oldnet = PVE::QemuServer::parse_net($conf->{$opt});
	my $newnet = PVE::QemuServer::parse_net($value);

	if($oldnet->{model} ne $newnet->{model}){
	    #if model change, we try to hot-unplug
            die "error hot-unplug $opt for update" if !PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);
	}else{

	    if($newnet->{bridge} && $oldnet->{bridge}){
		my $iface = "tap".$vmid."i".$1 if $opt =~ m/net(\d+)/;

		if($newnet->{rate} ne $oldnet->{rate}){
		    PVE::Network::tap_rate_limit($iface, $newnet->{rate});
		}

		if(($newnet->{bridge} ne $oldnet->{bridge}) || ($newnet->{tag} ne $oldnet->{tag}) || ($newnet->{firewall} ne $oldnet->{firewall})){
		    PVE::Network::tap_unplug($iface);
		    PVE::Network::tap_plug($iface, $newnet->{bridge}, $newnet->{tag}, $newnet->{firewall});
		}

	    }else{
		#if bridge/nat mode change, we try to hot-unplug
		die "error hot-unplug $opt for update" if !PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);
	    }
	}

    }
    $conf->{$opt} = $value;
    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);
    $conf = PVE::QemuServer::load_config($vmid); # update/reload

    my $net = PVE::QemuServer::parse_net($conf->{$opt});

    die "error hotplug $opt" if !PVE::QemuServer::vm_deviceplug($storecfg, $conf, $vmid, $opt, $net);
};

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

    my @paramarr = (); # used for log message
    foreach my $key (keys %$param) {
	push @paramarr, "-$key", $param->{$key};
    }

    my $skiplock = extract_param($param, 'skiplock');
    raise_param_exc({ skiplock => "Only root may use this option." })
	if $skiplock && $authuser ne 'root@pam';

    my $delete_str = extract_param($param, 'delete');

    my $force = extract_param($param, 'force');

    die "no options specified\n" if !$delete_str && !scalar(keys %$param);

    my $storecfg = PVE::Storage::config();

    my $defaults = PVE::QemuServer::load_defaults();

    &$resolve_cdrom_alias($param);

    # now try to verify all parameters

    my @delete = ();
    foreach my $opt (PVE::Tools::split_list($delete_str)) {
	$opt = 'ide2' if $opt eq 'cdrom';
	raise_param_exc({ delete => "you can't use '-$opt' and " .
			      "-delete $opt' at the same time" })
	    if defined($param->{$opt});

	if (!PVE::QemuServer::option_exists($opt)) {
	    raise_param_exc({ delete => "unknown option '$opt'" });
	}

	push @delete, $opt;
    }

    foreach my $opt (keys %$param) {
	if (PVE::QemuServer::valid_drivename($opt)) {
	    # cleanup drive path
	    my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
	    PVE::QemuServer::cleanup_drive_path($opt, $storecfg, $drive);
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

	my $conf = PVE::QemuServer::load_config($vmid);

	die "checksum missmatch (file change by other user?)\n"
	    if $digest && $digest ne $conf->{digest};

	PVE::QemuServer::check_lock($conf) if !$skiplock;

	if ($param->{memory} || defined($param->{balloon})) {
	    my $maxmem = $param->{memory} || $conf->{memory} || $defaults->{memory};
	    my $balloon = defined($param->{balloon}) ?  $param->{balloon} : $conf->{balloon};

	    die "balloon value too large (must be smaller than assigned memory)\n"
		if $balloon && $balloon > $maxmem;
	}

	PVE::Cluster::log_msg('info', $authuser, "update VM $vmid: " . join (' ', @paramarr));

	my $worker = sub {

	    print "update VM $vmid: " . join (' ', @paramarr) . "\n";

	    foreach my $opt (@delete) { # delete
		$conf = PVE::QemuServer::load_config($vmid); # update/reload
		&$vmconfig_delete_option($rpcenv, $authuser, $conf, $storecfg, $vmid, $opt, $force);
	    }

	    my $running = PVE::QemuServer::check_running($vmid);

	    foreach my $opt (keys %$param) { # add/change

		$conf = PVE::QemuServer::load_config($vmid); # update/reload

		next if $conf->{$opt} && ($param->{$opt} eq $conf->{$opt}); # skip if nothing changed

		if (PVE::QemuServer::valid_drivename($opt)) {

		    &$vmconfig_update_disk($rpcenv, $authuser, $conf, $storecfg, $vmid,
					   $opt, $param->{$opt}, $force);

		} elsif ($opt =~ m/^net(\d+)$/) { #nics

		    &$vmconfig_update_net($rpcenv, $authuser, $conf, $storecfg, $vmid,
					  $opt, $param->{$opt});

		} else {

		    if($opt eq 'tablet' && $param->{$opt} == 1){
			PVE::QemuServer::vm_deviceplug(undef, $conf, $vmid, $opt);
		    } elsif($opt eq 'tablet' && $param->{$opt} == 0){
			PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);
		    }
		
		    if($opt eq 'cores' && $conf->{maxcpus}){
			PVE::QemuServer::qemu_cpu_hotplug($vmid, $conf, $param->{$opt});
		    }

		    $conf->{$opt} = $param->{$opt};
		    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);
		}
	    }

	    # allow manual ballooning if shares is set to zero
	    if ($running && defined($param->{balloon}) &&
		defined($conf->{shares}) && ($conf->{shares} == 0)) {
		my $balloon = $param->{'balloon'} || $conf->{memory} || $defaults->{memory};
		PVE::QemuServer::vm_mon_cmd($vmid, "balloon", value => $balloon*1024*1024);
	    }
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

    return PVE::QemuServer::lock_config($vmid, $updatefn);
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
		vmid => get_standard_option('pve-vmid'),
		skiplock => get_standard_option('skiplock'),
		delete => {
		    type => 'string', format => 'pve-configid-list',
		    description => "A list of settings you want to delete.",
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
	    vmid => get_standard_option('pve-vmid'),
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
	my $conf = PVE::QemuServer::load_config($vmid);

	my $storecfg = PVE::Storage::config();

	my $delVMfromPoolFn = sub {
	    my $usercfg = cfs_read_file("user.cfg");
	    if (my $pool = $usercfg->{vms}->{$vmid}) {
		if (my $data = $usercfg->{pools}->{$pool}) {
		    delete $data->{vms}->{$vmid};
		    delete $usercfg->{vms}->{$vmid};
		    cfs_write_file("user.cfg", $usercfg);
		}
	    }
	};

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "destroy VM $vmid: $upid\n");

	    PVE::QemuServer::vm_destroy($storecfg, $vmid, $skiplock);

	    PVE::AccessControl::remove_vm_from_pool($vmid);
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
	    vmid => get_standard_option('pve-vmid'),
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

	my $conf = PVE::QemuServer::load_config($vmid, $node); # check if VM exists

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

	$sslcert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192)
	    if !$sslcert;

	my $port = PVE::Tools::next_vnc_port();

	my $remip;
	my $remcmd = [];

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    $remip = PVE::Cluster::remote_node_ip($node);
	    # NOTE: kvm VNC traffic is already TLS encrypted or is known unsecure
	    $remcmd = ['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes', $remip];
	}

	my $timeout = 10;

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "starting vnc proxy $upid\n");

	    my $cmd;

	    if ($conf->{vga} && ($conf->{vga} =~ m/^serial\d+$/)) {

		die "Websocket mode is not supported in vga serial mode!" if $websocket;

		my $termcmd = [ '/usr/sbin/qm', 'terminal', $vmid, '-iface', $conf->{vga} ];
		#my $termcmd = "/usr/bin/qm terminal -iface $conf->{vga}";
		$cmd = ['/usr/bin/vncterm', '-rfbport', $port,
			'-timeout', $timeout, '-authpath', $authpath,
			'-perm', 'Sys.Console', '-c', @$remcmd, @$termcmd];
	    } else {

		$ENV{LC_PVE_TICKET} = $ticket if $websocket; # set ticket with "qm vncproxy"

		my $qmcmd = [@$remcmd, "/usr/sbin/qm", 'vncproxy', $vmid];

		my $qmstr = join(' ', @$qmcmd);

		# also redirect stderr (else we get RFB protocol errors)
		$cmd = ['/bin/nc', '-l', '-p', $port, '-w', $timeout, '-c', "$qmstr 2>/dev/null"];
	    }

	    PVE::Tools::run_command($cmd);

	    return;
	};

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd);

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
    name => 'vncwebsocket',
    path => '{vmid}/vncwebsocket',
    method => 'GET',
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
    },
    description => "Opens a weksocket for VNV traffic.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
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

	my $conf = PVE::QemuServer::load_config($vmid, $node); # VM exists ?

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

	my $conf = PVE::QemuServer::load_config($vmid, $node);
	my $title = "VM $vmid - $conf->{'name'}",

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
	my $conf = PVE::QemuServer::load_config($param->{vmid});

	my $res = [
	    { subdir => 'current' },
	    { subdir => 'start' },
	    { subdir => 'stop' },
	    ];

	return $res;
    }});

my $vm_is_ha_managed = sub {
    my ($vmid) = @_;

    my $cc = PVE::Cluster::cfs_read_file('cluster.conf');
    if (PVE::Cluster::cluster_conf_lookup_pvevm($cc, 0, $vmid, 1)) {
	return 1;
    }
    return 0;
};

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
	my $conf = PVE::QemuServer::load_config($param->{vmid});

	my $vmstatus = PVE::QemuServer::vmstatus($param->{vmid}, 1);
	my $status = $vmstatus->{$param->{vmid}};

	$status->{ha} = &$vm_is_ha_managed($param->{vmid});

	$status->{spice} = 1 if PVE::QemuServer::vga_conf_has_spice($conf->{vga});

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
	    vmid => get_standard_option('pve-vmid'),
	    skiplock => get_standard_option('skiplock'),
	    stateuri => get_standard_option('pve-qm-stateuri'),
	    migratedfrom => get_standard_option('pve-node',{ optional => 1 }),
	    machine => get_standard_option('pve-qm-machine'),
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

	# read spice ticket from STDIN
	my $spice_ticket;
	if ($stateuri && ($stateuri eq 'tcp') && $migratedfrom && ($rpcenv->{type} eq 'cli')) {
	    if (defined(my $line = <>)) {
		chomp $line;
		$spice_ticket = $line;
	    }
	}

	my $storecfg = PVE::Storage::config();

	if (&$vm_is_ha_managed($vmid) && !$stateuri &&
	    $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "pvevm:$vmid";

		my $cmd = ['clusvcadm', '-e', $service, '-m', $node];

		print "Executing HA start for VM $vmid\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hastart', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		syslog('info', "start VM $vmid: $upid\n");

		PVE::QemuServer::vm_start($storecfg, $vmid, $stateuri, $skiplock, $migratedfrom, undef,
					  $machine, $spice_ticket);

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
    description => "Stop virtual machine.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    skiplock => get_standard_option('skiplock'),
	    migratedfrom => get_standard_option('pve-node',{ optional => 1 }),
	    timeout => {
		description => "Wait maximal timeout seconds.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    keepActive => {
		description => "Do not decativate storage volumes.",
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

	if (&$vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "pvevm:$vmid";

		my $cmd = ['clusvcadm', '-d', $service];

		print "Executing HA stop for VM $vmid\n";

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
	    vmid => get_standard_option('pve-vmid'),
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
    description => "Shutdown virtual machine.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.PowerMgmt' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
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
		description => "Do not decativate storage volumes.",
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

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "shutdown VM $vmid: $upid\n");

	    PVE::QemuServer::vm_stop($storecfg, $vmid, $skiplock, 0, $param->{timeout},
				     1, $param->{forceStop}, $keepActive);

	    return;
	};

	return $rpcenv->fork_worker('qmshutdown', $vmid, $authuser, $realcmd);
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
	    vmid => get_standard_option('pve-vmid'),
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
	    vmid => get_standard_option('pve-vmid'),
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

	    syslog('info', "resume VM $vmid: $upid\n");

	    PVE::QemuServer::vm_resume($vmid, $skiplock);

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
	    vmid => get_standard_option('pve-vmid'),
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

	my $conf = PVE::QemuServer::load_config($vmid);

	if($snapname){
	    my $snap = $conf->{snapshots}->{$snapname};
            die "snapshot '$snapname' does not exist\n" if !defined($snap);
	    $conf = $snap;
	}
	my $storecfg = PVE::Storage::config();

	my $nodelist = PVE::QemuServer::shared_nodes($conf, $storecfg);
	my $hasFeature = PVE::QemuServer::has_feature($feature, $conf, $storecfg, $snapname, $running);

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
	    vmid => get_standard_option('pve-vmid'),
	    newid => get_standard_option('pve-vmid', { description => 'VMID for the clone.' }),
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
 		requires => 'full',
		optional => 1,
            }),
	    storage => get_standard_option('pve-storage-id', {
		description => "Target storage for full clone.",
		requires => 'full',
		optional => 1,
	    }),
	    'format' => {
		description => "Target format for file storage.",
		requires => 'full',
		type => 'string',
		optional => 1,
	        enum => [ 'raw', 'qcow2', 'vmdk'],
	    },
	    full => {
		optional => 1,
	        type => 'boolean',
	        description => "Create a full copy of all disk. This is always done when " .
		    "you clone a normal VM. For VM templates, we try to create a linked clone by default.",
		default => 0,
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

	    my $conf = PVE::QemuServer::load_config($vmid);

	    PVE::QemuServer::check_lock($conf);

	    my $verify_running = PVE::QemuServer::check_running($vmid) || 0;

	    die "unexpected state change\n" if $verify_running != $running;

	    die "snapshot '$snapname' does not exist\n"
		if $snapname && !defined( $conf->{snapshots}->{$snapname});

	    my $oldconf = $snapname ? $conf->{snapshots}->{$snapname} : $conf;

	    my $sharedvm = &$check_storage_access_clone($rpcenv, $authuser, $storecfg, $oldconf, $storage);

	    die "can't clone VM to node '$target' (VM uses local storage)\n" if $target && !$sharedvm;

	    my $conffile = PVE::QemuServer::config_file($newid);

	    die "unable to create VM $newid: config file already exists\n"
		if -f $conffile;

	    my $newconf = { lock => 'clone' };
	    my $drives = {};
	    my $vollist = [];

	    foreach my $opt (keys %$oldconf) {
		my $value = $oldconf->{$opt};

		# do not copy snapshot related info
		next if $opt eq 'snapshots' ||  $opt eq 'parent' || $opt eq 'snaptime' ||
		    $opt eq 'vmstate' || $opt eq 'snapstate';

		# always change MAC! address
		if ($opt =~ m/^net(\d+)$/) {
		    my $net = PVE::QemuServer::parse_net($value);
		    $net->{macaddr} =  PVE::Tools::random_ether_addr();
		    $newconf->{$opt} = PVE::QemuServer::print_net($net);
		} elsif (PVE::QemuServer::valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $value);
		    die "unable to parse drive options for '$opt'\n" if !$drive;
		    if (PVE::QemuServer::drive_is_cdrom($drive)) {
			$newconf->{$opt} = $value; # simply copy configuration
		    } else {
			if ($param->{full} || !PVE::Storage::volume_is_base($storecfg,  $drive->{file})) {
			    die "Full clone feature is not available"
				if !PVE::Storage::volume_has_feature($storecfg, 'copy', $drive->{file}, $snapname, $running);
			    $drive->{full} = 1;
			}
			$drives->{$opt} = $drive;
			push @$vollist, $drive->{file};
		    }
		} else {
		    # copy everything else
		    $newconf->{$opt} = $value;
		}
	    }

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

		eval {
		    local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = sub { die "interrupted by signal\n"; };

		    PVE::Storage::activate_volumes($storecfg, $vollist);

		    foreach my $opt (keys %$drives) {
			my $drive = $drives->{$opt};

			my $newdrive = PVE::QemuServer::clone_disk($storecfg, $vmid, $running, $opt, $drive, $snapname,
								   $newid, $storage, $format, $drive->{full}, $newvollist);

			$newconf->{$opt} = PVE::QemuServer::print_drive($vmid, $newdrive);

			PVE::QemuServer::update_config_nolock($newid, $newconf, 1);
		    }

		    delete $newconf->{lock};
		    PVE::QemuServer::update_config_nolock($newid, $newconf, 1);

                    if ($target) {
			# always deactivate volumes - avoid lvm LVs to be active on several nodes
			PVE::Storage::deactivate_volumes($storecfg, $vollist);

			my $newconffile = PVE::QemuServer::config_file($newid, $target);
			die "Failed to move config to node '$target' - rename failed: $!\n"
			    if !rename($conffile, $newconffile);
		    }

		    PVE::AccessControl::add_vm_to_pool($newid, $pool) if $pool;
		};
		if (my $err = $@) {
		    unlink $conffile;

		    sleep 1; # some storage like rbd need to wait before release volume - really?

		    foreach my $volid (@$newvollist) {
			eval { PVE::Storage::vdisk_free($storecfg, $volid); };
			warn $@ if $@;
		    }
		    die "clone failed: $err";
		}

		return;
	    };

	    return $rpcenv->fork_worker('qmclone', $vmid, $authuser, $realcmd);
	};

	return PVE::QemuServer::lock_config_mode($vmid, 1, $shared_lock, sub {
	    # Aquire exclusive lock lock for $newid
	    return PVE::QemuServer::lock_config_full($newid, 1, $clonefn);
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
	description => "You need 'VM.Config.Disk' permissions on /vms/{vmid}, " .
	    "and 'Datastore.AllocateSpace' permissions on the storage.",
	check =>
	[ 'and',
	  ['perm', '/vms/{vmid}', [ 'VM.Config.Disk' ]],
	  ['perm', '/storage/{storage}', [ 'Datastore.AllocateSpace' ]],
	],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    disk => {
	        type => 'string',
		description => "The disk you want to move.",
		enum => [ PVE::QemuServer::disknames() ],
	    },
            storage => get_standard_option('pve-storage-id', { description => "Target Storage." }),
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

	    my $conf = PVE::QemuServer::load_config($vmid);

	    die "checksum missmatch (file change by other user?)\n"
		if $digest && $digest ne $conf->{digest};

	    die "disk '$disk' does not exist\n" if !$conf->{$disk};

	    my $drive = PVE::QemuServer::parse_drive($disk, $conf->{$disk});

	    my $old_volid = $drive->{file} || die "disk '$disk' has no associated volume\n";

	    die "you can't move a cdrom\n" if PVE::QemuServer::drive_is_cdrom($drive);

	    my $oldfmt;
	    my ($oldstoreid, $oldvolname) = PVE::Storage::parse_volume_id($old_volid);
	    if ($oldvolname =~ m/\.(raw|qcow2|vmdk)$/){
		$oldfmt = $1;
	    }

	    die "you can't move on the same storage with same format\n" if $oldstoreid eq $storeid &&
                (!$format || !$oldfmt || $oldfmt eq $format);

	    PVE::Cluster::log_msg('info', $authuser, "move disk VM $vmid: move --disk $disk --storage $storeid");

	    my $running = PVE::QemuServer::check_running($vmid);

	    PVE::Storage::activate_volumes($storecfg, [ $drive->{file} ]);

	    my $realcmd = sub {

		my $newvollist = [];

		eval {
		    local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = sub { die "interrupted by signal\n"; };

		    my $newdrive = PVE::QemuServer::clone_disk($storecfg, $vmid, $running, $disk, $drive, undef,
							       $vmid, $storeid, $format, 1, $newvollist);

		    $conf->{$disk} = PVE::QemuServer::print_drive($vmid, $newdrive);

		    PVE::QemuServer::add_unused_volume($conf, $old_volid) if !$param->{delete};

		    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);

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
                    my $used_paths = PVE::QemuServer::get_used_paths($vmid, $storecfg, $conf, 1, 1);
                    my $path = PVE::Storage::path($storecfg, $old_volid);
		    if ($used_paths->{$path}){
			warn "volume $old_volid have snapshots. Can't delete it\n";
			PVE::QemuServer::add_unused_volume($conf, $old_volid);
			PVE::QemuServer::update_config_nolock($vmid, $conf, 1);
		    } else {
			eval { PVE::Storage::vdisk_free($storecfg, $old_volid); };
			warn $@ if $@;
		    }
		}
	    };

            return $rpcenv->fork_worker('qmmove', $vmid, $authuser, $realcmd);
	};

	return PVE::QemuServer::lock_config($vmid, $updatefn);
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
	    vmid => get_standard_option('pve-vmid'),
	    target => get_standard_option('pve-node', { description => "Target node." }),
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

	# test if VM exists
	my $conf = PVE::QemuServer::load_config($vmid);

	# try to detect errors early

	PVE::QemuServer::check_lock($conf);

	if (PVE::QemuServer::check_running($vmid)) {
	    die "cant migrate running VM without --online\n"
		if !$param->{online};
	}

	my $storecfg = PVE::Storage::config();
	PVE::QemuServer::check_storage_availability($storecfg, $conf, $target);

	if (&$vm_is_ha_managed($vmid) && $rpcenv->{type} ne 'ha') {

	    my $hacmd = sub {
		my $upid = shift;

		my $service = "pvevm:$vmid";

		my $cmd = ['clusvcadm', '-M', $service, '-m', $target];

		print "Executing HA migrate for VM $vmid to node $target\n";

		PVE::Tools::run_command($cmd);

		return;
	    };

	    return $rpcenv->fork_worker('hamigrate', $vmid, $authuser, $hacmd);

	} else {

	    my $realcmd = sub {
		my $upid = shift;

		PVE::QemuMigrate->migrate($target, $targetip, $vmid, $param);
	    };

	    return $rpcenv->fork_worker('qmigrate', $vmid, $authuser, $realcmd);
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

	my $vmid = $param->{vmid};

	my $conf = PVE::QemuServer::load_config ($vmid); # check if VM exists

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
	    vmid => get_standard_option('pve-vmid'),
	    skiplock => get_standard_option('skiplock'),
	    disk => {
		type => 'string',
		description => "The disk you want to resize.",
		enum => [PVE::QemuServer::disknames()],
	    },
	    size => {
		type => 'string',
		pattern => '\+?\d+(\.\d+)?[KMGT]?',
		description => "The new size. With the '+' sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.",
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

            my $conf = PVE::QemuServer::load_config($vmid);

            die "checksum missmatch (file change by other user?)\n"
                if $digest && $digest ne $conf->{digest};
            PVE::QemuServer::check_lock($conf) if !$skiplock;

	    die "disk '$disk' does not exist\n" if !$conf->{$disk};

	    my $drive = PVE::QemuServer::parse_drive($disk, $conf->{$disk});

	    my $volid = $drive->{file};

	    die "disk '$disk' has no associated volume\n" if !$volid;

	    die "you can't resize a cdrom\n" if PVE::QemuServer::drive_is_cdrom($drive);

	    die "you can't online resize a virtio windows bootdisk\n"
		if PVE::QemuServer::check_running($vmid) && $conf->{bootdisk} eq $disk && $conf->{ostype} =~ m/^w/ && $disk =~ m/^virtio/;

	    my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

	    $rpcenv->check($authuser, "/storage/$storeid", ['Datastore.AllocateSpace']);

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

	    die "unable to skrink disk size\n" if $newsize < $size;

	    return if $size == $newsize;

            PVE::Cluster::log_msg('info', $authuser, "update VM $vmid: resize --disk $disk --size $sizestr");

	    PVE::QemuServer::qemu_block_resize($vmid, "drive-$disk", $storecfg, $volid, $newsize);

	    $drive->{size} = $newsize;
	    $conf->{$disk} = PVE::QemuServer::print_drive($vmid, $drive);

	    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);
	};

        PVE::QemuServer::lock_config($vmid, $updatefn);
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
	    vmid => get_standard_option('pve-vmid'),
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

	my $conf = PVE::QemuServer::load_config($vmid);
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
	    vmid => get_standard_option('pve-vmid'),
	    snapname => get_standard_option('pve-snapshot-name'),
	    vmstate => {
		optional => 1,
		type => 'boolean',
		description => "Save the vmstate",
	    },
	    freezefs => {
		optional => 1,
		type => 'boolean',
		description => "Freeze the filesystem",
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
	    PVE::QemuServer::snapshot_create($vmid, $snapname, $param->{vmstate},
					     $param->{freezefs}, $param->{description});
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

	    my $conf = PVE::QemuServer::load_config($vmid);

	    PVE::QemuServer::check_lock($conf);

	    my $snap = $conf->{snapshots}->{$snapname};

	    die "snapshot '$snapname' does not exist\n" if !defined($snap);

	    $snap->{description} = $param->{description} if defined($param->{description});

	     PVE::QemuServer::update_config_nolock($vmid, $conf, 1);
	};

	PVE::QemuServer::lock_config($vmid, $updatefn);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'get_snapshot_config',
    path => '{vmid}/snapshot/{snapname}/config',
    method => 'GET',
    proxyto => 'node',
    description => "Get snapshot configuration",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
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

	my $conf = PVE::QemuServer::load_config($vmid);

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
	check => ['perm', '/vms/{vmid}', [ 'VM.Snapshot' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
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
	    PVE::QemuServer::snapshot_rollback($vmid, $snapname);
	};

	return $rpcenv->fork_worker('qmrollback', $vmid, $authuser, $realcmd);
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
	    vmid => get_standard_option('pve-vmid'),
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
	    PVE::QemuServer::snapshot_delete($vmid, $snapname, $param->{force});
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
	    vmid => get_standard_option('pve-vmid'),
	    disk => {
		optional => 1,
		type => 'string',
		description => "If you want to convert only 1 disk to base image.",
		enum => [PVE::QemuServer::disknames()],
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

	    my $conf = PVE::QemuServer::load_config($vmid);

	    PVE::QemuServer::check_lock($conf);

	    die "unable to create template, because VM contains snapshots\n"
		if $conf->{snapshots} && scalar(keys %{$conf->{snapshots}});

	    die "you can't convert a template to a template\n"
		if PVE::QemuServer::is_template($conf) && !$disk;

	    die "you can't convert a VM to template if VM is running\n"
		if PVE::QemuServer::check_running($vmid);

	    my $realcmd = sub {
		PVE::QemuServer::template_create($vmid, $conf, $disk);
	    };

	    $conf->{template} = 1;
	    PVE::QemuServer::update_config_nolock($vmid, $conf, 1);

	    return $rpcenv->fork_worker('qmtemplate', $vmid, $authuser, $realcmd);
	};

	PVE::QemuServer::lock_config($vmid, $updatefn);
	return undef;
    }});

1;
