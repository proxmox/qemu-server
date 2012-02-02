package PVE::API2::Qemu;

use strict;
use warnings;
use Cwd 'abs_path';

use PVE::Cluster;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::Exception qw(raise raise_param_exc);
use PVE::Storage;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::QemuServer;
use PVE::QemuMigrate;
use PVE::RPCEnvironment;
use PVE::AccessControl;
use PVE::INotify;

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

my $check_volume_access = sub {
    my ($rpcenv, $authuser, $storecfg, $vmid, $volid, $pool) = @_;

    my $path;
    if (my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1)) {
	my ($ownervm, $vtype);
	($path, $ownervm, $vtype) = PVE::Storage::path($storecfg, $volid);
	if ($vtype eq 'iso' || $vtype eq 'vztmpl') {
	    # we simply allow access 
	} elsif (!$ownervm || ($ownervm != $vmid)) {
	    # allow if we are Datastore administrator
	    $rpcenv->check_storage_perm($authuser, $vmid, $pool, $sid, [ 'Datastore.Allocate' ]);
	}
    } else {
	die "Only root can pass arbitrary filesystem paths."
	    if $authuser ne 'root@pam';

	$path = abs_path($volid);
    }
    return $path;
};

# Note: $pool is only needed when creating a VM, because pool permissions
# are automatically inherited if VM already exists inside a pool.
my $create_disks = sub {
    my ($rpcenv, $authuser, $storecfg, $vmid, $pool, $settings, $conf, $default_storage) = @_;

    # check permissions first

    my $alloc = [];
    foreach_drive($settings, sub {
	my ($ds, $disk) = @_;

	return if drive_is_cdrom($disk);

	my $volid = $disk->{file};

	if ($volid =~ m/^(([^:\s]+):)?(\d+(\.\d+)?)$/) {
	    my ($storeid, $size) = ($2 || $default_storage, $3);
	    die "no storage ID specified (and no default storage)\n" if !$storeid;
	    $rpcenv->check_storage_perm($authuser, $vmid, $pool, $storeid, [ 'Datastore.AllocateSpace' ]);
	    my $defformat = PVE::Storage::storage_default_format($storecfg, $storeid);
	    my $fmt = $disk->{format} || $defformat;
	    push @$alloc, [$ds, $disk, $storeid, $size, $fmt];
	} else {
	    my $path = &$check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $volid, $pool);
	    die "image '$path' does not exists\n" if (!(-f $path || -b $path));
	}
    });

    # now try to allocate everything

    my $vollist = [];
    eval {
	foreach my $task (@$alloc) {
	    my ($ds, $disk, $storeid, $size, $fmt) = @$task;

	    my $volid = PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid,
						  $fmt, undef, $size*1024*1024);

	    $disk->{file} = $volid;
	    push @$vollist, $volid;
	}
    };

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
    foreach my $task (@$alloc) {
	my ($ds, $disk) = @$task;
	delete $disk->{format}; # no longer needed
	$settings->{$ds} = PVE::QemuServer::print_drive($vmid, $disk);
    }

    return $vollist;
};

my $check_vm_modify_config_perm = sub {
    my ($rpcenv, $authuser, $vmid, $pool, $param) = @_;

    return 1 if $authuser ne 'root@pam';

    foreach my $opt (keys %$param) {
	# disk checks need to be done somewhere else
	next if PVE::QemuServer::valid_drivename($opt);

	if ($opt eq 'sockets' || $opt eq 'cores' ||
	    $opt eq 'cpu' || $opt eq 'smp' || 
	    $opt eq 'cpuimit' || $opt eq 'cpuunits') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.CPU']);
	} elsif ($opt eq 'boot' || $opt eq 'bootdisk') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Disk']);
	} elsif ($opt eq 'memory' || $opt eq 'balloon') {
	    $rpcenv->check_vm_perm($authuser, $vmid, $pool, ['VM.Config.Memory']);
	} elsif ($opt eq 'args' || $opt eq 'lock') {
	    die "only root can set '$opt' config\n";
	} elsif ($opt eq 'cpu' || $opt eq 'kvm' || $opt eq 'acpi' || 
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
	description => "You need 'VM.Allocate' permissions on /vms/{vmid} or on the VM pool /pool/{pool}. If you create disks you need 'Datastore.AllocateSpace' on any used storage.",
	check => [ 'or', 
		   [ 'perm', '/vms/{vmid}', ['VM.Allocate']],
		   [ 'perm', '/pool/{pool}', ['VM.Allocate'], require_param => 'pool'],
	    ],
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
	    $rpcenv->check_perm_modify($authuser, "/pool/$pool");
	} 

	$rpcenv->check_storage_perm($authuser, $vmid, $pool, $storage, [ 'Datastore.AllocateSpace' ])
	    if defined($storage);

	if (!$archive) {
	    &$resolve_cdrom_alias($param);

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
		    && $rpcenv->{type} ne 'cli';
	    } else {
		my $path = &$check_volume_access($rpcenv, $authuser, $storecfg, $vmid, $archive, $pool);
		die "can't find archive file '$archive'\n" if !($path && -f $path);
		$archive = $path;
	    }
	}

	my $restorefn = sub {

	    if (-f $filename) {
		die "unable to restore vm $vmid: config file already exists\n"
		    if !$force;

		die "unable to restore vm $vmid: vm is running\n"
		    if PVE::QemuServer::check_running($vmid);

		# destroy existing data - keep empty config
		PVE::QemuServer::destroy_vm($storecfg, $vmid, 1);
	    }

	    my $realcmd = sub {
		PVE::QemuServer::restore_archive($archive, $vmid, $authuser, {
		    storage => $storage,
		    pool => $pool,
		    unique => $unique });
	    };

	    return $rpcenv->fork_worker('qmrestore', $vmid, $authuser, $realcmd);
	};

	&$check_vm_modify_config_perm($rpcenv, $authuser, $vmid, $pool, $param);

	my $createfn = sub {

	    # second test (after locking test is accurate)
	    die "unable to create vm $vmid: config file already exists\n"
		if -f $filename;

	    my $realcmd = sub {

		my $vollist = [];

		eval {
		    $vollist = &$create_disks($rpcenv, $authuser, $storecfg, $vmid, $pool, $param, $storage);

		    # try to be smart about bootdisk
		    my @disks = PVE::QemuServer::disknames();
		    my $firstdisk;
		    foreach my $ds (reverse @disks) {
			next if !$param->{$ds};
			my $disk = PVE::QemuServer::parse_drive($ds, $param->{$ds});
			next if PVE::QemuServer::drive_is_cdrom($disk);
			$firstdisk = $ds;
		    }

		    if (!$param->{bootdisk} && $firstdisk) {
			$param->{bootdisk} = $firstdisk;
		    }

		    PVE::QemuServer::create_conf_nolock($vmid, $param);
		};
		my $err = $@;

		if ($err) {
		    foreach my $volid (@$vollist) {
			eval { PVE::Storage::vdisk_free($storecfg, $volid); };
			warn $@ if $@;
		    }
		    die "create failed - $err";
		}
	    };

	    return $rpcenv->fork_worker('qmcreate', $vmid, $authuser, $realcmd);
	};

	return PVE::QemuServer::lock_config($vmid, $archive ? $restorefn : $createfn);
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
	    { subdir => 'rrd' },
	    { subdir => 'rrddata' },
	    { subdir => 'monitor' },
	    ];

	return $res;
    }});

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

	return $conf;
    }});

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
    name => 'update_vm',
    path => '{vmid}/config',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Set virtual machine options.",
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
		}
	    }),
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $authuser = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $digest = extract_param($param, 'digest');

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

	my $storecfg = PVE::Storage::config();

	&$resolve_cdrom_alias($param);

	my $updatefn =  sub {

	    my $conf = PVE::QemuServer::load_config($vmid);

	    die "checksum missmatch (file change by other user?)\n"
		if $digest && $digest ne $conf->{digest};

	    PVE::QemuServer::check_lock($conf) if !$skiplock;

	    PVE::Cluster::log_msg('info', $authuser, "update VM $vmid: " . join (' ', @paramarr));

	    #delete
	    foreach my $opt (@delete) {

		next if !defined($conf->{$opt});

		die "error hot-unplug $opt" if !PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);

		#drive
		if (PVE::QemuServer::valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
		    #hdd
		    if (!PVE::QemuServer::drive_is_cdrom($drive)) {
			my $volid = $drive->{file};
			
			if ($volid !~  m|^/|) {
			    my ($path, $owner);
			    eval { ($path, $owner) = PVE::Storage::path($storecfg, $volid); };
			    if ($owner && ($owner == $vmid)) {
				if ($force) {
				    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
				    # fixme: log ?
				    warn $@ if $@;
				} else {
				    PVE::QemuServer::add_unused_volume($conf, $volid, $vmid);
				}
			    }
			}
		    }
		} elsif ($opt =~ m/^unused/) {
	            my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
                    my $volid = $drive->{file};
		    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	            # fixme: log ?
        	    warn $@ if $@;
		}

		PVE::QemuServer::change_config_nolock($vmid, {}, { $opt => 1 }, 1);
	    }

	    #add
	    foreach my $opt (keys %$param) {

		#drives
		if (PVE::QemuServer::valid_drivename($opt)) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
		    raise_param_exc({ $opt => "unable to parse drive options" }) if !$drive;

		    PVE::QemuServer::cleanup_drive_path($opt, $storecfg, $drive);
		    $param->{$opt} = PVE::QemuServer::print_drive($vmid, $drive);

		    #cdrom
		    if (PVE::QemuServer::drive_is_cdrom($drive) && PVE::QemuServer::check_running($vmid)) {
			if ($drive->{file} eq 'none') {
			    PVE::QemuServer::vm_monitor_command($vmid, "eject -f drive-$opt", 0);
			    #delete $param->{$opt};
			}
			else {
			    my $path = PVE::QemuServer::get_iso_path($storecfg, $vmid, $drive->{file});
			    PVE::QemuServer::vm_monitor_command($vmid, "eject -f drive-$opt", 0); #force eject if locked
			    PVE::QemuServer::vm_monitor_command($vmid, "change drive-$opt \"$path\"", 0) if $path;
			}
		    }
		    #hdd
		    else {
			#swap drive
			if ($conf->{$opt}){
			    my $old_drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
			    if ($drive->{file} ne $old_drive->{file} && !PVE::QemuServer::drive_is_cdrom($old_drive)) {
				
				my ($path, $owner);
				eval { ($path, $owner) = PVE::Storage::path($storecfg, $old_drive->{file}); };
				if ($owner && ($owner == $vmid)) {
				    die "error hot-unplug $opt" if !PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);
				    PVE::QemuServer::add_unused_volume($conf, $old_drive->{file}, $vmid);
				}
			    }
			}
			my $settings = { $opt => $param->{$opt} };
			&$create_disks($rpcenv, $authuser, $storecfg, $vmid, undef, $settings, $conf);
			$param->{$opt} = $settings->{$opt};
			#hotplug disks
			if(!PVE::QemuServer::vm_deviceplug($storecfg, $conf, $vmid, $opt, $drive)) {
			    PVE::QemuServer::add_unused_volume($conf,$drive->{file},$vmid);
			    PVE::QemuServer::change_config_nolock($vmid, {}, { $opt => 1 }, 1);
			    die "error hotplug $opt - put disk in unused";
			}
		    }
		}
		#nics
		my $net = undef;
		if ($opt =~ m/^net(\d+)$/) {
		    $net = PVE::QemuServer::parse_net($param->{$opt});
		    $param->{$opt} = PVE::QemuServer::print_net($net);
		    #if online update, then unplug first
		    die "error hot-unplug $opt for update" if $conf->{$opt} && !PVE::QemuServer::vm_deviceunplug($vmid, $conf, $opt);
		}

		PVE::QemuServer::change_config_nolock($vmid, { $opt => $param->{$opt} }, {}, 1);

		#nic hotplug after config write as we need it for pve-bridge script
		if (defined ($net)) {
		    if(!PVE::QemuServer::vm_deviceplug($storecfg, $conf, $vmid, $opt, $net)) {
		    #rewrite conf to remove nic if hotplug fail
		    PVE::QemuServer::change_config_nolock($vmid, {}, { $opt => 1 }, 1);
		    die "error hotplug $opt";
		    }
		}
	    }
	};

	PVE::QemuServer::lock_config($vmid, $updatefn);

	return undef;
    }});


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

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "destroy VM $vmid: $upid\n");

	    PVE::QemuServer::vm_destroy($storecfg, $vmid, $skiplock);
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

	my $authpath = "/vms/$vmid";

	my $ticket = PVE::AccessControl::assemble_vnc_ticket($authuser, $authpath);

	$sslcert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192)
	    if !$sslcert;

	my $port = PVE::Tools::next_vnc_port();

	my $remip;

	if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
	    $remip = PVE::Cluster::remote_node_ip($node);
	}

	# NOTE: kvm VNC traffic is already TLS encrypted,
	# so we select the fastest chipher here (or 'none'?)
	my $remcmd = $remip ? ['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes',
			       '-c', 'blowfish-cbc', $remip] : [];

	my $timeout = 10;

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "starting vnc proxy $upid\n");

	    my $qmcmd = [@$remcmd, "/usr/sbin/qm", 'vncproxy', $vmid];

	    my $qmstr = join(' ', @$qmcmd);

	    # also redirect stderr (else we get RFB protocol errors)
	    my $cmd = ['/bin/nc', '-l', '-p', $port, '-w', $timeout, '-c', "$qmstr 2>/dev/null"];

	    PVE::Tools::run_command($cmd);

	    return;
	};

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $authuser, $realcmd);

	return {
	    user => $authuser,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	    cert => $sslcert,
	};
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

	my $vmstatus = PVE::QemuServer::vmstatus($param->{vmid});
	my $status = $vmstatus->{$param->{vmid}};

	my $cc = PVE::Cluster::cfs_read_file('cluster.conf');
	if (PVE::Cluster::cluster_conf_lookup_pvevm($cc, 0, $param->{vmid}, 1)) {
	    $status->{ha} = 1;
	} else {
	    $status->{ha} = 0;
	}

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

	my $stateuri = extract_param($param, 'stateuri');
	raise_param_exc({ stateuri => "Only root may use this option." })
	    if $stateuri && $authuser ne 'root@pam';

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." })
	    if $skiplock && $authuser ne 'root@pam';

	my $storecfg = PVE::Storage::config();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "start VM $vmid: $upid\n");

	    PVE::QemuServer::vm_start($storecfg, $vmid, $stateuri, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmstart', $vmid, $authuser, $realcmd);
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

	my $storecfg = PVE::Storage::config();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "stop VM $vmid: $upid\n");

	    PVE::QemuServer::vm_stop($storecfg, $vmid, $skiplock, 0,
				     $param->{timeout}, 0, 1, $keepActive);

	    return;
	};

	return $rpcenv->fork_worker('qmstop', $vmid, $authuser, $realcmd);
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

	my $realcmd = sub {
	    my $upid = shift;

	    PVE::QemuMigrate->migrate($target, $targetip, $vmid, $param);
	};

	my $upid = $rpcenv->fork_worker('qmigrate', $vmid, $authuser, $realcmd);

	return $upid;
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
	    $res = PVE::QemuServer::vm_monitor_command($vmid, $param->{command});
	};
	$res = "ERROR: $@" if $@;

	return $res;
    }});

1;
