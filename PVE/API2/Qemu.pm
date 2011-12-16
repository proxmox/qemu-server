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

__PACKAGE__->register_method({
    name => 'vmlist', 
    path => '', 
    method => 'GET',
    description => "Virtual machine index (per node).",
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

	my $vmstatus = PVE::QemuServer::vmstatus();

	return PVE::RESTHandler::hash_to_array($vmstatus, 'vmid');

    }});

__PACKAGE__->register_method({
    name => 'create_vm', 
    path => '', 
    method => 'POST',
    description => "Create or restore a virtual machine.",
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
	    }),
    },
    returns => { 
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $archive = extract_param($param, 'archive');

	my $storage = extract_param($param, 'storage');

	my $force = extract_param($param, 'force');

	my $unique = extract_param($param, 'unique');

	my $filename = PVE::QemuServer::config_file($vmid);
	
	my $storecfg = PVE::Storage::config(); 

	PVE::Cluster::check_cfs_quorum();

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
		my $path;
		if (PVE::Storage::parse_volume_id($archive, 1)) {
		    $path = PVE::Storage::path($storecfg, $archive);
		} else {
		    raise_param_exc({ archive => "Only root can pass arbitrary paths." }) 
			if $user ne 'root@pam';

		    $path = abs_path($archive);
		}
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
		PVE::QemuServer::restore_archive($archive, $vmid, { 
		    storage => $storage,
		    unique => $unique });
	    };

	    return $rpcenv->fork_worker('qmrestore', $vmid, $user, $realcmd);
	};

	my $createfn = sub {

	    # second test (after locking test is accurate)
	    die "unable to create vm $vmid: config file already exists\n" 
		if -f $filename;

	    my $realcmd = sub {

		my $vollist = [];

		eval {
		    $vollist = PVE::QemuServer::create_disks($storecfg, $vmid, $param, $storage);

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

	    return $rpcenv->fork_worker('qmcreate', $vmid, $user, $realcmd);
	};

	return PVE::QemuServer::lock_config($vmid, $archive ? $restorefn : $createfn);
    }});

__PACKAGE__->register_method({
    name => 'vmdiridx',
    path => '{vmid}', 
    method => 'GET',
    proxyto => 'node',
    description => "Directory index",
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
	path => '/vms/{vmid}',
	privs => [ 'VM.Audit' ],
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
	path => '/vms/{vmid}',
	privs => [ 'VM.Audit' ],
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

__PACKAGE__->register_method({
    name => 'update_vm', 
    path => '{vmid}/config', 
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Set virtual machine options.",
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

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $digest = extract_param($param, 'digest');

	my @paramarr = (); # used for log message
	foreach my $key (keys %$param) {
	    push @paramarr, "-$key", $param->{$key};
	}

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	my $delete = extract_param($param, 'delete');
	my $force = extract_param($param, 'force');

	die "no options specified\n" if !$delete && !scalar(keys %$param);

	my $storecfg = PVE::Storage::config(); 

	&$resolve_cdrom_alias($param);

	my $eject = {};
	my $cdchange = {};

	foreach my $opt (keys %$param) {
	    if (PVE::QemuServer::valid_drivename($opt)) {
		my $drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
		raise_param_exc({ $opt => "unable to parse drive options" }) if !$drive;
		if ($drive->{file} eq 'eject') {
		    $eject->{$opt} = 1;
		    delete $param->{$opt};
		    next;
		}

		PVE::QemuServer::cleanup_drive_path($opt, $storecfg, $drive);
		$param->{$opt} = PVE::QemuServer::print_drive($vmid, $drive);

		if (PVE::QemuServer::drive_is_cdrom($drive)) {
		    $cdchange->{$opt} = PVE::QemuServer::get_iso_path($storecfg, $vmid, $drive->{file});
		}
	    }
	}

	foreach my $opt (PVE::Tools::split_list($delete)) {
	    $opt = 'ide2' if $opt eq 'cdrom';
	    die "you can't use '-$opt' and '-delete $opt' at the same time\n"
		if defined($param->{$opt});
	}

	PVE::QemuServer::add_random_macs($param);

	my $vollist = [];

	my $updatefn =  sub {

	    my $conf = PVE::QemuServer::load_config($vmid);

	    die "checksum missmatch (file change by other user?)\n" 
		if $digest && $digest ne $conf->{digest};

	    PVE::QemuServer::check_lock($conf) if !$skiplock;

	    PVE::Cluster::log_msg('info', $user, "update VM $vmid: " . join (' ', @paramarr));

	    foreach my $opt (keys %$eject) {
		if ($conf->{$opt}) {
		    my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
		    $cdchange->{$opt} = undef if PVE::QemuServer::drive_is_cdrom($drive);
		} else {
		    raise_param_exc({ $opt => "eject failed - drive does not exist." });
		}
	    }

	    foreach my $opt (keys %$param) {
		next if !PVE::QemuServer::valid_drivename($opt);
		next if !$conf->{$opt};
		my $old_drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
		next if PVE::QemuServer::drive_is_cdrom($old_drive);
		my $new_drive = PVE::QemuServer::parse_drive($opt, $param->{$opt});
		if ($new_drive->{file} ne $old_drive->{file}) {
		    my ($path, $owner);
		    eval { ($path, $owner) = PVE::Storage::path($storecfg, $old_drive->{file}); };
		    if ($owner && ($owner == $vmid)) {
			PVE::QemuServer::add_unused_volume($conf, $param, $old_drive->{file});
		    }
		}
	    }

	    my $unset = {};

	    foreach my $opt (PVE::Tools::split_list($delete)) {
		$opt = 'ide2' if $opt eq 'cdrom';
		if (!PVE::QemuServer::option_exists($opt)) {
		    raise_param_exc({ delete => "unknown option '$opt'" });
		} 
		next if !defined($conf->{$opt});
		if (PVE::QemuServer::valid_drivename($opt)) {
		    PVE::QemuServer::vm_devicedel($vmid, $conf, $opt);
		    my $drive = PVE::QemuServer::parse_drive($opt, $conf->{$opt});
		    if (PVE::QemuServer::drive_is_cdrom($drive)) {
			$cdchange->{$opt} = undef;
		    } else {
			my $volid = $drive->{file};

			if ($volid !~  m|^/|) {
			    my ($path, $owner);
			    eval { ($path, $owner) = PVE::Storage::path($storecfg, $volid); };
			    if ($owner && ($owner == $vmid)) {
				if ($force) {
				    push @$vollist, $volid;
				} else {
				    PVE::QemuServer::add_unused_volume($conf, $param, $volid);
				}
			    }
			}
		    }
		} elsif ($opt =~ m/^unused/) {
		    push @$vollist, $conf->{$opt};
		}

		$unset->{$opt} = 1;
	    }

	    PVE::QemuServer::create_disks($storecfg, $vmid, $param, $conf);

	    PVE::QemuServer::change_config_nolock($vmid, $param, $unset, 1);

	    return if !PVE::QemuServer::check_running($vmid);

	    foreach my $opt (keys %$cdchange) {
		my $qdn = PVE::QemuServer::qemu_drive_name($opt, 'cdrom');
		my $path = $cdchange->{$opt};
		PVE::QemuServer::vm_monitor_command($vmid, "eject $qdn", 0);
		PVE::QemuServer::vm_monitor_command($vmid, "change $qdn \"$path\"", 0) if $path;
	    }
	};

	PVE::QemuServer::lock_config($vmid, $updatefn);

	foreach my $volid (@$vollist) {
	    eval { PVE::Storage::vdisk_free($storecfg, $volid); };
	    # fixme: log ?
	    warn $@ if $@;
	}

	return undef;
    }});


__PACKAGE__->register_method({
    name => 'destroy_vm', 
    path => '{vmid}', 
    method => 'DELETE',
    protected => 1,
    proxyto => 'node',
    description => "Destroy the vm (also delete all used/owned volumes).",
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

	my $user = $rpcenv->get_user();

	my $vmid = $param->{vmid};

	my $skiplock = $param->{skiplock};
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	# test if VM exists
	my $conf = PVE::QemuServer::load_config($vmid);

	my $storecfg = PVE::Storage::config(); 

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "destroy VM $vmid: $upid\n");

	    PVE::QemuServer::vm_destroy($storecfg, $vmid, $skiplock);
	};

	return $rpcenv->fork_worker('qmdestroy', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'unlink', 
    path => '{vmid}/unlink', 
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Unlink/delete disk images.",
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
	path => '/vms/{vmid}',
	privs => [ 'VM.Console' ],
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

	my $user = $rpcenv->get_user();
	my $ticket = PVE::AccessControl::assemble_ticket($user);

	my $vmid = $param->{vmid};
	my $node = $param->{node};

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

	my $upid = $rpcenv->fork_worker('vncproxy', $vmid, $user, $realcmd);

	return {
	    user => $user,
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

	return $vmstatus->{$param->{vmid}};
    }});

__PACKAGE__->register_method({
    name => 'vm_start', 
    path => '{vmid}/status/start',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Start virtual machine.",
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

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $stateuri = extract_param($param, 'stateuri');
	raise_param_exc({ stateuri => "Only root may use this option." }) 
	    if $stateuri && $user ne 'root@pam';

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	my $storecfg = PVE::Storage::config(); 

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "start VM $vmid: $upid\n");

	    PVE::QemuServer::vm_start($storecfg, $vmid, $stateuri, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmstart', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_stop', 
    path => '{vmid}/status/stop',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Stop virtual machine.",
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
	    }
	},
    },
    returns => { 
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	my $storecfg = PVE::Storage::config();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "stop VM $vmid: $upid\n");

	    PVE::QemuServer::vm_stop($storecfg, $vmid, $skiplock, 0, $param->{timeout});

	    return;
	};

	return $rpcenv->fork_worker('qmstop', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_reset', 
    path => '{vmid}/status/reset',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Reset virtual machine.",
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

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    PVE::QemuServer::vm_reset($vmid, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmreset', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_shutdown', 
    path => '{vmid}/status/shutdown',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Shutdown virtual machine.",
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
	    }
	},
    },
    returns => { 
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	my $storecfg = PVE::Storage::config();

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "shutdown VM $vmid: $upid\n");

	    PVE::QemuServer::vm_stop($storecfg, $vmid, $skiplock, 0, 
				     $param->{timeout}, 1, $param->{forceStop});

	    return;
	};

	return $rpcenv->fork_worker('qmshutdown', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_suspend', 
    path => '{vmid}/status/suspend',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Suspend virtual machine.",
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

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "suspend VM $vmid: $upid\n");

	    PVE::QemuServer::vm_suspend($vmid, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmsuspend', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_resume', 
    path => '{vmid}/status/resume',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Resume virtual machine.",
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

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	my $realcmd = sub {
	    my $upid = shift;

	    syslog('info', "resume VM $vmid: $upid\n");

	    PVE::QemuServer::vm_resume($vmid, $skiplock);

	    return;
	};

	return $rpcenv->fork_worker('qmresume', $vmid, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'vm_sendkey', 
    path => '{vmid}/sendkey',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Send key event to virtual machine.",
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

	my $user = $rpcenv->get_user();

	my $node = extract_param($param, 'node');

	my $vmid = extract_param($param, 'vmid');

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

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

	my $user = $rpcenv->get_user();

	my $target = extract_param($param, 'target');

	my $localnode = PVE::INotify::nodename();
	raise_param_exc({ target => "target is local node."}) if $target eq $localnode;

	PVE::Cluster::check_cfs_quorum();

	PVE::Cluster::check_node_exists($target);

	my $targetip = PVE::Cluster::remote_node_ip($target);

	my $vmid = extract_param($param, 'vmid');

	raise_param_exc({ force => "Only root may use this option." }) 
	    if $param->{force} && $user ne 'root@pam';

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

	my $upid = $rpcenv->fork_worker('qmigrate', $vmid, $user, $realcmd);

	return $upid;
    }});

__PACKAGE__->register_method({
    name => 'monitor', 
    path => '{vmid}/monitor', 
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Execute Qemu monitor commands.",
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
