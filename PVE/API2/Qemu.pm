package PVE::API2::Qemu;

use strict;
use warnings;

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
    description => "Create new virtual machine.",
    protected => 1,
    proxyto => 'node',
    parameters => {
    	additionalProperties => 0,
	properties => PVE::QemuServer::json_config_properties(
	    {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
	    }),
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $node = extract_param($param, 'node');

	# fixme: fork worker?

	my $vmid = extract_param($param, 'vmid');

	my $filename = PVE::QemuServer::config_file($vmid);
	# first test (befor locking)
	die "unable to create vm $vmid: config file already exists\n" 
	    if -f $filename;
	
	my $storecfg = PVE::Storage::config(); 

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

	#fixme: ? syslog ('info', "VM $vmid creating new virtual machine");
	
	my $vollist = [];

	my $createfn = sub {

	    # second test (after locking test is accurate)
	    die "unable to create vm $vmid: config file already exists\n" 
		if -f $filename;

	    $vollist = PVE::QemuServer::create_disks($storecfg, $vmid, $param);

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

	eval { PVE::QemuServer::lock_config($vmid, $createfn); };
	my $err = $@;

	if ($err) {
	    foreach my $volid (@$vollist) {
		eval { PVE::Storage::vdisk_free($storecfg, $volid); };
		warn $@ if $@;
	    }
	    die "create failed - $err";
	}

	return undef;
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

	my $skiplock = extract_param($param, 'skiplock');
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	my $delete = extract_param($param, 'delete');
	my $force = extract_param($param, 'force');

	die "no options specified\n" if !$delete && !scalar(keys %$param);

	my $digest = extract_param($param, 'digest');

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

	    PVE::QemuServer::create_disks($storecfg, $vmid, $param);

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
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $user = $rpcenv->get_user();

	my $vmid = $param->{vmid};

	my $skiplock = $param->{skiplock};
	raise_param_exc({ skiplock => "Only root may use this option." }) 
	    if $skiplock && $user ne 'root@pam';

	my $storecfg = PVE::Storage::config(); 

	PVE::QemuServer::vm_destroy($storecfg, $vmid, $skiplock);

	return undef;
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
	
	if ($node ne PVE::INotify::nodename()) {
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
	    my @cmd = ('/bin/nc', '-l', '-p', $port, '-w', $timeout, '-c', "$qmstr 2>/dev/null");

	    my $cmdstr = join(' ', @cmd);
	    syslog('info', "CMD3: $cmdstr");

	    if (system(@cmd) != 0) {
		my $msg = "VM $vmid vnc proxy failed - $?";
		syslog('err', $msg);
		return;
	    }

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
    name => 'vm_status', 
    path => '{vmid}/status',
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

	my $vmstatus =  PVE::QemuServer::vmstatus($param->{vmid});

	return $vmstatus->{$param->{vmid}};
    }});

__PACKAGE__->register_method({
    name => 'vm_command', 
    path => '{vmid}/status',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    description => "Set virtual machine status (execute vm commands).",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid'),
	    skiplock => get_standard_option('skiplock'),
	    stateuri => get_standard_option('pve-qm-stateuri'),
	    command => { 
		description => "The command to execute.",
		type => 'string',
		enum => [qw(start stop reset shutdown cad suspend resume) ],
	    },
	},
    },
    returns => { type => 'null'},
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

	my $command = $param->{command};

	my $storecfg = PVE::Storage::config(); 
	
	if ($command eq 'start') {
	    PVE::QemuServer::vm_start($storecfg, $vmid, $stateuri, $skiplock);
	} elsif ($command eq 'stop') {
	    PVE::QemuServer::vm_stop($vmid, $skiplock);
	} elsif ($command eq 'reset') {
	    PVE::QemuServer::vm_reset($vmid, $skiplock);
	} elsif ($command eq 'shutdown') {
	    PVE::QemuServer::vm_shutdown($vmid, $skiplock);
	} elsif ($command eq 'suspend') {
	    PVE::QemuServer::vm_suspend($vmid, $skiplock);
	} elsif ($command eq 'resume') {
	    PVE::QemuServer::vm_resume($vmid, $skiplock);
	} elsif ($command eq 'cad') {
	    PVE::QemuServer::vm_cad($vmid, $skiplock);
	} else {
	    raise_param_exc({ command => "unknown command '$command'" }) 
	}

	return undef;
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

	raise_param_exc({ force => "Only root may use this option." }) if $user ne 'root@pam';

	# test if VM exists
	PVE::QemuServer::load_config($vmid);

	# try to detect errors early
	if (PVE::QemuServer::check_running($vmid)) {
	    die "cant migrate running VM without --online\n" 
		if !$param->{online};
	}

	my $realcmd = sub {
	    my $upid = shift;

	    PVE::QemuMigrate::migrate($target, $targetip, $vmid, $param->{online}, $param->{force});
	};

	my $upid = $rpcenv->fork_worker('qmigrate', $vmid, $user, $realcmd);

	return $upid;
    }});

1;
