package PVE::CLI::qm;

use strict;
use warnings;

# Note: disable '+' prefix for Getopt::Long (for resize command)
use Getopt::Long qw(:config no_getopt_compat);

use Fcntl ':flock';
use File::Path;
use IO::Select;
use IO::Socket::UNIX;
use JSON;
use POSIX qw(strftime);
use Term::ReadLine;
use URI::Escape;

use PVE::Cluster;
use PVE::Exception qw(raise_param_exc);
use PVE::GuestHelpers;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Network;
use PVE::RPCEnvironment;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);

use PVE::API2::Qemu::Agent;
use PVE::API2::Qemu;
use PVE::QemuConfig;
use PVE::QemuServer::Drive;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Agent qw(agent_available);
use PVE::QemuServer::ImportDisk;
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::OVF;
use PVE::QemuServer;

use PVE::CLIHandler;
use base qw(PVE::CLIHandler);

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    exit(PVE::Tools::upid_status_is_error($status) ? -1 : 0);
};

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PVE::RPCEnvironment->setup_default_cli_env();
}

sub run_vnc_proxy {
    my ($path) = @_;

    my $c;
    while ( ++$c < 10 && !-e $path ) { sleep(1); }

    my $s = IO::Socket::UNIX->new(Peer => $path, Timeout => 120);

    die "unable to connect to socket '$path' - $!" if !$s;

    my $select = IO::Select->new();

    $select->add(\*STDIN);
    $select->add($s);

    my $timeout = 60*15; # 15 minutes

    my @handles;
    while ($select->count &&
	   scalar(@handles = $select->can_read ($timeout))) {
	foreach my $h (@handles) {
	    my $buf;
	    my $n = $h->sysread($buf, 4096);

	    if ($h == \*STDIN) {
		if ($n) {
		    syswrite($s, $buf);
		} else {
		    exit(0);
		}
	    } elsif ($h == $s) {
		if ($n) {
		    syswrite(\*STDOUT, $buf);
		} else {
		    exit(0);
		}
	    }
	}
    }
    exit(0);
}

sub print_recursive_hash {
    my ($prefix, $hash, $key) = @_;

    if (ref($hash) eq 'HASH') {
	if (defined($key)) {
	    print "$prefix$key:\n";
	}
	for my $itemkey (sort keys %$hash) {
	    print_recursive_hash("\t$prefix", $hash->{$itemkey}, $itemkey);
	}
    } elsif (ref($hash) eq 'ARRAY') {
	if (defined($key)) {
	    print "$prefix$key:\n";
	}
	for my $item (@$hash) {
	    print_recursive_hash("\t$prefix", $item);
	}
    } elsif ((!ref($hash) && defined($hash)) || ref($hash) eq 'JSON::PP::Boolean') {
	if (defined($key)) {
	    print "$prefix$key: $hash\n";
	} else {
	    print "$prefix$hash\n";
	}
    }
}

__PACKAGE__->register_method ({
    name => 'showcmd',
    path => 'showcmd',
    method => 'GET',
    description => "Show command line which is used to start the VM (debug info).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    pretty => {
		description => "Puts each option on a new line to enhance human readability",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    snapshot => get_standard_option('pve-snapshot-name', {
		description => "Fetch config values from given snapshot.",
		optional => 1,
		completion => sub {
		    my ($cmd, $pname, $cur, $args) = @_;
		    PVE::QemuConfig->snapshot_list($args->[0]);
		}
	    }),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $storecfg = PVE::Storage::config();
	my $cmdline = PVE::QemuServer::vm_commandline($storecfg, $param->{vmid}, $param->{snapshot});

	$cmdline =~ s/ -/ \\\n  -/g if $param->{pretty};

	print "$cmdline\n";

	return;
    }});

__PACKAGE__->register_method ({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Show VM status.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	    verbose => {
		description => "Verbose output format",
		type => 'boolean',
		optional => 1,
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	# test if VM exists
	my $conf = PVE::QemuConfig->load_config ($param->{vmid});

	my $vmstatus = PVE::QemuServer::vmstatus($param->{vmid}, 1);
	my $stat = $vmstatus->{$param->{vmid}};
	if ($param->{verbose}) {
	    foreach my $k (sort (keys %$stat)) {
		next if $k eq 'cpu' || $k eq 'relcpu'; # always 0
		my $v = $stat->{$k};
		print_recursive_hash("", $v, $k);
	    }
	} else {
	    my $status = $stat->{qmpstatus} || 'unknown';
	    print "status: $status\n";
	}

	return;
    }});

__PACKAGE__->register_method ({
    name => 'vncproxy',
    path => 'vncproxy',
    method => 'PUT',
    description => "Proxy VM VNC traffic to stdin/stdout",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_running }),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};
	PVE::QemuConfig::assert_config_exists_on_node($vmid);
	my $vnc_socket = PVE::QemuServer::Helpers::vnc_socket($vmid);

	if (my $ticket = $ENV{LC_PVE_TICKET}) {  # NOTE: ssh on debian only pass LC_* variables
	    mon_cmd($vmid, "set_password", protocol => 'vnc', password => $ticket);
	    mon_cmd($vmid, "expire_password", protocol => 'vnc', time => "+30");
	} else {
	    die "LC_PVE_TICKET not set, VNC proxy without password is forbidden\n";
	}

	run_vnc_proxy($vnc_socket);

	return;
    }});

__PACKAGE__->register_method ({
    name => 'unlock',
    path => 'unlock',
    method => 'PUT',
    description => "Unlock the VM.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	PVE::QemuConfig->lock_config ($vmid, sub {
	    my $conf = PVE::QemuConfig->load_config($vmid);
	    delete $conf->{lock};
	    delete $conf->{pending}->{lock} if $conf->{pending}; # just to be sure
	    PVE::QemuConfig->write_config($vmid, $conf);
	});

	return;
    }});

__PACKAGE__->register_method ({
    name => 'nbdstop',
    path => 'nbdstop',
    method => 'PUT',
    description => "Stop embedded nbd server.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid }),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	eval { PVE::QemuServer::nbd_stop($vmid) };
	warn $@ if $@;

	return;
    }});

__PACKAGE__->register_method ({
    name => 'mtunnel',
    path => 'mtunnel',
    method => 'POST',
    description => "Used by qmigrate - do not use manually.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	if (!PVE::Cluster::check_cfs_quorum(1)) {
	    print "no quorum\n";
	    return;
	}

	my $tunnel_write = sub {
	    my $text = shift;
	    chomp $text;
	    print "$text\n";
	    *STDOUT->flush();
	};

	$tunnel_write->("tunnel online");
	$tunnel_write->("ver 1");

	while (my $line = <STDIN>) {
	    chomp $line;
	    if ($line =~ /^quit$/) {
		$tunnel_write->("OK");
		last;
	    } elsif ($line =~ /^resume (\d+)$/) {
		my $vmid = $1;
		if (PVE::QemuServer::check_running($vmid, 1)) {
		    eval { PVE::QemuServer::vm_resume($vmid, 1, 1); };
		    if ($@) {
			$tunnel_write->("ERR: resume failed - $@");
		    } else {
			$tunnel_write->("OK");
		    }
		} else {
		    $tunnel_write->("ERR: resume failed - VM $vmid not running");
		}
	    }
	}

	return;
    }});

__PACKAGE__->register_method ({
    name => 'wait',
    path => 'wait',
    method => 'GET',
    description => "Wait until the VM is stopped.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_running }),
	    timeout => {
		description => "Timeout in seconds. Default is to wait forever.",
		type => 'integer',
		minimum => 1,
		optional => 1,
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};
	my $timeout = $param->{timeout};

	my $pid = PVE::QemuServer::check_running ($vmid);
	return if !$pid;

	print "waiting until VM $vmid stops (PID $pid)\n";

	my $count = 0;
	while ((!$timeout || ($count < $timeout)) && PVE::QemuServer::check_running ($vmid)) {
	    $count++;
	    sleep 1;
	}

	die "wait failed - got timeout\n" if PVE::QemuServer::check_running ($vmid);

	return;
    }});

__PACKAGE__->register_method ({
    name => 'monitor',
    path => 'monitor',
    method => 'POST',
    description => "Enter Qemu Monitor interface.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_running }),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	my $conf = PVE::QemuConfig->load_config ($vmid); # check if VM exists

	print "Entering Qemu Monitor for VM $vmid - type 'help' for help\n";

	my $term = Term::ReadLine->new('qm');

	while (defined(my $input = $term->readline('qm> '))) {
	    chomp $input;
	    next if $input =~ m/^\s*$/;
	    last if $input =~ m/^\s*q(uit)?\s*$/;

	    eval { print PVE::QemuServer::Monitor::hmp_cmd($vmid, $input) };
	    print "ERROR: $@" if $@;
	}

	return;

    }});

__PACKAGE__->register_method ({
    name => 'rescan',
    path => 'rescan',
    method => 'POST',
    description => "Rescan all storages and update disk sizes and unused disk images.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', {
		optional => 1,
		completion => \&PVE::QemuServer::complete_vmid,
	    }),
	    dryrun => {
		type => 'boolean',
		optional => 1,
		default => 0,
		description => 'Do not actually write changes out to VM config(s).',
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $dryrun = $param->{dryrun};

	print "NOTE: running in dry-run mode, won't write changes out!\n" if $dryrun;

	PVE::QemuServer::rescan($param->{vmid}, 0, $dryrun);

	return;
    }});

__PACKAGE__->register_method ({
    name => 'importdisk',
    path => 'importdisk',
    method => 'POST',
    description => "Import an external disk image as an unused disk in a VM. The
 image format has to be supported by qemu-img(1).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', {completion => \&PVE::QemuServer::complete_vmid}),
	    source => {
		description => 'Path to the disk image to import',
		type => 'string',
		optional => 0,
	    },
            storage => get_standard_option('pve-storage-id', {
		description => 'Target storage ID',
		completion => \&PVE::QemuServer::complete_storage,
		optional => 0,
            }),
	    format => {
		type => 'string',
		description => 'Target format',
		enum => [ 'raw', 'qcow2', 'vmdk' ],
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = extract_param($param, 'vmid');
	my $source = extract_param($param, 'source');
	my $storeid = extract_param($param, 'storage');
	my $format = extract_param($param, 'format');

	my $vm_conf = PVE::QemuConfig->load_config($vmid);
	PVE::QemuConfig->check_lock($vm_conf);
	die "$source: non-existent or non-regular file\n" if (! -f $source);

	my $storecfg = PVE::Storage::config();
	PVE::Storage::storage_check_enabled($storecfg, $storeid);

	my $target_storage_config =  PVE::Storage::storage_config($storecfg, $storeid);
	die "storage $storeid does not support vm images\n"
	    if !$target_storage_config->{content}->{images};

	print "importing disk '$source' to VM $vmid ...\n";
	my ($drive_id, $volid) = PVE::QemuServer::ImportDisk::do_import($source, $vmid, $storeid, { format => $format });
	print "Successfully imported disk as '$drive_id:$volid'\n";

	return;
    }});

__PACKAGE__->register_method ({
    name => 'terminal',
    path => 'terminal',
    method => 'POST',
    description => "Open a terminal using a serial device (The VM need to have a serial device configured, for example 'serial0: socket')",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_running }),
	    iface => {
		description => "Select the serial device. By default we simply use the first suitable device.",
		type => 'string',
		optional => 1,
		enum => [qw(serial0 serial1 serial2 serial3)],
	    },
	    escape => {
		description => "Escape character.",
		type => 'string',
		optional => 1,
		default => '^O',
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	my $escape = $param->{escape} // '^O';
	if ($escape =~ /^\^([\x40-\x7a])$/) {
	    $escape = ord($1) & 0x1F;
	} elsif ($escape =~ /^0x[0-9a-f]+$/i) {
	    $escape = hex($escape);
	} elsif ($escape =~ /^[0-9]+$/) {
	    $escape = int($escape);
	} else {
	    die "invalid escape character definition: $escape\n";
	}
	my $escapemsg = '';
	if ($escape) {
	    $escapemsg = sprintf(' (press Ctrl+%c to exit)', $escape+0x40);
	    $escape = sprintf(',escape=0x%x', $escape);
	} else {
	    $escape = '';
	}

	my $conf = PVE::QemuConfig->load_config ($vmid); # check if VM exists

	my $iface = $param->{iface};

	if ($iface) {
	    die "serial interface '$iface' is not configured\n" if !$conf->{$iface};
	    die "wrong serial type on interface '$iface'\n" if $conf->{$iface} ne 'socket';
	} else {
	    foreach my $opt (qw(serial0 serial1 serial2 serial3)) {
		if ($conf->{$opt} && ($conf->{$opt} eq 'socket')) {
		    $iface = $opt;
		    last;
		}
	    }
	    die "unable to find a serial interface\n" if !$iface;
	}

	die "VM $vmid not running\n" if !PVE::QemuServer::check_running($vmid);

	my $socket = "/var/run/qemu-server/${vmid}.$iface";

	my $cmd = "socat UNIX-CONNECT:$socket STDIO,raw,echo=0$escape";

	print "starting serial terminal on interface ${iface}${escapemsg}\n";

	system($cmd);

	return;
    }});

__PACKAGE__->register_method ({
    name => 'importovf',
    path => 'importovf',
    description => "Create a new VM using parameters read from an OVF manifest",
    parameters => {
	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::Cluster::complete_next_vmid }),
	    manifest => {
		type => 'string',
		description => 'path to the ovf file',
		},
	    storage => get_standard_option('pve-storage-id', {
		description => 'Target storage ID',
		completion => \&PVE::QemuServer::complete_storage,
		optional => 0,
	    }),
	    format => {
		type => 'string',
		description => 'Target format',
		enum => [ 'raw', 'qcow2', 'vmdk' ],
		optional => 1,
	    },
	    dryrun => {
		type => 'boolean',
		description => 'Print a parsed representation of the extracted OVF parameters, but do not create a VM',
		optional => 1,
	    }
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $vmid = PVE::Tools::extract_param($param, 'vmid');
	my $ovf_file = PVE::Tools::extract_param($param, 'manifest');
	my $storeid = PVE::Tools::extract_param($param, 'storage');
	my $format = PVE::Tools::extract_param($param, 'format');
	my $dryrun = PVE::Tools::extract_param($param, 'dryrun');

	die "$ovf_file: non-existent or non-regular file\n" if (! -f $ovf_file);
	my $storecfg = PVE::Storage::config();
	PVE::Storage::storage_check_enabled($storecfg, $storeid);

	my $parsed = PVE::QemuServer::OVF::parse_ovf($ovf_file);

	if ($dryrun) {
	    print to_json($parsed, { pretty => 1, canonical => 1});
	    return;
	}

	eval { PVE::QemuConfig->create_and_lock_config($vmid) };
	die "Reserving empty config for OVF import to VM $vmid failed: $@" if $@;

	my $conf = PVE::QemuConfig->load_config($vmid);
	die "Internal error: Expected 'create' lock in config of VM $vmid!"
	    if !PVE::QemuConfig->has_lock($conf, "create");

	$conf->{name} = $parsed->{qm}->{name} if defined($parsed->{qm}->{name});
	$conf->{memory} = $parsed->{qm}->{memory} if defined($parsed->{qm}->{memory});
	$conf->{cores} = $parsed->{qm}->{cores} if defined($parsed->{qm}->{cores});

	my $imported_disks = [];
	eval {
	    # order matters, as do_import() will load_config() internally
	    $conf->{vmgenid} = PVE::QemuServer::generate_uuid();
	    $conf->{smbios1} = PVE::QemuServer::generate_smbios1_uuid();
	    PVE::QemuConfig->write_config($vmid, $conf);

	    foreach my $disk (@{ $parsed->{disks} }) {
		my ($file, $drive) = ($disk->{backing_file}, $disk->{disk_address});
		my ($name, $volid) = PVE::QemuServer::ImportDisk::do_import($file, $vmid, $storeid, {
		    drive_name => $drive,
		    format => $format,
		    skiplock => 1,
		});
		# for cleanup on (later) error
		push @$imported_disks, $volid;
	    }

	    # reload after disks entries have been created
	    $conf = PVE::QemuConfig->load_config($vmid);
	    my $devs = PVE::QemuServer::get_default_bootdevices($conf);
	    $conf->{boot} = PVE::QemuServer::print_bootorder($devs);
	    PVE::QemuConfig->write_config($vmid, $conf);
	};

	if (my $err = $@) {
	    my $skiplock = 1;
	    warn "error during import, cleaning up created resources...\n";
	    for my $volid (@$imported_disks) {
		eval { PVE::Storage::vdisk_free($storecfg, $volid) };
		warn "cleanup of $volid failed: $@\n" if $@;
	    }
	    eval { PVE::QemuServer::destroy_vm($storecfg, $vmid, $skiplock) };
	    warn "Could not destroy VM $vmid: $@" if "$@";
	    die "import failed - $err";
	}

	PVE::QemuConfig->remove_lock($vmid, "create");

	return;

    }
});

__PACKAGE__->register_method({
    name => 'exec',
    path => 'exec',
    method => 'POST',
    protected => 1,
    description => "Executes the given command via the guest agent",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', {
		    completion => \&PVE::QemuServer::complete_vmid_running }),
	    synchronous => {
		type => 'boolean',
		optional => 1,
		default => 1,
		description => "If set to off, returns the pid immediately instead of waiting for the commmand to finish or the timeout.",
	    },
	    'timeout' => {
		type => 'integer',
		description => "The maximum time to wait synchronously for the command to finish. If reached, the pid gets returned. Set to 0 to deactivate",
		minimum => 0,
		optional => 1,
		default => 30,
	    },
	    'pass-stdin' => {
		type => 'boolean',
		description => "When set, read STDIN until EOF and forward to guest agent via 'input-data' (usually treated as STDIN to process launched by guest agent). Allows maximal 1 MiB.",
		optional => 1,
		default => 0,
	    },
	    'extra-args' => get_standard_option('extra-args'),
	},
    },
    returns => {
	type => 'object',
    },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};
	my $sync = $param->{synchronous} // 1;
	my $pass_stdin = $param->{'pass-stdin'};
	if (defined($param->{timeout}) && !$sync) {
	    raise_param_exc({ synchronous => "needs to be set for 'timeout'"});
	}

	my $input_data = undef;
	if ($pass_stdin) {
	    $input_data = '';
	    while (my $line = <STDIN>) {
		$input_data .= $line;
		if (length($input_data) > 1024*1024) {
		    # not sure how QEMU handles large amounts of data being
		    # passed into the QMP socket, so limit to be safe
		    die "'input-data' (STDIN) is limited to 1 MiB, aborting\n";
		}
	    }
	}

	my $args = $param->{'extra-args'};
	$args = undef if !$args || !@$args;

	my $res = PVE::QemuServer::Agent::qemu_exec($vmid, $input_data, $args);

	if ($sync) {
	    my $pid = $res->{pid};
	    my $timeout = $param->{timeout} // 30;
	    my $starttime = time();

	    while ($timeout == 0 || (time() - $starttime) < $timeout) {
		my $out = PVE::QemuServer::Agent::qemu_exec_status($vmid, $pid);
		if ($out->{exited}) {
		    $res = $out;
		    last;
		}
		sleep 1;
	    }

	    if (!$res->{exited}) {
		warn "timeout reached, returning pid\n";
	    }
	}

	return { result => $res };
    }});

__PACKAGE__->register_method({
    name => 'cleanup',
    path => 'cleanup',
    method => 'POST',
    protected => 1,
    description => "Cleans up resources like tap devices, vgpus, etc. Called after a vm shuts down, crashes, etc.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', {
		    completion => \&PVE::QemuServer::complete_vmid_running }),
	    'clean-shutdown' => {
		type => 'boolean',
		description => "Indicates if qemu shutdown cleanly.",
	    },
	    'guest-requested' => {
		type => 'boolean',
		description => "Indicates if the shutdown was requested by the guest or via qmp.",
	    },
	},
    },
    returns => { type => 'null', },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};
	my $clean = $param->{'clean-shutdown'};
	my $guest = $param->{'guest-requested'};
	my $restart = 0;

	# return if we do not have the config anymore
	return if !-f PVE::QemuConfig->config_file($vmid);

	my $storecfg = PVE::Storage::config();
	warn "Starting cleanup for $vmid\n";

	PVE::QemuConfig->lock_config($vmid, sub {
	    my $conf = PVE::QemuConfig->load_config ($vmid);
	    my $pid = PVE::QemuServer::check_running ($vmid);
	    die "vm still running\n" if $pid;

	    if (!$clean) {
		# we have to cleanup the tap devices after a crash

		foreach my $opt (keys %$conf) {
		    next if $opt !~  m/^net(\d)+$/;
		    my $interface = $1;
		    PVE::Network::tap_unplug("tap${vmid}i${interface}");
		}
	    }

	    if (!$clean || $guest) {
		# vm was shutdown from inside the guest or crashed, doing api cleanup
		PVE::QemuServer::vm_stop_cleanup($storecfg, $vmid, $conf, 0, 0);
	    }
	    PVE::GuestHelpers::exec_hookscript($conf, $vmid, 'post-stop');

	    $restart = eval { PVE::QemuServer::clear_reboot_request($vmid) };
	    warn $@ if $@;
	});

	warn "Finished cleanup for $vmid\n";

	if ($restart) {
	    warn "Restarting VM $vmid\n";
	    PVE::API2::Qemu->vm_start({
		vmid => $vmid,
		node => $nodename,
	    });
	}

	return;
    }});

my $print_agent_result = sub {
    my ($data) = @_;

    my $result = $data->{result} // $data;
    return if !defined($result);

    my $class = ref($result);

    if (!$class) {
	chomp $result;
	return if $result =~ m/^\s*$/;
	print "$result\n";
	return;
    }

    if (($class eq 'HASH') && !scalar(keys %$result)) { # empty hash
	return;
    }

    print to_json($result, { pretty => 1, canonical => 1});
};

sub param_mapping {
    my ($name) = @_;

    my $ssh_key_map = ['sshkeys', sub {
	return URI::Escape::uri_escape(PVE::Tools::file_get_contents($_[0]));
    }];
    my $cipassword_map = PVE::CLIHandler::get_standard_mapping('pve-password', { name => 'cipassword' });
    my $password_map = PVE::CLIHandler::get_standard_mapping('pve-password');
    my $mapping = {
	'update_vm' => [$ssh_key_map, $cipassword_map],
	'create_vm' => [$ssh_key_map, $cipassword_map],
	'set-user-password' => [$password_map],
    };

    return $mapping->{$name};
}

our $cmddef = {
    list => [ "PVE::API2::Qemu", 'vmlist', [],
	     { node => $nodename }, sub {
		 my $vmlist = shift;

		 exit 0 if (!scalar(@$vmlist));

		 printf "%10s %-20s %-10s %-10s %12s %-10s\n",
		 qw(VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID);

		 foreach my $rec (sort { $a->{vmid} <=> $b->{vmid} } @$vmlist) {
		     printf "%10s %-20s %-10s %-10s %12.2f %-10s\n", $rec->{vmid}, $rec->{name},
		     $rec->{qmpstatus} || $rec->{status},
		     ($rec->{maxmem} || 0)/(1024*1024),
		     ($rec->{maxdisk} || 0)/(1024*1024*1024),
		     $rec->{pid}||0;
		 }


	      } ],

    create => [ "PVE::API2::Qemu", 'create_vm', ['vmid'], { node => $nodename }, $upid_exit ],

    destroy => [ "PVE::API2::Qemu", 'destroy_vm', ['vmid'], { node => $nodename }, $upid_exit ],

    clone => [ "PVE::API2::Qemu", 'clone_vm', ['vmid', 'newid'], { node => $nodename }, $upid_exit ],

    migrate => [ "PVE::API2::Qemu", 'migrate_vm', ['vmid', 'target'], { node => $nodename }, $upid_exit ],

    set => [ "PVE::API2::Qemu", 'update_vm', ['vmid'], { node => $nodename } ],

    resize => [ "PVE::API2::Qemu", 'resize_vm', ['vmid', 'disk', 'size'], { node => $nodename } ],

    move_disk => [ "PVE::API2::Qemu", 'move_vm_disk', ['vmid', 'disk', 'storage'], { node => $nodename }, $upid_exit ],

    unlink => [ "PVE::API2::Qemu", 'unlink', ['vmid'], { node => $nodename } ],

    config => [ "PVE::API2::Qemu", 'vm_config', ['vmid'],
		{ node => $nodename }, sub {
		    my $config = shift;
		    foreach my $k (sort (keys %$config)) {
			next if $k eq 'digest';
			my $v = $config->{$k};
			if ($k eq 'description') {
			    $v = PVE::Tools::encode_text($v);
			}
			print "$k: $v\n";
		    }
		}],

    pending => [ "PVE::API2::Qemu", 'vm_pending', ['vmid'], { node => $nodename }, \&PVE::GuestHelpers::format_pending ],
    showcmd => [ __PACKAGE__, 'showcmd', ['vmid']],

    status => [ __PACKAGE__, 'status', ['vmid']],

    snapshot => [ "PVE::API2::Qemu", 'snapshot', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],

    delsnapshot => [ "PVE::API2::Qemu", 'delsnapshot', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],

    listsnapshot => [ "PVE::API2::Qemu", 'snapshot_list', ['vmid'], { node => $nodename }, \&PVE::GuestHelpers::print_snapshot_tree],

    rollback => [ "PVE::API2::Qemu", 'rollback', ['vmid', 'snapname'], { node => $nodename } , $upid_exit ],

    template => [ "PVE::API2::Qemu", 'template', ['vmid'], { node => $nodename }],

    start => [ "PVE::API2::Qemu", 'vm_start', ['vmid'], { node => $nodename } , $upid_exit ],

    stop => [ "PVE::API2::Qemu", 'vm_stop', ['vmid'], { node => $nodename }, $upid_exit ],

    reset => [ "PVE::API2::Qemu", 'vm_reset', ['vmid'], { node => $nodename }, $upid_exit ],

    shutdown => [ "PVE::API2::Qemu", 'vm_shutdown', ['vmid'], { node => $nodename }, $upid_exit ],

    reboot => [ "PVE::API2::Qemu", 'vm_reboot', ['vmid'], { node => $nodename }, $upid_exit ],

    suspend => [ "PVE::API2::Qemu", 'vm_suspend', ['vmid'], { node => $nodename }, $upid_exit ],

    resume => [ "PVE::API2::Qemu", 'vm_resume', ['vmid'], { node => $nodename }, $upid_exit ],

    sendkey => [ "PVE::API2::Qemu", 'vm_sendkey', ['vmid', 'key'], { node => $nodename } ],

    vncproxy => [ __PACKAGE__, 'vncproxy', ['vmid']],

    wait => [ __PACKAGE__, 'wait', ['vmid']],

    unlock => [ __PACKAGE__, 'unlock', ['vmid']],

    rescan  => [ __PACKAGE__, 'rescan', []],

    monitor  => [ __PACKAGE__, 'monitor', ['vmid']],

    agent  => { alias => 'guest cmd' },

    guest => {
	cmd  => [ "PVE::API2::Qemu::Agent", 'agent', ['vmid', 'command'], { node => $nodename }, $print_agent_result ],
	passwd => [ "PVE::API2::Qemu::Agent", 'set-user-password', [ 'vmid', 'username' ], { node => $nodename }],
	exec => [ __PACKAGE__, 'exec', [ 'vmid', 'extra-args' ], { node => $nodename }, $print_agent_result],
	'exec-status' => [ "PVE::API2::Qemu::Agent", 'exec-status', [ 'vmid', 'pid' ], { node => $nodename }, $print_agent_result],
    },

    mtunnel => [ __PACKAGE__, 'mtunnel', []],

    nbdstop => [ __PACKAGE__, 'nbdstop', ['vmid']],

    terminal => [ __PACKAGE__, 'terminal', ['vmid']],

    importdisk => [ __PACKAGE__, 'importdisk', ['vmid', 'source', 'storage']],

    importovf => [ __PACKAGE__, 'importovf', ['vmid', 'manifest', 'storage']],

    cleanup => [ __PACKAGE__, 'cleanup', ['vmid', 'clean-shutdown', 'guest-requested'], { node => $nodename }],

    cloudinit => {
	dump => [ "PVE::API2::Qemu", 'cloudinit_generated_config_dump', ['vmid', 'type'], { node => $nodename }, sub {
		my $data = shift;
		print "$data\n";
	    }],
    },

};

1;
