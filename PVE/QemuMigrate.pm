package PVE::QemuMigrate;

use strict;
use warnings;
use PVE::AbstractMigrate;
use IO::File;
use IPC::Open2;
use POSIX qw( WNOHANG );
use PVE::INotify;
use PVE::Tools;
use PVE::Cluster;
use PVE::Storage;
use PVE::QemuServer;
use Time::HiRes qw( usleep );
use PVE::RPCEnvironment;
use PVE::ReplicationConfig;
use PVE::ReplicationState;
use PVE::Replication;

use base qw(PVE::AbstractMigrate);

sub fork_command_pipe {
    my ($self, $cmd) = @_;

    my $reader = IO::File->new();
    my $writer = IO::File->new();

    my $orig_pid = $$;

    my $cpid;

    eval { $cpid = open2($reader, $writer, @$cmd); };

    my $err = $@;

    # catch exec errors
    if ($orig_pid != $$) {
	$self->log('err', "can't fork command pipe\n");
	POSIX::_exit(1);
	kill('KILL', $$);
    }

    die $err if $err;

    return { writer => $writer, reader => $reader, pid => $cpid };
}

sub finish_command_pipe {
    my ($self, $cmdpipe, $timeout) = @_;

    my $cpid = $cmdpipe->{pid};
    return if !defined($cpid);

    my $writer = $cmdpipe->{writer};
    my $reader = $cmdpipe->{reader};

    $writer->close();
    $reader->close();

    my $collect_child_process = sub {
	my $res = waitpid($cpid, WNOHANG);
	if (defined($res) && ($res == $cpid)) {
	    delete $cmdpipe->{cpid};
	    return 1;
	} else {
	    return 0;
	}
     };

    if ($timeout) {
	for (my $i = 0; $i < $timeout; $i++) {
	    return if &$collect_child_process();
	    sleep(1);
	}
    }

    $self->log('info', "ssh tunnel still running - terminating now with SIGTERM\n");
    kill(15, $cpid);

    # wait again
    for (my $i = 0; $i < 10; $i++) {
	return if &$collect_child_process();
	sleep(1);
    }

    $self->log('info', "ssh tunnel still running - terminating now with SIGKILL\n");
    kill 9, $cpid;
    sleep 1;

    $self->log('err', "ssh tunnel child process (PID $cpid) couldn't be collected\n")
	if !&$collect_child_process();
}

sub read_tunnel {
    my ($self, $tunnel, $timeout) = @_;

    $timeout = 60 if !defined($timeout);

    my $reader = $tunnel->{reader};

    my $output;
    eval {
	PVE::Tools::run_with_timeout($timeout, sub { $output = <$reader>; });
    };
    die "reading from tunnel failed: $@\n" if $@;

    chomp $output;

    return $output;
}

sub write_tunnel {
    my ($self, $tunnel, $timeout, $command) = @_;

    $timeout = 60 if !defined($timeout);

    my $writer = $tunnel->{writer};

    eval {
	PVE::Tools::run_with_timeout($timeout, sub {
	    print $writer "$command\n";
	    $writer->flush();
	});
    };
    die "writing to tunnel failed: $@\n" if $@;

    if ($tunnel->{version} && $tunnel->{version} >= 1) {
	my $res = eval { $self->read_tunnel($tunnel, 10); };
	die "no reply to command '$command': $@\n" if $@;

	if ($res eq 'OK') {
	    return;
	} else {
	    die "tunnel replied '$res' to command '$command'\n";
	}
    }
}

sub fork_tunnel {
    my ($self, $tunnel_addr) = @_;

    my @localtunnelinfo = defined($tunnel_addr) ? ('-L' , $tunnel_addr ) : ();

    my $cmd = [@{$self->{rem_ssh}}, '-o ExitOnForwardFailure=yes', @localtunnelinfo, '/usr/sbin/qm', 'mtunnel' ];

    my $tunnel = $self->fork_command_pipe($cmd);

    eval {
	my $helo = $self->read_tunnel($tunnel, 60);
	die "no reply\n" if !$helo;
	die "no quorum on target node\n" if $helo =~ m/^no quorum$/;
	die "got strange reply from mtunnel ('$helo')\n"
	    if $helo !~ m/^tunnel online$/;
    };
    my $err = $@;

    eval {
	my $ver = $self->read_tunnel($tunnel, 10);
	if ($ver =~ /^ver (\d+)$/) {
	    $tunnel->{version} = $1;
	    $self->log('info', "ssh tunnel $ver\n");
	} else {
	    $err = "received invalid tunnel version string '$ver'\n" if !$err;
	}
    };

    if ($err) {
	$self->finish_command_pipe($tunnel);
	die "can't open migration tunnel - $err";
    }
    return $tunnel;
}

sub finish_tunnel {
    my ($self, $tunnel) = @_;

    eval { $self->write_tunnel($tunnel, 30, 'quit'); };
    my $err = $@;

    $self->finish_command_pipe($tunnel, 30);

    if ($tunnel->{sock_addr}) {
	# ssh does not clean up on local host
	my $cmd = ['rm', '-f', $tunnel->{sock_addr}]; #
	PVE::Tools::run_command($cmd);

	# .. and just to be sure check on remote side
	unshift @{$cmd}, @{$self->{rem_ssh}};
	PVE::Tools::run_command($cmd);
    }

    die $err if $err;
}

sub lock_vm {
    my ($self, $vmid, $code, @param) = @_;

    return PVE::QemuConfig->lock_config($vmid, $code, @param);
}

sub prepare {
    my ($self, $vmid) = @_;

    my $online = $self->{opts}->{online};

    $self->{storecfg} = PVE::Storage::config();

    # test if VM exists
    my $conf = $self->{vmconf} = PVE::QemuConfig->load_config($vmid);

    PVE::QemuConfig->check_lock($conf);

    my $running = 0;
    if (my $pid = PVE::QemuServer::check_running($vmid)) {
	die "can't migrate running VM without --online\n" if !$online;
	$running = $pid;

	$self->{forcemachine} = PVE::QemuServer::qemu_machine_pxe($vmid, $conf);

    }

    if (my $loc_res = PVE::QemuServer::check_local_resources($conf, 1)) {
	if ($self->{running} || !$self->{opts}->{force}) {
	    die "can't migrate VM which uses local devices\n";
	} else {
	    $self->log('info', "migrating VM which uses local devices");
	}
    }

    my $vollist = PVE::QemuServer::get_vm_volumes($conf);

    my $need_activate = [];
    foreach my $volid (@$vollist) {
	my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

	# check if storage is available on both nodes
	my $targetsid = $self->{opts}->{targetstorage} ? $self->{opts}->{targetstorage} : $sid;

	my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $sid);
	PVE::Storage::storage_check_node($self->{storecfg}, $targetsid, $self->{node});

	if ($scfg->{shared}) {
	    # PVE::Storage::activate_storage checks this for non-shared storages
	    my $plugin = PVE::Storage::Plugin->lookup($scfg->{type});
	    warn "Used shared storage '$sid' is not online on source node!\n"
		if !$plugin->check_connection($sid, $scfg);
	} else {
	    # only activate if not shared
	    push @$need_activate, $volid;
	}
    }

    # activate volumes
    PVE::Storage::activate_volumes($self->{storecfg}, $need_activate);

    # test ssh connection
    my $cmd = [ @{$self->{rem_ssh}}, '/bin/true' ];
    eval { $self->cmd_quiet($cmd); };
    die "Can't connect to destination address using public key\n" if $@;

    return $running;
}

sub sync_disks {
    my ($self, $vmid) = @_;

    my $conf = $self->{vmconf};

    # local volumes which have been copied
    $self->{volumes} = [];

    eval {

	# found local volumes and their origin
	my $local_volumes = {};
	my $local_volumes_errors = {};
	my $other_errors = [];
	my $abort = 0;

	my $sharedvm = 1;

	my $log_error = sub {
	    my ($msg, $volid) = @_;

	    if (defined($volid)) {
		$local_volumes_errors->{$volid} = $msg;
	    } else {
		push @$other_errors, $msg;
	    }
	    $abort = 1;
	};

	my @sids = PVE::Storage::storage_ids($self->{storecfg});
	foreach my $storeid (@sids) {
	    my $scfg = PVE::Storage::storage_config($self->{storecfg}, $storeid);
	    next if $scfg->{shared};
	    next if !PVE::Storage::storage_check_enabled($self->{storecfg}, $storeid, undef, 1);

	    # get list from PVE::Storage (for unused volumes)
	    my $dl = PVE::Storage::vdisk_list($self->{storecfg}, $storeid, $vmid);

	    next if @{$dl->{$storeid}} == 0;

	    my $targetsid = $self->{opts}->{targetstorage} ? $self->{opts}->{targetstorage} : $storeid;

	    # check if storage is available on target node
	    PVE::Storage::storage_check_node($self->{storecfg}, $targetsid, $self->{node});
	    $sharedvm = 0; # there is a non-shared disk

	    PVE::Storage::foreach_volid($dl, sub {
		my ($volid, $sid, $volname) = @_;

		$local_volumes->{$volid}->{ref} = 'storage';
	    });
	}

	my $test_volid = sub {
	    my ($volid, $attr) = @_;

	    if ($volid =~ m|^/|) {
		return if $attr->{shared};
		$local_volumes->{$volid}->{ref} = 'config';
		die "local file/device\n";
	    }

	    my $snaprefs = $attr->{referenced_in_snapshot};

	    if ($attr->{cdrom}) {
		if ($volid eq 'cdrom') {
		    my $msg = "can't migrate local cdrom drive";
		    if (defined($snaprefs) && !$attr->{referenced_in_config}) {
			my $snapnames = join(', ', sort keys %$snaprefs);
			$msg .= " (referenced in snapshot - $snapnames)";
		    }
		    &$log_error("$msg\n");
		    return;
		}
		return if $volid eq 'none';
	    }

	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);

	    my $targetsid = $self->{opts}->{targetstorage} ? $self->{opts}->{targetstorage} : $sid;
	    # check if storage is available on both nodes
	    my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $sid);
	    PVE::Storage::storage_check_node($self->{storecfg}, $targetsid, $self->{node});

	    return if $scfg->{shared};

	    $sharedvm = 0;

	    $local_volumes->{$volid}->{ref} = $attr->{referenced_in_config} ? 'config' : 'snapshot';

	    die "local cdrom image\n" if $attr->{cdrom};

	    my ($path, $owner) = PVE::Storage::path($self->{storecfg}, $volid);

	    die "owned by other VM (owner = VM $owner)\n"
		if !$owner || ($owner != $self->{vmid});

	    my $format = PVE::QemuServer::qemu_img_format($scfg, $volname);
	    $local_volumes->{$volid}->{snapshots} = defined($snaprefs) || ($format =~ /^(?:qcow2|vmdk)$/);
	    if (defined($snaprefs)) {
		# we cannot migrate shapshots on local storage
		# exceptions: 'zfspool' or 'qcow2' files (on directory storage)

		die "online storage migration not possible if snapshot exists\n" if $self->{running};
		if (!($scfg->{type} eq 'zfspool' || $format eq 'qcow2')) {
		    die "non-migratable snapshot exists\n";
		}
	    }

	    die "referenced by linked clone(s)\n"
		if PVE::Storage::volume_is_base_and_used($self->{storecfg}, $volid);
	};

	PVE::QemuServer::foreach_volid($conf, sub {
	    my ($volid, $attr) = @_;
	    eval { $test_volid->($volid, $attr); };
	    if (my $err = $@) {
		&$log_error($err, $volid);
	    }
        });

	foreach my $vol (sort keys %$local_volumes) {
	    my $ref = $local_volumes->{$vol}->{ref};
	    if ($ref eq 'storage') {
		$self->log('info', "found local disk '$vol' (via storage)\n");
	    } elsif ($ref eq 'config') {
		&$log_error("can't live migrate attached local disks without with-local-disks option\n", $vol)
		    if $self->{running} && !$self->{opts}->{"with-local-disks"};
		$self->log('info', "found local disk '$vol' (in current VM config)\n");
	    } elsif ($ref eq 'snapshot') {
		$self->log('info', "found local disk '$vol' (referenced by snapshot(s))\n");
	    } else {
		$self->log('info', "found local disk '$vol'\n");
	    }
	}

	foreach my $vol (sort keys %$local_volumes_errors) {
	    $self->log('warn', "can't migrate local disk '$vol': $local_volumes_errors->{$vol}");
	}
	foreach my $err (@$other_errors) {
	    $self->log('warn', "$err");
	}

	if ($self->{running} && !$sharedvm && !$self->{opts}->{targetstorage}) {
	    $self->{opts}->{targetstorage} = 1; #use same sid for remote local
	}

	if ($abort) {
	    die "can't migrate VM - check log\n";
	}

	# additional checks for local storage
	foreach my $volid (keys %$local_volumes) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    my $scfg =  PVE::Storage::storage_config($self->{storecfg}, $sid);

	    my $migratable = ($scfg->{type} eq 'dir') || ($scfg->{type} eq 'zfspool') ||
		($scfg->{type} eq 'lvmthin') || ($scfg->{type} eq 'lvm');

	    die "can't migrate '$volid' - storage type '$scfg->{type}' not supported\n"
		if !$migratable;

	    # image is a linked clone on local storage, se we can't migrate.
	    if (my $basename = (PVE::Storage::parse_volname($self->{storecfg}, $volid))[3]) {
		die "can't migrate '$volid' as it's a clone of '$basename'";
	    }
	}

	my $rep_volumes;

	$self->log('info', "copying disk images");

	my $rep_cfg = PVE::ReplicationConfig->new();

	if (my $jobcfg = $rep_cfg->find_local_replication_job($vmid, $self->{node})) {
	    die "can't live migrate VM with replicated volumes\n" if $self->{running};
	    my $start_time = time();
	    my $logfunc = sub { my ($msg) = @_;  $self->log('info', $msg); };
	    $rep_volumes = PVE::Replication::run_replication(
	       'PVE::QemuConfig', $jobcfg, $start_time, $start_time, $logfunc);
	    $self->{replicated_volumes} = $rep_volumes;
	}

	foreach my $volid (keys %$local_volumes) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    if ($self->{running} && $self->{opts}->{targetstorage} && $local_volumes->{$volid}->{ref} eq 'config') {
		push @{$self->{online_local_volumes}}, $volid;
	    } else {
		next if $rep_volumes->{$volid};
		push @{$self->{volumes}}, $volid;
		my $insecure = $self->{opts}->{migration_type} eq 'insecure';
		my $with_snapshots = $local_volumes->{$volid}->{snapshots};
		PVE::Storage::storage_migrate($self->{storecfg}, $volid, $self->{ssh_info}, $sid,
					      undef, undef, undef, undef, $insecure, $with_snapshots);
	    }
	}
    };
    die "Failed to sync data - $@" if $@;
}

sub cleanup_remotedisks {
    my ($self) = @_;

    foreach my $target_drive (keys %{$self->{target_drive}}) {

	my $drive = PVE::QemuServer::parse_drive($target_drive, $self->{target_drive}->{$target_drive}->{volid});
	my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file});

	my $cmd = [@{$self->{rem_ssh}}, 'pvesm', 'free', "$storeid:$volname"];

	eval{ PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => sub {}) };
	if (my $err = $@) {
	    $self->log('err', $err);
	    $self->{errors} = 1;
	}
    }
}

sub phase1 {
    my ($self, $vmid) = @_;

    $self->log('info', "starting migration of VM $vmid to node '$self->{node}' ($self->{nodeip})");

    my $conf = $self->{vmconf};

    # set migrate lock in config file
    $conf->{lock} = 'migrate';
    PVE::QemuConfig->write_config($vmid, $conf);

    sync_disks($self, $vmid);

};

sub phase1_cleanup {
    my ($self, $vmid, $err) = @_;

    $self->log('info', "aborting phase 1 - cleanup resources");

    my $conf = $self->{vmconf};
    delete $conf->{lock};
    eval { PVE::QemuConfig->write_config($vmid, $conf) };
    if (my $err = $@) {
	$self->log('err', $err);
    }

    if ($self->{volumes}) {
	foreach my $volid (@{$self->{volumes}}) {
	    $self->log('err', "found stale volume copy '$volid' on node '$self->{node}'");
	    # fixme: try to remove ?
	}
    }
}

sub phase2 {
    my ($self, $vmid) = @_;

    my $conf = $self->{vmconf};

    $self->log('info', "starting VM $vmid on remote node '$self->{node}'");

    my $raddr;
    my $rport;
    my $ruri; # the whole migration dst. URI (protocol:address[:port])
    my $nodename = PVE::INotify::nodename();

    ## start on remote node
    my $cmd = [@{$self->{rem_ssh}}];

    my $spice_ticket;
    if (PVE::QemuServer::vga_conf_has_spice($conf->{vga})) {
	my $res = PVE::QemuServer::vm_mon_cmd($vmid, 'query-spice');
	$spice_ticket = $res->{ticket};
    }

    push @$cmd , 'qm', 'start', $vmid, '--skiplock', '--migratedfrom', $nodename;

    my $migration_type = $self->{opts}->{migration_type};

    push @$cmd, '--migration_type', $migration_type;

    push @$cmd, '--migration_network', $self->{opts}->{migration_network}
      if $self->{opts}->{migration_network};

    if ($migration_type eq 'insecure') {
	push @$cmd, '--stateuri', 'tcp';
    } else {
	push @$cmd, '--stateuri', 'unix';
    }

    if ($self->{forcemachine}) {
	push @$cmd, '--machine', $self->{forcemachine};
    }

    if ($self->{opts}->{targetstorage}) {
	push @$cmd, '--targetstorage', $self->{opts}->{targetstorage};
    }

    my $spice_port;

    # Note: We try to keep $spice_ticket secret (do not pass via command line parameter)
    # instead we pipe it through STDIN
    PVE::Tools::run_command($cmd, input => $spice_ticket, outfunc => sub {
	my $line = shift;

	if ($line =~ m/^migration listens on tcp:(localhost|[\d\.]+|\[[\d\.:a-fA-F]+\]):(\d+)$/) {
	    $raddr = $1;
	    $rport = int($2);
	    $ruri = "tcp:$raddr:$rport";
	}
	elsif ($line =~ m!^migration listens on unix:(/run/qemu-server/(\d+)\.migrate)$!) {
	    $raddr = $1;
	    die "Destination UNIX sockets VMID does not match source VMID" if $vmid ne $2;
	    $ruri = "unix:$raddr";
	}
	elsif ($line =~ m/^migration listens on port (\d+)$/) {
	    $raddr = "localhost";
	    $rport = int($1);
	    $ruri = "tcp:$raddr:$rport";
	}
        elsif ($line =~ m/^spice listens on port (\d+)$/) {
	    $spice_port = int($1);
	}
        elsif ($line =~ m/^storage migration listens on nbd:(localhost|[\d\.]+|\[[\d\.:a-fA-F]+\]):(\d+):exportname=(\S+) volume:(\S+)$/) {
	    my $volid = $4;
	    my $nbd_uri = "nbd:$1:$2:exportname=$3";
	    my $targetdrive = $3;
	    $targetdrive =~ s/drive-//g;

	    $self->{target_drive}->{$targetdrive}->{volid} = $volid;
	    $self->{target_drive}->{$targetdrive}->{nbd_uri} = $nbd_uri;

	}
    }, errfunc => sub {
	my $line = shift;
	$self->log('info', $line);
    });

    die "unable to detect remote migration address\n" if !$raddr;

    $self->log('info', "start remote tunnel");

    if ($migration_type eq 'secure') {

	if ($ruri =~ /^unix:/) {
	    unlink $raddr;
	    $self->{tunnel} = $self->fork_tunnel("$raddr:$raddr");
	    $self->{tunnel}->{sock_addr} = $raddr;

	    my $unix_socket_try = 0; # wait for the socket to become ready
	    while (! -S $raddr) {
		$unix_socket_try++;
		if ($unix_socket_try > 100) {
		    $self->{errors} = 1;
		    $self->finish_tunnel($self->{tunnel});
		    die "Timeout, migration socket $ruri did not get ready";
		}

		usleep(50000);
	    }

	} elsif ($ruri =~ /^tcp:/) {
	    my $tunnel_addr;
	    if ($raddr eq "localhost") {
		# for backwards compatibility with older qemu-server versions
		my $pfamily = PVE::Tools::get_host_address_family($nodename);
		my $lport = PVE::Tools::next_migrate_port($pfamily);
		$tunnel_addr = "$lport:localhost:$rport";
	    }

	    $self->{tunnel} = $self->fork_tunnel($tunnel_addr);

	} else {
	    die "unsupported protocol in migration URI: $ruri\n";
	}
    } else {
	#fork tunnel for insecure migration, to send faster commands like resume
	$self->{tunnel} = $self->fork_tunnel();
    }

    my $start = time();

    if ($self->{opts}->{targetstorage} && defined($self->{online_local_volumes})) {
	$self->{storage_migration} = 1;
	$self->{storage_migration_jobs} = {};
	$self->log('info', "starting storage migration");

	die "The number of local disks does not match between the source and the destination.\n"
	    if (scalar(keys %{$self->{target_drive}}) != scalar @{$self->{online_local_volumes}});
	foreach my $drive (keys %{$self->{target_drive}}){
	    my $nbd_uri = $self->{target_drive}->{$drive}->{nbd_uri};
	    $self->log('info', "$drive: start migration to $nbd_uri");
	    PVE::QemuServer::qemu_drive_mirror($vmid, $drive, $nbd_uri, $vmid, undef, $self->{storage_migration_jobs}, 1);
	}
    }

    $self->log('info', "starting online/live migration on $ruri");
    $self->{livemigration} = 1;

    # load_defaults
    my $defaults = PVE::QemuServer::load_defaults();

    # always set migrate speed (overwrite kvm default of 32m)
    # we set a very hight default of 8192m which is basically unlimited
    my $migrate_speed = $defaults->{migrate_speed} || 8192;
    $migrate_speed = $conf->{migrate_speed} || $migrate_speed;
    $migrate_speed = $migrate_speed * 1048576;
    $self->log('info', "migrate_set_speed: $migrate_speed");
    eval {
        PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate_set_speed", value => int($migrate_speed));
    };
    $self->log('info', "migrate_set_speed error: $@") if $@;

    my $migrate_downtime = $defaults->{migrate_downtime};
    $migrate_downtime = $conf->{migrate_downtime} if defined($conf->{migrate_downtime});
    if (defined($migrate_downtime)) {
	$self->log('info', "migrate_set_downtime: $migrate_downtime");
	eval {
	    PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate_set_downtime", value => int($migrate_downtime*100)/100);
	};
	$self->log('info', "migrate_set_downtime error: $@") if $@;
    }

    $self->log('info', "set migration_caps");
    eval {
	PVE::QemuServer::set_migration_caps($vmid);
    };
    warn $@ if $@;

    # set cachesize to 10% of the total memory
    my $memory =  $conf->{memory} || $defaults->{memory};
    my $cachesize = int($memory * 1048576 / 10);
    $cachesize = round_powerof2($cachesize);

    $self->log('info', "set cachesize: $cachesize");
    eval {
	PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate-set-cache-size", value => int($cachesize));
    };
    $self->log('info', "migrate-set-cache-size error: $@") if $@;

    if (PVE::QemuServer::vga_conf_has_spice($conf->{vga})) {
	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my (undef, $proxyticket) = PVE::AccessControl::assemble_spice_ticket($authuser, $vmid, $self->{node});

	my $filename = "/etc/pve/nodes/$self->{node}/pve-ssl.pem";
        my $subject =  PVE::AccessControl::read_x509_subject_spice($filename);

	$self->log('info', "spice client_migrate_info");

	eval {
	    PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "client_migrate_info", protocol => 'spice', 
						hostname => $proxyticket, 'tls-port' => $spice_port, 
						'cert-subject' => $subject);
	};
	$self->log('info', "client_migrate_info error: $@") if $@;

    }

    $self->log('info', "start migrate command to $ruri");
    eval {
        PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate", uri => $ruri);
    };
    my $merr = $@;
    $self->log('info', "migrate uri => $ruri failed: $merr") if $merr;

    my $lstat = 0;
    my $usleep = 1000000;
    my $i = 0;
    my $err_count = 0;
    my $lastrem = undef;
    my $downtimecounter = 0;
    while (1) {
	$i++;
	my $avglstat = $lstat/$i if $lstat;

	usleep($usleep);
	my $stat;
	eval {
	    $stat = PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "query-migrate");
	};
	if (my $err = $@) {
	    $err_count++;
	    warn "query migrate failed: $err\n";
	    $self->log('info', "query migrate failed: $err");
	    if ($err_count <= 5) {
		usleep(1000000);
		next;
	    }
	    die "too many query migrate failures - aborting\n";
	}

        if (defined($stat->{status}) && $stat->{status} =~ m/^(setup)$/im) {
            sleep(1);
            next;
        }

	if (defined($stat->{status}) && $stat->{status} =~ m/^(active|completed|failed|cancelled)$/im) {
	    $merr = undef;
	    $err_count = 0;
	    if ($stat->{status} eq 'completed') {
		my $delay = time() - $start;
		if ($delay > 0) {
		    my $mbps = sprintf "%.2f", $memory / $delay;
		    my $downtime = $stat->{downtime} || 0;
		    $self->log('info', "migration speed: $mbps MB/s - downtime $downtime ms");
		}
	    }

	    if ($stat->{status} eq 'failed' || $stat->{status} eq 'cancelled') {
		$self->log('info', "migration status error: $stat->{status}");
		die "aborting\n"
	    }

	    if ($stat->{status} ne 'active') {
		$self->log('info', "migration status: $stat->{status}");
		last;
	    }

	    if ($stat->{ram}->{transferred} ne $lstat) {
		my $trans = $stat->{ram}->{transferred} || 0;
		my $rem = $stat->{ram}->{remaining} || 0;
		my $total = $stat->{ram}->{total} || 0;
		my $xbzrlecachesize = $stat->{"xbzrle-cache"}->{"cache-size"} || 0;
		my $xbzrlebytes = $stat->{"xbzrle-cache"}->{"bytes"} || 0;
		my $xbzrlepages = $stat->{"xbzrle-cache"}->{"pages"} || 0;
		my $xbzrlecachemiss = $stat->{"xbzrle-cache"}->{"cache-miss"} || 0;
		my $xbzrleoverflow = $stat->{"xbzrle-cache"}->{"overflow"} || 0;
		# reduce sleep if remainig memory is lower than the average transfer speed
		$usleep = 100000 if $avglstat && $rem < $avglstat;

		$self->log('info', "migration status: $stat->{status} (transferred ${trans}, " .
			   "remaining ${rem}), total ${total})");

		if (${xbzrlecachesize}) {
		    $self->log('info', "migration xbzrle cachesize: ${xbzrlecachesize} transferred ${xbzrlebytes} pages ${xbzrlepages} cachemiss ${xbzrlecachemiss} overflow ${xbzrleoverflow}");
		}

		if (($lastrem  && $rem > $lastrem ) || ($rem == 0)) {
		    $downtimecounter++;
		}
		$lastrem = $rem;

		if ($downtimecounter > 5) {
		    $downtimecounter = 0;
		    $migrate_downtime *= 2;
		    $self->log('info', "migrate_set_downtime: $migrate_downtime");
		    eval {
			PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate_set_downtime", value => int($migrate_downtime*100)/100);
		    };
		    $self->log('info', "migrate_set_downtime error: $@") if $@;
            	}

	    }


	    $lstat = $stat->{ram}->{transferred};
	    
	} else {
	    die $merr if $merr;
	    die "unable to parse migration status '$stat->{status}' - aborting\n";
	}
    }
}

sub phase2_cleanup {
    my ($self, $vmid, $err) = @_;

    return if !$self->{errors};
    $self->{phase2errors} = 1;

    $self->log('info', "aborting phase 2 - cleanup resources");

    $self->log('info', "migrate_cancel");
    eval {
	PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate_cancel");
    };
    $self->log('info', "migrate_cancel error: $@") if $@;

    my $conf = $self->{vmconf};
    delete $conf->{lock};
    eval { PVE::QemuConfig->write_config($vmid, $conf) };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    # cleanup ressources on target host
    if ($self->{storage_migration}) {

	eval { PVE::QemuServer::qemu_blockjobs_cancel($vmid, $self->{storage_migration_jobs}) };
	if (my $err = $@) {
	    $self->log('err', $err);
	}

	eval { PVE::QemuMigrate::cleanup_remotedisks($self) };
	if (my $err = $@) {
	    $self->log('err', $err);
	}
    }

    my $nodename = PVE::INotify::nodename();
 
    my $cmd = [@{$self->{rem_ssh}}, 'qm', 'stop', $vmid, '--skiplock', '--migratedfrom', $nodename];
    eval{ PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => sub {}) };
    if (my $err = $@) {
        $self->log('err', $err);
        $self->{errors} = 1;
    }

    if ($self->{tunnel}) {
	eval { finish_tunnel($self, $self->{tunnel});  };
	if (my $err = $@) {
	    $self->log('err', $err);
	    $self->{errors} = 1;
	}
    }
}

sub phase3 {
    my ($self, $vmid) = @_;

    my $volids = $self->{volumes};
    return if $self->{phase2errors};

    # destroy local copies
    foreach my $volid (@$volids) {
	eval { PVE::Storage::vdisk_free($self->{storecfg}, $volid); };
	if (my $err = $@) {
	    $self->log('err', "removing local copy of '$volid' failed - $err");
	    $self->{errors} = 1;
	    last if $err =~ /^interrupted by signal$/;
	}
    }
}

sub phase3_cleanup {
    my ($self, $vmid, $err) = @_;

    my $conf = $self->{vmconf};
    return if $self->{phase2errors};

    my $tunnel = $self->{tunnel};

    if ($self->{storage_migration}) {
	# finish block-job
	eval { PVE::QemuServer::qemu_drive_mirror_monitor($vmid, undef, $self->{storage_migration_jobs}); };

	if (my $err = $@) {
	    eval { PVE::QemuServer::qemu_blockjobs_cancel($vmid, $self->{storage_migration_jobs}) };
	    eval { PVE::QemuMigrate::cleanup_remotedisks($self) };
	    die "Failed to completed storage migration\n";
	} else {
	    foreach my $target_drive (keys %{$self->{target_drive}}) {
		my $drive = PVE::QemuServer::parse_drive($target_drive, $self->{target_drive}->{$target_drive}->{volid});
		$conf->{$target_drive} = PVE::QemuServer::print_drive($vmid, $drive);
		PVE::QemuConfig->write_config($vmid, $conf);
	    }
	}
    }

    # transfer replication state before move config
    $self->transfer_replication_state() if $self->{replicated_volumes};

    # move config to remote node
    my $conffile = PVE::QemuConfig->config_file($vmid);
    my $newconffile = PVE::QemuConfig->config_file($vmid, $self->{node});

    die "Failed to move config to node '$self->{node}' - rename failed: $!\n"
        if !rename($conffile, $newconffile);

    $self->switch_replication_job_target() if $self->{replicated_volumes};

    if ($self->{livemigration}) {
	if ($self->{storage_migration}) {
	    # stop nbd server on remote vm - requirement for resume since 2.9
	    my $cmd = [@{$self->{rem_ssh}}, 'qm', 'nbdstop', $vmid];

	    eval{ PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => sub {}) };
	    if (my $err = $@) {
		$self->log('err', $err);
		$self->{errors} = 1;
	    }
	}

	# config moved and nbd server stopped - now we can resume vm on target
	if ($tunnel && $tunnel->{version} && $tunnel->{version} >= 1) {
	    eval {
		$self->write_tunnel($tunnel, 30, "resume $vmid");
	    };
	    if (my $err = $@) {
		$self->log('err', $err);
		$self->{errors} = 1;
	    }
	} else {
	    my $cmd = [@{$self->{rem_ssh}}, 'qm', 'resume', $vmid, '--skiplock', '--nocheck'];
	    my $logf = sub {
		my $line = shift;
		$self->log('err', $line);
	    };
	    eval { PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => $logf); };
	    if (my $err = $@) {
		$self->log('err', $err);
		$self->{errors} = 1;
	    }
	}
    }

    # close tunnel on successful migration, on error phase2_cleanup closed it
    if ($tunnel) {
	eval { finish_tunnel($self, $tunnel);  };
	if (my $err = $@) {
	    $self->log('err', $err);
	    $self->{errors} = 1;
	}
    }

    eval {
	my $timer = 0;
	if (PVE::QemuServer::vga_conf_has_spice($conf->{vga}) && $self->{running}) {
	    $self->log('info', "Waiting for spice server migration");
	    while (1) {
		my $res = PVE::QemuServer::vm_mon_cmd_nocheck($vmid, 'query-spice');
		last if int($res->{'migrated'}) == 1;
		last if $timer > 50;
		$timer ++;
		usleep(200000);
 	    }
	}
    };

    # always stop local VM
    eval { PVE::QemuServer::vm_stop($self->{storecfg}, $vmid, 1, 1); };
    if (my $err = $@) {
	$self->log('err', "stopping vm failed - $err");
	$self->{errors} = 1;
    }

    # always deactivate volumes - avoid lvm LVs to be active on several nodes
    eval {
	my $vollist = PVE::QemuServer::get_vm_volumes($conf);
	PVE::Storage::deactivate_volumes($self->{storecfg}, $vollist);
    };
    if (my $err = $@) {
	$self->log('err', $err);
	$self->{errors} = 1;
    }

    if($self->{storage_migration}) {
	# destroy local copies
	my $volids = $self->{online_local_volumes};

	foreach my $volid (@$volids) {
	    eval { PVE::Storage::vdisk_free($self->{storecfg}, $volid); };
	    if (my $err = $@) {
		$self->log('err', "removing local copy of '$volid' failed - $err");
		$self->{errors} = 1;
		last if $err =~ /^interrupted by signal$/;
	    }
	}

    }

    # clear migrate lock
    my $cmd = [ @{$self->{rem_ssh}}, 'qm', 'unlock', $vmid ];
    $self->cmd_logerr($cmd, errmsg => "failed to clear migrate lock");
}

sub final_cleanup {
    my ($self, $vmid) = @_;

    # nothing to do
}

sub round_powerof2 {
    return 1 if $_[0] < 2;
    return 2 << int(log($_[0]-1)/log(2));
}

1;
