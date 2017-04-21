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

sub fork_tunnel {
    my ($self, $tunnel_addr) = @_;

    my @localtunnelinfo = defined($tunnel_addr) ? ('-L' , $tunnel_addr ) : ();

    my $cmd = [@{$self->{rem_ssh}}, '-o ExitOnForwardFailure=yes', @localtunnelinfo, 'qm', 'mtunnel' ];

    my $tunnel = $self->fork_command_pipe($cmd);

    my $reader = $tunnel->{reader};

    my $helo;
    eval {
	PVE::Tools::run_with_timeout(60, sub { $helo = <$reader>; });
	die "no reply\n" if !$helo;
	die "no quorum on target node\n" if $helo =~ m/^no quorum$/;
	die "got strange reply from mtunnel ('$helo')\n"
	    if $helo !~ m/^tunnel online$/;
    };
    my $err = $@;

    if ($err) {
	$self->finish_command_pipe($tunnel);
	die "can't open migration tunnel - $err";
    }
    return $tunnel;
}

sub finish_tunnel {
    my ($self, $tunnel) = @_;

    my $writer = $tunnel->{writer};

    eval {
	PVE::Tools::run_with_timeout(30, sub {
	    print $writer "quit\n";
	    $writer->flush();
	});
    };
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

    my $res = [];

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

		$local_volumes->{$volid} = 'storage';
	    });
	}

	my $test_volid = sub {
	    my ($volid, $is_cdrom, $snapname) = @_;

	    return if !$volid;

	    if ($volid =~ m|^/|) {
		$local_volumes->{$volid} = 'config';
		die "local file/device\n";
	    }

	    if ($is_cdrom) {
		if ($volid eq 'cdrom') {
		    my $msg = "can't migrate local cdrom drive";
		    $msg .= " (referenced in snapshot '$snapname')"
			if defined($snapname);

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

	    $local_volumes->{$volid} = defined($snapname) ? 'snapshot' : 'config';

	    die "local cdrom image\n" if $is_cdrom;

	    my ($path, $owner) = PVE::Storage::path($self->{storecfg}, $volid);

	    die "owned by other VM (owner = VM $owner)\n"
		if !$owner || ($owner != $self->{vmid});

	    if (defined($snapname)) {
		# we cannot migrate shapshots on local storage
		# exceptions: 'zfspool' or 'qcow2' files (on directory storage)

		my $format = PVE::QemuServer::qemu_img_format($scfg, $volname);
		die "online storage migration not possible if snapshot exists\n" if $self->{running};
		if (!($scfg->{type} eq 'zfspool' || $format eq 'qcow2')) {
		    die "non-migratable snapshot exists\n";
		}
	    }

	    die "referenced by linked clone(s)\n"
		if PVE::Storage::volume_is_base_and_used($self->{storecfg}, $volid);
	};

	my $test_drive = sub {
	    my ($ds, $drive, $snapname) = @_;

	    eval {
		&$test_volid($drive->{file}, PVE::QemuServer::drive_is_cdrom($drive), $snapname);
	    };

	    &$log_error($@, $drive->{file}) if $@;
	};

	foreach my $snapname (keys %{$conf->{snapshots}}) {
	    eval {
		&$test_volid($conf->{snapshots}->{$snapname}->{'vmstate'}, 0, undef)
		    if defined($conf->{snapshots}->{$snapname}->{'vmstate'});
	    };
	    &$log_error($@, $conf->{snapshots}->{$snapname}->{'vmstate'}) if $@;

	    PVE::QemuServer::foreach_drive($conf->{snapshots}->{$snapname}, $test_drive, $snapname);
	}
	PVE::QemuServer::foreach_drive($conf, $test_drive);

	foreach my $vol (sort keys %$local_volumes) {
	    if ($local_volumes->{$vol} eq 'storage') {
		$self->log('info', "found local disk '$vol' (via storage)\n");
	    } elsif ($local_volumes->{$vol} eq 'config') {
		die "can't live migrate attached local disks without with-local-disks option\n" if $self->{running} && !$self->{opts}->{"with-local-disks"};
		$self->log('info', "found local disk '$vol' (in current VM config)\n");
	    } elsif ($local_volumes->{$vol} eq 'snapshot') {
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

	$self->log('info', "copying disk images");

	foreach my $volid (keys %$local_volumes) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    if ($self->{running} && $self->{opts}->{targetstorage} && $local_volumes->{$volid} eq 'config') {
		push @{$self->{online_local_volumes}}, $volid;
	    } else {
		push @{$self->{volumes}}, $volid;
		PVE::Storage::storage_migrate($self->{storecfg}, $volid, $self->{nodeip}, $sid);
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

    # we use TCP only for unsecure migrations as TCP ssh forward tunnels often
    # did appeared to late (they are hard, if not impossible, to check for)
    # secure migration use UNIX sockets now, this *breaks* compatibilty when trying
    # to migrate from new to old but *not* from old to new.
    my $datacenterconf = PVE::Cluster::cfs_read_file('datacenter.cfg');

    my $migration_type = 'secure';
    if (defined($self->{opts}->{migration_type})) {
	$migration_type = $self->{opts}->{migration_type};
    } elsif (defined($datacenterconf->{migration}->{type})) {
        $migration_type = $datacenterconf->{migration}->{type};
    }

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

    if ($migration_type eq 'secure') {
	$self->log('info', "start remote tunnel");

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
	    $self->log('info', "$drive: start migration to to $nbd_uri");
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

    #set cachesize 10% of the total memory
    my $cachesize = int($conf->{memory}*1048576/10);
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
    my $usleep = 2000000;
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
		    my $mbps = sprintf "%.2f", $conf->{memory}/$delay;
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
		#reduce sleep if remainig memory if lower than the everage transfert 
		$usleep = 300000 if $avglstat && $rem < $avglstat;

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

    # just to be sure that the tunnel gets closed on successful migration, on error
    # phase2_cleanup closes it *after* stopping the remote waiting VM
    if (!$self->{errors} && $self->{tunnel}) {
	eval { finish_tunnel($self, $self->{tunnel});  };
	if (my $err = $@) {
	    $self->log('err', $err);
	    $self->{errors} = 1;
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

    # move config to remote node
    my $conffile = PVE::QemuConfig->config_file($vmid);
    my $newconffile = PVE::QemuConfig->config_file($vmid, $self->{node});

    die "Failed to move config to node '$self->{node}' - rename failed: $!\n"
        if !rename($conffile, $newconffile);

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
	my $cmd = [@{$self->{rem_ssh}}, 'qm', 'resume', $vmid, '--skiplock', '--nocheck'];
	eval{ PVE::Tools::run_command($cmd, outfunc => sub {}, 
		errfunc => sub {
		    my $line = shift;
        	    $self->log('err', $line);
		});
	};
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

1;
