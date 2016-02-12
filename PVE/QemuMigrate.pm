package PVE::QemuMigrate;

use strict;
use warnings;
use PVE::AbstractMigrate;
use IO::File;
use IPC::Open2;
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

    my $writer = $cmdpipe->{writer};
    my $reader = $cmdpipe->{reader};

    $writer->close();
    $reader->close();

    my $cpid = $cmdpipe->{pid};

    if ($timeout) {
	for (my $i = 0; $i < $timeout; $i++) {
	    return if !PVE::ProcFSTools::check_process_running($cpid);
	    sleep(1);
	}
    }

    $self->log('info', "ssh tunnel still running - terminating now with SIGTERM\n");
    kill(15, $cpid);

    # wait again
    for (my $i = 0; $i < 10; $i++) {
	return if !PVE::ProcFSTools::check_process_running($cpid);
	sleep(1);
    }

    $self->log('info', "ssh tunnel still running - terminating now with SIGKILL\n");
    kill 9, $cpid;
    sleep 1;
}

sub fork_tunnel {
    my ($self, $nodeip, $lport, $rport) = @_;

    my @localtunnelinfo = $lport ? ('-L' , "$lport:localhost:$rport" ) : ();

    my $cmd = [@{$self->{rem_ssh}}, @localtunnelinfo, 'qm', 'mtunnel' ];

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

    die $err if $err;
}

sub lock_vm {
    my ($self, $vmid, $code, @param) = @_;

    return PVE::QemuServer::lock_config($vmid, $code, @param);
}

sub prepare {
    my ($self, $vmid) = @_;

    my $online = $self->{opts}->{online};

    $self->{storecfg} = PVE::Storage::config();

    # test is VM exist
    my $conf = $self->{vmconf} = PVE::QemuServer::load_config($vmid);

    PVE::QemuServer::check_lock($conf);

    my $running = 0;
    if (my $pid = PVE::QemuServer::check_running($vmid)) {
	die "cant migrate running VM without --online\n" if !$online;
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

    # activate volumes
    my $vollist = PVE::QemuServer::get_vm_volumes($conf);
    PVE::Storage::activate_volumes($self->{storecfg}, $vollist);

    # fixme: check if storage is available on both nodes

    # test ssh connection
    my $cmd = [ @{$self->{rem_ssh}}, '/bin/true' ];
    eval { $self->cmd_quiet($cmd); };
    die "Can't connect to destination address using public key\n" if $@;

    return $running;
}

sub sync_disks {
    my ($self, $vmid) = @_;

    $self->log('info', "copying disk images");

    my $conf = $self->{vmconf};

    $self->{volumes} = [];

    my $res = [];

    eval {

	my $volhash = {};
	my $cdromhash = {};

	my $sharedvm = 1;

	my @sids = PVE::Storage::storage_ids($self->{storecfg});
        foreach my $storeid (@sids) {
	    my $scfg = PVE::Storage::storage_config($self->{storecfg}, $storeid);
            next if $scfg->{shared};
	    next if !PVE::Storage::storage_check_enabled($self->{storecfg}, $storeid, undef, 1);

            # get list from PVE::Storage (for unused volumes)
            my $dl = PVE::Storage::vdisk_list($self->{storecfg}, $storeid, $vmid);
            PVE::Storage::foreach_volid($dl, sub {
                my ($volid, $sid, $volname) = @_;

                # check if storage is available on target node
                PVE::Storage::storage_check_node($self->{storecfg}, $sid, $self->{node});

                $volhash->{$volid} = 1;
		$sharedvm = 0; # there is a non-shared disk
            });
        }

	# and add used, owned/non-shared disks (just to be sure we have all)

	PVE::QemuServer::foreach_volid($conf, sub {
	    my ($volid, $is_cdrom) = @_;

	    return if !$volid;

	    die "cant migrate local file/device '$volid'\n" if $volid =~ m|^/|;

	    if ($is_cdrom) {
		die "cant migrate local cdrom drive\n" if $volid eq 'cdrom';
		return if $volid eq 'none';
		$cdromhash->{$volid} = 1;
	    }

	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);

	    # check if storage is available on both nodes
	    my $scfg = PVE::Storage::storage_check_node($self->{storecfg}, $sid);
	    PVE::Storage::storage_check_node($self->{storecfg}, $sid, $self->{node});

	    return if $scfg->{shared};

	    die "can't migrate local cdrom '$volid'\n" if $cdromhash->{$volid};

	    $sharedvm = 0;

	    my ($path, $owner) = PVE::Storage::path($self->{storecfg}, $volid);

	    die "can't migrate volume '$volid' - owned by other VM (owner = VM $owner)\n"
		if !$owner || ($owner != $self->{vmid});

	    $volhash->{$volid} = 1;
	});

	if ($self->{running} && !$sharedvm) {
	    die "can't do online migration - VM uses local disks\n";
	}

	# do some checks first
	foreach my $volid (keys %$volhash) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    my $scfg =  PVE::Storage::storage_config($self->{storecfg}, $sid);

	    die "can't migrate '$volid' - storage type '$scfg->{type}' not supported\n"
		if (!($scfg->{type} eq 'dir' || $scfg->{type} eq 'zfspool') && (!$sharedvm));

	    # if file, check if a backing file exist
	    if (!($scfg->{type} eq 'dir' || $scfg->{type} eq 'zfspool') && (!$sharedvm)) {
		my (undef, undef, undef, $parent) = PVE::Storage::volume_size_info($self->{storecfg}, $volid, 1);
		die "can't migrate '$volid' as it's a clone of '$parent'" if $parent;
	    }
	}

	foreach my $volid (keys %$volhash) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    push @{$self->{volumes}}, $volid;
	    PVE::Storage::storage_migrate($self->{storecfg}, $volid, $self->{nodeip}, $sid);
	}
    };
    die "Failed to sync data - $@" if $@;
}

sub phase1 {
    my ($self, $vmid) = @_;

    $self->log('info', "starting migration of VM $vmid to node '$self->{node}' ($self->{nodeip})");

    my $conf = $self->{vmconf};

    # set migrate lock in config file
    $conf->{lock} = 'migrate';
    PVE::QemuServer::write_config($vmid, $conf);

    sync_disks($self, $vmid);

};

sub phase1_cleanup {
    my ($self, $vmid, $err) = @_;

    $self->log('info', "aborting phase 1 - cleanup resources");

    my $conf = $self->{vmconf};
    delete $conf->{lock};
    eval { PVE::QemuServer::write_config($vmid, $conf) };
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
    my $nodename = PVE::INotify::nodename();

    ## start on remote node
    my $cmd = [@{$self->{rem_ssh}}];

    my $spice_ticket;
    if (PVE::QemuServer::vga_conf_has_spice($conf->{vga})) {
	my $res = PVE::QemuServer::vm_mon_cmd($vmid, 'query-spice');
	$spice_ticket = $res->{ticket};
    }

    push @$cmd , 'qm', 'start', $vmid, '--stateuri', 'tcp', '--skiplock', '--migratedfrom', $nodename;

    if ($self->{forcemachine}) {
	push @$cmd, '--machine', $self->{forcemachine};
    }

    my $spice_port;

    # Note: We try to keep $spice_ticket secret (do not pass via command line parameter)
    # instead we pipe it through STDIN
    PVE::Tools::run_command($cmd, input => $spice_ticket, outfunc => sub {
	my $line = shift;

	if ($line =~ m/^migration listens on tcp:(localhost|[\d\.]+|\[[\d\.:a-fA-F]+\]):(\d+)$/) {
	    $raddr = $1;
	    $rport = int($2);
	}
	elsif ($line =~ m/^migration listens on port (\d+)$/) {
	    $raddr = "localhost";
	    $rport = int($1);
	}
        elsif ($line =~ m/^spice listens on port (\d+)$/) {
	    $spice_port = int($1);
	}
    }, errfunc => sub {
	my $line = shift;
	$self->log('info', $line);
    });

    die "unable to detect remote migration address\n" if !$raddr;

    ## create tunnel to remote port
    $self->log('info', "starting ssh migration tunnel");
    my $pfamily = PVE::Tools::get_host_address_family($nodename);
    my $lport = ($raddr eq "localhost") ? PVE::Tools::next_migrate_port($pfamily) : undef;
    $self->{tunnel} = $self->fork_tunnel($self->{nodeip}, $lport, $rport);

    my $start = time();
    $self->log('info', "starting online/live migration on $raddr:$rport");
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

    eval {
	PVE::QemuServer::set_migration_caps($vmid);
    };
    warn $@ if $@;

    #set cachesize 10% of the total memory
    my $cachesize = int($conf->{memory}*1048576/10);
    eval {
	PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate-set-cache-size", value => $cachesize);
    };
	
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

    eval {
        PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "migrate", uri => "tcp:$raddr:$rport");
    };
    my $merr = $@;
    $self->log('info', "migrate uri => tcp:$raddr:$rport failed: $merr") if $merr;

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
	    if ($err_count <= 5) {
		usleep(1000000);
		next;
	    }
	    die "too many query migrate failures - aborting\n";
	}

        if ($stat->{status} =~ m/^(setup)$/im) {
            sleep(1);
            next;
        }

	if ($stat->{status} =~ m/^(active|completed|failed|cancelled)$/im) {
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
    #to be sure tat the tunnel is closed 
    if ($self->{tunnel}) {
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
    eval { PVE::QemuServer::write_config($vmid, $conf) };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    # cleanup ressources on target host
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

    # move config to remote node
    my $conffile = PVE::QemuServer::config_file($vmid);
    my $newconffile = PVE::QemuServer::config_file($vmid, $self->{node});

    die "Failed to move config to node '$self->{node}' - rename failed: $!\n"
        if !rename($conffile, $newconffile);

    if ($self->{livemigration}) {
	# now that config file is move, we can resume vm on target if livemigrate
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

    # clear migrate lock
    my $cmd = [ @{$self->{rem_ssh}}, 'qm', 'unlock', $vmid ];
    $self->cmd_logerr($cmd, errmsg => "failed to clear migrate lock");
}

sub final_cleanup {
    my ($self, $vmid) = @_;

    # nothing to do
}

1;
