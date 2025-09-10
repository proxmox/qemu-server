package PVE::QemuMigrate;

use strict;
use warnings;

use IO::File;
use IPC::Open2;
use Storable qw(dclone);
use Time::HiRes qw( usleep );

use PVE::AccessControl;
use PVE::Cluster;
use PVE::Format qw(render_bytes);
use PVE::GuestHelpers qw(safe_boolean_ne safe_string_ne);
use PVE::INotify;
use PVE::JSONSchema;
use PVE::RPCEnvironment;
use PVE::Replication;
use PVE::ReplicationConfig;
use PVE::ReplicationState;
use PVE::Storage::Plugin;
use PVE::Storage;
use PVE::StorageTunnel;
use PVE::Tools;
use PVE::Tunnel;

use PVE::QemuConfig;
use PVE::QemuServer::CPUConfig;
use PVE::QemuServer::Drive qw(checked_volume_format);
use PVE::QemuServer::Helpers qw(min_version);
use PVE::QemuServer::Machine;
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::Memory qw(get_current_memory);
use PVE::QemuServer::QMPHelpers;
use PVE::QemuServer;

use PVE::AbstractMigrate;
use base qw(PVE::AbstractMigrate);

# compared against remote end's minimum version
our $WS_TUNNEL_VERSION = 2;

sub fork_tunnel {
    my ($self, $ssh_forward_info) = @_;

    my $cmd = ['/usr/sbin/qm', 'mtunnel'];
    my $log = sub {
        my ($level, $msg) = @_;
        $self->log($level, $msg);
    };

    return PVE::Tunnel::fork_ssh_tunnel($self->{rem_ssh}, $cmd, $ssh_forward_info, $log);
}

sub fork_websocket_tunnel {
    my ($self, $storages, $bridges) = @_;

    my $remote = $self->{opts}->{remote};
    my $conn = $remote->{conn};

    my $log = sub {
        my ($level, $msg) = @_;
        $self->log($level, $msg);
    };

    my $websocket_url =
        "https://$conn->{host}:$conn->{port}/api2/json/nodes/$self->{node}/qemu/$remote->{vmid}/mtunnelwebsocket";
    my $url = "/nodes/$self->{node}/qemu/$remote->{vmid}/mtunnel";

    my $tunnel_params = {
        url => $websocket_url,
    };

    my $storage_list = join(',', keys %$storages);
    my $bridge_list = join(',', keys %$bridges);

    my $req_params = {
        storages => $storage_list,
        bridges => $bridge_list,
    };

    return PVE::Tunnel::fork_websocket_tunnel($conn, $url, $req_params, $tunnel_params, $log);
}

# tunnel_info:
#   proto: unix (secure) or tcp (insecure/legacy compat)
#   addr: IP or UNIX socket path
#   port: optional TCP port
#   unix_sockets: additional UNIX socket paths to forward
sub start_remote_tunnel {
    my ($self, $tunnel_info) = @_;

    my $nodename = PVE::INotify::nodename();
    my $migration_type = $self->{opts}->{migration_type};

    if ($migration_type eq 'secure') {

        if ($tunnel_info->{proto} eq 'unix') {
            my $ssh_forward_info = [];

            my $unix_sockets = [keys %{ $tunnel_info->{unix_sockets} }];
            push @$unix_sockets, $tunnel_info->{addr};
            for my $sock (@$unix_sockets) {
                push @$ssh_forward_info, "$sock:$sock";
                unlink $sock;
            }

            $self->{tunnel} = $self->fork_tunnel($ssh_forward_info);

            my $unix_socket_try = 0; # wait for the socket to become ready
            while ($unix_socket_try <= 100) {
                $unix_socket_try++;
                my $available = 0;
                foreach my $sock (@$unix_sockets) {
                    if (-S $sock) {
                        $available++;
                    }
                }

                if ($available == @$unix_sockets) {
                    last;
                }

                usleep(50000);
            }
            if ($unix_socket_try > 100) {
                $self->{errors} = 1;
                PVE::Tunnel::finish_tunnel($self->{tunnel});
                die "Timeout, migration socket $tunnel_info->{addr} did not get ready";
            }
            $self->{tunnel}->{unix_sockets} = $unix_sockets if (@$unix_sockets);

        } elsif ($tunnel_info->{proto} eq 'tcp') {
            my $ssh_forward_info = [];
            if ($tunnel_info->{addr} eq "localhost") {
                # for backwards compatibility with older qemu-server versions
                my $pfamily = PVE::Tools::get_host_address_family($nodename);
                my $lport = PVE::Tools::next_migrate_port($pfamily);
                push @$ssh_forward_info, "$lport:localhost:$tunnel_info->{port}";
            }

            $self->{tunnel} = $self->fork_tunnel($ssh_forward_info);

        } else {
            die "unsupported protocol in migration URI: $tunnel_info->{proto}\n";
        }
    } else {
        #fork tunnel for insecure migration, to send faster commands like resume
        $self->{tunnel} = $self->fork_tunnel();
    }
}

sub lock_vm {
    my ($self, $vmid, $code, @param) = @_;

    return PVE::QemuConfig->lock_config($vmid, $code, @param);
}

sub target_storage_check_available {
    my ($self, $storecfg, $targetsid, $volid) = @_;

    if (!$self->{opts}->{remote}) {
        # check if storage is available on target node
        my $target_scfg = PVE::Storage::storage_check_enabled(
            $storecfg, $targetsid, $self->{node},
        );
        my ($vtype) = PVE::Storage::parse_volname($storecfg, $volid);
        die "$volid: content type '$vtype' is not available on storage '$targetsid'\n"
            if !$target_scfg->{content}->{$vtype};
    }
}

sub prepare {
    my ($self, $vmid) = @_;

    my $online = $self->{opts}->{online};

    my $storecfg = $self->{storecfg} = PVE::Storage::config();

    # updates the configuration, so ordered before saving the configuration in $self
    eval {
        PVE::QemuConfig::cleanup_fleecing_images(
            $vmid,
            $storecfg,
            sub { $self->log($_[0], $_[1]); },
        );
    };
    $self->log('warn', "attempt to clean up left-over fleecing images failed - $@") if $@;

    # test if VM exists
    my $conf = $self->{vmconf} = PVE::QemuConfig->load_config($vmid);

    my $version = PVE::QemuServer::Helpers::get_node_pvecfg_version($self->{node});

    my $repl_conf = PVE::ReplicationConfig->new();
    $self->{replication_jobcfg} = $repl_conf->find_local_replication_job($vmid, $self->{node});
    $self->{is_replicated} = $repl_conf->check_for_existing_jobs($vmid, 1);

    if ($self->{replication_jobcfg} && defined($self->{replication_jobcfg}->{remove_job})) {
        die "refusing to migrate replicated VM whose replication job is marked for removal\n";
    }

    PVE::QemuConfig->check_lock($conf);

    my $running = 0;
    if (my $pid = PVE::QemuServer::check_running($vmid)) {
        die "can't migrate running VM without --online\n" if !$online;
        $running = $pid;

        if ($self->{is_replicated} && !$self->{replication_jobcfg}) {
            if ($self->{opts}->{force}) {
                $self->log(
                    'warn',
                    "WARNING: Node '$self->{node}' is not a replication target. Existing "
                        . "replication jobs will fail after migration!\n",
                );
            } else {
                die "Cannot live-migrate replicated VM to node '$self->{node}' - not a replication "
                    . "target. Use 'force' to override.\n";
            }
        }

        $self->{forcemachine} = PVE::QemuServer::Machine::qemu_machine_pxe($vmid, $conf);

        # To support custom CPU types, we keep QEMU's "-cpu" parameter intact.
        # Since the parameter itself contains no reference to a custom model,
        # this makes migration independent of changes to "cpu-models.conf".
        if ($conf->{cpu}) {
            my $cpuconf = PVE::JSONSchema::parse_property_string('pve-cpu-conf', $conf->{cpu});
            if ($cpuconf && PVE::QemuServer::CPUConfig::is_custom_model($cpuconf->{cputype})) {
                $self->{forcecpu} = PVE::QemuServer::CPUConfig::get_cpu_from_running_vm($pid);
            }
        }

        # Do not treat a suspended VM as paused, as it might wake up
        # during migration and remain paused after migration finishes.
        $self->{vm_was_paused} = 1 if PVE::QemuServer::vm_is_paused($vmid, 0);
    }

    my ($loc_res, $mapped_res, $missing_mappings_by_node) =
        PVE::QemuServer::check_local_resources($conf, $running, 1);
    my $blocking_resources = [];
    for my $res ($loc_res->@*) {
        if (!defined($mapped_res->{$res})) {
            push $blocking_resources->@*, $res;
        }
    }
    if (scalar($blocking_resources->@*)) {
        if ($self->{running} || !$self->{opts}->{force}) {
            die "can't migrate VM which uses local devices: "
                . join(", ", $blocking_resources->@*) . "\n";
        } else {
            $self->log('info', "migrating VM which uses local devices");
        }
    }

    if (scalar(keys $mapped_res->%*)) {
        my $missing_mappings = $missing_mappings_by_node->{ $self->{node} };
        my $missing_live_mappings = [];
        for my $key (sort keys $mapped_res->%*) {
            my $res = $mapped_res->{$key};
            my $name = "$key:$res->{name}";
            push $missing_live_mappings->@*, $name if !$res->{'live-migration'};
        }
        if (scalar($missing_mappings->@*)) {
            my $missing = join(", ", $missing_mappings->@*);
            die "can't migrate to '$self->{node}': missing mapped devices $missing\n";
        } elsif ($running && scalar($missing_live_mappings->@*)) {
            my $missing = join(", ", $missing_live_mappings->@*);
            die "can't live migrate running VM which uses following mapped devices: $missing\n";
        } else {
            $self->log('info', "migrating VM which uses mapped local devices");
        }
    }

    my $vga = PVE::QemuServer::parse_vga($conf->{vga});
    if ($running && $vga->{'clipboard'} && $vga->{'clipboard'} eq 'vnc') {
        die "VMs with 'clipboard' set to 'vnc' are not live migratable!\n";
    }

    my $vollist = PVE::QemuServer::get_vm_volumes($conf);

    my $storages = {};
    foreach my $volid (@$vollist) {
        my ($sid, $volname) = PVE::Storage::parse_volume_id($volid, 1);

        # check if storage is available on source node
        my $scfg = PVE::Storage::storage_check_enabled($storecfg, $sid);

        my $targetsid = $sid;
        # NOTE: local ignores shared mappings, remote maps them
        if (!$scfg->{shared} || $self->{opts}->{remote}) {
            $targetsid = PVE::JSONSchema::map_id($self->{opts}->{storagemap}, $sid);
        }

        $storages->{$targetsid} = 1;

        $self->target_storage_check_available($storecfg, $targetsid, $volid);

        if ($scfg->{shared}) {
            # PVE::Storage::activate_storage checks this for non-shared storages
            my $plugin = PVE::Storage::Plugin->lookup($scfg->{type});
            warn "Used shared storage '$sid' is not online on source node!\n"
                if !$plugin->check_connection($sid, $scfg);
        }
    }

    if ($self->{opts}->{remote}) {
        # test & establish websocket connection
        my $bridges = map_bridges($conf, $self->{opts}->{bridgemap}, 1);
        my $tunnel = $self->fork_websocket_tunnel($storages, $bridges);
        my $min_version = $tunnel->{version} - $tunnel->{age};
        $self->log('info', "local WS tunnel version: $WS_TUNNEL_VERSION");
        $self->log('info', "remote WS tunnel version: $tunnel->{version}");
        $self->log('info', "minimum required WS tunnel version: $min_version");
        die "Remote tunnel endpoint not compatible, upgrade required\n"
            if $WS_TUNNEL_VERSION < $min_version;
        die "Remote tunnel endpoint too old, upgrade required\n"
            if $WS_TUNNEL_VERSION > $tunnel->{version};

        print "websocket tunnel started\n";
        $self->{tunnel} = $tunnel;
    } else {
        # test ssh connection
        my $cmd = [@{ $self->{rem_ssh} }, '/bin/true'];
        eval { $self->cmd_quiet($cmd); };
        die "Can't connect to destination address using public key\n" if $@;
    }

    return $running;
}

sub scan_local_volumes {
    my ($self, $vmid) = @_;

    my $conf = $self->{vmconf};

    # local volumes which have been copied
    # and their old_id => new_id pairs
    $self->{volume_map} = {};
    $self->{local_volumes} = {};

    my $storecfg = $self->{storecfg};
    eval {
        # found local volumes and their origin
        my $local_volumes = $self->{local_volumes};
        my $local_volumes_errors = {};
        my $other_errors = [];
        my $abort = 0;
        my $path_to_volid = {};

        my $log_error = sub {
            my ($msg, $volid) = @_;

            if (defined($volid)) {
                $local_volumes_errors->{$volid} = $msg;
            } else {
                push @$other_errors, $msg;
            }
            $abort = 1;
        };

        my $replicatable_volumes =
            !$self->{replication_jobcfg}
            ? {}
            : PVE::QemuConfig->get_replicatable_volumes($storecfg, $vmid, $conf, 0, 1);
        foreach my $volid (keys %{$replicatable_volumes}) {
            $local_volumes->{$volid}->{replicated} = 1;
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
                    if (defined($snaprefs) && !$attr->{is_attached}) {
                        my $snapnames = join(', ', sort keys %$snaprefs);
                        $msg .= " (referenced in snapshot - $snapnames)";
                    }
                    &$log_error("$msg\n");
                    return;
                }
                return if $volid eq 'none';
            }

            my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);

            # check if storage is available on both nodes
            my $scfg = PVE::Storage::storage_check_enabled($storecfg, $sid);

            my $targetsid = $sid;
            # NOTE: local ignores shared mappings, remote maps them
            if (!$scfg->{shared} || $self->{opts}->{remote}) {
                $targetsid = PVE::JSONSchema::map_id($self->{opts}->{storagemap}, $sid);
            }

            $self->target_storage_check_available($storecfg, $targetsid, $volid);
            return if $scfg->{shared} && !$self->{opts}->{remote};

            $local_volumes->{$volid}->{ref} = 'pending' if $attr->{referenced_in_pending};
            $local_volumes->{$volid}->{ref} = 'snapshot' if $attr->{referenced_in_snapshot};
            $local_volumes->{$volid}->{ref} = 'unused' if $attr->{is_unused};
            $local_volumes->{$volid}->{ref} = 'attached' if $attr->{is_attached};
            $local_volumes->{$volid}->{ref} = 'generated' if $attr->{is_tpmstate};

            $local_volumes->{$volid}->{bwlimit} = $self->get_bwlimit($sid, $targetsid);
            $local_volumes->{$volid}->{targetsid} = $targetsid;

            $local_volumes->{$volid}->@{qw(size format)} =
                PVE::Storage::volume_size_info($storecfg, $volid);

            $local_volumes->{$volid}->{is_vmstate} = $attr->{is_vmstate} ? 1 : 0;

            $local_volumes->{$volid}->{drivename} = $attr->{drivename}
                if $attr->{drivename};

            # If with_snapshots is not set for storage migrate, it tries to use
            # a raw+size stream, but on-the-fly conversion from qcow2 to raw+size
            # back to qcow2 is currently not possible.
            $local_volumes->{$volid}->{snapshots} =
                ($local_volumes->{$volid}->{format} =~ /^(?:qcow2|vmdk)$/);

            if ($attr->{cdrom}) {
                if ($volid =~ /vm-\d+-cloudinit/) {
                    $local_volumes->{$volid}->{ref} = 'generated';
                    return;
                }
                die "local cdrom image\n";
            }

            my ($path, $owner) = PVE::Storage::path($storecfg, $volid);

            die "owned by other VM (owner = VM $owner)\n"
                if !$owner || ($owner != $vmid);

            $path_to_volid->{$path}->{$volid} = 1;

            return if $attr->{is_vmstate};

            if (defined($snaprefs)) {
                $local_volumes->{$volid}->{snapshots} = 1;

                # we cannot migrate snapshots on local storage
                # exceptions: 'zfspool' or 'qcow2' files (on directory storage)

                die "online storage migration not possible if non-replicated snapshot exists\n"
                    if $self->{running} && !$local_volumes->{$volid}->{replicated};

                die "remote migration with snapshots not supported yet\n"
                    if $self->{opts}->{remote};

                if (!(
                    $scfg->{type} eq 'zfspool'
                    || ($scfg->{type} eq 'btrfs' && $local_volumes->{$volid}->{format} eq 'raw')
                    || $local_volumes->{$volid}->{format} eq 'qcow2'
                )) {
                    die "non-migratable snapshot exists\n";
                }
            }

            die "referenced by linked clone(s)\n"
                if PVE::Storage::volume_is_base_and_used($storecfg, $volid);
        };

        PVE::QemuServer::foreach_volid(
            $conf,
            sub {
                my ($volid, $attr) = @_;
                eval { $test_volid->($volid, $attr); };
                if (my $err = $@) {
                    &$log_error($err, $volid);
                }
            },
        );

        for my $path (keys %$path_to_volid) {
            my @volids = keys $path_to_volid->{$path}->%*;
            die "detected not supported aliased volumes: '" . join("', '", @volids) . "'\n"
                if (scalar(@volids) > 1);
        }

        foreach my $vol (sort keys %$local_volumes) {
            my $type = $replicatable_volumes->{$vol} ? 'local, replicated' : 'local';
            my $ref = $local_volumes->{$vol}->{ref};
            if ($ref eq 'attached') {
                &$log_error(
                    "can't live migrate attached local disks without with-local-disks option\n",
                    $vol,
                ) if $self->{running} && !$self->{opts}->{"with-local-disks"};
                $self->log('info', "found $type disk '$vol' (attached)\n");
            } elsif ($ref eq 'unused') {
                $self->log('info', "found $type disk '$vol' (unused)\n");
            } elsif ($ref eq 'snapshot') {
                $self->log('info', "found $type disk '$vol' (referenced by snapshot(s))\n");
            } elsif ($ref eq 'pending') {
                $self->log('info', "found $type disk '$vol' (pending change)\n");
            } elsif ($ref eq 'generated') {
                $self->log('info', "found generated disk '$vol' (in current VM config)\n");
            } else {
                $self->log('info', "found $type disk '$vol'\n");
            }
        }

        foreach my $vol (sort keys %$local_volumes_errors) {
            $self->log('warn',
                "can't migrate local disk '$vol': $local_volumes_errors->{$vol}");
        }
        foreach my $err (@$other_errors) {
            $self->log('warn', "$err");
        }

        if ($abort) {
            die "can't migrate VM - check log\n";
        }

        # additional checks for local storage
        foreach my $volid (keys %$local_volumes) {
            my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
            my $scfg = PVE::Storage::storage_config($storecfg, $sid);

            my $migratable = $scfg->{type} =~ /^(?:dir|btrfs|zfspool|lvmthin|lvm)$/;

            # TODO: what is this even here for?
            $migratable = 1 if $self->{opts}->{remote};

            die "can't migrate '$volid' - storage type '$scfg->{type}' not supported\n"
                if !$migratable;

            # image is a linked clone on local storage, se we can't migrate.
            if (my $basename = (PVE::Storage::parse_volname($storecfg, $volid))[3]) {
                die "can't migrate '$volid' as it's a clone of '$basename'";
            }
        }

        foreach my $volid (sort keys %$local_volumes) {
            my $ref = $local_volumes->{$volid}->{ref};
            if ($self->{running} && $ref eq 'attached') {
                $local_volumes->{$volid}->{migration_mode} = 'online';
            } elsif ($self->{running} && $ref eq 'generated') {
                # offline migrate the cloud-init ISO and don't regenerate on VM start
                #
                # tpmstate will also be offline migrated first, and in case of
                # live migration then updated by QEMU/swtpm if necessary
                $local_volumes->{$volid}->{migration_mode} = 'offline';
            } else {
                $local_volumes->{$volid}->{migration_mode} = 'offline';
            }
        }
    };
    die "Problem found while scanning volumes - $@" if $@;
}

sub handle_replication {
    my ($self, $vmid) = @_;

    my $conf = $self->{vmconf};
    my $local_volumes = $self->{local_volumes};

    return if !$self->{replication_jobcfg};

    die "can't migrate VM with replicated volumes to remote cluster/node\n"
        if $self->{opts}->{remote};

    if ($self->{running}) {
        my @live_replicatable_volumes = $self->filter_local_volumes('online', 1);
        foreach my $volid (@live_replicatable_volumes) {
            my $drive = $local_volumes->{$volid}->{drivename};
            die "internal error - no drive for '$volid'\n" if !defined($drive);

            my $bitmap = "repl_$drive";

            # start tracking before replication to get full delta + a few duplicates
            $self->log('info', "$drive: start tracking writes using block-dirty-bitmap '$bitmap'");
            mon_cmd($vmid, 'block-dirty-bitmap-add', node => "drive-$drive", name => $bitmap);

            # other info comes from target node in phase 2
            $self->{target_drive}->{$drive}->{bitmap} = $bitmap;
        }
    }
    $self->log('info', "replicating disk images");

    my $start_time = time();
    my $logfunc = sub { $self->log('info', shift) };
    my $actual_replicated_volumes = PVE::Replication::run_replication(
        'PVE::QemuConfig',
        $self->{replication_jobcfg},
        $start_time,
        $start_time,
        $logfunc,
    );

    # extra safety check
    my @replicated_volumes = $self->filter_local_volumes(undef, 1);
    foreach my $volid (@replicated_volumes) {
        die "expected volume '$volid' to get replicated, but it wasn't\n"
            if !$actual_replicated_volumes->{$volid};
    }
}

sub config_update_local_disksizes {
    my ($self) = @_;

    my $conf = $self->{vmconf};
    my $local_volumes = $self->{local_volumes};

    PVE::QemuConfig->foreach_volume(
        $conf,
        sub {
            my ($key, $drive) = @_;
            # skip special disks, will be handled later
            return if $key eq 'efidisk0';
            return if $key eq 'tpmstate0';

            my $volid = $drive->{file};
            return if !defined($local_volumes->{$volid}); # only update sizes for local volumes

            my ($updated, $msg) =
                PVE::QemuServer::Drive::update_disksize($drive, $local_volumes->{$volid}->{size});
            if (defined($updated)) {
                $conf->{$key} = PVE::QemuServer::print_drive($updated);
                $self->log('info', "drive '$key': $msg");
            }
        },
    );

    # we want to set the efidisk size in the config to the size of the
    # real OVMF_VARS.fd image, else we can create a too big image, which does not work
    if (defined($conf->{efidisk0})) {
        PVE::QemuServer::update_efidisk_size($conf);
    }

    # TPM state might have an irregular filesize, to avoid problems on transfer
    # we always assume the static size of 4M to allocate on the target
    if (defined($conf->{tpmstate0})) {
        PVE::QemuServer::update_tpmstate_size($conf);
    }
}

sub filter_local_volumes {
    my ($self, $migration_mode, $replicated) = @_;

    my $volumes = $self->{local_volumes};
    my @filtered_volids;

    foreach my $volid (sort keys %{$volumes}) {
        next
            if defined($migration_mode)
            && safe_string_ne($volumes->{$volid}->{migration_mode}, $migration_mode);
        next
            if defined($replicated)
            && safe_boolean_ne($volumes->{$volid}->{replicated}, $replicated);
        push @filtered_volids, $volid;
    }

    return @filtered_volids;
}

sub sync_offline_local_volumes {
    my ($self) = @_;

    my $local_volumes = $self->{local_volumes};
    my @volids = $self->filter_local_volumes('offline', 0);

    my $storecfg = $self->{storecfg};
    my $opts = $self->{opts};

    $self->log('info', "copying local disk images") if scalar(@volids);

    foreach my $volid (@volids) {
        my $new_volid;

        my $opts = $self->{opts};
        if ($opts->{remote}) {
            my $log = sub {
                my ($level, $msg) = @_;
                $self->log($level, $msg);
            };

            $new_volid = PVE::StorageTunnel::storage_migrate(
                $self->{tunnel},
                $storecfg,
                $volid,
                $self->{vmid},
                $opts->{remote}->{vmid},
                $local_volumes->{$volid},
                $log,
            );
        } else {
            my $targetsid = $local_volumes->{$volid}->{targetsid};

            my $bwlimit = $local_volumes->{$volid}->{bwlimit};
            $bwlimit = $bwlimit * 1024 if defined($bwlimit); # storage_migrate uses bps

            my $storage_migrate_opts = {
                'ratelimit_bps' => $bwlimit,
                'insecure' => $opts->{migration_type} eq 'insecure',
                'with_snapshots' => $local_volumes->{$volid}->{snapshots},
                'allow_rename' => !$local_volumes->{$volid}->{is_vmstate},
            };

            my $logfunc = sub { $self->log('info', $_[0]); };
            $new_volid = eval {
                PVE::Storage::storage_migrate(
                    $storecfg,
                    $volid,
                    $self->{ssh_info},
                    $targetsid,
                    $storage_migrate_opts,
                    $logfunc,
                );
            };
            if (my $err = $@) {
                die "storage migration for '$volid' to storage '$targetsid' failed - $err\n";
            }
        }

        $self->{volume_map}->{$volid} = $new_volid;
        $self->log('info', "volume '$volid' is '$new_volid' on the target\n");

        eval { PVE::Storage::deactivate_volumes($storecfg, [$volid]); };
        if (my $err = $@) {
            $self->log('warn', $err);
        }
    }
}

sub cleanup_remotedisks {
    my ($self) = @_;

    if ($self->{opts}->{remote}) {
        PVE::Tunnel::finish_tunnel($self->{tunnel}, 1);
        delete $self->{tunnel};
        return;
    }

    my $local_volumes = $self->{local_volumes};

    foreach my $volid (values %{ $self->{volume_map} }) {
        # don't clean up replicated disks!
        next if $local_volumes->{$volid}->{replicated};

        my ($storeid, $volname) = PVE::Storage::parse_volume_id($volid);

        my $cmd = [@{ $self->{rem_ssh} }, 'pvesm', 'free', "$storeid:$volname"];

        eval {
            PVE::Tools::run_command($cmd, outfunc => sub { }, errfunc => sub { });
        };
        if (my $err = $@) {
            $self->log('err', $err);
            $self->{errors} = 1;
        }
    }
}

sub cleanup_bitmaps {
    my ($self) = @_;
    foreach my $drive (keys %{ $self->{target_drive} }) {
        my $bitmap = $self->{target_drive}->{$drive}->{bitmap};
        next if !$bitmap;
        $self->log('info', "$drive: removing block-dirty-bitmap '$bitmap'");
        mon_cmd(
            $self->{vmid}, 'block-dirty-bitmap-remove',
            node => "drive-$drive",
            name => $bitmap,
        );
    }
}

sub phase1 {
    my ($self, $vmid) = @_;

    $self->log('info', "starting migration of VM $vmid to node '$self->{node}' ($self->{nodeip})");

    my $conf = $self->{vmconf};

    # set migrate lock in config file
    $conf->{lock} = 'migrate';
    PVE::QemuConfig->write_config($vmid, $conf);

    $self->scan_local_volumes($vmid);

    # fix disk sizes to match their actual size and write changes,
    # so that the target allocates the correct volumes
    $self->config_update_local_disksizes();
    PVE::QemuConfig->write_config($vmid, $conf);

    $self->handle_replication($vmid);

    $self->sync_offline_local_volumes();
    $self->phase1_remote($vmid) if $self->{opts}->{remote};
}

sub map_bridges {
    my ($conf, $map, $scan_only) = @_;

    my $bridges = {};

    foreach my $opt (keys %$conf) {
        next if $opt !~ m/^net\d+$/;

        next if !$conf->{$opt};
        my $d = PVE::QemuServer::parse_net($conf->{$opt});
        next if !$d || !$d->{bridge};

        my $target_bridge = PVE::JSONSchema::map_id($map, $d->{bridge});
        $bridges->{$target_bridge}->{$opt} = $d->{bridge};

        next if $scan_only;

        $d->{bridge} = $target_bridge;
        $conf->{$opt} = PVE::QemuServer::print_net($d);
    }

    return $bridges;
}

sub phase1_remote {
    my ($self, $vmid) = @_;

    my $remote_conf = PVE::QemuConfig->load_config($vmid);
    PVE::QemuConfig->update_volume_ids($remote_conf, $self->{volume_map});

    my $bridges = map_bridges($remote_conf, $self->{opts}->{bridgemap});
    for my $target (keys $bridges->%*) {
        for my $nic (keys $bridges->{$target}->%*) {
            $self->log('info', "mapped: $nic from $bridges->{$target}->{$nic} to $target");
        }
    }

    my @online_local_volumes = $self->filter_local_volumes('online');

    my $storage_map = $self->{opts}->{storagemap};
    $self->{nbd} = {};
    PVE::QemuConfig->foreach_volume(
        $remote_conf,
        sub {
            my ($ds, $drive) = @_;

            # TODO eject CDROM?
            return if PVE::QemuServer::drive_is_cdrom($drive);

            my $volid = $drive->{file};
            return if !$volid;

            return if !grep { $_ eq $volid } @online_local_volumes;

            my ($storeid) = PVE::Storage::parse_volume_id($volid);
            my $source_format = checked_volume_format($self->{storecfg}, $volid);

            # set by target cluster
            my $oldvolid = delete $drive->{file};
            delete $drive->{format};

            my $targetsid = PVE::JSONSchema::map_id($storage_map, $storeid);

            my $params = {
                format => $source_format,
                storage => $targetsid,
                drive => $drive,
            };

            $self->log(
                'info',
                "Allocating volume for drive '$ds' on remote storage '$targetsid'..",
            );
            my $res = PVE::Tunnel::write_tunnel($self->{tunnel}, 600, 'disk', $params);

            $self->log('info', "volume '$oldvolid' is '$res->{volid}' on the target\n");
            $remote_conf->{$ds} = $res->{drivestr};
            $self->{nbd}->{$ds} = $res;
        },
    );

    my $conf_str = PVE::QemuServer::write_vm_config("remote", $remote_conf);

    # TODO expose in PVE::Firewall?
    my $vm_fw_conf_path = "/etc/pve/firewall/$vmid.fw";
    my $fw_conf_str;
    $fw_conf_str = PVE::Tools::file_get_contents($vm_fw_conf_path)
        if -e $vm_fw_conf_path;
    my $params = {
        conf => $conf_str,
        'firewall-config' => $fw_conf_str,
    };

    PVE::Tunnel::write_tunnel($self->{tunnel}, 10, 'config', $params);
}

sub phase1_cleanup {
    my ($self, $vmid, $err) = @_;

    $self->log('info', "aborting phase 1 - cleanup resources");

    my $conf = $self->{vmconf};
    delete $conf->{lock};
    eval { PVE::QemuConfig->write_config($vmid, $conf) };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    eval { $self->cleanup_remotedisks() };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    eval { $self->cleanup_bitmaps() };
    if (my $err = $@) {
        $self->log('err', $err);
    }
}

sub phase2_start_local_cluster {
    my ($self, $vmid, $params) = @_;

    my $conf = $self->{vmconf};
    my $local_volumes = $self->{local_volumes};
    my @online_local_volumes = $self->filter_local_volumes('online');

    my $start = $params->{start_params};
    my $migrate = $params->{migrate_opts};

    $self->log('info', "starting VM $vmid on remote node '$self->{node}'");

    my $tunnel_info = {};

    ## start on remote node
    my $cmd = [@{ $self->{rem_ssh} }];

    push @$cmd, 'qm', 'start', $vmid;

    if ($start->{skiplock}) {
        push @$cmd, '--skiplock';
    }

    push @$cmd, '--migratedfrom', $migrate->{migratedfrom};

    push @$cmd, '--migration_type', $migrate->{type};

    push @$cmd, '--migration_network', $migrate->{network}
        if $migrate->{network};

    push @$cmd, '--stateuri', $start->{statefile};

    if ($start->{forcemachine}) {
        push @$cmd, '--machine', $start->{forcemachine};
    }

    if ($start->{forcecpu}) {
        push @$cmd, '--force-cpu', $start->{forcecpu};
    }

    if ($start->{'nets-host-mtu'}) {
        push @$cmd, '--nets-host-mtu', $start->{'nets-host-mtu'};
    }

    if ($self->{storage_migration}) {
        push @$cmd, '--targetstorage', ($self->{opts}->{targetstorage} // '1');
    }

    my $spice_port;
    my $input = "nbd_protocol_version: $migrate->{nbd_proto_version}\n";

    my @offline_local_volumes = $self->filter_local_volumes('offline');
    for my $volid (@offline_local_volumes) {
        my $drivename = $local_volumes->{$volid}->{drivename};
        next if !$drivename || !$conf->{$drivename};

        my $new_volid = $self->{volume_map}->{$volid};
        next if !$new_volid || $volid eq $new_volid;

        # FIXME PVE 8.x only use offline_volume variant once all targets can handle it
        if ($drivename eq 'tpmstate0') {
            $input .= "$drivename: $new_volid\n";
        } else {
            $input .= "offline_volume: $drivename: $new_volid\n";
        }
    }

    $input .= "spice_ticket: $migrate->{spice_ticket}\n" if $migrate->{spice_ticket};

    my @online_replicated_volumes = $self->filter_local_volumes('online', 1);
    foreach my $volid (@online_replicated_volumes) {
        $input .= "replicated_volume: $volid\n";
    }

    my $handle_storage_migration_listens = sub {
        my ($drive_key, $drivestr, $nbd_uri) = @_;

        $self->{stopnbd} = 1;
        $self->{target_drive}->{$drive_key}->{drivestr} = $drivestr;
        $self->{target_drive}->{$drive_key}->{nbd_uri} = $nbd_uri;

        my $source_drive = PVE::QemuServer::parse_drive($drive_key, $conf->{$drive_key});
        my $target_drive = PVE::QemuServer::parse_drive($drive_key, $drivestr);
        my $source_volid = $source_drive->{file};
        my $target_volid = $target_drive->{file};

        $self->{volume_map}->{$source_volid} = $target_volid;
        $self->log('info', "volume '$source_volid' is '$target_volid' on the target\n");
    };

    my $target_replicated_volumes = {};
    my $target_nets_host_mtu_not_supported;

    # Note: We try to keep $spice_ticket secret (do not pass via command line parameter)
    # instead we pipe it through STDIN
    my $exitcode = PVE::Tools::run_command(
        $cmd,
        input => $input,
        outfunc => sub {
            my $line = shift;

            if ($line =~
                m/^migration listens on (tcp):(localhost|[\d\.]+|\[[\d\.:a-fA-F]+\]):(\d+)$/
            ) {
                $tunnel_info->{addr} = $2;
                $tunnel_info->{port} = int($3);
                $tunnel_info->{proto} = $1;
            } elsif ($line =~ m!^migration listens on (unix):(/run/qemu-server/(\d+)\.migrate)$!
            ) {
                $tunnel_info->{addr} = $2;
                die "Destination UNIX sockets VMID does not match source VMID" if $vmid ne $3;
                $tunnel_info->{proto} = $1;
            } elsif ($line =~ m/^migration listens on port (\d+)$/) {
                $tunnel_info->{addr} = "localhost";
                $tunnel_info->{port} = int($1);
                $tunnel_info->{proto} = "tcp";
            } elsif ($line =~ m/^spice listens on port (\d+)$/) {
                $spice_port = int($1);
            } elsif ($line =~
                m/^storage migration listens on nbd:(localhost|[\d\.]+|\[[\d\.:a-fA-F]+\]):(\d+):exportname=(\S+) volume:(\S+)$/
            ) {
                my $drivestr = $4;
                my $nbd_uri = "nbd:$1:$2:exportname=$3";
                my $targetdrive = $3;
                $targetdrive =~ s/drive-//g;

                $handle_storage_migration_listens->($targetdrive, $drivestr, $nbd_uri);
            } elsif ($line =~
                m!^storage migration listens on nbd:unix:(/run/qemu-server/(\d+)_nbd\.migrate):exportname=(\S+) volume:(\S+)$!
            ) {
                my $drivestr = $4;
                die "Destination UNIX socket's VMID does not match source VMID" if $vmid ne $2;
                my $nbd_unix_addr = $1;
                my $nbd_uri = "nbd:unix:$nbd_unix_addr:exportname=$3";
                my $targetdrive = $3;
                $targetdrive =~ s/drive-//g;

                $handle_storage_migration_listens->($targetdrive, $drivestr, $nbd_uri);
                $tunnel_info->{unix_sockets}->{$nbd_unix_addr} = 1;
            } elsif ($line =~ m/^re-using replicated volume: (\S+) - (.*)$/) {
                my $drive = $1;
                my $volid = $2;
                $target_replicated_volumes->{$volid} = $drive;
            } elsif ($line =~ m/^QEMU: (.*)$/) {
                $self->log('info', "[$self->{node}] $1\n");
            }
        },
        errfunc => sub {
            my $line = shift;
            $target_nets_host_mtu_not_supported = 1
                if $line =~ m/^Unknown option: nets-host-mtu/;
            $self->log('info', "[$self->{node}] $line");
        },
        noerr => 1,
    );

    die "node $self->{node} is too old for preserving VirtIO-net MTU, please upgrade\n"
        if $target_nets_host_mtu_not_supported;

    die "remote command failed with exit code $exitcode\n" if $exitcode;

    die "unable to detect remote migration address\n"
        if !$tunnel_info->{addr} || !$tunnel_info->{proto};

    if (scalar(keys %$target_replicated_volumes) != scalar(@online_replicated_volumes)) {
        die
            "number of replicated disks on source and target node do not match - target node too old?\n";
    }

    return ($tunnel_info, $spice_port);
}

sub phase2_start_remote_cluster {
    my ($self, $vmid, $params) = @_;

    die "insecure migration to remote cluster not implemented\n"
        if $params->{migrate_opts}->{type} ne 'websocket';

    my $remote_vmid = $self->{opts}->{remote}->{vmid};

    # like regular start but with some overhead accounted for
    my $memory = get_current_memory($self->{vmconf}->{memory});
    my $timeout = PVE::QemuServer::Helpers::config_aware_timeout($self->{vmconf}, $memory) + 10;

    my $res = PVE::Tunnel::write_tunnel($self->{tunnel}, $timeout, "start", $params);

    foreach my $drive (keys %{ $res->{drives} }) {
        $self->{stopnbd} = 1;
        $self->{target_drive}->{$drive}->{drivestr} = $res->{drives}->{$drive}->{drivestr};
        my $nbd_uri = $res->{drives}->{$drive}->{nbd_uri};
        die "unexpected NBD uri for '$drive': $nbd_uri\n"
            if $nbd_uri !~ s!/run/qemu-server/$remote_vmid\_!/run/qemu-server/$vmid\_!;

        $self->{target_drive}->{$drive}->{nbd_uri} = $nbd_uri;
    }

    return ($res->{migrate}, $res->{spice_port});
}

sub phase2 {
    my ($self, $vmid) = @_;

    my $conf = $self->{vmconf};
    my $local_volumes = $self->{local_volumes};

    # version > 0 for unix socket support
    my $nbd_protocol_version = 1;

    my $spice_ticket;
    if (PVE::QemuServer::vga_conf_has_spice($conf->{vga})) {
        my $res = mon_cmd($vmid, 'query-spice');
        $spice_ticket = $res->{ticket};
    }

    my $migration_type = $self->{opts}->{migration_type};
    my $state_uri = $migration_type eq 'insecure' ? 'tcp' : 'unix';

    my $params = {
        start_params => {
            statefile => $state_uri,
            forcemachine => $self->{forcemachine},
            forcecpu => $self->{forcecpu},
            skiplock => 1,
        },
        migrate_opts => {
            spice_ticket => $spice_ticket,
            type => $migration_type,
            network => $self->{opts}->{migration_network},
            storagemap => $self->{opts}->{storagemap},
            migratedfrom => PVE::INotify::nodename(),
            nbd_proto_version => $nbd_protocol_version,
            nbd => $self->{nbd},
        },
    };

    my $target_version = PVE::QemuServer::Helpers::get_node_pvecfg_version($self->{node});
    my $only_inherited_mtus =
        $target_version && !PVE::QemuServer::Helpers::pvecfg_min_version($target_version, 9, 0, 0);
    my $nets_host_mtu = PVE::QemuServer::get_nets_host_mtu($vmid, $conf, $only_inherited_mtus);
    $params->{start_params}->{'nets-host-mtu'} = $nets_host_mtu if $nets_host_mtu;

    my ($tunnel_info, $spice_port);

    my @online_local_volumes = $self->filter_local_volumes('online');
    $self->{storage_migration} = 1 if scalar(@online_local_volumes);

    if (my $remote = $self->{opts}->{remote}) {
        my $remote_vmid = $remote->{vmid};
        $params->{migrate_opts}->{remote_node} = $self->{node};
        ($tunnel_info, $spice_port) = $self->phase2_start_remote_cluster($vmid, $params);
        die "only UNIX sockets are supported for remote migration\n"
            if $tunnel_info->{proto} ne 'unix';

        # untaint
        my ($remote_socket) = $tunnel_info->{addr} =~ m|^(/run/qemu-server/\d+\.migrate)$|
            or die "unexpected socket address '$tunnel_info->{addr}'\n";
        my $local_socket = $remote_socket;
        $local_socket =~ s/$remote_vmid/$vmid/g;
        $tunnel_info->{addr} = $local_socket;

        $self->log('info', "Setting up tunnel for '$local_socket'");
        PVE::Tunnel::forward_unix_socket($self->{tunnel}, $local_socket, $remote_socket);

        foreach my $remote_socket (@{ $tunnel_info->{unix_sockets} }) {
            # untaint
            ($remote_socket) = $remote_socket =~ m|^(/run/qemu-server/(?:(?!\.\./).)+\.migrate)$|
                or die "unexpected socket address '$remote_socket'\n";
            my $local_socket = $remote_socket;
            $local_socket =~ s/$remote_vmid/$vmid/g;
            next if $self->{tunnel}->{forwarded}->{$local_socket};
            $self->log('info', "Setting up tunnel for '$local_socket'");
            PVE::Tunnel::forward_unix_socket($self->{tunnel}, $local_socket, $remote_socket);
        }
    } else {
        ($tunnel_info, $spice_port) = $self->phase2_start_local_cluster($vmid, $params);

        $self->log('info', "start remote tunnel");
        $self->start_remote_tunnel($tunnel_info);
    }

    my $migrate_uri = "$tunnel_info->{proto}:$tunnel_info->{addr}";
    $migrate_uri .= ":$tunnel_info->{port}"
        if defined($tunnel_info->{port});

    if ($self->{storage_migration}) {
        $self->{storage_migration_jobs} = {};
        $self->log('info', "starting storage migration");

        die "The number of local disks does not match between the source and the destination.\n"
            if (scalar(keys %{ $self->{target_drive} }) != scalar(@online_local_volumes));
        foreach my $drive (keys %{ $self->{target_drive} }) {
            my $target = $self->{target_drive}->{$drive};
            my $nbd_uri = $target->{nbd_uri};

            my $source_drive = PVE::QemuServer::parse_drive($drive, $conf->{$drive});
            my $source_volid = $source_drive->{file};

            my $bwlimit = $self->{local_volumes}->{$source_volid}->{bwlimit};
            my $bitmap = $target->{bitmap};

            $self->log('info', "$drive: start migration to $nbd_uri");
            PVE::QemuServer::qemu_drive_mirror(
                $vmid,
                $drive,
                $nbd_uri,
                $vmid,
                undef,
                $self->{storage_migration_jobs},
                'skip',
                undef,
                $bwlimit,
                $bitmap,
            );
        }

        if (PVE::QemuServer::QMPHelpers::runs_at_least_qemu_version($vmid, 8, 2)) {
            $self->log('info', "switching mirror jobs to actively synced mode");
            PVE::QemuServer::qemu_drive_mirror_switch_to_active_mode(
                $vmid,
                $self->{storage_migration_jobs},
            );
        }
    }

    $self->log('info', "starting online/live migration on $migrate_uri");
    $self->{livemigration} = 1;

    # load_defaults
    my $defaults = PVE::QemuServer::load_defaults();

    $self->log('info', "set migration capabilities");
    eval { PVE::QemuServer::set_migration_caps($vmid) };
    warn $@ if $@;

    my $qemu_migrate_params = {};

    # migrate speed can be set via bwlimit (datacenter.cfg and API) and via the
    # migrate_speed parameter in qm.conf - take the lower of the two.
    my $bwlimit = $self->get_bwlimit();

    my $migrate_speed = $conf->{migrate_speed} // 0;
    $migrate_speed *= 1024; # migrate_speed is in MB/s, bwlimit in KB/s

    if ($bwlimit && $migrate_speed) {
        $migrate_speed = ($bwlimit < $migrate_speed) ? $bwlimit : $migrate_speed;
    } else {
        $migrate_speed ||= $bwlimit;
    }
    $migrate_speed ||= ($defaults->{migrate_speed} || 0) * 1024;

    if ($migrate_speed) {
        $migrate_speed *= 1024; # qmp takes migrate_speed in B/s.
        $self->log('info', "migration speed limit: " . render_bytes($migrate_speed, 1) . "/s");
    } else {
        # always set migrate speed as QEMU default to 128 MiBps == 1 Gbps, use 16 GiBps == 128 Gbps
        $migrate_speed = (16 << 30);
    }
    $qemu_migrate_params->{'max-bandwidth'} = int($migrate_speed);

    my $migrate_downtime = $defaults->{migrate_downtime};
    $migrate_downtime = $conf->{migrate_downtime} if defined($conf->{migrate_downtime});
    # migrate-set-parameters expects limit in ms
    $migrate_downtime *= 1000;
    $self->log('info', "migration downtime limit: $migrate_downtime ms");
    $qemu_migrate_params->{'downtime-limit'} = int($migrate_downtime);

    # set cachesize to 10% of the total memory
    my $memory = get_current_memory($conf->{memory});
    my $cachesize = int($memory * 1048576 / 10);
    $cachesize = round_powerof2($cachesize);

    $self->log('info', "migration cachesize: " . render_bytes($cachesize, 1));
    $qemu_migrate_params->{'xbzrle-cache-size'} = int($cachesize);

    $self->log('info', "set migration parameters");
    eval { mon_cmd($vmid, "migrate-set-parameters", %{$qemu_migrate_params}); };
    $self->log('info', "migrate-set-parameters error: $@") if $@;

    if (PVE::QemuServer::vga_conf_has_spice($conf->{vga}) && !$self->{opts}->{remote}) {
        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my (undef, $proxyticket) =
            PVE::AccessControl::assemble_spice_ticket($authuser, $vmid, $self->{node});

        my $filename = "/etc/pve/nodes/$self->{node}/pve-ssl.pem";
        my $subject = PVE::AccessControl::read_x509_subject_spice($filename);

        $self->log('info', "spice client_migrate_info");

        eval {
            mon_cmd(
                $vmid, "client_migrate_info",
                protocol => 'spice',
                hostname => $proxyticket,
                'port' => 0,
                'tls-port' => $spice_port,
                'cert-subject' => $subject,
            );
        };
        $self->log('info', "client_migrate_info error: $@") if $@;

    }

    my $start = time();

    $self->log('info', "start migrate command to $migrate_uri");
    eval { mon_cmd($vmid, "migrate", uri => $migrate_uri); };
    my $merr = $@;
    $self->log('info', "migrate uri => $migrate_uri failed: $merr") if $merr;

    my $last_mem_transferred = 0;
    my $last_vfio_transferred = 0;
    my $usleep = 1000000;
    my $i = 0;
    my $err_count = 0;
    my $lastrem = undef;
    my $downtimecounter = 0;
    while (1) {
        $i++;
        my $avglstat = $last_mem_transferred ? $last_mem_transferred / $i : 0;

        usleep($usleep);

        my $stat = eval { mon_cmd($vmid, "query-migrate") };
        if (my $err = $@) {
            $err_count++;
            warn "query migrate failed: $err\n";
            $self->log('info', "query migrate failed: $err");
            if ($err_count <= 5) {
                usleep(1_000_000);
                next;
            }
            die "too many query migrate failures - aborting\n";
        }

        my $status = $stat->{status};
        if (defined($status) && $status =~ m/^(setup)$/im) {
            sleep(1);
            next;
        }

        if (!defined($status) || $status !~ m/^(active|completed|failed|cancelled)$/im) {
            die $merr if $merr;
            die "unable to parse migration status '$status' - aborting\n";
        }
        $merr = undef;
        $err_count = 0;

        my $memstat = $stat->{ram};

        my $mem_transferred = $memstat->{transferred} || 0;
        my $vfio_transferred = $stat->{vfio}->{transferred} || 0;

        if ($status eq 'completed') {
            my $delay = time() - $start;
            if ($delay > 0) {
                my $total = $memstat->{total} || 0;
                my $avg_speed = render_bytes($total / $delay, 1);
                my $downtime = $stat->{downtime} || 0;
                $self->log('info', "average migration speed: $avg_speed/s - downtime $downtime ms");
            }

            if ($mem_transferred > 0 || $vfio_transferred > 0) {
                my $transferred_h = render_bytes($mem_transferred, 1);
                my $summary = "transferred $transferred_h VM-state";

                if ($vfio_transferred > 0) {
                    my $vfio_h = render_bytes($vfio_transferred, 1);
                    $summary .= " (+ $vfio_h VFIO-state)";
                }

                $self->log('info', "migration $status, $summary");
            }
        }

        if ($status eq 'failed' || $status eq 'cancelled') {
            my $message = $stat->{'error-desc'} ? "$status - $stat->{'error-desc'}" : $status;
            $self->log('info', "migration status error: $message");
            die "aborting\n";
        }

        if ($status ne 'active') {
            $self->log('info', "migration status: $status");
            last;
        }

        if (
            $mem_transferred ne $last_mem_transferred
            || $vfio_transferred ne $last_vfio_transferred
        ) {
            my $rem = $memstat->{remaining} || 0;
            my $total = $memstat->{total} || 0;
            my $speed = ($memstat->{'pages-per-second'} // 0) * ($memstat->{'page-size'} // 0);
            my $dirty_rate = ($memstat->{'dirty-pages-rate'} // 0) * ($memstat->{'page-size'} // 0);

            # reduce sleep if remaining memory is lower than the average transfer speed
            $usleep = 100_000 if $avglstat && $rem < $avglstat;

            # also reduce logging if we poll more frequent
            my $should_log = $usleep > 100_000 ? 1 : ($i % 10) == 0;

            my $total_h = render_bytes($total, 1);
            my $transferred_h = render_bytes($mem_transferred, 1);
            my $speed_h = render_bytes($speed, 1);

            my $progress = "transferred $transferred_h of $total_h VM-state, ${speed_h}/s";

            if ($vfio_transferred > 0) {
                my $vfio_h = render_bytes($vfio_transferred, 1);
                $progress .= " (+ $vfio_h VFIO-state)";
            }

            if ($dirty_rate > $speed) {
                my $dirty_rate_h = render_bytes($dirty_rate, 1);
                $progress .= ", VM dirties lots of memory: $dirty_rate_h/s";
            }

            $self->log('info', "migration $status, $progress") if $should_log;

            my $xbzrle = $stat->{"xbzrle-cache"} || {};
            my ($xbzrlebytes, $xbzrlepages) = $xbzrle->@{ 'bytes', 'pages' };
            if ($xbzrlebytes || $xbzrlepages) {
                my $bytes_h = render_bytes($xbzrlebytes, 1);

                my $msg = "send updates to $xbzrlepages pages in $bytes_h encoded memory";

                $msg .= sprintf(", cache-miss %.2f%%", $xbzrle->{'cache-miss-rate'} * 100)
                    if $xbzrle->{'cache-miss-rate'};

                $msg .= ", overflow $xbzrle->{overflow}" if $xbzrle->{overflow};

                $self->log('info', "xbzrle: $msg") if $should_log;
            }

            if (($lastrem && $rem > $lastrem) || ($rem == 0)) {
                $downtimecounter++;
            }
            $lastrem = $rem;

            if ($downtimecounter > 5) {
                $downtimecounter = 0;
                $migrate_downtime *= 2;
                $self->log(
                    'info',
                    "auto-increased downtime to continue migration: $migrate_downtime ms",
                );
                eval {
                    # migrate-set-parameters does not touch values not
                    # specified, so this only changes downtime-limit
                    mon_cmd(
                        $vmid,
                        "migrate-set-parameters",
                        'downtime-limit' => int($migrate_downtime),
                    );
                };
                $self->log('info', "migrate-set-parameters error: $@") if $@;
            }
        }

        $last_mem_transferred = $mem_transferred;
        $last_vfio_transferred = $vfio_transferred;
    }

    if ($self->{storage_migration}) {
        # finish block-job with block-job-cancel, to disconnect source VM from NBD
        # to avoid it trying to re-establish it. We are in blockjob ready state,
        # thus, this command changes to it to blockjob complete (see qapi docs)
        eval {
            PVE::QemuServer::qemu_drive_mirror_monitor(
                $vmid, undef, $self->{storage_migration_jobs}, 'cancel',
            );
        };
        if (my $err = $@) {
            die "Failed to complete storage migration: $err\n";
        }
    }
}

sub phase2_cleanup {
    my ($self, $vmid, $err) = @_;

    return if !$self->{errors};
    $self->{phase2errors} = 1;

    $self->log('info', "aborting phase 2 - cleanup resources");

    $self->log('info', "migrate_cancel");
    eval { mon_cmd($vmid, "migrate_cancel"); };
    $self->log('info', "migrate_cancel error: $@") if $@;

    my $vm_status =
        eval { mon_cmd($vmid, 'query-status')->{status} or die "no 'status' in result\n"; };
    $self->log('err', "query-status error: $@") if $@;

    # Can end up in POSTMIGRATE state if failure occurred after convergence. Try going back to
    # original state. Unfortunately, direct transition from POSTMIGRATE to PAUSED is not possible.
    if ($vm_status && $vm_status eq 'postmigrate') {
        if (!$self->{vm_was_paused}) {
            eval { mon_cmd($vmid, 'cont'); };
            $self->log('err', "resuming VM failed: $@") if $@;
        } else {
            $self->log('err', "VM was paused, but ended in postmigrate state");
        }
    }

    my $conf = $self->{vmconf};
    delete $conf->{lock};
    eval { PVE::QemuConfig->write_config($vmid, $conf) };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    # cleanup resources on target host
    if ($self->{storage_migration}) {
        eval { PVE::QemuServer::qemu_blockjobs_cancel($vmid, $self->{storage_migration_jobs}) };
        if (my $err = $@) {
            $self->log('err', $err);
        }
    }

    eval { $self->cleanup_bitmaps() };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    my $nodename = PVE::INotify::nodename();

    if ($self->{tunnel} && $self->{tunnel}->{version} >= 2) {
        PVE::Tunnel::write_tunnel($self->{tunnel}, 10, 'stop');
    } else {
        my $cmd =
            [@{ $self->{rem_ssh} }, 'qm', 'stop', $vmid, '--skiplock', '--migratedfrom', $nodename];
        eval {
            PVE::Tools::run_command($cmd, outfunc => sub { }, errfunc => sub { });
        };
        if (my $err = $@) {
            $self->log('err', $err);
            $self->{errors} = 1;
        }
    }

    # cleanup after stopping, otherwise disks might be in-use by target VM!
    eval { PVE::QemuMigrate::cleanup_remotedisks($self) };
    if (my $err = $@) {
        $self->log('err', $err);
    }

    if ($self->{tunnel}) {
        eval { PVE::Tunnel::finish_tunnel($self->{tunnel}); };
        if (my $err = $@) {
            $self->log('err', $err);
            $self->{errors} = 1;
        }
    }
}

sub phase3 {
    my ($self, $vmid) = @_;

    return;
}

sub phase3_cleanup {
    my ($self, $vmid, $err) = @_;

    my $conf = $self->{vmconf};
    return if $self->{phase2errors};

    my $tunnel = $self->{tunnel};

    # we'll need an unmodified copy of the config later for the cleanup
    my $oldconf = dclone($conf);

    if ($self->{volume_map} && !$self->{opts}->{remote}) {
        my $target_drives = $self->{target_drive};

        # FIXME: for NBD storage migration we now only update the volid, and
        # not the full drivestr from the target node. Workaround that until we
        # got some real rescan, to avoid things like wrong format in the drive
        delete $conf->{$_} for keys %$target_drives;
        PVE::QemuConfig->update_volume_ids($conf, $self->{volume_map});

        for my $drive (keys %$target_drives) {
            $conf->{$drive} = $target_drives->{$drive}->{drivestr};
        }
        PVE::QemuConfig->write_config($vmid, $conf);
    }

    # transfer replication state before move config
    if (!$self->{opts}->{remote}) {
        $self->transfer_replication_state() if $self->{is_replicated};
        PVE::QemuConfig->move_config_to_node($vmid, $self->{node});
        $self->switch_replication_job_target() if $self->{is_replicated};
    }

    if ($self->{livemigration}) {
        if ($self->{stopnbd}) {
            $self->log('info', "stopping NBD storage migration server on target.");
            # stop nbd server on remote vm - requirement for resume since 2.9
            if ($tunnel && $tunnel->{version} && $tunnel->{version} >= 2) {
                eval { PVE::Tunnel::write_tunnel($tunnel, 30, 'nbdstop'); };
                if (my $err = $@) {
                    $self->log('err', $err);
                    $self->{errors} = 1;
                }
            } else {
                my $cmd = [@{ $self->{rem_ssh} }, 'qm', 'nbdstop', $vmid];

                eval {
                    PVE::Tools::run_command($cmd, outfunc => sub { }, errfunc => sub { });
                };
                if (my $err = $@) {
                    $self->log('err', $err);
                    $self->{errors} = 1;
                }
            }
        }

        # deletes local FDB entries if learning is disabled, they'll be re-added on target on resume
        PVE::QemuServer::del_nets_bridge_fdb($conf, $vmid);

        if (!$self->{vm_was_paused}) {
            # config moved and nbd server stopped - now we can resume vm on target
            if ($tunnel && $tunnel->{version} && $tunnel->{version} >= 1) {
                my $cmd = $tunnel->{version} == 1 ? "resume $vmid" : "resume";
                eval { PVE::Tunnel::write_tunnel($tunnel, 30, $cmd); };
                if (my $err = $@) {
                    $self->log('err', $err);
                    $self->{errors} = 1;
                }
            } else {
                # nocheck in case target node hasn't processed the config move/rename yet
                my $cmd = [@{ $self->{rem_ssh} }, 'qm', 'resume', $vmid, '--skiplock', '--nocheck'];
                my $logf = sub {
                    my $line = shift;
                    $self->log('err', $line);
                };
                eval {
                    PVE::Tools::run_command($cmd, outfunc => sub { }, errfunc => $logf);
                };
                if (my $err = $@) {
                    $self->log('err', $err);
                    $self->{errors} = 1;
                }
            }
        }

        if (
            $self->{storage_migration}
            && PVE::QemuServer::parse_guest_agent($conf)->{fstrim_cloned_disks}
            && $self->{running}
        ) {
            if (!$self->{vm_was_paused}) {
                $self->log('info', "issuing guest fstrim");
                if ($self->{opts}->{remote}) {
                    PVE::Tunnel::write_tunnel($self->{tunnel}, 600, 'fstrim');
                } else {
                    my $cmd = [@{ $self->{rem_ssh} }, 'qm', 'guest', 'cmd', $vmid, 'fstrim'];
                    eval {
                        PVE::Tools::run_command($cmd, outfunc => sub { }, errfunc => sub { });
                    };
                    if (my $err = $@) {
                        $self->log('err', "fstrim failed - $err");
                        $self->{errors} = 1;
                    }
                }
            } else {
                $self->log('info', "skipping guest fstrim, because VM is paused");
            }
        }
    }

    # close tunnel on successful migration, on error phase2_cleanup closed it
    if ($tunnel && $tunnel->{version} == 1) {
        eval { PVE::Tunnel::finish_tunnel($tunnel); };
        if (my $err = $@) {
            $self->log('err', $err);
            $self->{errors} = 1;
        }
        $tunnel = undef;
        delete $self->{tunnel};
    }

    eval {
        my $timer = 0;
        if (PVE::QemuServer::vga_conf_has_spice($conf->{vga}) && $self->{running}) {
            $self->log('info', "Waiting for spice server migration");
            while (1) {
                my $res = mon_cmd($vmid, 'query-spice');
                last if int($res->{'migrated'}) == 1;
                last if $timer > 50;
                $timer++;
                usleep(200000);
            }
        }
    };

    # always stop local VM with nocheck, since config is moved already
    eval { PVE::QemuServer::vm_stop($self->{storecfg}, $vmid, 1, 1); };
    if (my $err = $@) {
        $self->log('err', "stopping vm failed - $err");
        $self->{errors} = 1;
    }

    # stop with nocheck does not do a cleanup, so do it here with the original config
    eval { PVE::QemuServer::vm_stop_cleanup($self->{storecfg}, $vmid, $oldconf) };
    if (my $err = $@) {
        $self->log('err', "Cleanup after stopping VM failed - $err");
        $self->{errors} = 1;
    }

    my @not_replicated_volumes = $self->filter_local_volumes(undef, 0);

    # destroy local copies
    foreach my $volid (@not_replicated_volumes) {
        # remote is cleaned up below
        next if $self->{opts}->{remote};

        eval { PVE::Storage::vdisk_free($self->{storecfg}, $volid); };
        if (my $err = $@) {
            $self->log('err', "removing local copy of '$volid' failed - $err");
            $self->{errors} = 1;
            last if $err =~ /^interrupted by signal$/;
        }
    }

    # clear migrate lock
    if ($tunnel && $tunnel->{version} >= 2) {
        PVE::Tunnel::write_tunnel($tunnel, 10, "unlock");

        PVE::Tunnel::finish_tunnel($tunnel);
    } else {
        my $cmd = [@{ $self->{rem_ssh} }, 'qm', 'unlock', $vmid];
        $self->cmd_logerr($cmd, errmsg => "failed to clear migrate lock");
    }

    if ($self->{opts}->{remote} && $self->{opts}->{delete}) {
        eval { PVE::QemuServer::destroy_vm($self->{storecfg}, $vmid, 1, undef, 0) };
        warn "Failed to remove source VM - $@\n" if $@;
    }
}

sub final_cleanup {
    my ($self, $vmid) = @_;

    # nothing to do
}

sub round_powerof2 {
    return 1 if $_[0] < 2;
    return 2 << int(log($_[0] - 1) / log(2));
}

1;
