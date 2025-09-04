package PVE::QemuServer::RunState;

use strict;
use warnings;

use POSIX qw(strftime);

use PVE::Cluster;
use PVE::RPCEnvironment;
use PVE::Storage;

use PVE::QemuConfig;
use PVE::QemuMigrate::Helpers;
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::Network;

# note: if using the statestorage parameter, the caller has to check privileges
sub vm_suspend {
    my ($vmid, $skiplock, $includestate, $statestorage) = @_;

    my $conf;
    my $path;
    my $storecfg;
    my $vmstate;

    PVE::QemuConfig->lock_config(
        $vmid,
        sub {

            $conf = PVE::QemuConfig->load_config($vmid);

            my $is_backing_up = PVE::QemuConfig->has_lock($conf, 'backup');
            PVE::QemuConfig->check_lock($conf)
                if !($skiplock || $is_backing_up);

            die "cannot suspend to disk during backup\n"
                if $is_backing_up && $includestate;

            PVE::QemuMigrate::Helpers::check_non_migratable_resources($conf, $includestate, 0);

            if ($includestate) {
                $conf->{lock} = 'suspending';
                my $date = strftime("%Y-%m-%d", localtime(time()));
                $storecfg = PVE::Storage::config();
                if (!$statestorage) {
                    $statestorage = PVE::QemuConfig::find_vmstate_storage($conf, $storecfg);
                    # check permissions for the storage
                    my $rpcenv = PVE::RPCEnvironment::get();
                    if ($rpcenv->{type} ne 'cli') {
                        my $authuser = $rpcenv->get_user();
                        $rpcenv->check(
                            $authuser,
                            "/storage/$statestorage",
                            ['Datastore.AllocateSpace'],
                        );
                    }
                }

                $vmstate = PVE::QemuConfig->__snapshot_save_vmstate(
                    $vmid, $conf, "suspend-$date", $storecfg, $statestorage, 1,
                );
                $path = PVE::Storage::path($storecfg, $vmstate);
                PVE::QemuConfig->write_config($vmid, $conf);
            } else {
                mon_cmd($vmid, "stop");
            }
        },
    );

    if ($includestate) {
        # save vm state
        PVE::Storage::activate_volumes($storecfg, [$vmstate]);

        eval {
            PVE::QemuMigrate::Helpers::set_migration_caps($vmid, 1);
            mon_cmd($vmid, "savevm-start", statefile => $path);
            for (;;) {
                my $state = mon_cmd($vmid, "query-savevm");
                if (!$state->{status}) {
                    die "savevm not active\n";
                } elsif ($state->{status} eq 'active') {
                    sleep(1);
                    next;
                } elsif ($state->{status} eq 'completed') {
                    print "State saved, quitting\n";
                    last;
                } elsif ($state->{status} eq 'failed' && $state->{error}) {
                    die "query-savevm failed with error '$state->{error}'\n";
                } else {
                    die "query-savevm returned status '$state->{status}'\n";
                }
            }
        };
        my $err = $@;

        PVE::QemuConfig->lock_config(
            $vmid,
            sub {
                $conf = PVE::QemuConfig->load_config($vmid);
                if ($err) {
                    # cleanup, but leave suspending lock, to indicate something went wrong
                    eval {
                        eval { mon_cmd($vmid, "savevm-end"); };
                        warn $@ if $@;
                        PVE::Storage::deactivate_volumes($storecfg, [$vmstate]);
                        PVE::Storage::vdisk_free($storecfg, $vmstate);
                        delete $conf->@{
                            qw(vmstate runningmachine runningcpu running-nets-host-mtu)};
                        PVE::QemuConfig->write_config($vmid, $conf);
                    };
                    warn $@ if $@;
                    die $err;
                }

                die "lock changed unexpectedly\n"
                    if !PVE::QemuConfig->has_lock($conf, 'suspending');

                mon_cmd($vmid, "quit");
                $conf->{lock} = 'suspended';
                PVE::QemuConfig->write_config($vmid, $conf);
            },
        );
    }
}

# $nocheck is set when called as part of a migration - in this context the
# location of the config file (source or target node) is not deterministic,
# since migration cannot wait for pmxcfs to process the rename
sub vm_resume {
    my ($vmid, $skiplock, $nocheck) = @_;

    PVE::QemuConfig->lock_config(
        $vmid,
        sub {
            # After migration, the VM might not immediately be able to respond to QMP commands, because
            # activating the block devices might take a bit of time.
            my $res = mon_cmd($vmid, 'query-status', timeout => 60);
            my $resume_cmd = 'cont';
            my $reset = 0;
            my $conf;
            if ($nocheck) {
                $conf = eval { PVE::QemuConfig->load_config($vmid) }; # try on target node
                if ($@) {
                    my $vmlist = PVE::Cluster::get_vmlist();
                    if (exists($vmlist->{ids}->{$vmid})) {
                        my $node = $vmlist->{ids}->{$vmid}->{node};
                        $conf = eval { PVE::QemuConfig->load_config($vmid, $node) }; # try on source node
                    }
                    if (!$conf) {
                        PVE::Cluster::cfs_update(); # vmlist was wrong, invalidate cache
                        $conf = PVE::QemuConfig->load_config($vmid); # last try on target node again
                    }
                }
            } else {
                $conf = PVE::QemuConfig->load_config($vmid);
            }

            die "VM $vmid is a template and cannot be resumed!\n"
                if PVE::QemuConfig->is_template($conf);

            if ($res->{status}) {
                return if $res->{status} eq 'running'; # job done, go home
                $resume_cmd = 'system_wakeup' if $res->{status} eq 'suspended';
                $reset = 1 if $res->{status} eq 'shutdown';
            }

            if (!$nocheck) {
                PVE::QemuConfig->check_lock($conf)
                    if !($skiplock || PVE::QemuConfig->has_lock($conf, 'backup'));
            }

            if ($reset) {
                # required if a VM shuts down during a backup and we get a resume
                # request before the backup finishes for example
                mon_cmd($vmid, "system_reset");
            }

            PVE::QemuServer::Network::add_nets_bridge_fdb($conf, $vmid)
                if $resume_cmd eq 'cont';

            mon_cmd($vmid, $resume_cmd);
        },
    );
}

1;
