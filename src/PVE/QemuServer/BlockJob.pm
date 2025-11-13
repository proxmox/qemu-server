package PVE::QemuServer::BlockJob;

use strict;
use warnings;

use JSON;
use Storable qw(dclone);

use PVE::Format qw(render_duration render_bytes);
use PVE::RESTEnvironment qw(log_warn);
use PVE::Storage;

use PVE::QemuServer::Agent qw(qga_check_running);
use PVE::QemuServer::Blockdev;
use PVE::QemuServer::Drive qw(checked_volume_format);
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::RunState;

# If the job was started with auto-dismiss=false, it's necessary to dismiss it manually. Using this
# option is useful to get the error for failed jobs here. QEMU's job lock should make it impossible
# to see a job in 'concluded' state when auto-dismiss=true.
# $info is the 'BlockJobInfo' for the job returned by query-block-jobs.
# $job is the information about the job recorded on the PVE-side.
# A block node $job->{'detach-node-name'} will be detached if present.
sub qemu_handle_concluded_blockjob {
    my ($vmid, $job_id, $qmp_info, $job) = @_;

    eval { mon_cmd($vmid, 'job-dismiss', id => $job_id); };
    log_warn("$job_id: failed to dismiss job - $@") if $@;

    # If there was an error or if the job was cancelled, always detach the target. This is correct
    # even when the job was cancelled after completion, because then the disk is not switched over
    # to use the target.
    $job->{'detach-node-name'} = $job->{'target-node-name'} if $qmp_info->{error} || $job->{cancel};

    if (my $node_name = $job->{'detach-node-name'}) {
        eval { PVE::QemuServer::Blockdev::detach($vmid, $node_name); };
        log_warn($@) if $@;
    }

    die "$job_id: $qmp_info->{error} (io-status: $qmp_info->{'io-status'})\n" if $qmp_info->{error};
}

sub qemu_blockjobs_cancel {
    my ($vmid, $jobs) = @_;

    foreach my $job (keys %$jobs) {
        print "$job: Cancelling block job\n";
        eval { mon_cmd($vmid, "block-job-cancel", device => $job); };
        $jobs->{$job}->{cancel} = 1;
    }

    while (1) {
        my $stats = mon_cmd($vmid, "query-block-jobs");

        my $running_jobs = {};
        foreach my $stat (@$stats) {
            $running_jobs->{ $stat->{device} } = $stat;
        }

        foreach my $job (keys %$jobs) {
            my $info = $running_jobs->{$job};
            eval {
                qemu_handle_concluded_blockjob($vmid, $job, $info, $jobs->{$job})
                    if $info && $info->{status} eq 'concluded';
            };
            log_warn($@) if $@; # only warn and proceed with canceling other jobs

            if (defined($jobs->{$job}->{cancel}) && !defined($info)) {
                print "$job: Done.\n";
                delete $jobs->{$job};
            }
        }

        last if scalar(keys %$jobs) == 0;

        sleep 1;
    }
}

# $completion can be either
# 'complete': wait until all jobs are ready, block-job-complete them (default)
# 'cancel': wait until all jobs are ready, block-job-cancel them
# 'skip': wait until all jobs are ready, return with block jobs in ready state
# 'auto': wait until all jobs disappear, only use for jobs which complete automatically
sub qemu_drive_mirror_monitor {
    my ($vmid, $vmiddst, $jobs, $completion, $qga, $op) = @_;

    $completion //= 'complete';
    $op //= "mirror";

    eval {
        my $err_complete = 0;

        my $starttime = time();
        while (1) {
            die "block job ('$op') timed out\n" if $err_complete > 300;

            my $stats = mon_cmd($vmid, "query-block-jobs");
            my $ctime = time();

            my $running_jobs = {};
            for my $stat (@$stats) {
                next if $stat->{type} ne $op;
                $running_jobs->{ $stat->{device} } = $stat;
            }

            my $readycounter = 0;

            for my $job_id (sort keys %$jobs) {
                my $job = $running_jobs->{$job_id};

                my $vanished = !defined($job);
                my $complete = defined($jobs->{$job_id}->{complete}) && $vanished;
                if ($complete || ($vanished && $completion eq 'auto')) {
                    print "$job_id: $op-job finished\n";
                    delete $jobs->{$job_id};
                    next;
                }

                die "$job_id: '$op' has been cancelled\n" if !defined($job);

                qemu_handle_concluded_blockjob($vmid, $job_id, $job, $jobs->{$job_id})
                    if $job && $job->{status} eq 'concluded';

                my $busy = $job->{busy};
                my $ready = $job->{ready};
                if (my $total = $job->{len}) {
                    my $transferred = $job->{offset} || 0;
                    my $remaining = $total - $transferred;
                    my $percent = sprintf "%.2f", ($transferred * 100 / $total);

                    my $duration = $ctime - $starttime;
                    my $total_h = render_bytes($total, 1);
                    my $transferred_h = render_bytes($transferred, 1);

                    my $status = sprintf(
                        "transferred $transferred_h of $total_h ($percent%%) in %s",
                        render_duration($duration),
                    );

                    if ($ready) {
                        if ($busy) {
                            $status .= ", still busy"; # shouldn't even happen? but mirror is weird
                        } else {
                            $status .= ", ready";
                        }
                    }
                    print "$job_id: $status\n" if !$jobs->{$job_id}->{ready};
                    $jobs->{$job_id}->{ready} = $ready;
                }

                $readycounter++ if $job->{ready};
            }

            last if scalar(keys %$jobs) == 0;

            if ($readycounter == scalar(keys %$jobs)) {
                print "all '$op' jobs are ready\n";

                # do the complete later (or has already been done)
                last if $completion eq 'skip' || $completion eq 'auto';

                if ($vmiddst && $vmiddst != $vmid) {
                    my $agent_running = $qga && qga_check_running($vmid);
                    if ($agent_running) {
                        print "freeze filesystem\n";
                        eval { PVE::QemuServer::Agent::guest_fsfreeze($vmid); };
                        warn $@ if $@;
                    } else {
                        print "suspend vm\n";
                        eval { PVE::QemuServer::RunState::vm_suspend($vmid, 1); };
                        warn $@ if $@;
                    }

                    # if we clone a disk for a new target vm, we don't switch the disk
                    qemu_blockjobs_cancel($vmid, $jobs);

                    if ($agent_running) {
                        print "unfreeze filesystem\n";
                        eval { mon_cmd($vmid, "guest-fsfreeze-thaw"); };
                        warn $@ if $@;
                    } else {
                        print "resume vm\n";
                        eval { PVE::QemuServer::RunState::vm_resume($vmid, 1, 1); };
                        warn $@ if $@;
                    }

                    last;
                } else {

                    for my $job_id (sort keys %$jobs) {
                        # try to switch the disk if source and destination are on the same guest
                        print "$job_id: Completing block job...\n";

                        my $completion_command;
                        # For blockdev, need to detach appropriate node. QEMU will only drop it if
                        # it was implicitly added (e.g. as the child of a top throttle node), but
                        # not if it was explicitly added via blockdev-add (e.g. as a previous mirror
                        # target).
                        my $detach_node_name;
                        if ($completion eq 'complete') {
                            $completion_command = 'block-job-complete';
                            $detach_node_name = $jobs->{$job_id}->{'source-node-name'};
                        } elsif ($completion eq 'cancel') {
                            $completion_command = 'block-job-cancel';
                            $detach_node_name = $jobs->{$job_id}->{'target-node-name'};
                        } else {
                            die "invalid completion value: $completion\n";
                        }
                        eval { mon_cmd($vmid, $completion_command, device => $job_id) };
                        my $err = $@;
                        if ($err && $err =~ m/cannot be completed/) {
                            print "$job_id: block job cannot be completed, trying again.\n";
                            $err_complete++;
                        } elsif ($err) {
                            die "$job_id: block job cannot be completed - $err\n";
                        } else {
                            $jobs->{$job_id}->{'detach-node-name'} = $detach_node_name
                                if $detach_node_name;

                            print "$job_id: Completed successfully.\n";
                            $jobs->{$job_id}->{complete} = 1;
                        }
                    }
                }
            }
            sleep 1;
        }
    };
    my $err = $@;

    if ($err) {
        eval { qemu_blockjobs_cancel($vmid, $jobs) };
        die "block job ($op) error: $err";
    }
}

my sub common_mirror_qmp_options {
    my ($device_id, $qemu_target, $src_bitmap, $bwlimit) = @_;

    my $opts = {
        timeout => 10,
        device => "$device_id",
        sync => "full",
        target => $qemu_target,
        'auto-dismiss' => JSON::false,
    };

    if (defined($src_bitmap)) {
        $opts->{sync} = 'incremental';
        $opts->{bitmap} = $src_bitmap;
        print "drive mirror re-using dirty bitmap '$src_bitmap'\n";
    }

    if (defined($bwlimit)) {
        $opts->{speed} = $bwlimit * 1024;
        print "drive mirror is starting for $device_id with bandwidth limit: ${bwlimit} KB/s\n";
    } else {
        print "drive mirror is starting for $device_id\n";
    }

    return $opts;
}

sub qemu_drive_mirror {
    my (
        $vmid,
        $drive_id,
        $dst_volid,
        $vmiddst,
        $is_zero_initialized,
        $jobs,
        $completion,
        $qga,
        $bwlimit,
        $src_bitmap,
    ) = @_;

    my $device_id = "drive-$drive_id";

    $jobs = {} if !$jobs;

    my $qemu_target;
    my $format;
    $jobs->{$device_id} = {};

    if ($dst_volid =~ /^nbd:/) {
        $qemu_target = $dst_volid;
        $format = "nbd";
    } else {
        my $storecfg = PVE::Storage::config();

        $format = checked_volume_format($storecfg, $dst_volid);

        my $dst_path = PVE::Storage::path($storecfg, $dst_volid);

        $qemu_target = $is_zero_initialized ? "zeroinit:$dst_path" : $dst_path;
    }

    my $opts = common_mirror_qmp_options($device_id, $qemu_target, $src_bitmap, $bwlimit);
    $opts->{mode} = "existing";
    $opts->{format} = $format if $format;

    # if a job already runs for this device we get an error, catch it for cleanup
    eval { mon_cmd($vmid, "drive-mirror", %$opts); };
    if (my $err = $@) {
        eval { qemu_blockjobs_cancel($vmid, $jobs) };
        warn "$@\n" if $@;
        die "mirroring error: $err\n";
    }

    qemu_drive_mirror_monitor($vmid, $vmiddst, $jobs, $completion, $qga);
}

# Callers should version guard this (only available with a binary >= QEMU 8.2)
sub qemu_drive_mirror_switch_to_active_mode {
    my ($vmid, $jobs) = @_;

    my $switching = {};

    for my $job (sort keys $jobs->%*) {
        print "$job: switching to actively synced mode\n";

        eval {
            mon_cmd(
                $vmid,
                "block-job-change",
                id => $job,
                type => 'mirror',
                'copy-mode' => 'write-blocking',
            );
            $switching->{$job} = 1;
        };
        die "could not switch mirror job $job to active mode - $@\n" if $@;
    }

    while (1) {
        my $stats = mon_cmd($vmid, "query-block-jobs");

        my $running_jobs = {};
        $running_jobs->{ $_->{device} } = $_ for $stats->@*;

        for my $job (sort keys $switching->%*) {
            die "$job: vanished while switching to active mode\n" if !$running_jobs->{$job};

            my $info = $running_jobs->{$job};
            if ($info->{status} eq 'concluded') {
                qemu_handle_concluded_blockjob($vmid, $job, $info, $jobs->{$job});
                # The 'concluded' state should occur here if and only if the job failed, so the
                # 'die' below should be unreachable, but play it safe.
                die "$job: expected job to have failed, but no error was set\n";
            }

            if ($info->{'actively-synced'}) {
                print "$job: successfully switched to actively synced mode\n";
                delete $switching->{$job};
            }
        }

        last if scalar(keys $switching->%*) == 0;

        sleep 1;
    }
}

=pod

=head3 blockdev_mirror

    blockdev_mirror($source, $dest, $jobs, $completion, $options)

Mirrors the volume of a running VM specified by C<$source> to destination C<$dest>.

=over

=item C<$source>: The source information consists of:

=over

=item C<< $source->{vmid} >>: The ID of the running VM the source volume belongs to.

=item C<< $source->{drive} >>: The drive configuration of the source volume as currently attached to
the VM.

=item C<< $source->{bitmap} >>: (optional) Use incremental mirroring based on the specified bitmap.

=back

=item C<$dest>: The destination information consists of:

=over

=item C<< $dest->{volid} >>: The volume ID of the target volume.

=item C<< $dest->{vmid} >>: (optional) The ID of the VM the target volume belongs to. Defaults to
C<< $source->{vmid} >>.

=item C<< $dest->{'zero-initialized'} >>: (optional) True, if the target volume is zero-initialized.

=back

=item C<$jobs>: (optional) Other jobs in the transaction when multiple volumes should be mirrored.
All jobs must be ready before completion can happen.

=item C<$completion>: Completion mode, default is C<complete>:

=over

=item C<complete>: Wait until all jobs are ready, block-job-complete them (default). This means
switching the orignal drive to use the new target.

=item C<cancel>: Wait until all jobs are ready, block-job-cancel them. This means not switching thex
original drive to use the new target.

=item C<skip>: Wait until all jobs are ready, return with block jobs in ready state.

=item C<auto>: Wait until all jobs disappear, only use for jobs which complete automatically.

=back

=item C<$options>: Further options:

=over

=item C<< $options->{'guest-agent'} >>: If the guest agent is configured for the VM. It will be used
to freeze and thaw the filesystems for consistency when the target belongs to a different VM.

=item C<< $options->{'bwlimit'} >>: The bandwidth limit to use for the mirroring operation, in
KiB/s.

=back

=back

=cut

sub blockdev_mirror {
    my ($source, $dest, $jobs, $completion, $options) = @_;

    my $vmid = $source->{vmid};

    my $drive_id = PVE::QemuServer::Drive::get_drive_id($source->{drive});
    my $device_id = "drive-$drive_id";

    my $storecfg = PVE::Storage::config();

    # Need to replace the node below the top node. This is not necessarily a format node, for
    # example, it can also be a zeroinit node by a previous mirror! So query QEMU itself.
    my $source_node_name =
        PVE::QemuServer::Blockdev::get_node_name_below_throttle($vmid, $device_id, 1);

    # Copy original drive config (aio, cache, discard, ...):
    my $dest_drive = dclone($source->{drive});
    delete($dest_drive->{format}); # cannot use the source's format
    $dest_drive->{file} = $dest->{volid};

    # Mirror happens below the throttle filter, so if the target is for the same VM, it will end up
    # below the source's throttle filter, which is inserted for the drive device.
    my $attach_dest_opts = { 'no-throttle' => 1 };
    $attach_dest_opts->{'zero-initialized'} = 1 if $dest->{'zero-initialized'};

    # Source and target need to have the exact same virtual size, see bug #3227.
    # However, it won't be possible to resize a disk with 'size' explicitly set afterwards, so only
    # set it for EFI disks.
    if ($drive_id eq 'efidisk0' && !PVE::QemuServer::Blockdev::is_nbd($dest_drive)) {
        my ($storeid) = PVE::Storage::parse_volume_id($dest_drive->{file}, 1);
        if (
            $storeid
            && PVE::QemuServer::Drive::checked_volume_format($storecfg, $dest->{volid}) eq 'raw'
        ) {
            my $block_info = PVE::QemuServer::Blockdev::get_block_info($vmid);
            if (my $size = $block_info->{$drive_id}->{inserted}->{image}->{'virtual-size'}) {
                $attach_dest_opts->{size} = $size;
            } else {
                log_warn("unable to determine source block node size - continuing anyway");
            }
        }
    }

    # Note that if 'aio' is not explicitly set, i.e. default, it can change if source and target
    # don't both allow or both not allow 'io_uring' as the default.
    my ($target_node_name) =
        PVE::QemuServer::Blockdev::attach($storecfg, $vmid, $dest_drive, $attach_dest_opts);

    $jobs = {} if !$jobs;
    my $jobid = "mirror-$drive_id";
    $jobs->{$jobid} = {
        'source-node-name' => $source_node_name,
        'target-node-name' => $target_node_name,
    };

    my $qmp_opts = common_mirror_qmp_options(
        $device_id, $target_node_name, $source->{bitmap}, $options->{bwlimit},
    );

    $qmp_opts->{'job-id'} = "$jobid";
    $qmp_opts->{replaces} = "$source_node_name";

    # if a job already runs for this device we get an error, catch it for cleanup
    eval { mon_cmd($vmid, "blockdev-mirror", $qmp_opts->%*); };
    if (my $err = $@) {
        eval { qemu_blockjobs_cancel($vmid, $jobs) };
        log_warn("unable to cancel block jobs - $@");
        eval { PVE::QemuServer::Blockdev::detach($vmid, $target_node_name); };
        log_warn("unable to delete blockdev '$target_node_name' - $@");
        die "error starting blockdev mirrror - $err";
    }
    qemu_drive_mirror_monitor(
        $vmid, $dest->{vmid}, $jobs, $completion, $options->{'guest-agent'}, 'mirror',
    );
}

sub mirror {
    my ($source, $dest, $jobs, $completion, $options) = @_;

    # for the switch to -blockdev
    my $machine_type = PVE::QemuServer::Machine::get_current_qemu_machine($source->{vmid});
    if (PVE::QemuServer::Machine::is_machine_version_at_least($machine_type, 10, 0)) {
        blockdev_mirror($source, $dest, $jobs, $completion, $options);
    } else {
        my $drive_id = PVE::QemuServer::Drive::get_drive_id($source->{drive});
        qemu_drive_mirror(
            $source->{vmid},
            $drive_id,
            $dest->{volid},
            $dest->{vmid},
            $dest->{'zero-initialized'},
            $jobs,
            $completion,
            $options->{'guest-agent'},
            $options->{bwlimit},
            $source->{bitmap},
        );
    }
}

1;
