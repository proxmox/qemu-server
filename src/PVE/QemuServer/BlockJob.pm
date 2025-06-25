package PVE::QemuServer::BlockJob;

use strict;
use warnings;

use JSON;

use PVE::Format qw(render_duration render_bytes);
use PVE::RESTEnvironment qw(log_warn);
use PVE::Storage;

use PVE::QemuServer::Agent qw(qga_check_running);
use PVE::QemuServer::Drive qw(checked_volume_format);
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::RunState;

# If the job was started with auto-dismiss=false, it's necessary to dismiss it manually. Using this
# option is useful to get the error for failed jobs here. QEMU's job lock should make it impossible
# to see a job in 'concluded' state when auto-dismiss=true.
# $info is the 'BlockJobInfo' for the job returned by query-block-jobs.
sub qemu_handle_concluded_blockjob {
    my ($vmid, $job_id, $info) = @_;

    eval { mon_cmd($vmid, 'job-dismiss', id => $job_id); };
    log_warn("$job_id: failed to dismiss job - $@") if $@;

    die "$job_id: $info->{error} (io-status: $info->{'io-status'})\n" if $info->{error};
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
                qemu_handle_concluded_blockjob($vmid, $job, $info)
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

                qemu_handle_concluded_blockjob($vmid, $job_id, $job)
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
                        eval { mon_cmd($vmid, "guest-fsfreeze-freeze"); };
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

                        my $op;
                        if ($completion eq 'complete') {
                            $op = 'block-job-complete';
                        } elsif ($completion eq 'cancel') {
                            $op = 'block-job-cancel';
                        } else {
                            die "invalid completion value: $completion\n";
                        }
                        eval { mon_cmd($vmid, $op, device => $job_id) };
                        my $err = $@;
                        if ($err && $err =~ m/cannot be completed/) {
                            print "$job_id: block job cannot be completed, trying again.\n";
                            $err_complete++;
                        } elsif ($err) {
                            die "$job_id: block job cannot be completed - $err\n";
                        } else {
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

sub qemu_drive_mirror {
    my (
        $vmid,
        $drive,
        $dst_volid,
        $vmiddst,
        $is_zero_initialized,
        $jobs,
        $completion,
        $qga,
        $bwlimit,
        $src_bitmap,
    ) = @_;

    $jobs = {} if !$jobs;

    my $qemu_target;
    my $format;
    $jobs->{"drive-$drive"} = {};

    if ($dst_volid =~ /^nbd:/) {
        $qemu_target = $dst_volid;
        $format = "nbd";
    } else {
        my $storecfg = PVE::Storage::config();

        $format = checked_volume_format($storecfg, $dst_volid);

        my $dst_path = PVE::Storage::path($storecfg, $dst_volid);

        $qemu_target = $is_zero_initialized ? "zeroinit:$dst_path" : $dst_path;
    }

    my $opts = {
        timeout => 10,
        device => "drive-$drive",
        mode => "existing",
        sync => "full",
        target => $qemu_target,
        'auto-dismiss' => JSON::false,
    };
    $opts->{format} = $format if $format;

    if (defined($src_bitmap)) {
        $opts->{sync} = 'incremental';
        $opts->{bitmap} = $src_bitmap;
        print "drive mirror re-using dirty bitmap '$src_bitmap'\n";
    }

    if (defined($bwlimit)) {
        $opts->{speed} = $bwlimit * 1024;
        print "drive mirror is starting for drive-$drive with bandwidth limit: ${bwlimit} KB/s\n";
    } else {
        print "drive mirror is starting for drive-$drive\n";
    }

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
                qemu_handle_concluded_blockjob($vmid, $job, $info);
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

sub mirror {
    my ($source, $dest, $jobs, $completion, $options) = @_;

    # for the switch to -blockdev

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

1;
