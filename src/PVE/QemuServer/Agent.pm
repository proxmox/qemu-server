package PVE::QemuServer::Agent;

use v5.36;

use JSON;
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX qw(strftime);
use Time::HiRes qw(time);

use PVE::JSONSchema;

use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;

use base 'Exporter';

our @EXPORT_OK = qw(
    check_agent_error
    agent_cmd
    get_qga_key
    parse_guest_agent
    qga_check_running
);

our $agent_fmt = {
    enabled => {
        description =>
            "Enable/disable communication with a QEMU Guest Agent (QGA) running in the VM.",
        type => 'boolean',
        default => 0,
        default_key => 1,
    },
    fstrim_cloned_disks => {
        description => "Run fstrim after moving a disk or migrating the VM.",
        type => 'boolean',
        optional => 1,
        default => 0,
    },
    # keep for old backup restore compatibility
    'freeze-fs-on-backup' => { alias => 'freeze-fs' },
    # TODO: was only on test repo, drop with PVE 10.
    'guest-fsfreeze' => { alias => 'freeze-fs' },
    'freeze-fs' => {
        description => "Freeze guest filesystems through QGA for consistent disk state on"
            . " operations such as snapshots, backups, replications and clones.",
        verbose_description =>
            "Whether to issue the guest-fsfreeze-freeze and guest-fsfreeze-thaw QEMU guest agent"
            . " commands. Backups in snapshot mode, clones, snapshots without RAM, importing"
            . " disks from a running guest, and replications normally issue a guest-fsfreeze-freeze"
            . " and a respective thaw command when the QEMU Guest agent option is enabled in the"
            . " guest's configuration and the agent is running inside of the guest.\n\nThe deprecated"
            . " 'freeze-fs-on-backup' setting is treated as an alias for this setting.",
        type => 'boolean',
        optional => 1,
        default => 1,
    },
    # FIXME: MAJOR VERSION: reconsider enabling this option by default
    'sync-time-on-resume' => {
        description =>
            "Synchronize the guest's clock through QGA after operations that can leave"
            . " the guest's clock behind.",
        verbose_description =>
            "Whether to issue the 'guest-set-time' QEMU guest agent command to synchronize the"
            . " guest's clock to the host's current time after operations that can leave the"
            . " guest's clock behind. This happens when resuming from hibernation, resuming from a"
            . " paused state, taking a snapshot, after a live migration, after a backup in suspend"
            . " mode, and after rolling back to a snapshot that includes RAM. In these cases the"
            . " guest's clock may still reflect an earlier time. The time is only synchronized"
            . " when the QEMU Guest Agent option is enabled in the guest's configuration and the"
            . " agent is running inside of the guest. For resume, hibernation resume and snapshot"
            . " rollback, the synchronization can be overridden per operation.",
        type => 'boolean',
        optional => 1,
        default => 0,
    },
    type => {
        description => "Select the agent type",
        type => 'string',
        default => 'virtio',
        optional => 1,
        enum => [qw(virtio isa)],
    },
};

sub parse_guest_agent($value) {
    return {} if !defined($value);

    my $res = eval { PVE::JSONSchema::parse_property_string($agent_fmt, $value) };
    warn $@ if $@;

    # if the agent is disabled ignore the other potentially set properties
    return {} if !$res->{enabled};
    return $res;
}

sub get_qga_key($conf, $key) {
    return undef if !defined($conf->{agent});

    my $agent = parse_guest_agent($conf->{agent});
    return $agent->{$key};
}

sub qga_check_running($vmid, $nowarn = 0) {
    eval { PVE::QemuServer::Monitor::mon_cmd($vmid, "guest-ping", timeout => 3); };
    if ($@) {
        warn "QEMU Guest Agent is not running - $@" if !$nowarn;
        return 0;
    }
    return 1;
}

sub check_agent_error($result, $errmsg, $noerr = 0) {
    my $error = '';
    if (ref($result) eq 'HASH' && $result->{error} && $result->{error}->{desc}) {
        $error = "Agent error: $result->{error}->{desc}\n";
    } elsif (!defined($result)) {
        $error = "Agent error: $errmsg\n";
    }

    if ($error) {
        die $error if !$noerr;

        warn $error;
        return;
    }

    return 1;
}

sub assert_agent_available($vmid, $conf) {
    die "No QEMU guest agent configured\n" if !defined($conf->{agent});
    die "VM $vmid is not running\n" if !PVE::QemuServer::Helpers::vm_running_locally($vmid);
    die "QEMU guest agent is not running\n" if !qga_check_running($vmid, 1);
}

# loads config, checks if available, executes command, checks for errors
sub agent_cmd($vmid, $conf, $cmd, $params, $errormsg) {
    assert_agent_available($vmid, $conf);

    my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, "guest-$cmd", %$params);
    check_agent_error($res, $errormsg);

    return $res;
}

sub qemu_exec($vmid, $conf, $input_data, $cmd) {
    my $args = {
        'capture-output' => JSON::true,
    };

    if ($cmd) {
        $args->{path} = shift @$cmd;
        $args->{arg} = $cmd;
    }

    $args->{'input-data'} = encode_base64($input_data, '') if defined($input_data);

    die "command or input-data (or both) required\n"
        if !defined($args->{'input-data'}) && !defined($args->{path});

    my $errmsg = "can't execute command";
    if ($cmd) {
        $errmsg .= " ($args->{path} $args->{arg})";
    }
    if (defined($input_data)) {
        $errmsg .= " (input-data given)";
    }

    my $res = agent_cmd($vmid, $conf, "exec", $args, $errmsg);

    return $res;
}

sub qemu_exec_status($vmid, $conf, $pid) {
    my $res =
        agent_cmd($vmid, $conf, "exec-status", { pid => $pid }, "can't get exec status for '$pid'");

    if ($res->{'out-data'}) {
        my $decoded = eval { decode_base64($res->{'out-data'}) };
        warn $@ if $@;
        if (defined($decoded)) {
            $res->{'out-data'} = $decoded;
        }
    }

    if ($res->{'err-data'}) {
        my $decoded = eval { decode_base64($res->{'err-data'}) };
        warn $@ if $@;
        if (defined($decoded)) {
            $res->{'err-data'} = $decoded;
        }
    }

    # convert JSON::Boolean to 1/0
    foreach my $d (keys %$res) {
        if (JSON::is_bool($res->{$d})) {
            $res->{$d} = ($res->{$d}) ? 1 : 0;
        }
    }

    return $res;
}

=head3 should_fs_freeze

Returns whether guest filesystem freeze/thaw should be attempted based on the agent configuration.
Does B<not> check whether the agent is actually running.

=cut

sub should_fs_freeze($agent_str) {
    my $agent = parse_guest_agent($agent_str);
    return 0 if !$agent->{enabled};
    return $agent->{'freeze-fs'} // 1;
}

=head3 guest_fs_freeze

    guest_fs_freeze($vmid);

Freeze the file systems of the guest C<$vmid>. Check that the guest agent is enabled and running
before calling this function. Dies if the file systems cannot be frozen.

With C<mon_cmd()>, it can happen that a guest agent command is read, but then the guest agent never
sends an answer, because the service in the guest is stopped/killed. For example, if a guest reboot
happens before the command can be successfully executed. This is usually not problematic, but the
fsfreeze-freeze command should use a timeout of 1 hour, so the guest agent socket would be blocked
for that amount of time, waiting on a command that is not being executed anymore.

This function uses a lower timeout for the initial fsfreeze-freeze command, and issues an
fsfreeze-status command afterwards, which will return immediately if the fsfreeze-freeze command
already finished, and which will be queued if not. This is used as a proxy to determine whether the
fsfreeze-freeze command is still running and to check whether it was successful. Using a too low
timeout would mean stuffing/queuing many fsfreeze-status commands while the guest agent might still
be busy actually doing the freeze. In total, fsfreeze-freeze is still allowed to take 1 hour, but
the time the socket is blocked after a lost command is at most 10 minutes.

=cut

sub guest_fs_freeze($vmid) {
    my $timeout = 10 * 60;

    my $result = eval {
        PVE::QemuServer::Monitor::mon_cmd($vmid, 'guest-fsfreeze-freeze', timeout => $timeout);
    };
    if ($result && ref($result) eq 'HASH' && $result->{error}) {
        my $error = $result->{error}->{desc} // 'unknown';
        die "unable to freeze guest fs - $error\n";
    } elsif (defined($result)) {
        return; # command successful
    }

    my $status;
    eval {
        my ($i, $last_iteration) = (0, 5);
        while ($i < $last_iteration && !defined($status)) {
            print "still waiting on guest fs freeze - timeout in "
                . ($timeout * ($last_iteration - $i) / 60)
                . " minutes\n";
            $i++;

            $status = PVE::QemuServer::Monitor::mon_cmd(
                $vmid, 'guest-fsfreeze-status',
                timeout => $timeout,
                noerr => 1,
            );

            if ($status && ref($status) eq 'HASH' && $status->{'error-is-timeout'}) {
                $status = undef;
            } else {
                check_agent_error($status, 'unknown error');
            }
        }
        if (!defined($status)) {
            die "timeout after " . ($timeout * ($last_iteration + 1) / 60) . " minutes\n";
        }
    };
    die "querying status after freezing guest fs failed - $@" if $@;

    die "unable to freeze guest fs - unexpected status '$status'\n" if $status ne 'frozen';
}

=head3 guest_fs_thaw

    guest_fs_thaw($vmid);

Thaws the file systems of the guest C<$vmid>. Dies if the file systems cannot be thawed.

If the thaw fails and the guest still reports its file systems as frozen, the thaw is retried once.

See C<guest_fs_freeze()> for more details.

=cut

sub guest_fs_thaw($vmid) {
    my $thaw = sub {
        my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, "guest-fsfreeze-thaw");
        check_agent_error($res, "unable to thaw guest filesystem");
    };

    eval { $thaw->() };
    my $err = $@;
    return if !$err;

    # A failed thaw can leave the guest frozen, for example, if the connection is closed with the
    # command still unsent. Later jobs skip freeze and thaw for a guest reported as frozen, so retry.
    die $err if !eval { guest_fs_is_frozen($vmid) };

    chomp($err);
    print "thawing guest filesystem failed - $err\n";
    print "guest filesystem is still frozen, trying to thaw it again\n";
    $thaw->();

    return;
}

=head3 guest_fs_is_frozen

    if (guest_fs_is_frozen($vmid)) {
        print "skipping guest fs freeze - already frozen\n";
    }

Check if the file systems of the guest C<$vmid> is currently frozen.

=cut

sub guest_fs_is_frozen($vmid) {
    my $status = PVE::QemuServer::Monitor::mon_cmd($vmid, "guest-fsfreeze-status");
    check_agent_error($status, "unable to check guest filesystem freeze status");

    return $status eq 'frozen';
}

=head3 guest_fs_freeze_applicable

    if (guest_fs_freeze_applicable($agent_str, $vmid, $logfunc)) {
        guest_fs_freeze($vmid);
    }

Check if the file systems of the guest C<$vmid> should be frozen according to the guest agent
property string C<$agent_str> and if freezing is actionable in practice, i.e. guest agent running
and file system not already frozen. Logs a message if skipped. Using a custom log function via
C<$logfunc> is supported. Otherwise, C<print()> and C<warn()> will be used.

=cut

sub guest_fs_freeze_applicable($agent_str, $vmid, $logfunc = undef) {
    $logfunc //= sub($msg, $level = 'info') {
        $level eq 'info' ? print("$msg\n") : warn("$msg\n");
    };

    if (!should_fs_freeze($agent_str)) {
        $logfunc->("skipping guest filesystem freeze - disabled in VM options");
        return;
    }

    if (!qga_check_running($vmid, 1)) {
        $logfunc->("skipping guest filesystem freeze - agent configured but not running?");
        return;
    }

    my $frozen = eval { PVE::QemuServer::Agent::guest_fs_is_frozen($vmid) };
    $logfunc->("unable to check guest fs freeze status - $@", 'warn') if $@;

    if ($frozen) {
        $logfunc->("skipping guest filesystem freeze - already frozen");
        return;
    }

    return 1;
}

=head3 should_sync_time_on_resume

Returns whether the guest's clock should be synchronized to the host's via the QEMU Guest Agent
after operations that can leave the guest's clock behind. Returns 0 if the agent is not enabled. An
explicit C<$override> (from an API parameter) takes precedence over the C<sync-time-on-resume> agent
config property when defined; otherwise the config value is used (defaulting to off). Does B<not>
check whether the agent is actually running.

=cut

sub should_sync_time_on_resume($agent_str, $override = undef) {
    my $agent = parse_guest_agent($agent_str);
    return 0 if !$agent->{enabled};
    return $override ? 1 : 0 if defined($override);
    return $agent->{'sync-time-on-resume'} // 0;
}

=head3 guest_set_time

Sets the guest's clock to the current host time via the QEMU Guest Agent's C<guest-set-time>
command. The host time is passed explicitly (as nanoseconds since the UNIX epoch) because the
argument-less form reads the time from the guest's RTC, which isn't supported on all platforms
(e.g. Windows); passing the value directly works regardless of guest OS.

Returns 1 if the time was set, 0 if it was skipped because the agent is not running. Dies if the
agent returns an error.

=cut

sub guest_set_time($vmid, $quiet = undef) {
    if (!qga_check_running($vmid, 1)) {
        print "skipping guest time sync - agent configured but not running?\n" if !$quiet;
        return 0;
    }
    my $time_ns = time() * 1_000_000_000;
    my $res = PVE::QemuServer::Monitor::mon_cmd($vmid, 'guest-set-time', time => int($time_ns));
    check_agent_error($res, "unable to set guest time");
    my $time_str = strftime("%F %T", localtime($time_ns / 1_000_000_000));
    print "synced guest clock via guest agent to $time_str\n" if !$quiet;
    return 1;
}

1;
