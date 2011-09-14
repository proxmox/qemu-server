package PVE::QemuMigrate;

use strict;
use warnings;
use POSIX qw(strftime);
use IO::File;
use IPC::Open2;
use PVE::Tools qw(run_command);
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Cluster;
use PVE::Storage;
use PVE::QemuServer;

my $delayed_interrupt = 0;

# blowfish is a fast block cipher, much faster then 3des
my @ssh_opts = ('-c', 'blowfish', '-o', 'BatchMode=yes');
my @ssh_cmd = ('/usr/bin/ssh', @ssh_opts);
my @scp_cmd = ('/usr/bin/scp', @ssh_opts);
my $qm_cmd = '/usr/sbin/qm';

sub logmsg {
    my ($level, $msg) = @_;

    chomp $msg;

    return if !$msg;

    my $tstr = strftime("%b %d %H:%M:%S", localtime);

    syslog($level, $msg);

    foreach my $line (split (/\n/, $msg)) {
	print STDOUT "$tstr $line\n";
    }
    \*STDOUT->flush();
}

sub eval_int {
    my ($func) = @_;

    eval {
	local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = sub {
	    $delayed_interrupt = 0;
	    logmsg('err', "received interrupt");
	    die "interrupted by signal\n";
	};
	local $SIG{PIPE} = sub {
	    $delayed_interrupt = 0;
	    logmsg('err', "received broken pipe interrupt");
	    die "interrupted by signal\n";
	};

	my $di = $delayed_interrupt;
	$delayed_interrupt = 0;

	die "interrupted by signal\n" if $di;

	&$func();
    };
}

sub fork_command_pipe {
    my ($cmd) = @_;

    my $reader = IO::File->new();
    my $writer = IO::File->new();

    my $orig_pid = $$;

    my $cpid;

    eval { $cpid = open2($reader, $writer, @$cmd); };

    my $err = $@;

    # catch exec errors
    if ($orig_pid != $$) {
	logmsg('err', "can't fork command pipe\n");
	POSIX::_exit(1);
	kill('KILL', $$);
    }

    die $err if $err;

    return { writer => $writer, reader => $reader, pid => $cpid };
}

sub finish_command_pipe {
    my $cmdpipe = shift;

    my $writer = $cmdpipe->{writer};
    my $reader = $cmdpipe->{reader};

    $writer->close();
    $reader->close();

    my $cpid = $cmdpipe->{pid};

    kill(15, $cpid) if kill(0, $cpid);

    waitpid($cpid, 0);
}

sub run_with_timeout {
    my ($timeout, $code, @param) = @_;

    die "got timeout\n" if $timeout <= 0;

    my $prev_alarm;

    my $sigcount = 0;

    my $res;

    eval {
	local $SIG{ALRM} = sub { $sigcount++; die "got timeout\n"; };
	local $SIG{PIPE} = sub { $sigcount++; die "broken pipe\n" };
	local $SIG{__DIE__};   # see SA bug 4631

	$prev_alarm = alarm($timeout);

	$res = &$code(@param);

	alarm(0); # avoid race conditions
    };

    my $err = $@;

    alarm($prev_alarm) if defined($prev_alarm);

    die "unknown error" if $sigcount && !$err; # seems to happen sometimes

    die $err if $err;

    return $res;
}

sub fork_tunnel {
    my ($nodeip, $lport, $rport) = @_;

    my $cmd = [@ssh_cmd, '-o', 'BatchMode=yes',
	       '-L', "$lport:localhost:$rport", $nodeip,
	       'qm', 'mtunnel' ];

    my $tunnel = fork_command_pipe($cmd);

    my $reader = $tunnel->{reader};

    my $helo;
    eval {
	run_with_timeout(60, sub { $helo = <$reader>; });
	die "no reply\n" if !$helo;
	die "no quorum on target node\n" if $helo =~ m/^no quorum$/;
	die "got strange reply from mtunnel ('$helo')\n"
	    if $helo !~ m/^tunnel online$/;
    };
    my $err = $@;

    if ($err) {
	finish_command_pipe($tunnel);
	die "can't open migration tunnel - $err";
    }
    return $tunnel;
}

sub finish_tunnel {
    my $tunnel = shift;

    my $writer = $tunnel->{writer};

    eval {
	run_with_timeout(30, sub {
	    print $writer "quit\n";
	    $writer->flush();
	});
    };
    my $err = $@;

    finish_command_pipe($tunnel);

    die $err if $err;
}

sub migrate {
    my ($node, $nodeip, $vmid, $online, $force) = @_;

    my $starttime = time();

    my $rem_ssh = [@ssh_cmd, "root\@$nodeip"];

    local $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = $SIG{HUP} = $SIG{PIPE} = sub {
	logmsg('err', "received interrupt - delayed");
	$delayed_interrupt = 1;
    };

    local $ENV{RSYNC_RSH} = join(' ', @ssh_cmd);

    my $session = {
	vmid => $vmid,
	node => $node,
	nodeip => $nodeip,
	force => $force,
	storecfg => PVE::Storage::config(),
	rem_ssh => $rem_ssh,
    };
    
    my $errors;

    # lock config during migration
    eval { PVE::QemuServer::lock_config($vmid, sub {

	eval_int(sub { prepare($session); });
	die $@ if $@;

	my $conf = PVE::QemuServer::load_config($vmid);

	PVE::QemuServer::check_lock($conf);

	my $running = 0;
	if (my $pid = PVE::QemuServer::check_running($vmid)) {
	    die "cant migrate running VM without --online\n" if !$online;
	    $running = $pid;
	}

	my $rhash = {};
	eval_int (sub { phase1($session, $conf, $rhash, $running); });
	my $err = $@;

	if ($err) {
	    if ($rhash->{clearlock}) {
		my $unset = { lock => 1 };
		eval { PVE::QemuServer::change_config_nolock($session->{vmid}, {}, $unset, 1) };
		logmsg('err', $@) if $@;
	    }
	    if ($rhash->{volumes}) {
		foreach my $volid (@{$rhash->{volumes}}) {
		    logmsg('err', "found stale volume copy '$volid' on node '$session->{node}'");
		}
	    }
	    die $err;
	}

	# vm is now owned by other node
	my $volids = $rhash->{volumes};

	if ($running) {

	    $rhash = {};
	    eval_int(sub { phase2($session, $conf, $rhash); });
	    my $err = $@;

	    # always kill tunnel
	    if ($rhash->{tunnel}) {
		eval_int(sub { finish_tunnel($rhash->{tunnel}) });
		if ($@) {
		    logmsg('err', "stopping tunnel failed - $@");
		    $errors = 1;
		}
	    }

	    # fixme: ther is no config file, so this will never work
	    # fixme: use kill(9, $running) to make sure it is stopped
	    # always stop local VM - no interrupts possible
	    eval { PVE::QemuServer::vm_stop($session->{vmid}, 1); };
	    if ($@) {
		logmsg('err', "stopping vm failed - $@");
		$errors = 1;
	    }

	    if ($err) {
		$errors = 1;
		logmsg('err', "online migrate failure - $err");
	    }
	}

	# finalize -- clear migrate lock
	eval_int(sub {
	    my $cmd = [ @{$session->{rem_ssh}}, $qm_cmd, 'unlock', $session->{vmid} ];
	    run_command($cmd);
	});
	if ($@) {
	    logmsg('err', "failed to clear migrate lock - $@");
	    $errors = 1;
	}

	# destroy local copies
	foreach my $volid (@$volids) {
	    eval_int(sub { PVE::Storage::vdisk_free($session->{storecfg}, $volid); });
	    my $err = $@;

	    if ($err) {
		logmsg('err', "removing local copy of '$volid' failed - $err");
		$errors = 1;

		last if $err =~ /^interrupted by signal$/;
	    }
	}
    })};

    my $err = $@;

    my $delay = time() - $starttime;
    my $mins = int($delay/60);
    my $secs = $delay - $mins*60;
    my $hours =  int($mins/60);
    $mins = $mins - $hours*60;

    my $duration = sprintf "%02d:%02d:%02d", $hours, $mins, $secs;

    if ($err) {
	my $msg = "migration aborted (duration $duration): $err\n";
	logmsg('err', $msg);
	die $msg;
    }

    if ($errors) {
	my $msg = "migration finished with problems (duration $duration)\n";
	logmsg('err', $msg);
	die $msg;
    }

    logmsg('info', "migration finished successfuly (duration $duration)");
}

sub prepare {
    my ($session) = @_;

    my $conffile = PVE::QemuServer::config_file($session->{vmid});
    die "VM $session->{vmid} does not exist on this node\n" if ! -f $conffile;

    # test ssh connection
    my $cmd = [ @{$session->{rem_ssh}}, '/bin/true' ];
    eval { run_command($cmd); };
    die "Can't connect to destination address using public key\n" if $@;
}

sub sync_disks {
    my ($session, $conf, $rhash, $running) = @_;

    logmsg('info', "copying disk images");

    my $res = [];

    eval {

	my $volhash = {};
	my $cdromhash = {};

	# get list from PVE::Storage (for unused volumes)
	my $dl = PVE::Storage::vdisk_list($session->{storecfg}, undef, $session->{vmid});
	PVE::Storage::foreach_volid($dl, sub {
	    my ($volid, $sid, $volname) = @_;

	    my $scfg =  PVE::Storage::storage_config($session->{storecfg}, $sid);

	    return if $scfg->{shared};

	    $volhash->{$volid} = 1;
	});

	# and add used,owned/non-shared disks (just to be sure we have all)

	my $sharedvm = 1;
	PVE::QemuServer::foreach_drive($conf, sub {
	    my ($ds, $drive) = @_;

	    my $volid = $drive->{file};
	    return if !$volid;

	    die "cant migrate local file/device '$volid'\n" if $volid =~ m|^/|;

	    if (PVE::QemuServer::drive_is_cdrom($drive)) {
		die "cant migrate local cdrom drive\n" if $volid eq 'cdrom';
		return if $volid eq 'none';
		$cdromhash->{$volid} = 1;
	    }

	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);

	    my $scfg =  PVE::Storage::storage_config($session->{storecfg}, $sid);

	    return if $scfg->{shared};

	    die "can't migrate local cdrom '$volid'\n" if $cdromhash->{$volid};

	    $sharedvm = 0;

	    my ($path, $owner) = PVE::Storage::path($session->{storecfg}, $volid);

	    die "can't migrate volume '$volid' - owned by other VM (owner = VM $owner)\n"
		if !$owner || ($owner != $session->{vmid});

	    $volhash->{$volid} = 1;
	});

	if ($running && !$sharedvm) {
	    die "can't do online migration - VM uses local disks\n";
	}

	# do some checks first
	foreach my $volid (keys %$volhash) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    my $scfg =  PVE::Storage::storage_config($session->{storecfg}, $sid);

	    die "can't migrate '$volid' - storagy type '$scfg->{type}' not supported\n"
		if $scfg->{type} ne 'dir';
	}

	foreach my $volid (keys %$volhash) {
	    my ($sid, $volname) = PVE::Storage::parse_volume_id($volid);
	    push @{$rhash->{volumes}}, $volid;
	    PVE::Storage::storage_migrate($session->{storecfg}, $volid, $session->{nodeip}, $sid);
	}
    };
    die "Failed to sync data - $@" if $@;
}

sub phase1 {
    my ($session, $conf, $rhash, $running) = @_;

    logmsg('info', "starting migration of VM $session->{vmid} to node '$session->{node}' ($session->{nodeip})");

    if (my $loc_res = PVE::QemuServer::check_local_resources($conf, 1)) {
	if ($running || !$session->{force}) {
	    die "can't migrate VM which uses local devices\n";
	} else {
	    logmsg('info', "migrating VM which uses local devices");
	}
    }

    # set migrate lock in config file
    $rhash->{clearlock} = 1;

    PVE::QemuServer::change_config_nolock($session->{vmid}, { lock => 'migrate' }, {}, 1);

    sync_disks($session, $conf, $rhash, $running);

    # move config to remote node
    my $conffile = PVE::QemuServer::config_file($session->{vmid});
    my $newconffile = PVE::QemuServer::config_file($session->{vmid}, $session->{node});

    die "Failed to move config to node '$session->{node}' - rename failed: $!\n"
	if !rename($conffile, $newconffile);
};

sub phase2 {
    my ($session, $conf, $rhash) = shift;

    logmsg('info', "starting VM on remote node '$session->{node}'");

    my $rport;

    ## start on remote node
    my $cmd = [@{$session->{rem_ssh}}, $qm_cmd, 'start', 
	       $session->{vmid}, '--stateuri', 'tcp', '--skiplock'];

    run_command($cmd, outfunc => sub {
	my $line = shift;

	if ($line =~ m/^migration listens on port (\d+)$/) {
	    $rport = $1;
	}
    });

    die "unable to detect remote migration port\n" if !$rport;

    logmsg('info', "starting migration tunnel");

    ## create tunnel to remote port
    my $lport = PVE::QemuServer::next_migrate_port();
    $rhash->{tunnel} = fork_tunnel($session->{nodeip}, $lport, $rport);

    logmsg('info', "starting online/live migration");
    # start migration

    my $start = time();

    PVE::QemuServer::vm_monitor_command($session->{vmid}, "migrate -d \"tcp:localhost:$lport\"");

    my $lstat = '';
    while (1) {
	sleep (2);
	my $stat = PVE::QemuServer::vm_monitor_command($session->{vmid}, "info migrate", 1);
	if ($stat =~ m/^Migration status: (active|completed|failed|cancelled)$/im) {
	    my $ms = $1;

	    if ($stat ne $lstat) {
		if ($ms eq 'active') {
		    my ($trans, $rem, $total) = (0, 0, 0);
		    $trans = $1 if $stat =~ m/^transferred ram: (\d+) kbytes$/im;
		    $rem = $1 if $stat =~ m/^remaining ram: (\d+) kbytes$/im;
		    $total = $1 if $stat =~ m/^total ram: (\d+) kbytes$/im;

		    logmsg('info', "migration status: $ms (transferred ${trans}KB, " .
			    "remaining ${rem}KB), total ${total}KB)");
		} else {
		    logmsg('info', "migration status: $ms");
		}
	    }

	    if ($ms eq 'completed') {
		my $delay = time() - $start;
		if ($delay > 0) {
		    my $mbps = sprintf "%.2f", $conf->{memory}/$delay;
		    logmsg('info', "migration speed: $mbps MB/s");
		}
	    }

	    if ($ms eq 'failed' || $ms eq 'cancelled') {
		die "aborting\n"
	    }

	    last if $ms ne 'active';
	} else {
	    die "unable to parse migration status '$stat' - aborting\n";
	}
	$lstat = $stat;
    };
}
