package PVE::QemuServer::Helpers;

use strict;
use warnings;

use File::stat;
use JSON;

use PVE::INotify;
use PVE::ProcFSTools;

use base 'Exporter';
our @EXPORT_OK = qw(
min_version
config_aware_timeout
parse_number_sets
windows_version
);

my $nodename = PVE::INotify::nodename();

# Paths and directories

our $var_run_tmpdir = "/var/run/qemu-server";
mkdir $var_run_tmpdir;

sub qmp_socket {
    my ($vmid, $qga) = @_;
    my $sockettype = $qga ? 'qga' : 'qmp';
    return "${var_run_tmpdir}/$vmid.$sockettype";
}

sub pidfile_name {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.pid";
}

sub vnc_socket {
    my ($vmid) = @_;
    return "${var_run_tmpdir}/$vmid.vnc";
}

# Parse the cmdline of a running kvm/qemu process and return arguments as hash
sub parse_cmdline {
    my ($pid) = @_;

    my $fh = IO::File->new("/proc/$pid/cmdline", "r");
    if (defined($fh)) {
	my $line = <$fh>;
	$fh->close;
	return if !$line;
	my @param = split(/\0/, $line);

	my $cmd = $param[0];
	return if !$cmd || ($cmd !~ m|kvm$| && $cmd !~ m@(?:^|/)qemu-system-[^/]+$@);

	my $phash = {};
	my $pending_cmd;
	for (my $i = 0; $i < scalar (@param); $i++) {
	    my $p = $param[$i];
	    next if !$p;

	    if ($p =~ m/^--?(.*)$/) {
		if ($pending_cmd) {
		    $phash->{$pending_cmd} = {};
		}
		$pending_cmd = $1;
	    } elsif ($pending_cmd) {
		$phash->{$pending_cmd} = { value => $p };
		$pending_cmd = undef;
	    }
	}

	return $phash;
    }
    return;
}

sub vm_running_locally {
    my ($vmid) = @_;

    my $pidfile = pidfile_name($vmid);

    if (my $fd = IO::File->new("<$pidfile")) {
	my $st = stat($fd);
	my $line = <$fd>;
	close($fd);

	my $mtime = $st->mtime;
	if ($mtime > time()) {
	    warn "file '$pidfile' modified in future\n";
	}

	if ($line =~ m/^(\d+)$/) {
	    my $pid = $1;
	    my $cmdline = parse_cmdline($pid);
	    if ($cmdline && defined($cmdline->{pidfile}) && $cmdline->{pidfile}->{value}
		&& $cmdline->{pidfile}->{value} eq $pidfile) {
		if (my $pinfo = PVE::ProcFSTools::check_process_running($pid)) {
		    return $pid;
		}
	    }
	}
    }

    return;
}

sub min_version {
    my ($verstr, $major, $minor, $pve) = @_;

    if ($verstr =~ m/^(\d+)\.(\d+)(?:\.(\d+))?(?:\+pve(\d+))?/) {
	return 1 if version_cmp($1, $major, $2, $minor, $4, $pve) >= 0;
	return 0;
    }

    die "internal error: cannot check version of invalid string '$verstr'";
}

# gets in pairs the versions you want to compares, i.e.:
# ($a-major, $b-major, $a-minor, $b-minor, $a-extra, $b-extra, ...)
# returns 0 if same, -1 if $a is older than $b, +1 if $a is newer than $b
sub version_cmp {
    my @versions = @_;

    my $size = scalar(@versions);

    return 0 if $size == 0;

    if ($size & 1) {
	my (undef, $fn, $line) = caller(0);
	die "cannot compare odd count of versions, called from $fn:$line\n";
    }

    for (my $i = 0; $i < $size; $i += 2) {
	my ($a, $b) = splice(@versions, 0, 2);
	$a //= 0;
	$b //= 0;

	return 1 if $a > $b;
	return -1 if $a < $b;
    }
    return 0;
}

sub config_aware_timeout {
    my ($config, $memory, $is_suspended) = @_;
    my $timeout = 30;

    # Based on user reported startup time for vm with 512GiB @ 4-5 minutes
    if (defined($memory) && $memory > 30720) {
	$timeout = int($memory/1024);
    }

    # When using PCI passthrough, users reported much higher startup times,
    # growing with the amount of memory configured. Constant factor chosen
    # based on user reports.
    if (grep(/^hostpci[0-9]+$/, keys %$config)) {
	$timeout *= 4;
    }

    if ($is_suspended && $timeout < 300) {
	$timeout = 300;
    }

    if ($config->{hugepages} && $timeout < 150) {
	$timeout = 150;
    }

    # Some testing showed that adding a NIC increased the start time by ~450ms
    # consistently across different NIC models, options and already existing
    # number of NICs.
    # So 10x that to account for any potential system differences seemed
    # reasonable. User reports with real-life values (20+: ~50s, 25: 45s, 17: 42s)
    # also make this seem a good value.
    my $nic_count = scalar (grep { /^net\d+/ } keys %{$config});
    $timeout += $nic_count * 5;

    return $timeout;
}

sub get_node_pvecfg_version {
    my ($node) = @_;

    my $nodes_version_info = PVE::Cluster::get_node_kv('version-info', $node);
    return if !$nodes_version_info->{$node};

    my $version_info = decode_json($nodes_version_info->{$node});
    return $version_info->{version};
}

sub pvecfg_min_version {
    my ($verstr, $major, $minor, $release) = @_;

    return 0 if !$verstr;

    if ($verstr =~ m/^(\d+)\.(\d+)(?:[.-](\d+))?/) {
	return 1 if version_cmp($1, $major, $2, $minor, $3 // 0, $release) >= 0;
	return 0;
    }

    die "internal error: cannot check version of invalid string '$verstr'";
}

sub parse_number_sets {
    my ($set) = @_;
    my $res = [];
    foreach my $part (split(/;/, $set)) {
	if ($part =~ /^\s*(\d+)(?:-(\d+))?\s*$/) {
	    die "invalid range: $part ($2 < $1)\n" if defined($2) && $2 < $1;
	    push @$res, [ $1, $2 ];
	} else {
	    die "invalid range: $part\n";
	}
    }
    return $res;
}

sub windows_version {
    my ($ostype) = @_;

    return 0 if !$ostype;

    my $winversion = 0;

    if($ostype eq 'wxp' || $ostype eq 'w2k3' || $ostype eq 'w2k') {
        $winversion = 5;
    } elsif($ostype eq 'w2k8' || $ostype eq 'wvista') {
        $winversion = 6;
    } elsif ($ostype =~ m/^win(\d+)$/) {
        $winversion = $1;
    }

    return $winversion;
}

sub needs_extraction {
    my ($vtype, $fmt) = @_;
    return $vtype eq 'import' && $fmt =~ m/^ova\+(.*)$/;
}

1;
