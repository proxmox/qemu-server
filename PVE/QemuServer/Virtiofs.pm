package PVE::QemuServer::Virtiofs;

use strict;
use warnings;

use Fcntl qw(F_GETFD F_SETFD FD_CLOEXEC);
use IO::Socket::UNIX;
use POSIX;
use Socket qw(SOCK_STREAM);

use PVE::JSONSchema qw(parse_property_string);
use PVE::Mapping::Dir;
use PVE::QemuServer::Helpers;
use PVE::RESTEnvironment qw(log_warn);

use base qw(Exporter);

our @EXPORT_OK = qw(
max_virtiofs
start_all_virtiofsd
);

my $MAX_VIRTIOFS = 10;
my $socket_path_root = "/run/qemu-server/virtiofsd";

my $virtiofs_fmt = {
    'dirid' => {
	type => 'string',
	default_key => 1,
	description => "Mapping identifier of the directory mapping to be shared with the guest."
	    ." Also used as a mount tag inside the VM.",
	format_description => 'mapping-id',
	format => 'pve-configid',
    },
    'cache' => {
	type => 'string',
	description => "The caching policy the file system should use (auto, always, metadata, never).",
	enum => [qw(auto always metadata never)],
	default => "auto",
	optional => 1,
    },
    'direct-io' => {
	type => 'boolean',
	description => "Honor the O_DIRECT flag passed down by guest applications.",
	default => 0,
	optional => 1,
    },
    'expose-xattr' => {
	type => 'boolean',
	description => "Enable support for extended attributes for this mount.",
	default => 0,
	optional => 1,
    },
    'expose-acl' => {
	type => 'boolean',
	description => "Enable support for POSIX ACLs (enabled ACL implies xattr) for this mount.",
	default => 0,
	optional => 1,
    },
};
PVE::JSONSchema::register_format('pve-qm-virtiofs', $virtiofs_fmt);

my $virtiofsdesc = {
    optional => 1,
    type => 'string', format => $virtiofs_fmt,
    description => "Configuration for sharing a directory between host and guest using Virtio-fs.",
};
PVE::JSONSchema::register_standard_option("pve-qm-virtiofs", $virtiofsdesc);

sub max_virtiofs {
    return $MAX_VIRTIOFS;
}

sub assert_virtiofs_config {
    my ($ostype, $virtiofs) = @_;

    my $dir_cfg = PVE::Mapping::Dir::find_on_current_node($virtiofs->{dirid});

    my $acl = $virtiofs->{'expose-acl'};
    if ($acl && PVE::QemuServer::Helpers::windows_version($ostype)) {
	die "Please disable ACLs for virtiofs on Windows VMs, otherwise"
	    ." the virtiofs shared directory cannot be mounted.\n";
    }

    eval { PVE::Mapping::Dir::assert_valid($dir_cfg) };
    die "directory mapping invalid: $@\n" if $@;
}

sub config {
    my ($conf, $vmid, $devices) = @_;

    for (my $i = 0; $i < max_virtiofs(); $i++) {
	my $opt = "virtiofs$i";

	next if !$conf->{$opt};
	my $virtiofs = parse_property_string('pve-qm-virtiofs', $conf->{$opt});

	assert_virtiofs_config($conf->{ostype}, $virtiofs);

	push @$devices, '-chardev', "socket,id=virtiofs$i,path=$socket_path_root/vm$vmid-fs$i";

	# queue-size is set 1024 because of bug with Windows guests:
	# https://bugzilla.redhat.com/show_bug.cgi?id=1873088
	# 1024 is also always used in the virtiofs documentations:
	# https://gitlab.com/virtio-fs/virtiofsd#examples
	push @$devices, '-device', 'vhost-user-fs-pci,queue-size=1024'
	    .",chardev=virtiofs$i,tag=$virtiofs->{dirid}";
    }
}

sub virtiofs_enabled {
    my ($conf) = @_;

    my $virtiofs_enabled = 0;
    for (my $i = 0; $i < max_virtiofs(); $i++) {
	my $opt = "virtiofs$i";
	next if !$conf->{$opt};
	parse_property_string('pve-qm-virtiofs', $conf->{$opt});
	$virtiofs_enabled = 1;
    }
    return $virtiofs_enabled;
}

sub start_all_virtiofsd {
    my ($conf, $vmid) = @_;
    my $virtiofs_sockets = [];
    for (my $i = 0; $i < max_virtiofs(); $i++) {
	my $opt = "virtiofs$i";

	next if !$conf->{$opt};
	my $virtiofs = parse_property_string('pve-qm-virtiofs', $conf->{$opt});

	my $virtiofs_socket = start_virtiofsd($vmid, $i, $virtiofs);
	push @$virtiofs_sockets, $virtiofs_socket;
    }
    return $virtiofs_sockets;
}

sub start_virtiofsd {
    my ($vmid, $fsid, $virtiofs) = @_;

    mkdir $socket_path_root;
    my $socket_path = "$socket_path_root/vm$vmid-fs$fsid";
    unlink($socket_path);
    my $socket = IO::Socket::UNIX->new(
	Type => SOCK_STREAM,
	Local => $socket_path,
	Listen => 1,
    ) or die "cannot create socket - $!\n";

    my $flags = fcntl($socket, F_GETFD, 0)
	or die "failed to get file descriptor flags: $!\n";
    fcntl($socket, F_SETFD, $flags & ~FD_CLOEXEC)
	or die "failed to remove FD_CLOEXEC from file descriptor\n";

    my $dir_cfg = PVE::Mapping::Dir::find_on_current_node($virtiofs->{dirid});

    my $virtiofsd_bin = '/usr/libexec/virtiofsd';
    if (! -f $virtiofsd_bin) {
	die "virtiofsd is not installed. To use virtio-fs, install virtiofsd via apt.\n";
    }
    my $fd = $socket->fileno();
    my $path = $dir_cfg->{path};

    my $could_not_fork_err = "could not fork to start virtiofsd\n";
    my $pid = fork();
    if ($pid == 0) {
	POSIX::setsid();
	$0 = "task pve-vm$vmid-virtiofs$fsid";
	my $pid2 = fork();
	if ($pid2 == 0) {
	    my $cmd = [$virtiofsd_bin, "--fd=$fd", "--shared-dir=$path"];
	    push @$cmd, '--xattr' if $virtiofs->{'expose-xattr'};
	    push @$cmd, '--posix-acl' if $virtiofs->{'expose-acl'};
	    push @$cmd, '--announce-submounts';
	    push @$cmd, '--allow-direct-io' if $virtiofs->{'direct-io'};
	    push @$cmd, '--cache='.$virtiofs->{cache} if $virtiofs->{cache};
	    push @$cmd, '--syslog';
	    exec(@$cmd);
	} elsif (!defined($pid2)) {
	    die $could_not_fork_err;
	} else {
	    POSIX::_exit(0);
	}
    } elsif (!defined($pid)) {
	die $could_not_fork_err;
    } else {
	waitpid($pid, 0);
    }

    # return socket to keep it alive,
    # so that QEMU will wait for virtiofsd to start
    return $socket;
}

sub close_sockets {
    my @sockets = @_;
    for my $socket (@sockets) {
	shutdown($socket, 2);
	close($socket);
    }
}

1;
