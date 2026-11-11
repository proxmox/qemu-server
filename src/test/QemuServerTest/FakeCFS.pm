package QemuServerTest::FakeCFS;

# Fake cluster filesystem for VM config files, so that tests can use the real config class methods
# of PVE::QemuConfig, including the guest identity handling of write_config, without pmxcfs.
#
# Configs are kept as raw text, indexed by VMID, and an empty file at the path that config_file()
# returns exists for each, for checks of the file's existence. Generated guest identities are
# deterministic: the n-th generated uid is 'a' repeated 17 times followed by the base32 encoding of
# n, and rtime is $now_ms.

use v5.36;

use File::Basename qw(dirname);
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempdir);
use Test::MockModule;

use PVE::GuestHelpers;
use PVE::GuestID;
use PVE::GuestIdentity;
use PVE::QemuConfig;
use PVE::QemuServer;

our $configs = {}; # VMID => raw config, for VMs on the local node
our $other_guests = {}; # VMID => raw 'meta' property of other guests, like on other nodes or CTs
our $now_ms = 1700000000000;
our $generated = 0;
our $lock_domain_error;
our $written = {}; # VMID => the written raw configs, in the order of the writes

my $tmpdir = tempdir('fake-cfs-XXXXXX', DIR => '.', CLEANUP => 1);
make_path("$tmpdir/lock");
$PVE::GuestHelpers::lockdir = "$tmpdir/lock";

sub reset() {
    remove_tree("$tmpdir/etc-pve");
    $configs = {};
    $other_guests = {};
    $now_ms = 1700000000000;
    $generated = 0;
    $lock_domain_error = undef;
    $written = {};
}

my sub vmid_of_path($path) {
    return $path =~ m|/qemu-server/(\d+)\.conf$| ? $1 : undef;
}

# Creates or removes the file at the path of the config of $vmid, matching the stored config.
my sub sync_config_file($vmid) {
    my $path = PVE::QemuConfig->config_file($vmid);
    if (defined($configs->{$vmid})) {
        make_path(dirname($path));
        open(my $fh, '>', $path) or die "unable to create '$path' - $!\n";
        close($fh);
    } else {
        unlink($path);
    }
}

# Stores the raw config $raw for $vmid, like a manual edit of the config file.
sub set_config($vmid, $raw) {
    $configs->{$vmid} = $raw;
    sync_config_file($vmid);
}

# Returns the last 'meta' property of the top-level section of the raw config $raw, like the config
# class reads the stored identity.
my sub top_level_meta($raw) {
    my $meta;
    for my $line (split(/\n/, $raw // '')) {
        last if $line =~ m/^\[/;
        # like pmxcfs, a line with nothing after the colon does not count
        $meta = $1 =~ s/^\s+|\s+$//gr if $line =~ m/^meta:(.+)$/;
    }

    return $meta;
}

# Returns the identity stored in the raw config of $vmid, undef if there is none.
sub stored_identity($vmid) {
    return PVE::GuestIdentity::parse_identity(top_level_meta($configs->{$vmid}));
}

# Returns the uid that the $n-th generation of an identity yields.
sub generated_uid($n) {
    my $alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    return ('a' x 17) . join('', map { substr($alphabet, ($n >> (5 * $_)) & 31, 1) } (2, 1, 0));
}

# the list of used guest IDs is not part of the fake cluster filesystem
our $guest_id_module = Test::MockModule->new('PVE::GuestID');
$guest_id_module->mock(register_used_id => sub { return; });

our $guest_identity_module = Test::MockModule->new('PVE::GuestIdentity');
$guest_identity_module->mock(
    __random_bytes => sub {
        my ($len) = @_;
        die "unexpected length $len\n" if $len != 20;
        $generated++;
        # one byte per uid character, the last three hold 5 bits of the counter each
        return ("\0" x 17) . pack('C3', map { ($generated >> $_) & 31 } (10, 5, 0));
    },
    __time_ms => sub {
        return $now_ms;
    },
);

our $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    get_config => sub {
        my ($path) = @_;
        my $vmid = vmid_of_path($path) // die "get_config (mocked) - unexpected path '$path'\n";
        return $configs->{$vmid};
    },
    cfs_read_file => sub {
        my ($path) = @_;
        return {} if $path eq 'datacenter.cfg';
        my $vmid = vmid_of_path($path)
            // die "cfs_read_file (mocked) - unexpected path '$path'\n";
        return PVE::QemuServer::parse_vm_config($path, $configs->{$vmid});
    },
    cfs_write_file => sub {
        my ($path, $conf) = @_;
        my $vmid = vmid_of_path($path)
            // die "cfs_write_file (mocked) - unexpected path '$path'\n";
        $configs->{$vmid} = PVE::QemuServer::write_vm_config($path, $conf);
        sync_config_file($vmid);
        push $written->{$vmid}->@*, $configs->{$vmid};
        return;
    },
    cfs_update => sub {
        return;
    },
    check_vmid_unused => sub {
        my ($vmid, $noerr) = @_;
        return 1 if !defined($configs->{$vmid}) && !defined($other_guests->{$vmid});
        return undef if $noerr;
        die "VM $vmid already exists\n";
    },
    cfs_lock_domain => sub {
        my ($domain, $timeout, $code, @param) = @_;
        die "cfs_lock_domain (mocked) - unexpected domain '$domain'\n"
            if $domain ne 'guest-identity';
        if ($lock_domain_error) {
            $@ = $lock_domain_error;
            return undef;
        }
        my $res = eval { $code->(@param) };
        return $res;
    },
    get_guest_config_properties => sub {
        my ($properties) = @_;
        die "get_guest_config_properties (mocked) - unexpected properties\n"
            if join(',', $properties->@*) ne 'meta';

        my $res = {};
        for my $vmid (keys $configs->%*) {
            my $meta = top_level_meta($configs->{$vmid});
            $res->{$vmid} = { meta => $meta } if defined($meta);
        }
        $res->{$_} = { meta => $other_guests->{$_} } for keys $other_guests->%*;
        return $res;
    },
);

our $qemu_config_module = Test::MockModule->new('PVE::QemuConfig');
$qemu_config_module->mock(
    config_file => sub {
        my ($class, $vmid, $node) = @_;
        return "$tmpdir/etc-pve/" . $class->cfs_config_path($vmid, $node);
    },
    config_file_lock => sub {
        my ($class, $vmid) = @_;
        return "$tmpdir/lock/lock-$vmid.conf";
    },
    destroy_config => sub {
        my ($class, $vmid) = @_;
        die "failed to remove config file: No such file or directory\n"
            if !defined($configs->{$vmid});
        delete $configs->{$vmid};
        sync_config_file($vmid);
    },
);

1;
