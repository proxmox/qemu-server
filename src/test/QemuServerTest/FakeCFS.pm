package QemuServerTest::FakeCFS;

# Fake cluster filesystem for VM config files, so that tests can use the real config class methods
# of PVE::QemuConfig without pmxcfs.
#
# Configs are kept as raw text, indexed by VMID, and an empty file at the path that config_file()
# returns exists for each, for checks of the file's existence.

use v5.36;

use File::Basename qw(dirname);
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempdir);
use Test::MockModule;

use PVE::GuestHelpers;
use PVE::GuestID;
use PVE::QemuConfig;
use PVE::QemuServer;

our $configs = {}; # VMID => raw config, for VMs on the local node
our $written = {}; # VMID => the written raw configs, in the order of the writes

my $tmpdir = tempdir('fake-cfs-XXXXXX', DIR => '.', CLEANUP => 1);
make_path("$tmpdir/lock");
$PVE::GuestHelpers::lockdir = "$tmpdir/lock";

sub reset() {
    remove_tree("$tmpdir/etc-pve");
    $configs = {};
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

# the list of used guest IDs is not part of the fake cluster filesystem
our $guest_id_module = Test::MockModule->new('PVE::GuestID');
$guest_id_module->mock(register_used_id => sub { return; });

our $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
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
        return 1 if !defined($configs->{$vmid});
        return undef if $noerr;
        die "VM $vmid already exists\n";
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
