#!/usr/bin/perl

# Tests that restoring a legacy tar archive refuses a config with options that the user may not
# set, like the restore paths of the other archive types. Extracting the archive, the storage and
# the cluster filesystem are mocked.

use strict;
use warnings;

use lib qw(..);

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::MockModule;
use Test::More;

use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::RPCEnvironment;
use PVE::Tools qw(file_get_contents file_set_contents);

my $config_dir = tempdir('restore-permission-XXXXXX', DIR => '.', CLEANUP => 1);
make_path("$config_dir/qemu-server");

my $backup_config; # raw config in the archive

my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    cfs_read_file => sub {
        my ($file) = @_;
        return {} if $file eq 'datacenter.cfg';
        die "cfs_read_file (mocked) - unexpected file '$file'\n";
    },
);

my $qemu_config_module = Test::MockModule->new('PVE::QemuConfig');
$qemu_config_module->mock(
    config_file => sub {
        my ($class, $vmid) = @_;
        return "$config_dir/qemu-server/$vmid.conf";
    },
    write_config => sub {
        my ($class, $vmid, $conf) = @_;
        my $path = $class->config_file($vmid);
        file_set_contents($path, PVE::QemuServer::write_vm_config($path, $conf));
    },
);

my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock(config => sub { return {}; });

my $guest_helpers_module = Test::MockModule->new('PVE::GuestHelpers');
$guest_helpers_module->mock(
    check_vnet_access => sub {
        my ($rpcenv, $user, $bridge) = @_;
        die "no 'SDN.Use' on bridge '$bridge'\n" if $bridge ne 'vmbr0';
    },
);

my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
$qemu_server_module->mock(
    rescan => sub { return; },
    tar_archive_read_firstfile => sub { return 'qemu-server.conf'; },
    # like 'tar' with qmextract for an archive without disks
    run_command => sub {
        my ($cmd) = @_;
        die "run_command (mocked) - unexpected command\n"
            if ref($cmd) || $cmd !~ m/^zcat -f\|tar xf /;
        file_set_contents("$ENV{VZDUMP_TMPDIR}/qemu-server.conf", $backup_config);
        return 0;
    },
);

my $rpcenv = PVE::RPCEnvironment->init('cli');

# Restores a tar archive with the raw config $backup to VMID 100 as $user. Returns the error and
# the written config, if any.
sub restore_tar {
    my ($user, $backup) = @_;

    $backup_config = $backup;
    $rpcenv->set_user($user);
    my $conffile = PVE::QemuConfig->config_file(100);
    unlink($conffile);

    my $output = '';
    open(my $out_fh, '>', \$output);
    my $oldfh = select($out_fh);
    eval {
        local *STDERR = $out_fh;
        PVE::QemuServer::restore_tar_archive(
            '/var/lib/vz/dump/vzdump-qemu-100-2025_01_01-00_00_00.tar',
            100,
            $user,
            { override_conf => {} },
        );
    };
    my $err = $@;
    select($oldfh);
    close($out_fh);

    return ($err, -e $conffile ? file_get_contents($conffile) : undef);
}

my $NET0 = 'net0: virtio=BC:24:11:00:00:01';

my $cases = [
    {
        name => 'PCI host device',
        user => 'user@pve',
        backup => "memory: 512\nhostpci0: 0000:01:00.0\n",
        error => "only root can set 'hostpci0' config for non-mapped devices\n",
    },
    {
        name => 'bridge without SDN.Use',
        user => 'user@pve',
        backup => "memory: 512\n$NET0,bridge=vmbr1\n",
        error => "no 'SDN.Use' on bridge 'vmbr1'\n",
    },
    {
        name => 'bridge with SDN.Use',
        user => 'user@pve',
        backup => "memory: 512\n$NET0,bridge=vmbr0\n",
        written => qr/^\Q$NET0\E,bridge=vmbr0$/m,
    },
    {
        name => 'PCI host device and bridge without SDN.Use as root',
        user => 'root@pam',
        backup => "memory: 512\nhostpci0: 0000:01:00.0\n$NET0,bridge=vmbr1\n",
        written => qr/^hostpci0: 0000:01:00\.0$/m,
    },
];

for my $case ($cases->@*) {
    my ($err, $written) = restore_tar($case->{user}, $case->{backup});

    if (my $expected = $case->{error}) {
        is($err, $expected, "$case->{name}: restore refused");
        ok(!defined($written), "$case->{name}: no config written");
    } else {
        is($err, '', "$case->{name}: restore succeeds");
        like($written // '', $case->{written}, "$case->{name}: config written");
    }
}

done_testing();
