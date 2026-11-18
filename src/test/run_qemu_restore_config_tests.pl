#!/usr/bin/perl

use strict;
use warnings;

use lib qw(.. .);

use Fcntl qw(O_RDONLY O_NONBLOCK);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON;
use Test::MockModule;
use Test::More;

use File::Basename;

use PVE::API2::Qemu;
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Helpers;
use PVE::RPCEnvironment;
use PVE::Tools qw(dir_glob_foreach file_get_contents file_set_contents);

# also provides the 'datacenter.cfg' that restore_update_config_line reads
use QemuServerTest::FakeCFS;
use QemuServerTest::Utils qw(capture_output);

my $INPUT_DIR = './restore-config-input';
my $EXPECTED_DIR = './restore-config-expected';

dir_glob_foreach(
    './restore-config-input',
    '[0-9]+.conf',
    sub {
        my ($file) = @_;

        my $vmid = basename($file, ('.conf'));

        my $fh = IO::File->new("${INPUT_DIR}/${file}", "r")
            or die "unable to read '$file' - $!\n";

        my $map = {};
        my $disknum = 0;

        # NOTE For now, the map is hardcoded to a file-based 'target' storage.
        # In the future, the test could be extended to include parse_backup_hints
        # and restore_allocate_devices. Even better if the config-related logic from
        # the restore_XYZ_archive functions could become a separate function.
        while (defined(my $line = <$fh>)) {
            if ($line =~ m/^\#qmdump\#map:(\S+):(\S+):(\S*):(\S*):$/) {
                my ($drive, undef, $storeid, $fmt) = ($1, $2, $3, $4);

                $fmt ||= 'raw';

                $map->{$drive} = "target:${vmid}/vm-${vmid}-disk-${disknum}.${fmt}";
                $disknum++;
            }
        }

        $fh->seek(0, 0) or die "seek failed - $!\n";

        my $got = '';
        my $cookie = { netcount => 0 };

        while (defined(my $line = <$fh>)) {
            $got .= PVE::QemuServer::restore_update_config_line(
                $cookie, $map, $line, 0,
            );
        }

        my $expected = file_get_contents("${EXPECTED_DIR}/${file}");

        is_deeply($got, $expected, $file);
    },
);

# Restores through the create API and the restore paths for PBS, backup providers, VMA and legacy
# tar archives, against the fake cluster filesystem. Storage, archive tools and other external
# effects are mocked. The backups have no disks, so that no volumes get allocated.

my $runtime_dir = tempdir('restore-run-XXXXXX', DIR => '.', CLEANUP => 1);
$PVE::QemuServer::Helpers::var_run_tmpdir = $runtime_dir;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->set_user('root@pam');

my $ARCHIVES = {
    pbs => 'pbs:backup/vm/100/2025-01-01T00:00:00Z',
    provider => 'provider:backup/vm-100-2025-01-01',
    'vma file' => '/var/lib/vz/dump/vzdump-qemu-100-2025_01_01-00_00_00.vma',
    'vma stdin' => '-',
    tar => '/var/lib/vz/dump/vzdump-qemu-100-2025_01_01-00_00_00.tar',
};
my $BACKUP_FIREWALL = "[OPTIONS]\nenable: 1\n";

our $current_backup; # raw config of the backup
# where the restore fails: 'read-config', 'data', 'after-restore' or 'live'
our $fail_at = '';
my $calls = {}; # calls with effects on the target VM that tests check

sub backup_config {
    my ($meta) = @_;

    return
        "boot: order=scsi0\ncores: 1\nmemory: 512\n"
        . (defined($meta) ? "meta: $meta\n" : '')
        . "name: backup\n";
}

package TestBackupProvider {

    sub new {
        my ($class) = @_;
        return bless {}, $class;
    }

    sub restore_get_mechanism { return ('qemu-img', 'qemu'); }
    sub restore_vm_init { return {}; }

    sub archive_get_guest_config {
        die "unable to read the backup\n" if $main::fail_at eq 'read-config';
        return $main::current_backup;
    }
    sub archive_get_firewall_config { return $BACKUP_FIREWALL; }
    sub restore_vm_cleanup { return; }
}

my $replication_state_module = Test::MockModule->new('PVE::ReplicationState');
$replication_state_module->mock(delete_guest_states => sub { $calls->{delete_guest_states}++; });

my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock(
    abs_filesystem_path => sub {
        my ($cfg, $path) = @_;
        return $path;
    },
    check_volume_access => sub { return; },
    config => sub { return {}; },
    deactivate_volumes => sub { return 1; },
    extract_vzdump_config => sub { return $current_backup; },
    new_backup_provider => sub { return TestBackupProvider->new(); },
    parse_volname => sub {
        return ('backup', 'vm/100/2025-01-01T00:00:00Z', 100, undef, undef, undef, 'pbs-vm');
    },
    parse_volume_id => sub {
        my ($volid, $noerr) = @_;
        return ($1, $2) if $volid =~ m/^([a-z]+):(.+)$/;
        die "unable to parse volume ID '$volid'\n" if !$noerr;
        return;
    },
    path_to_volume_id => sub { return; },
    storage_config => sub {
        my ($cfg, $storeid) = @_;
        return { type => 'pbs', server => 'localhost', datastore => 'ds' } if $storeid eq 'pbs';
        return { type => 'dir', path => '/mnt/provider' };
    },
    storage_has_feature => sub {
        my ($cfg, $storeid, $feature) = @_;
        return $storeid eq 'provider' && $feature eq 'backup-provider';
    },
);

my $pbs_plugin_module = Test::MockModule->new('PVE::Storage::PBSPlugin');
$pbs_plugin_module->mock(
    pbs_encryption_key_file_name => sub { return '/nonexistent/key'; },
    pbs_get_password => sub { return 'secret'; },
    run_raw_client_cmd => sub {
        my ($scfg, $storeid, $cmd, $param) = @_;
        my (undef, $file, $target) = $param->@*;
        if ($file eq 'index.json') {
            my $files =
                [{ filename => 'qemu-server.conf.blob' }, { filename => 'fw.conf.blob' }];
            file_set_contents($target, encode_json({ files => $files }));
        } elsif ($file eq 'qemu-server.conf') {
            die "unable to read the backup\n" if $fail_at eq 'read-config';
            file_set_contents($target, $current_backup);
        } elsif ($file eq 'fw.conf') {
            file_set_contents($target, $BACKUP_FIREWALL);
        } else {
            die "run_raw_client_cmd (mocked) - unexpected file '$file'\n";
        }
    },
);

my $network_module = Test::MockModule->new('PVE::QemuServer::Network');
$network_module->mock(
    create_ifaces_ipams_ips => sub {
        die "unable to register IPs\n" if $fail_at eq 'after-restore';
    },
);

my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
$qemu_server_module->mock(
    check_running => sub { return 0; },
    pbs_live_restore => sub {
        my ($vmid, $conf, $storecfg) = @_;
        die "live restore failed\n" if $fail_at eq 'live';
        $calls->{live_restore}++;
    },
    rescan => sub { return; },
    # the real one writes to the cluster filesystem of the host
    restore_firewall_config => sub { $calls->{firewall}++; },
    restore_update_config_line => sub {
        die "restoring the data failed\n" if $fail_at eq 'data';
        return $qemu_server_module->original('restore_update_config_line')->(@_);
    },
    tar_archive_read_firstfile => sub { return 'qemu-server.conf'; },
    # like 'tar' with qmextract and 'vma extract': write the config and report the VMA header
    run_command => sub {
        my ($cmd, %param) = @_;

        if (!ref($cmd) && $cmd =~ m/^zcat -f\|tar xf /) {
            die "unable to read the backup\n" if $fail_at eq 'read-config';
            file_set_contents("$ENV{VZDUMP_TMPDIR}/qemu-server.conf", $current_backup);
            return 0;
        }

        my $vma = $cmd->[-1];
        die "run_command (mocked) - unexpected command\n"
            if ref($vma) ne 'ARRAY' || $vma->[0] ne 'vma';
        my ($mapfifo, $tmpdir) = $vma->@[4, 6];

        die "unable to read the backup\n" if $fail_at eq 'read-config';

        make_path($tmpdir);
        file_set_contents("$tmpdir/qemu-server.conf", $current_backup);
        file_set_contents("$tmpdir/qemu-server.fw", $BACKUP_FIREWALL);

        sysopen(my $reader, $mapfifo, O_RDONLY | O_NONBLOCK)
            or die "unable to open fifo - $!\n";
        # the real run_command, which reports an error of the output callback as one of the command
        my $header = 'echo "CTIME: Wed Jan  1 00:00:00 2025"';
        eval { $qemu_server_module->original('run_command')->(['sh', '-c', $header], %param) };
        my $err = $@;
        close($reader);
        die $err if $err;

        return 0;
    },
);

my $task_error;
my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
$rpcenv_module->mock(
    check => sub { return 1; },
    fork_worker => sub {
        my ($self, $type, $id, $user, $code) = @_;
        eval { $code->('UPID:test') };
        $task_error = $@;
        return 'UPID:test';
    },
);

$QemuServerTest::FakeCFS::cluster_module->mock(check_cfs_quorum => sub { return 1; });

# Starts over with an empty fake cluster filesystem, or with the raw config $conf for VM 100.
sub reset_cluster {
    my ($conf) = @_;

    QemuServerTest::FakeCFS::reset();
    QemuServerTest::FakeCFS::set_config(100, $conf) if defined($conf);
}

sub stored_config {
    my ($vmid) = @_;

    return $QemuServerTest::FakeCFS::configs->{$vmid};
}

# Restores a backup with the raw config $backup to VMID 100 through the create API, from an archive
# of type $type with the additional API parameters $param. Returns the error of the API call or the
# task and the task output.
sub restore_api {
    my ($type, $backup, $param) = @_;

    $current_backup = $backup;
    $calls = {};
    $task_error = '';

    my $err;
    my $output = capture_output(sub {
        eval {
            PVE::API2::Qemu->create_vm({
                node => 'localhost',
                vmid => 100,
                archive => $ARCHIVES->{$type},
                $param->%*,
            });
        };
        $err = $@ || $task_error;
    });

    return ($err, $output);
}

my $TARGET_CONF = "memory: 1024\nmeta: creation-qemu=10.0.0,ctime=1700000000\nname: target\n";
my $NOT_CLEANED_UP = qr/VM 100 state is NOT cleaned up/;

for my $type (sort keys $ARCHIVES->%*) {
    subtest "$type: restore to a free VMID" => sub {
        reset_cluster();

        my ($err, $output) = restore_api($type, backup_config(), {});
        is($err, '', 'restore succeeded') or diag($output);
        like(stored_config(100), qr/^name: backup$/m, 'VM restored');
        unlike(stored_config(100), qr/^lock:/m, 'lock removed');
    };
}

subtest "'force' does not overwrite a VM created after the checks" => sub {
    reset_cluster();

    # the archive is checked after the target VM
    local *PVE::Storage::check_volume_access =
        sub { QemuServerTest::FakeCFS::set_config(100, $TARGET_CONF); };

    my ($err) = restore_api('pbs', backup_config(), { force => 1 });
    is($err, "unable to restore VM 100 - VM 100 already exists\n", 'restore refused');
    is(stored_config(100), $TARGET_CONF, 'VM created in between unchanged');
};

for my $type ('pbs', 'provider', 'vma file', 'vma stdin') {
    subtest "$type: failed restore over an existing VM" => sub {
        reset_cluster($TARGET_CONF);

        local $fail_at = 'read-config';
        my ($err, $output) = restore_api($type, backup_config(), { force => 1 });
        like($err, qr/unable to read the backup\n$/, 'fails before changing the VM');
        is(stored_config(100), $TARGET_CONF, 'config unchanged');
        is_deeply($calls, {}, 'replication state and firewall config untouched');

        $fail_at = 'data';
        ($err, $output) = restore_api($type, backup_config(), { force => 1 });
        like($err, qr/restoring the data failed\n$/, 'fails while restoring');
        like(stored_config(100), qr/^memory: 128$/m, 'temporary config');
        unlike($output, qr/no lock found/, 'temporary config had the create lock');
        unlike(stored_config(100), qr/^lock:/m, 'lock removed');
        like($output, qr/error before or during data restore/, 'warning about the changed VM');
    };
}

subtest 'failed live restore to a free VMID keeps the restored config' => sub {
    reset_cluster();

    local $fail_at = 'live';
    my ($err, $output) = restore_api('pbs', backup_config(), { 'live-restore' => 1 });
    is($err, "live restore failed\n", 'restore failed');
    like(stored_config(100), qr/^name: backup$/m, 'restored config kept');
    unlike(stored_config(100), qr/^lock:/m, 'lock removed');
    like($output, $NOT_CLEANED_UP, 'warning about the VM left behind');
};

subtest 'failure after the data was restored keeps the VM' => sub {
    reset_cluster();

    local $fail_at = 'after-restore';
    my ($err, $output) = restore_api('pbs', backup_config(), { unique => 1 });
    is($err, "unable to register IPs\n", 'restore failed');
    like(stored_config(100), qr/^name: backup$/m, 'restored config kept');
    like($output, qr/error after data was restored/, 'warning about the VM left behind');
};

done_testing();
