#!/usr/bin/perl

use strict;
use warnings;

use lib qw(.. .);

use Fcntl qw(:flock O_RDONLY O_NONBLOCK);
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempdir);
use JSON;
use Test::MockModule;
use Test::More;

use File::Basename;

use PVE::API2::Qemu;
use PVE::GuestHelpers;
use PVE::GuestIdentity;
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::MetaInfo;
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

subtest 'missing MAC addresses of the backup are added' => sub {
    my $restore_line = sub {
        my ($line, $unique) = @_;
        return PVE::QemuServer::restore_update_config_line({ netcount => 0 }, {}, $line,
            $unique);
    };

    my $with_mac = "net0: virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1\n";
    is($restore_line->($with_mac, 0), $with_mac, 'line with a MAC address is kept');

    my $restored = $restore_line->("net1: virtio,bridge=vmbr0,firewall=1\n", 0);
    my ($net1) = $restored =~ m/^net1: (.*)\n\z/;
    my $net = PVE::QemuServer::Network::parse_net($net1, 1);
    like($net->{macaddr}, qr/^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i,
        'missing MAC address is added');
    is($net->{firewall}, 1, 'other properties are kept');
};

# Restores through the create API and the restore paths for PBS, backup providers, VMA and legacy
# tar archives, against the fake cluster filesystem. Storage, archive tools and other external
# effects are mocked. The backups have no disks, so that no volumes get allocated.

my $runtime_dir = tempdir('restore-run-XXXXXX', DIR => '.', CLEANUP => 1);
$PVE::QemuServer::Helpers::var_run_tmpdir = $runtime_dir;
$PVE::GuestHelpers::firewall_config_dir = "$runtime_dir/firewall";

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
# where the restore fails: 'read-config', 'command', 'firewall', 'data', 'after-restore' or 'live'
our $fail_at = '';
# the stat file that qmextract leaves: undef for none, 'directory' for one that cannot be read, or
# its content
our $tar_stat_file;
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
        # like the start of the VM for the live phase
        PVE::QemuServer::vmconfig_apply_pending($vmid, $conf, $storecfg)
            if scalar(keys(($conf->{pending} // {})->%*));
        die "live restore failed\n" if $fail_at eq 'live';
        $calls->{live_restore}++;
    },
    rescan => sub { return; },
    restore_firewall_config => sub {
        die "unable to restore the firewall config\n" if $fail_at eq 'firewall';
        $calls->{firewall}++;
        return $qemu_server_module->original('restore_firewall_config')->(@_);
    },
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
            # a failed restore leaves its temporary directory behind
            my $statfile = "$ENV{VZDUMP_TMPDIR}/qmrestore.stat";
            remove_tree($statfile);
            if (defined($tar_stat_file)) {
                if ($tar_stat_file eq 'directory') {
                    make_path($statfile);
                } else {
                    file_set_contents($statfile, $tar_stat_file);
                }
            }
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
        my $script = $fail_at eq 'command' ? 'exit 1' : $header;
        eval { $qemu_server_module->original('run_command')->(['sh', '-c', $script], %param) };
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
    remove_tree($PVE::GuestHelpers::firewall_config_dir);
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

my $TARGET_CONF = "memory: 1024\nmeta: creation-qemu=10.0.0,ctime=1700000000,"
    . "rtime=1700000000000,uid=tttttttttttttttttttt\nname: target\n";
my $NOT_CLEANED_UP = qr/VM 100 state is NOT cleaned up/;
my $KEPT_LOCKED = 'WARN: keeping VM 100 locked, the cleanup left behind';

for my $type (sort keys $ARCHIVES->%*) {
    subtest "$type: restore to a free VMID" => sub {
        reset_cluster();

        my ($err, $output) = restore_api($type, backup_config(), {});
        is($err, '', 'restore succeeded') or diag($output);
        like(stored_config(100), qr/^name: backup$/m, 'VM restored');
        unlike(stored_config(100), qr/^lock:/m, 'lock removed');
        is(
            PVE::GuestHelpers::get_firewall_config_raw(100),
            # legacy tar archives have no firewall config
            $type eq 'tar' ? undef : $BACKUP_FIREWALL,
            'firewall config of the backup restored',
        );
    };
}

for my $type (sort keys $ARCHIVES->%*) {
    subtest "$type: failed restore to a free VMID" => sub {
        reset_cluster();

        local $fail_at = 'data';
        my ($err, $output) = restore_api($type, backup_config(), {});
        is($err, "restoring the data failed\n", 'restore failed');
        ok(!defined(stored_config(100)), 'reserved config removed');
        is(PVE::GuestHelpers::get_firewall_config_raw(100), undef, 'no firewall config left');
        unlike($output, $NOT_CLEANED_UP, 'no warning about a VM left behind');

        $fail_at = '';
        ($err, $output) = restore_api($type, backup_config(), {});
        is($err, '', 'retry needs no force') or diag($output);
        like(stored_config(100), qr/^name: backup$/m, 'VM restored');
    };
}

subtest 'failed restore to a free VMID before reading the backup' => sub {
    reset_cluster();

    local $fail_at = 'read-config';
    my ($err, $output) = restore_api('pbs', backup_config(), {});
    is($err, "unable to read the backup\n", 'restore failed');
    ok(!defined(stored_config(100)), 'reserved config removed');
    unlike($output, $NOT_CLEANED_UP, 'no warning about a VM left behind');
};

subtest 'vma: an error of the restore setup is reported without the command line' => sub {
    reset_cluster();
    local $fail_at = 'data';
    my ($err) = restore_api('vma file', backup_config(), {});
    is($err, "restoring the data failed\n", 'error of the setup alone');

    reset_cluster();
    $fail_at = 'command';
    ($err) = restore_api('vma file', backup_config(), {});
    like($err, qr/^command 'sh -c .*' failed: exit code 1$/, 'failed command is named');
};

# legacy tar archives have no firewall config
for my $type (grep { $_ ne 'tar' } sort keys $ARCHIVES->%*) {
    subtest "$type: failed restore puts the previous firewall config back" => sub {
        local $fail_at = 'data';
        for my $previous (undef, "[RULES]\nIN ACCEPT -p tcp -dport 22\n") {
            my $what =
                defined($previous) ? 'firewall config before' : 'no firewall config before';

            for my $target (undef, $TARGET_CONF) {
                reset_cluster($target);
                PVE::GuestHelpers::set_firewall_config_raw(100, $previous);

                my ($err) = restore_api($type, backup_config(), { force => $target ? 1 : 0 });
                like($err, qr/restoring the data failed\n$/, 'restore failed');
                is(
                    PVE::GuestHelpers::get_firewall_config_raw(100),
                    $previous,
                    ($target ? 'existing VM' : 'free VMID') . ", $what: as before",
                );
            }
        }
    };
}

subtest 'failure once the data is restored keeps the firewall config of the backup' => sub {
    my $previous = "[RULES]\nIN ACCEPT -p tcp -dport 22\n";
    # in the live phase, and after the restore of the data returned
    for my $case (['live', { 'live-restore' => 1 }], ['after-restore', { unique => 1 }]) {
        my ($failure, $param) = $case->@*;

        local $fail_at = $failure;
        for my $target (undef, $TARGET_CONF) {
            reset_cluster($target);
            PVE::GuestHelpers::set_firewall_config_raw(100, $previous);

            my ($err) =
                restore_api('pbs', backup_config(), { $param->%*, force => $target ? 1 : 0 });
            ok($err, "$failure: restore failed");
            is(
                PVE::GuestHelpers::get_firewall_config_raw(100),
                $BACKUP_FIREWALL,
                "$failure, "
                    . ($target ? 'existing VM' : 'free VMID')
                    . ': the one of the backup',
            );
        }
    }
};

subtest 'firewall config that cannot be put back keeps the VMID' => sub {
    reset_cluster();

    # only the removal of the firewall config of the backup fails
    my $set_firewall_config_raw = \&PVE::GuestHelpers::set_firewall_config_raw;
    local *PVE::GuestHelpers::set_firewall_config_raw = sub {
        my ($vmid, $raw) = @_;
        die "unable to remove the file - Permission denied\n" if !defined($raw);
        return $set_firewall_config_raw->($vmid, $raw);
    };

    local $fail_at = 'data';
    my ($err, $output) = restore_api('pbs', backup_config(), {});
    is($err, "restoring the data failed\n", 'restore failed');
    my $reported = 'unable to reset the firewall config - unable to remove the file';
    like($output, qr/^\Q$reported\E - Permission denied$/m, 'failure is reported');
    like($output, qr/^\Q$KEPT_LOCKED\E the firewall config$/m, 'what is left is reported');
    like(stored_config(100), qr/^lock: create$/m, 'reservation is kept, locked');
    unlike($output, $NOT_CLEANED_UP, 'no other warning about the VM left behind');
};

subtest 'firewall config is put back before the VMID is released' => sub {
    reset_cluster();

    my $reserved;
    my $set_firewall_config_raw = \&PVE::GuestHelpers::set_firewall_config_raw;
    local *PVE::GuestHelpers::set_firewall_config_raw = sub {
        $reserved = defined(stored_config(100));
        return $set_firewall_config_raw->(@_);
    };

    local $fail_at = 'data';
    restore_api('pbs', backup_config(), {});
    ok($reserved, 'VMID was still reserved');
    ok(!defined(stored_config(100)), 'and is released afterwards');
};

subtest 'tar: an allocation record that cannot be read keeps the VMID' => sub {
    for my $case (
        ['line that cannot be parsed', "garbage\n", qr/^unable to parse line in statfile/m],
        [
            'stat file that cannot be read',
            'directory',
            qr/^unable to read '.*qmrestore\.stat'/m,
        ],
    ) {
        my ($what, $stat_file, $reported) = $case->@*;
        reset_cluster();

        local $fail_at = 'data';
        local $tar_stat_file = $stat_file;
        my ($err, $output) = restore_api('tar', backup_config(), {});
        is($err, "restoring the data failed\n", "$what: restore failed");
        like($output, $reported, "$what: reported");
        like(stored_config(100), qr/^lock: create$/m, "$what: reservation is kept, locked");
        like(
            $output,
            qr/^\Q$KEPT_LOCKED\E volumes of the restore$/m,
            "$what: what is left is reported",
        );
    }
};

subtest 'failed removal of a restored volume keeps the VMID' => sub {
    reset_cluster();

    my $allocated = [];
    my $run_raw_client_cmd = \&PVE::Storage::PBSPlugin::run_raw_client_cmd;
    local *PVE::Storage::PBSPlugin::run_raw_client_cmd = sub {
        my ($scfg, $storeid, $cmd, $param) = @_;
        my (undef, $file, $target) = $param->@*;
        return $run_raw_client_cmd->(@_) if $file ne 'index.json';
        my $files = [
            { filename => 'qemu-server.conf.blob' },
            { filename => 'drive-scsi0.img.fidx', size => 1048576 },
        ];
        file_set_contents($target, encode_json({ files => $files }));
    };
    local *PVE::Storage::storage_config = sub {
        my ($cfg, $storeid) = @_;
        return { type => 'pbs', server => 'localhost', datastore => 'ds' } if $storeid eq 'pbs';
        return { type => 'dir', path => '/nonexistent', content => { images => 1 } };
    };
    local *PVE::Storage::resolve_format_hint = sub { return 'raw'; };
    local *PVE::Storage::vdisk_alloc = sub {
        my ($cfg, $storeid, $vmid) = @_;
        push $allocated->@*, "$storeid:vm-$vmid-disk-0";
        return "$storeid:vm-$vmid-disk-0";
    };
    local *PVE::Storage::activate_volumes = sub { return; };
    local *PVE::Storage::path = sub { return '/nonexistent/vm-100-disk-0.raw'; };
    local *PVE::Storage::volume_has_feature = sub { return 0; };
    local *PVE::Storage::vdisk_free = sub { die "volume is busy\n"; };
    my $run_command = \&PVE::QemuServer::run_command;
    local *PVE::QemuServer::run_command = sub {
        my ($cmd) = @_;
        return 0 if ref($cmd) && $cmd->[0] eq '/usr/bin/pbs-restore';
        return $run_command->(@_);
    };

    local $fail_at = 'data';
    my $backup = backup_config()
        . "scsi0: target:vm-100-disk-0,size=1M\n#qmdump#map:scsi0:drive-scsi0:target:raw:\n";
    my ($err, $output) = restore_api('pbs', $backup, {});
    is($err, "restoring the data failed\n", 'restore failed after allocating the volume');
    is_deeply($allocated, ['target:vm-100-disk-0'], 'volume was allocated');
    like($output, qr/^unable to cleanup 'target:vm-100-disk-0' - volume is busy$/m, 'reported');
    like(stored_config(100), qr/^lock: create$/m, 'reservation is kept, locked');
    like(
        $output, qr/^\Q$KEPT_LOCKED\E volumes of the restore$/m, 'what is left is reported',
    );

    # the leftover is no VM to restore over
    $fail_at = '';
    ($err) = restore_api('pbs', backup_config(), { force => 1 });
    is(
        $err,
        "unable to restore VM 100 - VM is locked (create)\n",
        'retry needs an unlock first',
    );
};

subtest "'force' does not overwrite a VM created after the checks" => sub {
    reset_cluster();

    # the archive is checked after the target VM
    local *PVE::Storage::check_volume_access =
        sub { QemuServerTest::FakeCFS::set_config(100, $TARGET_CONF); };

    my ($err) = restore_api('pbs', backup_config(), { force => 1 });
    is($err, "unable to restore VM 100 - VM 100 already exists\n", 'restore refused');
    is(stored_config(100), $TARGET_CONF, 'VM created in between unchanged');
};

subtest 'a restore that cannot take its guest lock removes the reservation' => sub {
    my $lock_config_full = PVE::QemuConfig->can('lock_config_full');
    my $before_timeout = sub { };
    local *PVE::QemuConfig::lock_config_full = sub {
        my ($class, $vmid, $timeout, @param) = @_;
        # the restore waits one second for the lock
        if ($timeout == 1) {
            $before_timeout->();
            die "can't lock file 'lock-$vmid.conf' - got timeout\n";
        }
        return $lock_config_full->($class, $vmid, $timeout, @param);
    };

    reset_cluster();
    my ($err, $output) = restore_api('pbs', backup_config(), {});
    like($err, qr/got timeout/, 'free VMID: restore failed');
    ok(!defined(stored_config(100)), 'free VMID: reservation removed');

    reset_cluster($TARGET_CONF);
    ($err, $output) = restore_api('pbs', backup_config(), { force => 1 });
    like($err, qr/got timeout/, 'existing VM: restore failed');
    like(stored_config(100), qr/^name: target$/m, 'existing VM: kept');
    unlike(stored_config(100), qr/^lock:/m, 'existing VM: lock removed');

    # without the lock of the reservation, the config is not one of this restore anymore
    reset_cluster();
    $before_timeout = sub { QemuServerTest::FakeCFS::set_config(100, "memory: 512\n"); };
    ($err, $output) = restore_api('pbs', backup_config(), {});
    like($err, qr/got timeout/, 'config changed meanwhile: restore failed');
    is(stored_config(100), "memory: 512\n", 'config changed meanwhile: kept');
};

subtest 'the permission to overwrite a VM does not cover creating it' => sub {
    # the VM goes away after the permission checks
    local *PVE::Storage::check_volume_access =
        sub { QemuServerTest::FakeCFS::set_config(100, undef); };

    reset_cluster($TARGET_CONF);
    my ($err) = restore_api('pbs', backup_config(), { force => 1 });
    is($err, '', 'with VM.Allocate: restored as a new VM');
    like(stored_config(100), qr/^name: backup$/m, 'with VM.Allocate: VM');

    local *PVE::RPCEnvironment::check = sub {
        my ($self, $user, $path, $privs) = @_;
        return !grep { $_ eq 'VM.Allocate' } $privs->@*;
    };
    reset_cluster($TARGET_CONF);
    ($err) = restore_api('pbs', backup_config(), { force => 1 });
    my $config_path = PVE::QemuConfig->cfs_config_path(100);
    is(
        $err,
        "unable to restore VM 100 - Configuration file '$config_path' does not exist\n",
        'with VM.Backup only: restore refused',
    );
    ok(!defined(stored_config(100)), 'with VM.Backup only: no VM');
    is_deeply($QemuServerTest::FakeCFS::written, {}, 'with VM.Backup only: nothing written');
};

subtest 'another restore right after a failed restore to a free VMID' => sub {
    reset_cluster();

    # run a second restore with 'force' as soon as the failed one releases the guest lock
    my $lock_config_full = PVE::QemuConfig->can('lock_config_full');
    my ($interposed, $lock_free, $second_err) = (0, 0, '');
    local *PVE::QemuConfig::lock_config_full = sub {
        my ($class, $vmid, @param) = @_;
        my $res = eval { $lock_config_full->($class, $vmid, @param) };
        my $err = $@;
        if ($err && !$interposed++) {
            open(my $fh, '>>', PVE::QemuConfig->config_file_lock($vmid)) or die "$!\n";
            $lock_free = flock($fh, LOCK_EX | LOCK_NB);
            close($fh);
            local $fail_at = '';
            ($second_err) = restore_api('pbs', backup_config(), { force => 1 });
        }
        die $err if $err;
        return $res;
    };

    local $fail_at = 'data';
    my ($err) = restore_api('vma file', backup_config(), {});

    is($err, "restoring the data failed\n", 'first restore failed');
    ok($lock_free, 'guest lock was free for the second restore');
    is($second_err, '', 'second restore succeeded');
    like(stored_config(100), qr/^name: backup$/m, 'its config stays');
    is(
        PVE::GuestHelpers::get_firewall_config_raw(100),
        $BACKUP_FIREWALL,
        'and its firewall config',
    );
};

for my $type ('pbs', 'provider', 'vma file', 'vma stdin') {
    subtest "$type: failed restore over an existing VM" => sub {
        reset_cluster($TARGET_CONF);

        local $fail_at = 'read-config';
        my ($err, $output) = restore_api($type, backup_config(), { force => 1 });
        like($err, qr/unable to read the backup\n$/, 'fails before changing the VM');
        is(stored_config(100), $TARGET_CONF, 'config unchanged');
        is_deeply($calls, {}, 'replication state and firewall config untouched');
        unlike($output, $NOT_CLEANED_UP, 'no warning about a changed VM');

        $fail_at = 'data';
        ($err, $output) = restore_api($type, backup_config(), { force => 1 });
        like($err, qr/restoring the data failed\n$/, 'fails while restoring');
        like(stored_config(100), qr/^memory: 128$/m, 'temporary config');
        unlike($output, qr/no lock found/, 'temporary config had the create lock');
        unlike(stored_config(100), qr/^lock:/m, 'lock removed');
        like($output, qr/error before or during data restore/, 'warning about the changed VM');
    };
}

subtest 'tar: failed restore over an existing VM' => sub {
    reset_cluster($TARGET_CONF);

    local $fail_at = 'data';
    my ($err, $output) = restore_api('tar', backup_config(), { force => 1 });
    is($err, "restoring the data failed\n", 'restore failed');
    unlike($output, qr/trying to remove 'create' lock/, "emptied config had the 'create' lock");
    ok(defined(stored_config(100)), 'emptied config is kept');
    unlike(stored_config(100), qr/^lock:/m, 'lock removed');
    like($output, qr/error before or during data restore/, 'warning about the changed VM');
};

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

# Guest identity of restored VMs

my $UID_BACKUP = 'bbbbbbbbbbbbbbbbbbbb';
my $UID_TARGET = 'tttttttttttttttttttt';

my $TARGET_CONF_NO_UID = "memory: 1024\nmeta: creation-qemu=8.0.2,ctime=1500000000\nname: target\n";

my $NOW = 1800000000000;
my $BACKUP_META = 'creation-qemu=9.2.0,ctime=1600000000';
my $REFUSED =
    "backup belongs to another guest: its uid '$UID_BACKUP' differs from uid '$UID_TARGET' of the"
    . " existing VM 100 - use 'allow-identity-mismatch' to overwrite the VM anyway\n";
my $IGNORED = "guest identity: ignoring backup uid $UID_BACKUP, VM 100 keeps uid $UID_TARGET";
# captures the uid that the VM keeps
my $ADOPT_FAILED = "WARN: guest identity: unable to adopt backup uid $UID_BACKUP, keeping uid"
    . " ([a-z2-7]{20}) - cfs-lock 'domain-guest-identity' error: no quorum!";
$ADOPT_FAILED = qr/^$ADOPT_FAILED$/m;
my $KEPT_TARGET = qr/^guest identity: kept uid $UID_TARGET$/m;

# legacy tar archives get no guest identity handling
my @IDENTITY_ARCHIVES = grep { $_ ne 'tar' } sort keys $ARCHIVES->%*;

my $cases = [
    {
        name => 'free VMID, backup uid unused',
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        result => { uid => $UID_BACKUP, rtime => $NOW },
        output => qr/^guest identity: adopted uid $UID_BACKUP from the backup$/m,
    },
    {
        name => 'free VMID, backup uid in use by another guest',
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        other => "rtime=1,uid=$UID_BACKUP",
        result => { uid => 'generated', rtime => $NOW },
        output => qr/: backup uid $UID_BACKUP is in use by guest 300, keeping uid \w{20}$/m,
    },
    {
        name => 'free VMID, backup without uid',
        backup => $BACKUP_META,
        result => { uid => 'generated', rtime => $NOW },
        output => qr/^guest identity: new uid aaaaaaaaaaaaaaaaaaab$/m,
    },
    {
        name => 'free VMID, unique',
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        param => { unique => 1 },
        result => { uid => 'generated', rtime => $NOW },
        output => qr/^guest identity: new uid aaaaaaaaaaaaaaaaaaab$/m,
    },
    {
        name => 'free VMID, identity lock fails',
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        lock_error => "cfs-lock 'domain-guest-identity' error: no quorum!\n",
        result => { uid => 'generated', rtime => $NOW },
        output => $ADOPT_FAILED,
    },
    {
        name => 'free VMID, backup meta with a member unknown to this version',
        backup => "$BACKUP_META,future=1,rtime=1600000000000,uid=$UID_BACKUP",
        result => { uid => $UID_BACKUP, rtime => $NOW },
        # the parser drops the whole property of the backup, as it does for other members
        meta => { rtime => $NOW, uid => $UID_BACKUP },
        output => qr/^guest identity: adopted uid $UID_BACKUP from the backup$/m,
    },
    {
        name => 'in place, backup of another guest',
        target => $TARGET_CONF,
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        error => $REFUSED,
    },
    {
        name => 'in place, backup of another guest, unique',
        target => $TARGET_CONF,
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        param => { unique => 1 },
        error => $REFUSED,
    },
    {
        name => 'in place, backup of another guest, override',
        target => $TARGET_CONF,
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        param => { 'allow-identity-mismatch' => 1 },
        result => { uid => $UID_TARGET, rtime => 1700000000000 },
        output => qr/^\Q$IGNORED\E\n(?:.*\n)*guest identity: kept uid $UID_TARGET$/m,
    },
    {
        name => 'in place, backup of the same guest',
        target => $TARGET_CONF,
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_TARGET",
        result => { uid => $UID_TARGET, rtime => 1700000000000 },
        output => $KEPT_TARGET,
    },
    {
        name => 'in place, backup without uid',
        target => $TARGET_CONF,
        backup => $BACKUP_META,
        result => { uid => $UID_TARGET, rtime => 1700000000000 },
        output => $KEPT_TARGET,
    },
    {
        name => 'in place, target without uid',
        target => $TARGET_CONF_NO_UID,
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        result => { uid => $UID_BACKUP, rtime => $NOW },
        output => qr/^guest identity: adopted uid $UID_BACKUP from the backup$/m,
    },
    {
        name => 'in place, target without uid, unique',
        target => $TARGET_CONF_NO_UID,
        backup => "$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP",
        param => { unique => 1 },
        result => { uid => 'generated', rtime => $NOW },
        output => qr/^guest identity: new uid aaaaaaaaaaaaaaaaaaab$/m,
    },
];

sub meta_of {
    my ($vmid) = @_;

    my $conf = PVE::QemuConfig->load_config($vmid);
    return PVE::QemuServer::MetaInfo::parse_meta_info($conf->{meta});
}

for my $type (@IDENTITY_ARCHIVES) {
    for my $case ($cases->@*) {
        subtest "$type: $case->{name}" => sub {
            QemuServerTest::FakeCFS::reset();
            $QemuServerTest::FakeCFS::now_ms = $NOW;
            QemuServerTest::FakeCFS::set_config(100, $case->{target}) if $case->{target};
            $QemuServerTest::FakeCFS::other_guests->{300} = $case->{other} if $case->{other};
            $QemuServerTest::FakeCFS::lock_domain_error = $case->{lock_error};

            my $param = { ($case->{param} // {})->%* };
            $param->{force} = 1 if $case->{target};
            my ($err, $output) = restore_api($type, backup_config($case->{backup}), $param);

            if (my $expected_err = $case->{error}) {
                is($err, $expected_err, 'restore refused');
                is(
                    $QemuServerTest::FakeCFS::configs->{100},
                    $case->{target},
                    'config unchanged',
                );
                is_deeply($calls, {}, 'replication state and firewall config untouched');
                unlike($output, $NOT_CLEANED_UP, 'no warning about a changed VM');
                return;
            }

            is($err, '', 'restore succeeded') or diag($output);
            like($output, $case->{output}, 'task log reports the identity');

            my $expected = { $case->{result}->%* };
            $expected->{uid} = QemuServerTest::FakeCFS::generated_uid(1)
                if $expected->{uid} eq 'generated';
            is_deeply(
                QemuServerTest::FakeCFS::stored_identity(100),
                $expected,
                'stored identity',
            );
            is_deeply(
                meta_of(100),
                $case->{meta}
                    // { 'creation-qemu' => '9.2.0', ctime => 1600000000, $expected->%* },
                'other members of meta come from the backup',
            );
        };
    }
}

subtest 'retry of a failed restore to a free VMID adopts the uid of the backup' => sub {
    QemuServerTest::FakeCFS::reset();
    my $backup = backup_config("$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP");

    $fail_at = 'data';
    my ($err) = restore_api('pbs', $backup, {});
    is($err, "restoring the data failed\n", 'first attempt failed');

    # the web interface sets 'force' for a retry
    $fail_at = '';
    ($err) = restore_api('pbs', $backup, { force => 1 });
    is($err, '', 'retry succeeds');
    is(QemuServerTest::FakeCFS::stored_identity(100)->{uid}, $UID_BACKUP, 'uid adopted');
};

subtest 'live restore adopts the uid of the backup only when complete' => sub {
    my $backup = backup_config("$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP");
    my $template = "$backup" . "template: 1\n";

    for my $failure ('before the live phase', 'during the live phase') {
        QemuServerTest::FakeCFS::reset();

        $fail_at = $failure eq 'during the live phase' ? 'live' : '';
        my ($err, $output) = restore_api(
            'pbs',
            $failure eq 'before the live phase' ? $template : $backup,
            { 'live-restore' => 1 },
        );
        ok($err, "restore fails $failure");
        isnt(
            QemuServerTest::FakeCFS::stored_identity(100)->{uid},
            $UID_BACKUP,
            "leftover VM does not have the uid of the backup ($failure)",
        );
        unlike($output, qr/^guest identity:/m, "no identity reported ($failure)");

        $fail_at = '';
        ($err, $output) = restore_api('pbs', $backup, { vmid => 101, 'live-restore' => 1 });
        is($err, '', "retry at another VMID succeeds ($failure)") or diag($output);
        is($calls->{live_restore}, 1, 'live phase ran');
        is(
            QemuServerTest::FakeCFS::stored_identity(101)->{uid},
            $UID_BACKUP,
            "retry adopts the uid of the backup ($failure)",
        );
        like(
            $output,
            qr/^guest identity: adopted uid $UID_BACKUP from the backup$/m,
            "adoption reported ($failure)",
        );
    }
};

# A VM that a restore leaves behind keeps the uid of the backup as pending uid, so that retrying
# the restore over it adopts the uid.

my $BACKUP_WITH_UID = backup_config("$BACKUP_META,rtime=1600000000000,uid=$UID_BACKUP");
my $ADOPTED = qr/^guest identity: adopted uid $UID_BACKUP from the backup$/m;

sub pending_uid_of {
    my ($vmid) = @_;

    return PVE::GuestIdentity::get_pending_uid(PVE::QemuConfig->load_config($vmid));
}

sub stored_uid_of {
    my ($vmid) = @_;

    my $identity = QemuServerTest::FakeCFS::stored_identity($vmid);
    return $identity ? $identity->{uid} : undef;
}

# Fails the live restore of a backup with uid to the free VMID 100 in its live phase.
sub failed_live_restore {
    QemuServerTest::FakeCFS::reset();
    $QemuServerTest::FakeCFS::now_ms = $NOW;

    local $fail_at = 'live';
    my ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, { 'live-restore' => 1 });
    is($err, "live restore failed\n", 'live restore failed in its live phase');
    unlike($output, qr/dropping pending uid/, 'starting the VM keeps the pending uid');
    isnt(stored_uid_of(100), $UID_BACKUP, 'leftover VM has a uid of its own');
    is(pending_uid_of(100), $UID_BACKUP, 'leftover VM has the uid of the backup as pending uid');
    unlike($QemuServerTest::FakeCFS::configs->{100}, qr/^lock:/m, 'leftover VM is not locked');
}

subtest 'retry in place after a failed live restore' => sub {
    for my $retry ({ 'live-restore' => 1 }, {}) {
        my $what = $retry->{'live-restore'} ? 'live' : 'regular';

        failed_live_restore();

        # the web interface restores from the backup list of the VM with 'force'
        my ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, { force => 1, $retry->%* });
        is($err, '', "$what retry succeeds") or diag($output);
        like($output, $ADOPTED, "$what retry adopts the uid of the backup");
        is(stored_uid_of(100), $UID_BACKUP, "$what retry: stored");
        is(pending_uid_of(100), undef, "$what retry: pending uid is removed");
    }
};

subtest 'retry in place after a failure once the restored volumes stay' => sub {
    QemuServerTest::FakeCFS::reset();
    my $backup = $BACKUP_WITH_UID . "hostpci0: 0000:01:00.0\n";

    # the permission check needs the restored config, so it runs once the data is restored
    $rpcenv->set_user('user@pve');
    my ($err, $output) = restore_api('vma file', $backup, {});
    $rpcenv->set_user('root@pam');
    is(
        $err,
        "only root can set 'hostpci0' config for non-mapped devices\n",
        'restore refused after restoring the data',
    );
    ok(defined($QemuServerTest::FakeCFS::configs->{100}), 'VM is left behind');
    is(pending_uid_of(100), $UID_BACKUP,
        'leftover VM has the uid of the backup as pending uid');

    ($err, $output) = restore_api('vma file', $backup, { force => 1 });
    is($err, '', 'retry succeeds') or diag($output);
    is(stored_uid_of(100), $UID_BACKUP, 'retry adopts the uid of the backup');
    is(pending_uid_of(100), undef, 'retry: pending uid is removed');
};

my $FAILURES = {
    # right after the check, before the restore writes a config itself
    firewall => "unable to restore the firewall config\n",
    data => "restoring the data failed\n",
};

for my $type ('pbs', 'provider', 'vma file', 'vma stdin') {
    for my $failure (sort keys $FAILURES->%*) {
        my $what = "$type: retry in place after a failed restore over a VM without uid";

        subtest "$what ($failure)" => sub {
            QemuServerTest::FakeCFS::reset();
            QemuServerTest::FakeCFS::set_config(100, $TARGET_CONF_NO_UID);

            local $fail_at = $failure;
            my ($err) = restore_api($type, $BACKUP_WITH_UID, { force => 1 });
            is($err, $FAILURES->{$failure}, 'restore failed');
            ok(stored_uid_of(100), 'VM got a uid of its own');
            isnt(stored_uid_of(100), $UID_BACKUP, 'not the one of the backup');
            is(pending_uid_of(100), $UID_BACKUP, 'VM has the uid of the backup as pending uid');

            $fail_at = '';
            ($err, my $output) = restore_api($type, $BACKUP_WITH_UID, { force => 1 });
            is($err, '', 'retry succeeds') or diag($output);
            is(stored_uid_of(100), $UID_BACKUP, 'retry adopts the uid of the backup');
            is(pending_uid_of(100), undef, 'retry: pending uid is removed');
        };
    }
}

subtest 'retry elsewhere, then over the VM left behind' => sub {
    failed_live_restore();
    my $leftover = stored_uid_of(100);

    my ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, { vmid => 101 });
    is($err, '', 'restore to another VMID succeeds') or diag($output);
    is(stored_uid_of(101), $UID_BACKUP, 'pending uid of the leftover VM is not in use');
    is(pending_uid_of(100), $UID_BACKUP, 'leftover VM keeps its pending uid');

    ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, { force => 1 });
    is($err, '', 'restore over the leftover VM is not refused') or diag($output);
    like(
        $output,
        qr/^guest identity: backup uid $UID_BACKUP is in use by guest 101, keeping uid $leftover$/m,
        'uid of the backup is in use by now',
    );
    is(stored_uid_of(100), $leftover, 'leftover VM keeps its uid');
    is(pending_uid_of(100), undef, 'pending uid is removed');
};

subtest 'using the VM left behind drops its pending uid' => sub {
    failed_live_restore();
    my $leftover = stored_uid_of(100);

    # like a start, or a config change of the stopped VM
    my $warnings = '';
    {
        local $SIG{__WARN__} = sub { $warnings .= $_[0]; };
        my $conf = PVE::QemuConfig->load_config(100);
        PVE::QemuServer::vmconfig_apply_pending(100, $conf, {});
    }
    my $dropped = "guest identity: dropping pending uid $UID_BACKUP of an unfinished restore"
        . " - a retry now needs 'allow-identity-mismatch'";
    like($warnings, qr/^\Q$dropped\E$/m, 'dropped');
    is(pending_uid_of(100), undef, 'pending uid is gone');

    my ($err) = restore_api('pbs', $BACKUP_WITH_UID, { force => 1 });
    like(
        $err,
        qr/^backup belongs to another guest: its uid .$UID_BACKUP. differs/,
        'retry is refused',
    );
    is(stored_uid_of(100), $leftover, 'VM stays its own guest');
};

subtest 'a restore with unique keeps a pending uid, but never adopts it' => sub {
    for my $retry ({ unique => 1 }, {}) {
        my $what = $retry->{unique} ? 'retry with unique' : 'retry without unique';
        QemuServerTest::FakeCFS::reset();

        # registering the addresses of the new MACs is the last step before the adoption
        local $fail_at = 'after-restore';
        my ($err) = restore_api('pbs', $BACKUP_WITH_UID, { unique => 1 });
        is($err, "unable to register IPs\n", 'restore with unique failed at its end');
        my $leftover = stored_uid_of(100);
        is(pending_uid_of(100), $UID_BACKUP, 'VM left behind has the pending uid');

        $fail_at = '';
        my $output;
        ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, { force => 1, $retry->%* });
        is($err, '', "$what succeeds") or diag($output);
        is(pending_uid_of(100), undef, "$what: pending uid is removed");
        if ($retry->{unique}) {
            is(stored_uid_of(100), $leftover, "$what: uid of the backup is not adopted");
        } else {
            is(stored_uid_of(100), $UID_BACKUP, "$what: uid of the backup is adopted");
        }
    }
};

subtest 'a failed adoption keeps the pending uid' => sub {
    QemuServerTest::FakeCFS::reset();

    $QemuServerTest::FakeCFS::lock_domain_error =
        "cfs-lock 'domain-guest-identity' error: no quorum!\n";
    my ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, {});
    $QemuServerTest::FakeCFS::lock_domain_error = undef;
    is($err, '', 'restore succeeds') or diag($output);
    my ($kept) = $output =~ $ADOPT_FAILED;
    ok(defined($kept), 'failed adoption is a warning') or diag($output);
    isnt(stored_uid_of(100), $UID_BACKUP, 'VM has a uid of its own');
    is($kept, stored_uid_of(100), 'warning names the uid that the VM keeps');
    is(pending_uid_of(100), $UID_BACKUP, 'nothing decided, pending uid stays');

    ($err, $output) = restore_api('pbs', $BACKUP_WITH_UID, { force => 1 });
    is($err, '', 'restore of the backup again is not refused') or diag($output);
    is(stored_uid_of(100), $UID_BACKUP, 'uid of the backup is adopted');
};

subtest 'config of a VM left behind shows its stored identity' => sub {
    failed_live_restore();
    my $meta = PVE::QemuConfig->load_config(100)->{meta};

    my $conf = PVE::API2::Qemu->vm_config({ node => 'localhost', vmid => 100 });
    is($conf->{meta}, $meta, 'config with pending changes applied: stored identity');
    $conf = PVE::API2::Qemu->vm_config({ node => 'localhost', vmid => 100, current => 1 });
    is($conf->{meta}, $meta, 'current config: stored identity');

    my $pending = PVE::API2::Qemu->vm_pending({ node => 'localhost', vmid => 100 });
    my ($item) = grep { $_->{key} eq 'meta' } $pending->@*;
    is($item->{value}, $meta, 'pending view: current value');
    is($item->{pending}, "uid=$UID_BACKUP", 'pending view: pending uid');
};

subtest 'removing the pending uid keeps an identity that the parser cannot read' => sub {
    QemuServerTest::FakeCFS::reset();

    # a member of a newer version makes the parser drop the whole property
    my $target_meta = "creation-qemu=10.0.0,ctime=1700000000,future-member=1,"
        . "rtime=1700000000000,uid=$UID_TARGET";
    QemuServerTest::FakeCFS::set_config(
        100,
        "memory: 512\nmeta: $target_meta\n\n[PENDING]\nmeta: uid=$UID_BACKUP\n",
    );
    my $reservation = {
        existed => 1,
        previous => { uid => $UID_TARGET, rtime => 1700000000000 },
        'previous-pending-uid' => $UID_BACKUP,
        assigned => { uid => $UID_TARGET, rtime => 1700000000000 },
    };
    my $res;
    {
        local $SIG{__WARN__} = sub { };
        $res =
            PVE::GuestIdentity::adopt('PVE::QemuConfig', 100, 'cccccccccccccccccccc', $reservation);
    }
    is($res->{result}, 'kept', 'identity of another backup is not adopted');
    is(stored_uid_of(100), $UID_TARGET, 'stored identity is kept');
    is(pending_uid_of(100), undef, 'pending uid is removed');
};

# vzdump never archives pending changes, a crafted backup must not bring any along
for my $type (sort keys $ARCHIVES->%*) {
    subtest "$type: pending changes of the backup are dropped" => sub {
        QemuServerTest::FakeCFS::reset();

        my $crafted = $BACKUP_WITH_UID
            . "\n[PENDING]\nargs: -device foo\nhostpci0: 0000:01:00.0\nmeta: uid=$UID_TARGET\n";
        my ($err, $output) = restore_api($type, $crafted, {});
        is($err, '', 'restore succeeds') or diag($output);
        my @writes = $QemuServerTest::FakeCFS::written->{100}->@*;
        ok(!grep({ m/^(args|hostpci0):|uid=$UID_TARGET/m } @writes), 'no write has them');
        unlike(
            $QemuServerTest::FakeCFS::configs->{100},
            qr/^\[PENDING\]/m,
            'no pending section',
        );
    };
}

# Once a write of the config of VMID 100 has the pending uid of the backup, all later writes of the
# restore have it, so that the VM keeps it whenever the restore stops. Only the adoption removes it.
for my $type (@IDENTITY_ARCHIVES, 'pbs live') {
    for my $target (undef, $TARGET_CONF_NO_UID) {
        my $what = $type . ($target ? ', in place over a VM without uid' : ', free VMID');

        subtest "$what: every write of the restore keeps the pending uid" => sub {
            QemuServerTest::FakeCFS::reset();
            QemuServerTest::FakeCFS::set_config(100, $target) if $target;

            my $param = { $target ? (force => 1) : () };
            $param->{'live-restore'} = 1 if $type eq 'pbs live';
            my ($err, $output) = restore_api($type =~ s/ live$//r, $BACKUP_WITH_UID, $param);
            is($err, '', 'restore succeeds') or diag($output);
            like($output, $ADOPTED, 'uid of the backup is adopted');

            my @writes = $QemuServerTest::FakeCFS::written->{100}->@*;
            my $last = pop(@writes);
            my $first = 0;
            $first++ while $first < @writes && $writes[$first] !~ m/^\[PENDING\]/m;
            ok($first < @writes, 'pending uid is written') or return;
            is(
                scalar(
                    grep { m/^\[PENDING\]\nmeta: uid=$UID_BACKUP$/m }
                        @writes[$first .. $#writes]
                ),
                scalar(@writes) - $first,
                'all later writes keep it',
            );
            unlike($last, qr/^\[PENDING\]/m, 'adoption removes it');
        };
    }
}

$fail_at = '';

done_testing();
