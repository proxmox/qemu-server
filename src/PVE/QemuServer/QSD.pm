package PVE::QemuServer::QSD;

use v5.36;

use JSON qw(to_json);

use PVE::JSONSchema qw(json_bool);
use PVE::SafeSyslog qw(syslog);
use PVE::Storage;
use PVE::Tools;

use PVE::QemuServer::Blockdev;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;

=head3 start

    PVE::QemuServer::QSD::start($id);

Start a QEMU storage daemon instance with ID C<$id>.

=cut

sub start($id) {
    my $name = "QEMU storage daemon $id";

    # If something is still mounted, that could block the new instance, try to clean up first.
    PVE::QemuServer::Helpers::qsd_fuse_export_cleanup_files($id);

    my $qmp_socket_path =
        PVE::QemuServer::Helpers::qmp_socket({ name => $name, id => $id, type => 'qsd' });
    my $pidfile = PVE::QemuServer::Helpers::qsd_pidfile_name($id);

    my $cmd = [
        'qemu-storage-daemon',
        '--daemonize',
        '--chardev',
        "socket,id=qmp,path=$qmp_socket_path,server=on,wait=off",
        '--monitor',
        'chardev=qmp,mode=control',
        '--pidfile',
        $pidfile,
    ];

    PVE::Tools::run_command($cmd);

    my $pid = PVE::QemuServer::Helpers::qsd_running_locally($id);
    syslog("info", "$name started with PID $pid.");

    return;
}

=head3 add_fuse_export

    my $path = PVE::QemuServer::QSD::add_fuse_export($id, $drive, $name);

Attach drive C<$drive> to the storage daemon with ID C<$id> and export it with name C<$name> via
FUSE. Returns the path to the file representing the export.

=cut

sub add_fuse_export($id, $drive, $name) {
    my $storage_config = PVE::Storage::config();

    PVE::Storage::activate_volumes($storage_config, [$drive->{file}]);

    my ($node_name, $read_only) =
        PVE::QemuServer::Blockdev::attach($storage_config, $id, $drive, { qsd => 1 });

    my $fuse_path = PVE::QemuServer::Helpers::qsd_fuse_export_path($id, $name);
    PVE::Tools::file_set_contents($fuse_path, '', 0600); # mountpoint file needs to exist up-front

    my $export = {
        type => 'fuse',
        id => "$name",
        mountpoint => $fuse_path,
        'node-name' => "$node_name",
        writable => json_bool(!$read_only),
        growable => JSON::false,
        'allow-other' => 'off',
    };

    PVE::QemuServer::Monitor::qsd_cmd($id, 'block-export-add', $export->%*);

    return $fuse_path;
}

=head3 quit

    PVE::QemuServer::QSD::quit($id);

Shut down the QEMU storage daemon with ID C<$id> and cleans up its PID file and socket. Waits for 60
seconds for clean shutdown, then sends SIGTERM and waits an additional 10 seconds before sending
SIGKILL.

=cut

sub quit($id) {
    my $name = "QEMU storage daemon $id";

    eval { PVE::QemuServer::Monitor::qsd_cmd($id, 'quit'); };
    my $qmp_err = $@;
    warn "$name failed to handle 'quit' - $qmp_err" if $qmp_err;

    my $count = $qmp_err ? 60 : 0; # can't wait for QMP 'quit' to terminate the process if it failed
    my $pid = PVE::QemuServer::Helpers::qsd_running_locally($id);
    while ($pid) {
        if ($count == 60) {
            warn "$name still running with PID $pid - terminating now with SIGTERM\n";
            kill 15, $pid;
        } elsif ($count == 70) {
            warn "$name still running with PID $pid - terminating now with SIGKILL\n";
            kill 9, $pid;
            last;
        }

        sleep 1;
        $count++;
        $pid = PVE::QemuServer::Helpers::qsd_running_locally($id);
    }

    unlink PVE::QemuServer::Helpers::qsd_pidfile_name($id);
    unlink PVE::QemuServer::Helpers::qmp_socket({ name => $name, id => $id, type => 'qsd' });

    PVE::QemuServer::Helpers::qsd_fuse_export_cleanup_files($id);

    return;
}

1;
