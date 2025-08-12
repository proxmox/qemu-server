package PVE::QemuServer::Monitor;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::QemuServer::Helpers;
use PVE::QMPClient;

use base 'Exporter';
our @EXPORT_OK = qw(
    mon_cmd
);

=head3 qmp_cmd

    my $cmd = { execute => $qmp_command_name, arguments => \%params };
    my $result = qmp_cmd($vmid, $cmd);

Execute the C<$qmp_command_name> with arguments C<%params> for VM C<$vmid>. Dies if the VM is not
running or the monitor socket cannot be reached, even if the C<noerr> argument is used. Returns the
structured result from the QMP side converted from JSON to structured Perl data. In case the
C<noerr> argument is used and the QMP command failed or timed out, the result is a hash reference
with an C<error> key containing the error message.

Parameters:

=over

=item C<$vmid>: The ID of the virtual machine.

=item C<$cmd>: Hash reference containing the QMP command name for the C<execute> key and additional
arguments for the QMP command under the C<arguments> key. The following custom arguments are not
part of the QMP schema and supported for all commands:

=over

=item C<timeout>: wait at most for this amount of time. If there was no actual error, the QMP/QGA
command will still continue to be executed even after the timeout reached.

=item C<noerr>: do not die when the command gets an error or the timeout is hit. The caller needs to
handle the error that is returned as a structured result.

=back

=back

=cut

sub qmp_cmd {
    my ($vmid, $cmd) = @_;

    my $res;

    my ($noerr, $timeout);
    if ($cmd->{arguments}) {
        ($noerr, $timeout) = delete($cmd->{arguments}->@{qw(noerr timeout)});
    }

    eval {
        die "VM $vmid not running\n" if !PVE::QemuServer::Helpers::vm_running_locally($vmid);
        my $sname = PVE::QemuServer::Helpers::qmp_socket($vmid);
        if (-e $sname) { # test if VM is reasonably new and supports qmp/qga
            my $qmpclient = PVE::QMPClient->new();

            $res = $qmpclient->cmd($vmid, $cmd, $timeout, $noerr);
        } else {
            die "unable to open monitor socket\n";
        }
    };
    if (my $err = $@) {
        syslog("err", "VM $vmid qmp command failed - $err");
        die $err;
    }

    return $res;
}

sub mon_cmd {
    my ($vmid, $execute, %params) = @_;

    my $cmd = { execute => $execute, arguments => \%params };

    return qmp_cmd($vmid, $cmd);
}

sub hmp_cmd {
    my ($vmid, $cmdline, $timeout) = @_;

    my $cmd = {
        execute => 'human-monitor-command',
        arguments => { 'command-line' => $cmdline, timeout => $timeout },
    };

    return qmp_cmd($vmid, $cmd);
}

1;
