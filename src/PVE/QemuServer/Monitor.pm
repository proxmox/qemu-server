package PVE::QemuServer::Monitor;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::QemuServer::Helpers;
use PVE::QMPClient;

use base 'Exporter';
our @EXPORT_OK = qw(
    mon_cmd
    qmp_cmd
    qsd_qmp_peer
    vm_qmp_peer
);

=head3 qmp_cmd

    my $peer = { name => $name, id => $id, type => $type };
    my $result = qmp_cmd($peer, $execute, %arguments);

Execute the C<$qmp_command_name> with arguments C<%params> for the peer C<$peer>. The type C<$type>
of the peer can be C<qmp> for the QEMU instance of the VM,  C<qga> for the guest agent of the VM or
C<qsd> for the QEMU storage daemon associated to the VM. Dies if the VM is not running or the
monitor socket cannot be reached, even if the C<noerr> argument is used. Returns the structured
result from the QMP side converted from JSON to structured Perl data. In case the C<noerr> argument
is used and the QMP command failed or timed out, the result is a hash reference with an C<error> key
containing the error message.

Parameters:

=over

=item C<$peer>: The peer to communicate with. A hash reference with:

=over

=item C<$name>: Name of the peer used in error messages.

=item C<$id>: Identifier for the peer. The pair C<($id, $type)> uniquely identifies a peer.

=item C<$type>: Type of the peer to communicate with. This can be C<qmp> for the VM's QEMU instance,
C<qga> for the VM's guest agent or C<qsd> for the QEMU storage daemon associated to the VM.

=back

=item C<$execute>: The QMP command name.

=item C<%arguments>: Additional arguments for the QMP command. The following custom arguments are
not part of the QMP schema and supported for all commands:

=over

=item C<timeout>: wait at most for this amount of time. If there was no actual error, the QMP/QGA
command will still continue to be executed even after the timeout reached.

=item C<noerr>: do not die when the command gets an error or the timeout is hit. The caller needs to
handle the error that is returned as a structured result.

=back

=back

=cut

sub qmp_cmd {
    my ($peer, $execute, %arguments) = @_;

    my $cmd = { execute => $execute, arguments => \%arguments };

    my $res;

    my ($noerr, $timeout);
    if ($cmd->{arguments}) {
        ($noerr, $timeout) = delete($cmd->{arguments}->@{qw(noerr timeout)});
    }

    eval {
        if ($peer->{type} eq 'qmp' || $peer->{type} eq 'qga') {
            die "$peer->{name} not running\n"
                if !PVE::QemuServer::Helpers::vm_running_locally($peer->{id});
        } elsif ($peer->{type} eq 'qsd') {
            die "$peer->{name} not running\n"
                if !PVE::QemuServer::Helpers::qsd_running_locally($peer->{id});
        } else {
            die "qmp_cmd - unknown peer type $peer->{type}\n";
        }

        my $sname = PVE::QemuServer::Helpers::qmp_socket($peer);
        if (-e $sname) { # test if VM is reasonably new and supports qmp/qga
            my $qmpclient = PVE::QMPClient->new();

            $res = $qmpclient->cmd($peer, $cmd, $timeout, $noerr);
        } else {
            die "unable to open monitor socket\n";
        }
    };
    if (my $err = $@) {
        syslog("err", "$peer->{name} $peer->{type} command failed - $err");
        die $err;
    }

    return $res;
}

sub vm_qmp_peer {
    my ($vmid) = @_;

    return { name => "VM $vmid", id => $vmid, type => 'qmp' };
}

sub qsd_qmp_peer {
    my ($id) = @_;

    return { name => "QEMU storage daemon $id", id => $id, type => 'qsd' };
}

sub qsd_cmd {
    my ($id, $execute, %params) = @_;

    return qmp_cmd(qsd_qmp_peer($id), $execute, %params);
}

sub mon_cmd {
    my ($vmid, $execute, %params) = @_;

    my $type = ($execute =~ /^guest\-+/) ? 'qga' : 'qmp';

    return qmp_cmd({ name => "VM $vmid", id => $vmid, type => $type }, $execute, %params);
}

sub hmp_cmd {
    my ($vmid, $cmdline, $timeout) = @_;

    return qmp_cmd(
        vm_qmp_peer($vmid), 'human-monitor-command',
        'command-line' => $cmdline,
        timeout => $timeout,
    );
}

sub object_commandline {
    my ($qemu_binary_version, $chardev) = @_;

    if (PVE::QemuServer::Helpers::min_version($qemu_binary_version, 11, 1)) {
        # use new style to avoid deprecation warning
        return ['-object', "monitor-qmp,chardev=${chardev},id=monitor-${chardev}"];
    }

    return ['-mon', "chardev=${chardev},mode=control"];
}

1;
