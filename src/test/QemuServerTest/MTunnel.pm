package QemuServerTest::MTunnel;

# Runs the migration tunnel endpoint of the API for tests, with a socket pair as connection and the
# listening socket in a directory of the test.

use v5.36;

use File::Temp qw(tempdir);
use IO::Handle;
use JSON;
use Socket;
use Test::MockModule;

use PVE::RPCEnvironment;
use PVE::Tools;

use PVE::QemuServer::Helpers;

use PVE::API2::Qemu;

use QemuServerTest::Utils qw(capture_output);

use base 'Exporter';

our @EXPORT_OK = qw(
    run_mtunnel
);

# the endpoint removes its socket path and changes its owner, which must not hit one of the host
my $mtunnel_dir = tempdir('mtunnel-XXXXXX', DIR => '.', CLEANUP => 1);
our $helpers_module = Test::MockModule->new('PVE::QemuServer::Helpers');
$helpers_module->mock(
    mtunnel_socket => sub {
        my ($vmid) = @_;
        return "$mtunnel_dir/$vmid.mtunnel";
    },
);

package TestListenSocket {

    sub accept($self) {
        return $self->{conn} // die "got timeout\n";
    }
}

# Runs the migration tunnel endpoint for $vmid with the commands @$commands from the source side
# and returns the decoded replies, the task output and the error of the task. Without $commands, no
# connection arrives.
sub run_mtunnel($vmid, $commands) {
    socketpair(my $client, my $server, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair failed - $!\n";
    $client->autoflush(1);

    print $client encode_json($_) . "\n" for ($commands // [])->@*;
    shutdown($client, 1);

    my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
    $rpcenv_module->mock(
        fork_worker => sub {
            my ($self, $type, $id, $user, $code) = @_;
            $code->('UPID:test');
            return 'UPID:test';
        },
    );
    my $access_control_module = Test::MockModule->new('PVE::AccessControl');
    $access_control_module->mock(assemble_tunnel_ticket => sub { return 'ticket'; });
    my $socket_module = Test::MockModule->new('IO::Socket::UNIX');
    $socket_module->mock(
        new => sub {
            my ($class, %param) = @_;
            PVE::Tools::file_set_contents($param{Local}, '');
            return bless { conn => $commands ? $server : undef }, 'TestListenSocket';
        },
    );

    my $err;
    my $output = capture_output(sub {
        eval { PVE::API2::Qemu->mtunnel({ node => 'localhost', vmid => $vmid }) };
        $err = $@;
    });
    close($server);

    my $replies = [];
    while (defined(my $line = <$client>)) {
        push $replies->@*, decode_json($line);
    }

    return ($replies, $output, $err);
}

1;
