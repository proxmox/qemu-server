package PVE::QemuServer::StateFile;

use strict;
use warnings;

use PVE::Cluster;
use PVE::Network;

sub get_migration_ip {
    my ($nodename, $cidr) = @_;

    if (!defined($cidr)) {
        my $dc_conf = PVE::Cluster::cfs_read_file('datacenter.cfg');
        $cidr = $dc_conf->{migration}->{network};
    }

    if (defined($cidr)) {
        my $ips = PVE::Network::get_local_ip_from_cidr($cidr);

        die "could not get IP: no address configured on local node for network '$cidr'\n"
            if scalar(@$ips) == 0;

        die "could not get IP: multiple addresses configured on local node for network '$cidr'\n"
            if scalar(@$ips) > 1;

        return $ips->[0];
    }

    return PVE::Cluster::remote_node_ip($nodename, 1);
}

# $migration_ip must be defined if using insecure TCP migration
sub statefile_cmdline_option {
    my ($storecfg, $vmid, $statefile, $migration_type, $migration_ip) = @_;

    my $statefile_is_a_volume = 0;
    my $res = {};
    my $cmd = [];

    if ($statefile eq 'tcp') {
        my $migrate = $res->{migrate} = { proto => 'tcp' };
        $migrate->{addr} = "localhost";

        die "no migration type set\n" if !defined($migration_type);

        if ($migration_type eq 'insecure') {
            $migrate->{addr} = $migration_ip // die "internal error - no migration IP";
            $migrate->{addr} = "[$migrate->{addr}]" if Net::IP::ip_is_ipv6($migrate->{addr});
        }

        # see #4501: port reservation should be done close to usage - tell QEMU where to listen
        # via QMP later
        push @$cmd, '-incoming', 'defer';
        push @$cmd, '-S';

    } elsif ($statefile eq 'unix') {
        # should be default for secure migrations as a ssh TCP forward
        # tunnel is not deterministic reliable ready and fails regurarly
        # to set up in time, so use UNIX socket forwards
        my $migrate = $res->{migrate} = { proto => 'unix' };
        $migrate->{addr} = "/run/qemu-server/$vmid.migrate";
        unlink $migrate->{addr};

        $migrate->{uri} = "unix:$migrate->{addr}";
        push @$cmd, '-incoming', $migrate->{uri};
        push @$cmd, '-S';

    } elsif (-e $statefile) {
        push @$cmd, '-loadstate', $statefile;
    } else {
        my $statepath = PVE::Storage::path($storecfg, $statefile);
        $statefile_is_a_volume = 1;
        push @$cmd, '-loadstate', $statepath;
    }

    return ($cmd, $res->{migrate}, $statefile_is_a_volume);
}

1;
