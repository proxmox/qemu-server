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

1;
