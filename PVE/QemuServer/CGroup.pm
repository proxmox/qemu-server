package PVE::QemuServer::CGroup;

use strict;
use warnings;
use PVE::CGroup;
use base('PVE::CGroup');

sub get_subdir {
    my ($self, $controller, $limiting) = @_;
    my $vmid = $self->{vmid};
    return "qemu.slice/$vmid.scope/";
}

1;
