package PVE::QemuServer::CGroup;

use strict;
use warnings;

use Net::DBus qw(dbus_uint64 dbus_boolean);

use PVE::Systemd;
use base('PVE::CGroup');

sub get_subdir {
    my ($self, $controller, $limiting) = @_;
    my $vmid = $self->{vmid};
    return "qemu.slice/$vmid.scope/";
}

sub scope {
    my ($self) = @_;
    return $self->{vmid} . '.scope';
}

my sub set_unit_properties : prototype($$) {
    my ($self, $properties) = @_;

    PVE::Systemd::systemd_call(sub {
	my ($if, $reactor, $finish_cb) = @_;
	$if->SetUnitProperties($self->scope(), dbus_boolean(1), $properties);
	return 1;
    });
}

# Update the 'cpulimit' of VM.
# Note that this is now the systemd API and we expect a value for `CPUQuota` as
# set on VM startup, rather than cgroup values.
sub change_cpu_quota {
    my ($self, $quota, $period) = @_;

    die "period is not controlled for VMs\n" if defined($period);

    $quota = dbus_uint64(defined($quota) ? ($quota * 10_000) : -1);
    set_unit_properties($self, [ [ CPUQuotaPerSecUSec => $quota ] ]);

    return;
}

# Update the 'cpuunits' of a VM.
# Note that this is now the systemd API and we expect a value for `CPUQuota` as
# set on VM startup, rather than cgroup values.
sub change_cpu_shares {
    my ($self, $shares) = @_;

    $shares //= -1;

    if (PVE::CGroup::cgroup_mode() == 2) {
	set_unit_properties($self, [ [ CPUWeight => dbus_uint64($shares) ] ]);
    } else {
	set_unit_properties($self, [ [ CPUShares => dbus_uint64($shares) ] ]);
    }

    return;
}

1;
