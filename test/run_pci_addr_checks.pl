#!/usr/bin/perl

use strict;
use warnings;
use experimental 'smartmatch';

use lib qw(..);

use Test::More;

use PVE::QemuServer::PCI;

print "testing PCI(e) address conflicts\n";

# exec tests

#FIXME: make cross PCI <-> PCIe check sense at all??
my $addr_map = {};
my ($fail, $ignored) = (0, 0);
sub check_conflict {
    my ($id, $what) = @_;

    my ($bus, $addr) = $what->@{qw(bus addr)};
    my $full_addr = "$bus:$addr";

    if (defined(my $conflict = $addr_map->{$full_addr})) {
	if (my @ignores = $what->{conflict_ok}) {
	    if ($conflict ~~ @ignores) {
		note("OK: ignore conflict for '$full_addr' between '$id' and '$conflict'");
		$ignored++;
		return;
	    }
	}
	note("ERR: conflict for '$full_addr' between '$id' and '$conflict'");
	$fail++;
    } else {
	$addr_map->{$full_addr} = $id;
    }
}


my $pci_map = PVE::QemuServer::PCI::get_pci_addr_map();
while (my ($id, $what) = each %$pci_map) {
    check_conflict($id, $what);
}

my $pcie_map = PVE::QemuServer::PCI::get_pcie_addr_map();
while (my ($id, $what) = each %$pcie_map) {
    check_conflict($id, $what);
}

if ($fail) {
    fail("PCI(e) address conflict check, ignored: $ignored, conflicts: $fail");
} else {
    pass("PCI(e) address conflict check, ignored: $ignored");
}

done_testing();
