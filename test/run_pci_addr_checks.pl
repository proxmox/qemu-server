#!/usr/bin/perl

use strict;
use warnings;
use experimental 'smartmatch';

use lib qw(..);

use Test::More;

use PVE::Tools qw(file_get_contents);
use PVE::QemuServer::PCI;

# not our format but that what QEMU gets passed with '-readconfig'
sub slurp_qemu_config {
    my ($fn) = @_;

    my $raw = file_get_contents($fn);

    my $lineno = 0;
    my $cfg = {};
    my $group;
    my $skip_to_next_group;
    while ($raw =~ /^\h*(.*?)\h*$/gm) {
	my $line = $1;
	$lineno++;
	next if !$line || $line =~ /^#/;

	# tried to follow qemu's qemu_config_parse function
	if ($line =~ /\[(\S{1,63}) "([^"\]]{1,63})"\]/) {
	    $group = $2;
	    $skip_to_next_group = 0;
	    if ($1 ne 'device') {
		$group = undef;
		$skip_to_next_group = 1;
	    }
	} elsif ($line =~ /\[([^\]]{1,63})\]/) {
	    $group = undef;
	    $skip_to_next_group = 1;
	} elsif ($group) {
	    if ($line =~ /(\S{1,63}) = "([^\"]{1,1023})"/) {
		my ($k, $v) = ($1, $2);
		$cfg->{$group}->{$k} = $v;
	    } else {
		print "ignoring $fn:$lineno: $line\n";
	    }
	} else {
	    warn "ignore $fn:$lineno, currently no group\n" if !$skip_to_next_group;
	}
    }

    #use Data::Dumper;
    #print Dumper($cfg) . "\n";
}
# FIXME: TODO! read those configs and check for conflicts!
# q35 stuff with PCIe and others with PCI
# slurp_qemu_config("../pve-q35.cfg");

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
