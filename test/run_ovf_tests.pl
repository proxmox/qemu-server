#!/usr/bin/perl

use strict;
use warnings;
use lib qw(..); # prepend .. to @INC so we use the local version of PVE packages

use FindBin '$Bin';
use PVE::QemuServer::OVF;
use Test::More;

use Data::Dumper;

my $test_manifests = join ('/', $Bin, 'ovf_manifests');

my $win2008 = PVE::QemuServer::OVF::parse_ovf("$test_manifests/Win_2008_R2_two-disks.ovf");
my $win10 = PVE::QemuServer::OVF::parse_ovf("$test_manifests/Win10-Liz.ovf");

print "testing disks\n";

is($win2008->{disks}->[0]->{disk_address}, 'scsi0', 'multidisk vm has the correct first disk controller');
is($win2008->{disks}->[0]->{backing_file}, "$test_manifests/disk1.vmdk", 'multidisk vm has the correct first disk backing device');
is($win2008->{disks}->[0]->{virtual_size}, 2048, 'multidisk vm has the correct first disk size');

is($win2008->{disks}->[1]->{disk_address}, 'scsi1', 'multidisk vm has the correct second disk controller');
is($win2008->{disks}->[1]->{backing_file}, "$test_manifests/disk2.vmdk", 'multidisk vm has the correct second disk backing device');
is($win2008->{disks}->[1]->{virtual_size}, 2048, 'multidisk vm has the correct second disk size');

is($win10->{disks}->[0]->{disk_address}, 'scsi0', 'single disk vm has the correct disk controller');
is($win10->{disks}->[0]->{backing_file}, "$test_manifests/Win10-Liz-disk1.vmdk", 'single disk vm has the correct disk backing device');
is($win10->{disks}->[0]->{virtual_size}, 2048, 'single disk vm has the correct size');

print "\ntesting vm.conf extraction\n";

is($win2008->{qm}->{name}, 'Win2008-R2x64', 'win2008 VM name is correct');
is($win2008->{qm}->{memory}, '2048', 'win2008 VM memory is correct');
is($win2008->{qm}->{cores}, '1', 'win2008 VM cores are correct');

is($win10->{qm}->{name}, 'Win10-Liz', 'win10 VM name is correct');
is($win10->{qm}->{memory}, '6144', 'win10 VM memory is correct');
is($win10->{qm}->{cores}, '4', 'win10 VM cores are correct');

done_testing();
