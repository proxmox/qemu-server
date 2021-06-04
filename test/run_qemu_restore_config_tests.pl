#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::MockModule;
use Test::More;
use Test::MockModule;

use File::Basename;

use PVE::QemuServer;
use PVE::Tools qw(dir_glob_foreach file_get_contents);

my $INPUT_DIR = './restore-config-input';
my $EXPECTED_DIR = './restore-config-expected';

my $pve_cluster_module = Test::MockModule->new('PVE::Cluster');
$pve_cluster_module->mock(
    cfs_read_file => sub {
	return {};
    },
);

# NOTE update when you add/remove tests
plan tests => 4;

my $cfs_mock = Test::MockModule->new("PVE::Cluster");
$cfs_mock->mock(
    cfs_read_file => sub {
	my ($file) = @_;

	if ($file eq 'datacenter.cfg') {
	    return {};
	} else {
	    die "'cfs_read_file' called - missing mock?\n";
	}
    },
);

dir_glob_foreach('./restore-config-input', '[0-9]+.conf', sub {
    my ($file) = @_;

    my $vmid = basename($file, ('.conf'));

    my $fh = IO::File->new("${INPUT_DIR}/${file}", "r") or
	die "unable to read '$file' - $!\n";

    my $map = {};
    my $disknum = 0;

    # NOTE For now, the map is hardcoded to a file-based 'target' storage.
    # In the future, the test could be extended to include parse_backup_hints
    # and restore_allocate_devices. Even better if the config-related logic from
    # the restore_XYZ_archive functions could become a separate function.
    while (defined(my $line = <$fh>)) {
	if ($line =~ m/^\#qmdump\#map:(\S+):(\S+):(\S*):(\S*):$/) {
	    my ($drive, undef, $storeid, $fmt) = ($1, $2, $3, $4);

	    $fmt ||= 'raw';

	    $map->{$drive} = "target:${vmid}/vm-${vmid}-disk-${disknum}.${fmt}";
	    $disknum++;
	}
    }

    $fh->seek(0, 0) or die "seek failed - $!\n";

    my $got = '';
    my $cookie = { netcount => 0 };

    while (defined(my $line = <$fh>)) {
	$got .= PVE::QemuServer::restore_update_config_line(
	    $cookie,
	    $map,
	    $line,
	    0,
	);
    }

    my $expected = file_get_contents("${EXPECTED_DIR}/${file}");

    is_deeply($got, $expected, $file);
});

done_testing();
