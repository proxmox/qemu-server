#!/usr/bin/perl

# Tests parsing and writing VM configuration files.
# The parsing part is already covered by the config2command test too, but that only focuses on the
# main section, not other section types and does not also test parsing in strict mode.
#
# If no expected file exists, the input is assumed to be equal to the expected output.
# If $file.strict.error (respectively $file.non-strict.error) exists, it is assumed to be the
# expected error when parsing the config in strict (respectively non-strict) mode.

use strict;
use warnings;

use lib qw(..);

use File::Path qw(make_path remove_tree);

use Test::MockModule;
use Test::More;

use PVE::QemuServer;
use PVE::Tools;

my $INPUT_DIR = './parse-config-input';
my $OUTPUT_DIR = './parse-config-output';
my $EXPECTED_DIR = './parse-config-expected';

# NOTE update when you add/remove tests
plan tests => 2 * 7;

sub run_tests {
    my ($strict) = @_;

    PVE::Tools::dir_glob_foreach('./parse-config-input', '.*\.conf', sub {
	my ($file) = @_;

	my $strict_mode = $strict ? 'strict' : 'non-strict';

	my $expected_err_file = "${EXPECTED_DIR}/${file}.${strict_mode}.error";
	my $expected_err;
	$expected_err = PVE::Tools::file_get_contents($expected_err_file) if -f $expected_err_file;

	my $fake_config_fn ="$file/qemu-server/8006.conf";
	my $input_file = "${INPUT_DIR}/${file}";
	my $input = PVE::Tools::file_get_contents($input_file);
	my $conf = eval {
	    PVE::QemuServer::parse_vm_config($fake_config_fn, $input, $strict);
	};
	if (my $err = $@) {
	    if ($expected_err) {
		is($err, $expected_err, $file);
	    } else {
		note("got unexpected error '$err'");
		fail($file);
	    }
	    return;
	}

	if ($expected_err) {
	    note("expected error for strict mode did not occur: '$expected_err'");
	    fail($file);
	    return;
	}

	my $output = eval { PVE::QemuServer::write_vm_config($fake_config_fn, $conf); };
	if (my $err = $@) {
	    note("got unexpected error '$err'");
	    fail($file);
	    return;
	}

	my $output_file = "${OUTPUT_DIR}/${file}";
	PVE::Tools::file_set_contents($output_file, $output);

	my $expected_file = "${EXPECTED_DIR}/${file}";
	$expected_file = $input_file if !-f $expected_file;

	my $cmd = ['diff', '-u', $expected_file, $output_file];
	if (system(@$cmd) == 0) {
	    pass($file);
	} else {
	    fail($file);
	}
    });
}

make_path(${OUTPUT_DIR});
run_tests(0);
run_tests(1);
remove_tree(${OUTPUT_DIR}) or die "failed to remove output directory\n";

done_testing();
