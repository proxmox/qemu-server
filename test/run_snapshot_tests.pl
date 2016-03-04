#!/usr/bin/perl

use strict;
use warnings;

use TAP::Harness;

my $harness = TAP::Harness->new( { "verbosity" => -2 });
$harness->runtests( "snapshot-test.pm");
system( "rm -rf snapshot-working/");
