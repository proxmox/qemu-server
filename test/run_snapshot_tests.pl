#!/usr/bin/perl

use strict;
use warnings;

use TAP::Harness;

my $harness = TAP::Harness->new( { "verbosity" => -2 });
my $res = $harness->runtests( "snapshot-test.pm");
system( "rm -rf snapshot-working/");
exit -1 if $res->{failed};
