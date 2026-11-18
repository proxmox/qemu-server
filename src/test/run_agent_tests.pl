#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::QemuServer::Agent;

# agent property string, override, expected result
my $sync_time_tests = [
    [undef, undef, 0],
    [undef, 1, 0],
    ['0,sync-time-on-resume=1', undef, 0],
    ['0', 1, 0],
    ['1', undef, 0],
    ['1,sync-time-on-resume=1', undef, 1],
    ['1,sync-time-on-resume=yes', undef, 1],
    ['1,sync-time-on-resume=1', 0, 0],
    ['1', 1, 1],
];

for my $test ($sync_time_tests->@*) {
    my ($agent, $override, $expected) = $test->@*;
    my $name = sprintf(
        "sync time with agent '%s' and override '%s'",
        $agent // 'unset',
        $override // 'unset',
    );
    my $sync = PVE::QemuServer::Agent::should_sync_time_on_resume($agent, $override);
    is($sync, $expected, $name);
}

done_testing();
