#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use Test::MockModule;
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

# The expected commands with the agent's replies, in order. A reference to a string is raised as
# the error of the command, anything else is returned as its result.
my $thaw_tests = [
    {
        name => 'thaw succeeds',
        replies => [['guest-fsfreeze-thaw', 1]],
        dies => 0,
    },
    {
        name => 'thaw fails, guest still frozen, retry succeeds',
        replies => [
            ['guest-fsfreeze-thaw', \"got wrong command id\n"],
            ['guest-fsfreeze-status', 'frozen'],
            ['guest-fsfreeze-thaw', 1],
        ],
        dies => 0,
    },
    {
        name => 'thaw fails, guest still frozen, retry fails',
        replies => [
            ['guest-fsfreeze-thaw', \"got wrong command id\n"],
            ['guest-fsfreeze-status', 'frozen'],
            ['guest-fsfreeze-thaw', \"thaw timeout\n"],
        ],
        dies => qr/^thaw timeout$/,
    },
    {
        name => 'thaw fails, guest thawed, no retry',
        replies => [
            ['guest-fsfreeze-thaw', \"thaw timeout\n"], ['guest-fsfreeze-status', 'thawed'],
        ],
        dies => qr/^thaw timeout$/,
    },
    {
        name => 'thaw fails, status query fails, no retry',
        replies => [
            ['guest-fsfreeze-thaw', \"thaw timeout\n"],
            ['guest-fsfreeze-status', \"status timeout\n"],
        ],
        dies => qr/^thaw timeout$/,
    },
    {
        name => 'thaw returns an agent error, guest still frozen, retry succeeds',
        replies => [
            ['guest-fsfreeze-thaw', { error => { desc => 'thaw hook failed' } }],
            ['guest-fsfreeze-status', 'frozen'],
            ['guest-fsfreeze-thaw', 1],
        ],
        dies => 0,
    },
];

my $monitor_module = Test::MockModule->new('PVE::QemuServer::Monitor');

for my $test ($thaw_tests->@*) {
    my @commands;
    $monitor_module->redefine(
        mon_cmd => sub {
            my ($vmid, $execute) = @_;
            my $answer = ($test->{replies}->[scalar(@commands)] // [])->[1];
            push @commands, $execute;
            die $answer->$* if ref($answer) eq 'SCALAR';
            return $answer;
        },
    );

    my $output = '';
    open(my $fh, '>', \$output) or die "unable to capture output - $!\n";
    my $stdout = select($fh);
    eval { PVE::QemuServer::Agent::guest_fs_thaw(100) };
    my $err = $@;
    select($stdout);

    if ($test->{dies}) {
        like($err =~ s/\n\z//r, $test->{dies}, "$test->{name}: dies");
    } else {
        is($err, '', "$test->{name}: does not die");
    }
    my $expected_commands = [map { $_->[0] } $test->{replies}->@*];
    is_deeply(\@commands, $expected_commands, "$test->{name}: issued commands");
}

done_testing();
