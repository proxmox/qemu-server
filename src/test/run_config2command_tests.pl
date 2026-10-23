#!/usr/bin/perl

use v5.36;

use lib qw(.. .);

use Test::More;
use Test::MockModule;

use PVE::File qw(file_get_contents file_set_contents);
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Monitor;
use PVE::QemuServer::QMPHelpers;
use PVE::QemuServer::CPUConfig;
use PVE::Storage;

use QemuServerTest::CommandLineMocks qw(get_storage_config get_test_qemu_version set_test_env);
use QemuServerTest::Utils qw(diff);

my $vmid = 8006;

my $current_test; # = {
#   description => 'Test description', # if available
#   qemu_version => '2.12',
#   host_arch => 'HOST_ARCH',
#   'host-cpu-vendor' => 'HOST_CPU_VENDOR',
#   expected_error => 'error message',
#   expected_warning => 'warning message',
#   config => { config hash },
#   expected => [ expected outcome cmd line array ],
# };

# use the config description to allow changing environment, fields are:
#   TEST: A single line describing the test, gets outputted
#   QEMU_VERSION: \d+\.\d+(\.\d+)? (defaults to current version)
#   HOST_ARCH: x86_64 | aarch64 (default to x86_64, to make tests stable)
#   HOST_CPU_VENDOR: AuthenticAMD | GenuineIntel | etc. (defaults to GenuineIntel)
#   EXPECT_ERROR: <error message> For negative tests
#   EXPECT_WARN(ING): <warning message> that is expected
#   HW_CAPABILITIES: <cpu-type-or-json-string> to defined the HW caps the test should expose
# all fields are optional
sub parse_test($config_fn) {
    $current_test = {}; # reset

    my $fake_config_fn = "$config_fn/qemu-server/8006.conf";
    my $config_raw = file_get_contents($config_fn);
    my $config = PVE::QemuServer::parse_vm_config($fake_config_fn, $config_raw);

    $current_test->{config} = $config;

    my $description = $config->{description} // '';

    while ($description =~ /^\h*(.*?)\h*$/gm) {
        my $line = $1;
        next if !$line || $line =~ /^#/;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;

        if ($line =~ /^TEST:\s*(.*)\s*$/) {
            $current_test->{description} = "$1";
        } elsif ($line =~ /^QEMU_VERSION:\s*(.*)\s*$/) {
            $current_test->{qemu_version} = "$1";
        } elsif ($line =~ /^HOST_ARCH:\s*(.*)\s*$/) {
            $current_test->{host_arch} = "$1";
        } elsif ($line =~ /^HOST_CPU_VENDOR:\s*(.*)\s*$/) {
            $current_test->{'host-cpu-vendor'} = "$1";
        } elsif ($line =~ /^EXPECT_ERROR:\s*(.*)\s*$/) {
            $current_test->{expect_error} = "$1";
        } elsif ($line =~ /^EXPECT_WARN(?:ING)?:\s*(.*)\s*$/) {
            $current_test->{expect_warning} = "$1";
        } elsif ($line =~ /^HW_CAPABILITIES:\s*(.*)\s*$/) {
            $current_test->{hw_capabilities} = "$1"; # either a CPU from above hash or raw JSON
        }
    }

    $config_fn =~ /([^\/]+)$/;
    my $testname = "$1";
    if (my $desc = $current_test->{description}) {
        $testname = "'$testname' - $desc";
    }
    $current_test->{testname} = $testname;

    set_test_env($current_test);

    PVE::QemuServer::CPUConfig::initialize_cpu_models();
}

my $qemu_server_config;
$qemu_server_config = Test::MockModule->new('PVE::QemuConfig');
$qemu_server_config->mock(
    load_config => sub {
        my ($class, $vmid, $node) = @_;

        return $current_test->{config};
    },
);

my $qemu_monitor_module;
$qemu_monitor_module = Test::MockModule->new('PVE::QemuServer::Monitor');
$qemu_monitor_module->mock(
    mon_cmd => sub {
        my ($id, $cmd) = @_;

        die "invalid vmid: $id (expected: $vmid)"
            if $id != $vmid;

        if ($cmd eq 'query-version') {
            my $ver = get_test_qemu_version();
            $ver =~ m/(\d+)\.(\d+)(?:\.(\d+))?/;
            return {
                qemu => {
                    major => $1,
                    minor => $2,
                    micro => $3,
                },
            };
        }

        die "unexpected QMP command: '$cmd'";
    },
);

$SIG{__WARN__} = sub {
    my $warning = shift;
    chomp $warning;
    if (my $warn_expect = $current_test->{expect_warning}) {
        if ($warn_expect ne $warning) {
            fail($current_test->{testname});
            note("warning does not match expected error: '$warning' != '$warn_expect'");
        } else {
            note("got expected warning '$warning'");
            return;
        }
    }

    fail($current_test->{testname});
    note("got unexpected warning '$warning'");
};

sub do_test($config_fn) {
    die "no such input test config: $config_fn\n" if !-f $config_fn;

    parse_test $config_fn;

    my $testname = $current_test->{testname};

    my $storecfg = get_storage_config();

    my $cmdline = eval { PVE::QemuServer::vm_commandline($storecfg, $vmid) };
    my $err = $@;

    if (my $err_expect = $current_test->{expect_error}) {
        if (!$err) {
            fail("$testname");
            note("did NOT get any error, but expected error: $err_expect");
            return;
        }
        chomp $err;
        if ($err ne $err_expect) {
            fail("$testname");
            note("error does not match expected error: '$err' !~ '$err_expect'");
        } else {
            pass("$testname");
        }
        return;
    } elsif ($err) {
        fail("$testname");
        note("got unexpected error: $err");
        return;
    }

    # check if QEMU version set correctly and test version_cmp
    (my $qemu_major, my $qemu_minor) = get_test_qemu_version() =~ m/^(\d+)\.(\d+)/;
    if (!PVE::QemuServer::QMPHelpers::runs_at_least_qemu_version($vmid, $qemu_major, $qemu_minor)) {
        die "runs_at_least_qemu_version returned false, maybe error in version_cmp?";
    }

    $cmdline =~ s/ -/ \\\n  -/g; # same as qm showcmd --pretty
    $cmdline .= "\n";

    my $cmd_fn = "$config_fn.cmd";

    if (-f $cmd_fn) {
        my $cmdline_expected = file_get_contents($cmd_fn);

        my $cmd_expected = [split /\s*\\?\n\s*/, $cmdline_expected];
        my $cmd = [split /\s*\\?\n\s*/, $cmdline];

        # uncomment for easier debugging
        #file_set_contents("$cmd_fn.tmp", $cmdline);

        my $exp = join("\n", @$cmd_expected);
        my $got = join("\n", @$cmd);

        if (my $diff = diff($exp, $got)) {
            fail("$testname");
            note("files differ:\n$diff");
        } else {
            pass("$testname");
        }
    } else {
        file_set_contents($cmd_fn, $cmdline);
    }
}

print "testing config to command stability\n";

# exec tests
my $test_target = shift // 'cfg2cmd';

if (-f $test_target) {
    do_test($test_target);
} elsif (-d $test_target) {
    PVE::File::dir_glob_foreach(
        $test_target,
        qr/.+\.conf/,
        sub {
            my ($file) = @_;

            do_test("${test_target}/${file}");
        },
    );
} else {
    die "test target '$test_target' is neither file nor directory, cannot proceed\n";
}

done_testing();
