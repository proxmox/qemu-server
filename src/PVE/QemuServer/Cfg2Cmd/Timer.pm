package PVE::QemuServer::Cfg2Cmd::Timer;

use warnings;
use strict;

sub generate {
    my ($cfg2cmd) = @_;

    my $time_drift_fix = $cfg2cmd->get_prop('tdf', 1);
    my $acpi = $cfg2cmd->get_prop('acpi');
    my $localtime = $cfg2cmd->get_prop('localtime', 1);
    my $startdate = $cfg2cmd->get_prop('startdate');

    if ($cfg2cmd->windows_version() >= 5) { # windows
        $localtime = 1 if !defined($localtime);

        # use time drift fix when acpi is enabled, but prefer explicitly set value
        $time_drift_fix = 1 if $acpi && !defined($time_drift_fix);
    }

    if ($cfg2cmd->windows_version() >= 6) {
        $cfg2cmd->add_global_flag('kvm-pit.lost_tick_policy=discard');
        $cfg2cmd->add_machine_flag_if_supported('hpet', 'off');
    } elsif ($cfg2cmd->is_linux() && $cfg2cmd->version_guard(10, 1, 0)) {
        $cfg2cmd->add_machine_flag_if_supported('hpet', 'off');
    }

    $cfg2cmd->add_rtc_flag('driftfix=slew') if $time_drift_fix;

    if ($startdate ne 'now') {
        $cfg2cmd->add_rtc_flag("base=$startdate");
    } elsif ($localtime) {
        $cfg2cmd->add_rtc_flag('base=localtime');
    }

    return;
}

1;
