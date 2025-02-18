package PVE::QemuConfig::NoWrite;

use strict;
use warnings;

use PVE::RESTEnvironment qw(log_warn);

use base qw(PVE::QemuConfig);

sub mark_config {
    my ($class, $conf) = @_;

    bless($conf, $class);
}

sub write_config {
    my ($class, $vmid, $conf) = @_;

    log_warn("refusing to write temporary configuration");
    return;
}

1;
