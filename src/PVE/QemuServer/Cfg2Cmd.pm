package PVE::QemuServer::Cfg2Cmd;

use warnings;
use strict;

use PVE::QemuServer::Cfg2Cmd::Timer;
use PVE::QemuServer::Helpers;

sub new {
    my ($class, $conf, $defaults) = @_;

    my $self = bless {
        conf => $conf,
        defaults => $defaults,
    }, $class;

    my $ostype = $self->get_prop('ostype');
    $self->{'windows-version'} = PVE::QemuServer::Helpers::windows_version($ostype);

    return $self;
}

=head3 get_prop

    my $value = $self->get_prop($prop);

Return the configured value for the property C<$prop>. If no fallback to the default value should be
made, use C<$only_explicit>. Note that any such usage is likely an indication that the default value
is not actually a static default, but that the default depends on context.

=cut

sub get_prop {
    my ($self, $prop, $only_explicit) = @_;

    my ($conf, $defaults) = $self->@{qw(conf defaults)};
    return $conf->{$prop} if $only_explicit;
    return defined($conf->{$prop}) ? $conf->{$prop} : $defaults->{$prop};
}

sub add_global_flag {
    my ($self, $flag) = @_;

    push $self->{'global-flags'}->@*, $flag;
}

sub global_flags {
    my ($self) = @_;

    return $self->{'global-flags'};
}

sub add_machine_flag {
    my ($self, $flag) = @_;

    push $self->{'machine-flags'}->@*, $flag;
}

sub machine_flags {
    my ($self) = @_;

    return $self->{'machine-flags'};
}

sub add_rtc_flag {
    my ($self, $flag) = @_;

    push $self->{'rtc-flags'}->@*, $flag;
}

sub rtc_flags {
    my ($self) = @_;

    return $self->{'rtc-flags'};
}

sub windows_version {
    my ($self) = @_;

    return $self->{'windows-version'};
}

sub generate {
    my ($self) = @_;

    PVE::QemuServer::Cfg2Cmd::Timer::generate($self);

    return $self;
}

1;
