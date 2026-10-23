package QemuServerTest::Utils;

use v5.36;

use IO::Handle;
use POSIX qw();

use base 'Exporter';

our @EXPORT_OK = qw(
    diff
);

sub diff($expected, $got) {
    return if $expected eq $got;

    my ($ra, $wa) = POSIX::pipe();
    my ($rb, $wb) = POSIX::pipe();
    my $ha = IO::Handle->new_from_fd($wa, 'w');
    my $hb = IO::Handle->new_from_fd($wb, 'w');

    open my $diffproc, '-|', 'diff', '-up', "/proc/self/fd/$ra", "/proc/self/fd/$rb" ## no critic
        or die "failed to run program 'diff': $!";
    POSIX::close($ra);
    POSIX::close($rb);

    open my $f1, '<', \$expected;
    open my $f2, '<', \$got;
    my ($line1, $line2);
    do {
        $ha->print($line1) if defined($line1 = <$f1>);
        $hb->print($line2) if defined($line2 = <$f2>);
    } while (defined($line1 // $line2));
    close $f1;
    close $f2;
    close $ha;
    close $hb;

    local $/ = undef;
    my $diff = <$diffproc>;
    close $diffproc;
    return $diff || "inputs differ, but `diff` produced no output.";
}

1;
