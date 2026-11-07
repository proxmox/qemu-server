#!/usr/bin/perl

# Guest config files must only be written through the write_config method of the config class,
# which keeps the guest identity published for the VMID. This checks the sources for writes that
# bypass it.
#
# It is a heuristic on the source text: it checks the path argument of file_set_contents and
# cfs_write_file calls for config paths built by the config class helpers or spelled out, directly
# or through a variable assigned such a path, or a string built from one, in the same sub. It does
# not recognize other writers like open, sysopen, rename or file_copy, nor paths passed through sub
# parameters, hash members, list assignments, conditional expressions or variables assigned outside
# of the sub.

use strict;
use warnings;

use File::Find;
use Test::More;

my $SOURCE_DIRS = ['../PVE', '../bin'];

my $CONFIG_PATH_HELPER_RE = qr/\b(?:config_file|cfs_config_path)\b/;
my $CONFIG_PATH_LITERAL_RE = qr{
    \bnodes/[^/\s]+/(?:lxc|qemu-server|openvz)/
    | /etc/pve/(?:local/)?(?:lxc|qemu-server|openvz)/
}x;
my $CONFIG_PATH_RE = qr/$CONFIG_PATH_HELPER_RE|$CONFIG_PATH_LITERAL_RE/;

my $WRITER_RE = qr/\b(file_set_contents|cfs_write_file)\b\s*\(?/;

# Returns the expression of the first argument of the call starting at $pos in $code.
my sub first_argument {
    my ($code, $pos) = @_;

    my ($depth, $quote, $arg) = (0, undef, '');
    for my $char (split(//, substr($code, $pos))) {
        if (defined($quote)) {
            $quote = undef if $char eq $quote;
        } elsif ($char eq '"' || $char eq "'") {
            $quote = $char;
        } elsif ($char =~ m/[(\[{]/) {
            $depth++;
        } elsif ($char =~ m/[)\]}]/) {
            last if $depth == 0;
            $depth--;
        } elsif ($depth == 0 && ($char eq ',' || $char eq ';')) {
            last;
        }
        $arg .= $char;
    }

    return $arg;
}

# Returns the line number and the path argument of all writes of a guest config path in the block
# of code $code, which starts at line $first_line.
my sub find_raw_config_writes_in_block {
    my ($code, $first_line) = @_;

    # variables assigned a config path, or a string built from one
    my $path_re = $CONFIG_PATH_RE;
    my $path_value_re = qr{
        ^\s*[\w:\$]+->$CONFIG_PATH_HELPER_RE
        | ^\s*"[^"]*$CONFIG_PATH_LITERAL_RE
    }x;
    my $path_vars = {};
    my $found_new = 1;
    while ($found_new) {
        $found_new = 0;
        while ($code =~ m/\$(\w+)\s*=(?![=~])\s*([^;]*);/g) {
            my ($var, $value) = ($1, $2);
            next if $path_vars->{$var} || $value !~ $path_value_re;
            $path_vars->{$var} = 1;
            $found_new = 1;
        }
        my $vars = join('|', map { quotemeta($_) } sort keys %$path_vars);
        next if !$vars;
        $path_re = qr/$CONFIG_PATH_RE|\$(?:$vars)\b/;
        $path_value_re = qr{
            ^\s*[\w:\$]+->$CONFIG_PATH_HELPER_RE
            | ^\s*"[^"]*(?:$CONFIG_PATH_LITERAL_RE|\$(?:$vars)\b)
            | ^\s*\$(?:$vars)\b\s*(?:\.|$)
        }x;
    }

    my $writes = [];
    while ($code =~ m/$WRITER_RE/g) {
        my $pos = pos($code);
        my $arg = first_argument($code, $pos);
        next if $arg !~ $path_re;

        my $line = $first_line + (substr($code, 0, $pos) =~ tr/\n//);
        push @$writes, [$line, $arg =~ s/^\s+|\s+$//gr];
    }

    return $writes;
}

# Returns the line number and the path argument of all writes of a guest config path in $code.
sub find_raw_config_writes {
    my ($code) = @_;

    $code =~ s/^[ \t]*#.*$//mg;
    $code =~ s/(^=[a-z].*?^=cut\b.*?$)/"\n" x ($1 =~ tr|\n||)/msge; # keep line numbers

    # track variables per sub, as other subs can use the same names for other paths
    my $blocks = [['', 1]];
    my $line = 0;
    for my $text (split(/^/, $code)) {
        $line++;
        push @$blocks, ['', $line]
            if $text =~
            m/^(?:(?:my\s+)?sub\s|__PACKAGE__->register_method\b|my\s+\$\w+\s*=\s*sub\b)/;
        $blocks->[-1]->[0] .= $text;
    }

    return [map { find_raw_config_writes_in_block($_->@*)->@* } @$blocks];
}

subtest 'detection of raw config writes' => sub {
    my $raw_writes = {
        'config_file helper' =>
            'PVE::Tools::file_set_contents(PVE::QemuConfig->config_file($vmid), $raw);',
        'config_file helper with node, spanning lines' => <<~'EOF',
            file_set_contents(
                PVE::QemuConfig->config_file($vmid, $node),
                $raw,
            );
            EOF
        'variable from config_file' => <<~'EOF',
            my $conffile = PVE::QemuConfig->config_file($vmid);
            PVE::Tools::file_set_contents($conffile, "memory: 128\nlock: create");
            EOF
        'variable derived from a path variable' => <<~'EOF',
            my $conffile = PVE::QemuConfig->config_file($vmid);
            my $tmpfn = "$conffile.tmp.$$";
            file_set_contents($tmpfn, $raw);
            EOF
        'literal path' => 'file_set_contents("/etc/pve/qemu-server/$vmid.conf", $raw);',
        'literal path of the local node' =>
            'file_set_contents("/etc/pve/local/qemu-server/$vmid.conf", $raw);',
        'variable from a literal path' => <<~'EOF',
            my $path = "/etc/pve/qemu-server/$vmid.conf";
            PVE::Tools::file_set_contents($path, $raw);
            EOF
        'cfs path' =>
            'PVE::Cluster::cfs_write_file("nodes/$node/qemu-server/$vmid.conf", $conf);',
        'cfs_config_path helper' =>
            'PVE::Cluster::cfs_write_file(PVE::QemuConfig->cfs_config_path($vmid), {});',
    };
    for my $name (sort keys %$raw_writes) {
        is(scalar(find_raw_config_writes($raw_writes->{$name})->@*), 1, "$name is detected");
    }

    my $other_writes = {
        'temporary file of a restore' => <<~'EOF',
            my $cfgfn = "$tmpdir/qemu-server.conf";
            PVE::Tools::file_set_contents($cfgfn, $data);
            EOF
        'firewall config' => <<~'EOF',
            my $firewall_config_fn = "$tmpdir/fw.conf";
            PVE::Tools::file_set_contents($firewall_config_fn, $data);
            EOF
        'pid file' => q{PVE::Tools::file_set_contents($pid_file, '', 0600);},
        'value read from a config path' => <<~'EOF',
            my $cfspath = PVE::QemuConfig->cfs_config_path($vmid);
            my $conf = PVE::Cluster::cfs_read_file($cfspath);
            PVE::Tools::file_set_contents("/run/$conf->{name}", $raw);
            EOF
        'comment' => '# never call file_set_contents(PVE::QemuConfig->config_file($vmid))',
        'same variable name in another sub' => <<~'EOF',
            sub exists_config {
                my $path = PVE::QemuConfig->config_file($vmid);
                return -f $path;
            }

            sub write_flag {
                my $path = "/run/flag";
                PVE::Tools::file_set_contents($path, '');
            }
            EOF
        'config class write' => 'PVE::QemuConfig->write_config($vmid, $conf);',
        'other cluster file' => 'cfs_write_file($cpu_models_filename, $conf);',
    };
    for my $name (sort keys %$other_writes) {
        is_deeply(find_raw_config_writes($other_writes->{$name}), [], "$name is ignored");
    }
};

subtest 'no raw writes of guest config files in the sources' => sub {
    my @files;
    find(
        {
            no_chdir => 1,
            wanted => sub {
                return if !-f $_;
                if ($_ !~ m/\.p[lm]$/) {
                    open(my $fh, '<', $_) or die "unable to open '$_' - $!\n";
                    my $first_line = <$fh> // '';
                    close($fh);
                    return if $first_line !~ m/^#!.*\bperl\b/;
                }
                push @files, $_;
            },
        },
        $SOURCE_DIRS->@*,
    );

    ok(scalar(grep { m|/PVE/QemuServer\.pm$| } @files), 'sources are found');

    for my $file (sort @files) {
        open(my $fh, '<', $file) or die "unable to open '$file' - $!\n";
        my $code = do { local $/; <$fh> };
        close($fh);

        for my $write (find_raw_config_writes($code)->@*) {
            my ($line, $arg) = $write->@*;
            fail("$file:$line writes the guest config path '$arg' without the config class");
        }
    }
};

done_testing();
