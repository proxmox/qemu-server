#!/usr/bin/perl

package main;

use strict;
use warnings;
use PVE::Tools;
use PVE::Cluster;
use PVE::PodParser;
use PVE::QemuServer;

my $prop = PVE::QemuServer::json_config_properties();
my $format = PVE::PodParser::dump_properties($prop);

my $parser = PVE::PodParser->new();
$parser->{include}->{format} = $format;
$parser->parse_from_file($0);

exit 0;

__END__

=head1 NAME

vm.conf - Proxmox VE virtual machine (qemu/kvm) configuration files.

=head1 SYNOPSYS

The F</etc/pve/qemu-server/C<VMID>.conf> files stores VM
configuration, where C<VMID> is the numeric ID of the given VM. Note
that C<VMID <= 100> are reserved for internal purposes.

=head1 FILE FORMAT

Configuration file use a simple colon separated key/value format. Each
line has the following format:

 OPTION: value

Blank lines in the file are ignored, and lines starting with a C<#>
character are treated as comments and are also ignored.

One can use the F<qm> command to generate and modify those files.

=head1 OPTIONS

=include format

=include pve_copyright
