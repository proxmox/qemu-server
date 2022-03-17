package PVE::API2::Qemu::OVF;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);
use PVE::QemuServer::OVF;
use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'readovf',
    path => '',
    method => 'GET',
    proxyto => 'node',
    description => "Read an .ovf manifest.",
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    manifest => {
		description => "Path to .ovf manifest.",
		type => 'string',
	    },
	},
    },
    returns => {
	type => 'object',
	additionalProperties => 1,
	properties => PVE::QemuServer::json_ovf_properties(),
	description => "VM config according to .ovf manifest.",
    },
    code => sub {
	my ($param) = @_;

	my $manifest = $param->{manifest};
	die "check for file $manifest failed - $!\n" if !-f $manifest;

	my $parsed = PVE::QemuServer::OVF::parse_ovf($manifest);
	my $result;
	$result->{cores} = $parsed->{qm}->{cores};
	$result->{name} =  $parsed->{qm}->{name};
	$result->{memory} = $parsed->{qm}->{memory};
	my $disks = $parsed->{disks};
	for my $disk (@$disks) {
	    $result->{$disk->{disk_address}} = $disk->{backing_file};
	}
	return $result;
    }});

1;
