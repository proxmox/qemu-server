package PVE::API2::Qemu::Machine;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw(file_get_contents);

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'types',
    path => '',
    method => 'GET',
    proxyto => 'node',
    description => "Get available QEMU/KVM machine types.",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => 'object',
	    properties => {
		name => {
		    type => 'string',
		    description => "Name of machine type.",
		},
	    },
	},
    },
    code => sub {
	my $content = eval {
	    file_get_contents("/usr/share/kvm/machine-versions-x86_64");
	};
	die "could not get supported machine versions (try updating 'pve-qemu-kvm') - $@" if $@;
	my @data = split(m/\n/, $content);
	@data = map { { name => $_ } } @data;
	return \@data;
    }});

1;
