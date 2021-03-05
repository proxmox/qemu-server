package PVE::API2::Qemu::Machine;

use strict;
use warnings;

use JSON;

use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
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
	    additionalProperties => 1,
	    properties => {
		id => {
		    type => 'string',
		    description => "Full name of machine type and version.",
		},
		type => {
		    type => 'string',
		    enum => ['q35', 'i440fx'],
		    description => "The machine type.",
		},
		version => {
		    type => 'string',
		    description => "The machine version.",
		},
	    },
	},
    },
    code => sub {
	my $machines = eval {
	    my $raw = file_get_contents('/usr/share/kvm/machine-versions-x86_64.json');
	    return from_json($raw, { utf8 => 1 });
	};
	die "could not load supported machine versions - $@\n" if $@;
	return $machines;
    }
});

1;
