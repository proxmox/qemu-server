package PVE::API2::Qemu::Machine;

use strict;
use warnings;

use JSON;

use PVE::JSONSchema qw(get_standard_option);
use PVE::QemuServer::Machine;
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
	my $supported_machine_list = eval {
	    my $raw = file_get_contents('/usr/share/kvm/machine-versions-x86_64.json');
	    my $machines = from_json($raw, { utf8 => 1 });

	    my $to_add = [];

	    for my $machine ($machines->@*) {
		my $base_version = $machine->{version};
		my $pvever = PVE::QemuServer::Machine::get_pve_version($base_version);
		for (my $i = 1; $i <= $pvever; $i++) {
		    my $version = $base_version . "+pve$i";
		    my $entry = {
			id => $machine->{id} . "+pve$i",
			type => $machine->{type},
			version => $version,
		    };

		    push $to_add->@*, $entry;
		}
	    }

	    push $machines->@*, $to_add->@*;

	    return [sort { $b->{id} cmp $a->{id} } $machines->@*];
	};
	die "could not load supported machine versions - $@\n" if $@;
	return $supported_machine_list;
    }
});

1;
