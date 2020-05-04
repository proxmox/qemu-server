package PVE::API2::Qemu::CPU;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::QemuServer::CPUConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => 'List all custom and default CPU models.',
    permissions => {
	user => 'all',
	description => 'Only returns custom models when the current user has'
		     . ' Sys.Audit on /nodes.',
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
		    description => "Name of the CPU model. Identifies it for"
				 . " subsequent API calls. Prefixed with"
				 . " 'custom-' for custom models.",
		},
		custom => {
		    type => 'boolean',
		    description => "True if this is a custom CPU model.",
		},
		vendor => {
		    type => 'string',
		    description => "CPU vendor visible to the guest when this"
				 . " model is selected. Vendor of"
				 . " 'reported-model' in case of custom models.",
		},
	    },
	},
	links => [ { rel => 'child', href => '{name}' } ],
    },
    code => sub {
	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();
	my $include_custom = $rpcenv->check($authuser, "/nodes", ['Sys.Audit'], 1);

	return PVE::QemuServer::CPUConfig::get_cpu_models($include_custom);
    }});

1;
