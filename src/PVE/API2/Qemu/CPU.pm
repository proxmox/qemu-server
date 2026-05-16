package PVE::API2::Qemu::CPU;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);
use PVE::RPCEnvironment;
use PVE::RESTHandler;
use PVE::Tools qw(extract_param);

use PVE::QemuServer::CPUConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => 'List all custom and default CPU models.',
    permissions => {
        user => 'all',
        description => "Custom models are filtered to those the current user has any of"
            . " Mapping.{Audit,Use,Modify} on /mapping/cpu/<name>; Sys.Audit on /nodes"
            . " continues to grant visibility of all custom models for back-compat.",
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            arch => get_standard_option('pve-qm-cpu-arch', { optional => 1 }),
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
                abstract => {
                    type => 'boolean',
                    description => "True for PVE-internal abstract profiles like x86-64-v2,"
                        . " -v3, -v4. These do not correspond to a QEMU CPU type and"
                        . " cannot be used as a custom model's 'reported-model'.",
                    optional => 1,
                },
                vendor => {
                    type => 'string',
                    description => "CPU vendor visible to the guest when this"
                        . " model is selected. Vendor of"
                        . " 'reported-model' in case of custom models.",
                },
            },
        },
        links => [{ rel => 'child', href => '{name}' }],
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();
        my $arch = extract_param($param, 'arch');

        my $models = PVE::QemuServer::CPUConfig::get_cpu_models(1, $arch);

        my $see_all_custom = $rpcenv->check($authuser, "/nodes", ['Sys.Audit'], 1);

        return [
            grep {
                !$_->{custom}
                    || $see_all_custom
                    || do {
                        (my $name = $_->{name}) =~ s/^custom-//;
                        $rpcenv->check_any(
                            $authuser,
                            "/mapping/cpu/$name",
                            ['Mapping.Audit', 'Mapping.Use', 'Mapping.Modify'],
                            1,
                        );
                    };
            } @$models
        ];
    },
});

1;
