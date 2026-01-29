package PVE::API2::Qemu::CPUFlags;

use v5.36;

use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::Tools qw(extract_param);

use PVE::QemuServer::CPUConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => 'List of available VM-specific CPU flags.',
    permissions => { user => 'all' },
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
                    description => "Name of the CPU flag.",
                },
                description => {
                    type => 'string',
                    description => "Description of the CPU flag.",
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $arch = extract_param($param, 'arch');

        return PVE::QemuServer::CPUConfig::get_supported_cpu_flags($arch);
    },
});

1;
