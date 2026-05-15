package PVE::API2::Qemu::CPUFlags;

use v5.36;

use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::Tools qw(extract_param);

use PVE::QemuServer::CPUFlags;
use PVE::QemuServer::Helpers;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description =>
        "List of available VM-specific CPU flags. Returns an empty list for 'aarch64' "
        . "as no VM-specific flags are defined for it yet.",
    permissions => { user => 'all' },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            arch => get_standard_option('pve-qm-cpu-arch', { optional => 1 }),
            accel => {
                description => 'Acceleration type to check node compatibility for.',
                type => 'string',
                enum => [qw(kvm tcg)],
                optional => 1,
                default => 'kvm',
            },
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
                    optional => 1,
                },
                'supported-on' => {
                    description =>
                        'List of nodes supporting the CPU flag with the selected acceleration type ("accel").',
                    type => 'array',
                    items => get_standard_option('pve-node'),
                    optional => 1,
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $arch = extract_param($param, 'arch') // PVE::QemuServer::Helpers::get_host_arch();
        my $accel = extract_param($param, 'accel') // 'kvm';

        return PVE::QemuServer::CPUFlags::query_available_cpu_flags($accel, 1, $arch);
    },
});

1;
