package PVE::API2::NodeCapabilities::Qemu::Migration;

use strict;
use warnings;

use JSON;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'capabilities',
    path => '',
    method => 'GET',
    proxyto => 'node',
    description => 'Get node-specific QEMU migration capabilities of the node.'
        . " Requires the 'Sys.Audit' permission on '/nodes/<node>'.",
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
        },
    },
    returns => {
        type => 'object',
        additionalProperties => 0,
        properties => {
            'has-dbus-vmstate' => {
                type => 'boolean',
                description => 'Whether the host supports live-migrating additional'
                    . ' VM state via the dbus-vmstate helper.',
            },
        },
    },
    code => sub {
        return {
            'has-dbus-vmstate' => -f '/usr/libexec/qemu-server/dbus-vmstate'
            ? JSON::true
            : JSON::false,
        };
    },
});

1;
