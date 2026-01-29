package PVE::API2::Qemu::Machine;

use strict;
use warnings;

use JSON;

use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::Tools qw(extract_param file_get_contents get_host_arch);

use PVE::QemuServer::Machine;

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
            arch => get_standard_option('pve-qm-cpu-arch', { optional => 1 }),
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
                changes => {
                    type => 'string',
                    optional => 1,
                    description =>
                        'Notable changes of a version, currently only set for +pveX versions.',
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $arch = extract_param($param, 'arch') // get_host_arch();

        my $supported_machine_list = eval {
            my $raw = file_get_contents("/usr/share/kvm/machine-versions-$arch.json");
            my $machines = from_json($raw, { utf8 => 1 });

            my $pve_machines = [];
            for my $machine ($machines->@*) {
                my $pve_machine =
                    PVE::QemuServer::Machine::get_machine_pve_revisions($machine->{version})
                    or next;

                for my $pve_revision (sort keys $pve_machine->{revisions}->%*) {
                    my $entry = {
                        id => $machine->{id} . $pve_revision,
                        type => $machine->{type},
                        version => $machine->{version} . $pve_revision,
                    };

                    if (defined(my $changes = $pve_machine->{revisions}->{$pve_revision})) {
                        $entry->{changes} = $changes;
                    }

                    push $pve_machines->@*, $entry;
                }
            }

            return [
                sort {
                    PVE::QemuServer::Machine::machine_version_cmp($b->{id}, $a->{id})
                } ($machines->@*, $pve_machines->@*)
            ]; # merge & sort
        };
        die "could not load supported machine versions - $@\n" if $@;
        return $supported_machine_list;
    },
});

1;
