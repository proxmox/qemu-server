package PVE::API2::Qemu::Agent;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::QemuServer;

use base qw(PVE::RESTHandler);

my $guest_agent_commands = [
    'ping',
    'get-time',
    'info',
    'fsfreeze-status',
    'fsfreeze-freeze',
    'fsfreeze-thaw',
    'fstrim',
    'network-get-interfaces',
    'get-vcpus',
    'get-fsinfo',
    'get-memory-blocks',
    'get-memory-block-info',
    'suspend-hybrid',
    'suspend-ram',
    'suspend-disk',
    'shutdown',
    ];

__PACKAGE__->register_method({
    name => 'agent',
    path => '',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Execute Qemu Guest Agent commands.",
    permissions => {
	check => ['perm', '/vms/{vmid}', [ 'VM.Monitor' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', {
                   completion => \&PVE::QemuServer::complete_vmid_running }),
	    command => {
		type => 'string',
		description => "The QGA command.",
		enum => $guest_agent_commands,
	    },
	},
    },
    returns => {
	type => 'object',
	description => "Returns an object with a single `result` property. The type of that
property depends on the executed command.",
    },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	my $conf = PVE::QemuConfig->load_config ($vmid); # check if VM exists

	die "No Qemu Guest Agent\n" if !defined($conf->{agent});
	die "VM $vmid is not running\n" if !PVE::QemuServer::check_running($vmid);

	my $cmd = $param->{command};

	my $res = PVE::QemuServer::vm_mon_cmd($vmid, "guest-$cmd");

	return { result => $res };
    }});

1;
