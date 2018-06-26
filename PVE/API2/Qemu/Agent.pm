package PVE::API2::Qemu::Agent;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::QemuServer;
use PVE::QemuServer::Agent qw(agent_available);
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON;

use base qw(PVE::RESTHandler);

# list of commands
# will generate one api endpoint per command
# needs a 'method' property and optionally a 'perms' property (default VM.Monitor)
my $guest_agent_commands = {
    'ping' => {
	method => 'POST',
    },
    'get-time' => {
	method => 'GET',
    },
    'info' => {
	method => 'GET',
    },
    'fsfreeze-status' => {
	method => 'POST',
    },
    'fsfreeze-freeze' => {
	method => 'POST',
    },
    'fsfreeze-thaw' => {
	method => 'POST',
    },
    'fstrim' => {
	method => 'POST',
    },
    'network-get-interfaces' => {
	method => 'GET',
    },
    'get-vcpus' => {
	method => 'GET',
    },
    'get-fsinfo' => {
	method => 'GET',
    },
    'get-memory-blocks' => {
	method => 'GET',
    },
    'get-memory-block-info' => {
	method => 'GET',
    },
    'suspend-hybrid' => {
	method => 'POST',
    },
    'suspend-ram' => {
	method => 'POST',
    },
    'suspend-disk' => {
	method => 'POST',
    },
    'shutdown' => {
	method => 'POST',
    },
    # added since qemu 2.9
    'get-host-name' => {
	method => 'GET',
    },
    'get-osinfo' => {
	method => 'GET',
    },
    'get-users' => {
	method => 'GET',
    },
    'get-timezone' => {
	method => 'GET',
    },
};

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    proxyto => 'node',
    method => 'GET',
    description => "Qemu Agent command index.",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 1,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', {
                   completion => \&PVE::QemuServer::complete_vmid_running }),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => '{name}' } ],
	description => "Returns the list of Qemu Agent commands",
    },
    code => sub {
	my ($param) = @_;

	my $result = [];

	my $cmds = [keys %$guest_agent_commands];
	push @$cmds, qw(
	    set-user-password
	);

	for my $cmd ( sort @$cmds) {
	    push @$result, { name => $cmd };
	}

	return $result;
    }});

sub register_command {
    my ($class, $command, $method, $perm) = @_;

    die "no method given\n" if !$method;
    die "no command given\n" if !defined($command);

    my $permission;

    if (ref($perm) eq 'HASH') {
	$permission = $perm;
    } else {
	$perm //= 'VM.Monitor';
	$permission = { check => [ 'perm', '/vms/{vmid}', [ $perm ]]};
    }

    my $parameters = {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', {
		    completion => \&PVE::QemuServer::complete_vmid_running }),
	    command => {
		type => 'string',
		description => "The QGA command.",
		enum => [ sort keys %$guest_agent_commands ],
	    },
	},
    };

    my $description = "Execute Qemu Guest Agent commands.";
    my $name = 'agent';

    if ($command ne '') {
	$description = "Execute $command.";
	$name = $command;
	delete $parameters->{properties}->{command};
    }

    __PACKAGE__->register_method({
	name => $name,
	path => $command,
	method => $method,
	protected => 1,
	proxyto => 'node',
	description => $description,
	permissions => $permission,
	parameters => $parameters,
	returns => {
	    type => 'object',
	    description => "Returns an object with a single `result` property.",
	},
	code => sub {
	    my ($param) = @_;

	    my $vmid = $param->{vmid};

	    my $conf = PVE::QemuConfig->load_config ($vmid); # check if VM exists

	    agent_available($vmid, $conf);

	    my $cmd = $param->{command} // $command;
	    my $res = PVE::QemuServer::vm_mon_cmd($vmid, "guest-$cmd");

	    return { result => $res };
	}});
}

# old {vmid}/agent POST endpoint, here for compatibility
__PACKAGE__->register_command('', 'POST');

for my $cmd (sort keys %$guest_agent_commands) {
    my $props = $guest_agent_commands->{$cmd};
    __PACKAGE__->register_command($cmd, $props->{method}, $props->{perms});
}

# commands with parameters are complicated and we want to register them manually
__PACKAGE__->register_method({
    name => 'set-user-password',
    path => 'set-user-password',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    description => "Sets the password for the given user to the given password",
    permissions => { check => [ 'perm', '/vms/{vmid}', [ 'VM.Monitor' ]]},
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vmid => get_standard_option('pve-vmid', {
		    completion => \&PVE::QemuServer::complete_vmid_running }),
	    username => {
		type => 'string',
		description => 'The user to set the password for.'
	    },
	    password => {
		type => 'string',
		description => 'The new password.',
		minLength => 5,
		maxLength => 64,
	    },
	    crypted => {
		type => 'boolean',
		description => 'set to 1 if the password has already been passed through crypt()',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'object',
	description => "Returns an object with a single `result` property.",
    },
    code => sub {
	my ($param) = @_;

	my $vmid = $param->{vmid};

	my $crypted = $param->{crypted} // 0;
	my $args = {
	    username => $param->{username},
	    password => encode_base64($param->{password}),
	    crypted => $crypted ? JSON::true : JSON::false,
	};
	my $res = agent_cmd($vmid, "set-user-password", %$args, 'cannot set user password');

	return { result => $res };
    }});

1;
