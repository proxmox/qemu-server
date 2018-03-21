package PVE::CLI::qmrestore;

use strict;
use warnings;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::RPCEnvironment;
use PVE::CLIHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::QemuServer;
use PVE::API2::Qemu;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PVE::RPCEnvironment->setup_default_cli_env();
}

__PACKAGE__->register_method({
    name => 'qmrestore', 
    path => 'qmrestore', 
    method => 'POST',
    description => "Restore QemuServer vzdump backups.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    vmid => get_standard_option('pve-vmid', { completion => \&PVE::Cluster::complete_next_vmid }),
	    archive => {
		description => "The backup file. You can pass '-' to read from standard input.",
		type => 'string', 
		maxLength => 255,
		completion => \&PVE::QemuServer::complete_backup_archives,
	    },
	    storage => get_standard_option('pve-storage-id', {
		description => "Default storage.",
		optional => 1,
		completion => \&PVE::QemuServer::complete_storage,
	    }),
	    force => {
		optional => 1, 
		type => 'boolean',
		description => "Allow to overwrite existing VM.",
	    },
	    unique => {
		optional => 1, 
		type => 'boolean',
		description => "Assign a unique random ethernet address.",
	    },
	    pool => { 
		optional => 1,
		type => 'string', format => 'pve-poolid',
		description => "Add the VM to the specified pool.",
	    },
	    bwlimit => {
		description => "Override i/o bandwidth limit (in KiB/s).",
		optional => 1,
		type => 'number',
		minimum => '0',
	    }
	},
    },
    returns => { 
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	$param->{node} = PVE::INotify::nodename();

	return PVE::API2::Qemu->create_vm($param);
    }});    

our $cmddef = [ __PACKAGE__, 'qmrestore', ['archive', 'vmid'], undef, 
		sub {
		    my $upid = shift;
		    my $status = PVE::Tools::upid_read_status($upid);
		    exit($status eq 'OK' ? 0 : -1);
		}];

1;
