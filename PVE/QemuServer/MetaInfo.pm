package PVE::QemuServer::MetaInfo;

use strict;
use warnings;

use PVE::JSONSchema;

use PVE::QemuServer::Helpers;

our $meta_info_fmt = {
    'ctime' => {
	type => 'integer',
	description => "The guest creation timestamp as UNIX epoch time",
	minimum => 0,
	optional => 1,
    },
    'creation-qemu' => {
	type => 'string',
	description => "The QEMU (machine) version from the time this VM was created.",
	pattern => '\d+(\.\d+)+',
	optional => 1,
    },
};

sub parse_meta_info {
    my ($value) = @_;

    return if !$value;

    my $res = eval { PVE::JSONSchema::parse_property_string($meta_info_fmt, $value) };
    warn $@ if $@;
    return $res;
}

sub new_meta_info_string {
    my () = @_; # for now do not allow to override any value

    return PVE::JSONSchema::print_property_string(
	{
	    'creation-qemu' => PVE::QemuServer::Helpers::kvm_user_version(),
	    ctime => "". int(time()),
	},
	$meta_info_fmt,
    );
}

1;
