# Open Virtualization Format import routines
# https://www.dmtf.org/standards/ovf
package PVE::QemuServer::OVF;

use strict;
use warnings;

use XML::LibXML;
use File::Spec;
use File::Basename;
use Data::Dumper;
use Cwd 'realpath';

use PVE::Tools;
use PVE::Storage;

# map OVF resources types to descriptive strings
# this will allow us to explore the xml tree without using magic numbers
# http://schemas.dmtf.org/wbem/cim-html/2/CIM_ResourceAllocationSettingData.html
my @resources = (
    { id => 1, dtmf_name => 'Other' },
    { id => 2, dtmf_name => 'Computer System' },
    { id => 3, dtmf_name => 'Processor' },
    { id => 4, dtmf_name => 'Memory' },
    { id => 5, dtmf_name => 'IDE Controller', pve_type => 'ide' },
    { id => 6, dtmf_name => 'Parallel SCSI HBA', pve_type => 'scsi' },
    { id => 7, dtmf_name => 'FC HBA' },
    { id => 8, dtmf_name => 'iSCSI HBA' },
    { id => 9, dtmf_name => 'IB HCA' },
    { id => 10, dtmf_name => 'Ethernet Adapter' },
    { id => 11, dtmf_name => 'Other Network Adapter' },
    { id => 12, dtmf_name => 'I/O Slot' },
    { id => 13, dtmf_name => 'I/O Device' },
    { id => 14, dtmf_name => 'Floppy Drive' },
    { id => 15, dtmf_name => 'CD Drive' },
    { id => 16, dtmf_name => 'DVD drive' },
    { id => 17, dtmf_name => 'Disk Drive' },
    { id => 18, dtmf_name => 'Tape Drive' },
    { id => 19, dtmf_name => 'Storage Extent' },
    { id => 20, dtmf_name => 'Other storage device', pve_type => 'sata'},
    { id => 21, dtmf_name => 'Serial port' },
    { id => 22, dtmf_name => 'Parallel port' },
    { id => 23, dtmf_name => 'USB Controller' },
    { id => 24, dtmf_name => 'Graphics controller' },
    { id => 25, dtmf_name => 'IEEE 1394 Controller' },
    { id => 26, dtmf_name => 'Partitionable Unit' },
    { id => 27, dtmf_name => 'Base Partitionable Unit' },
    { id => 28, dtmf_name => 'Power' },
    { id => 29, dtmf_name => 'Cooling Capacity' },
    { id => 30, dtmf_name => 'Ethernet Switch Port' },
    { id => 31, dtmf_name => 'Logical Disk' },
    { id => 32, dtmf_name => 'Storage Volume' },
    { id => 33, dtmf_name => 'Ethernet Connection' },
    { id => 34, dtmf_name => 'DMTF reserved' },
    { id => 35, dtmf_name => 'Vendor Reserved'}
);

sub find_by {
    my ($key, $param) = @_;
    foreach my $resource (@resources) {
	if ($resource->{$key} eq $param) {
	    return ($resource);
	}
    }
    return undef;
}

sub dtmf_name_to_id {
    my ($dtmf_name) = @_;
    my $found = find_by('dtmf_name', $dtmf_name);
    if ($found) {
	return $found->{id};
    } else {
	return undef;
    }
}

sub id_to_pve {
    my ($id) = @_;
    my $resource = find_by('id', $id);
    if ($resource) {
	return $resource->{pve_type};
    } else {
	return undef;
    }
}

# returns two references, $qm which holds qm.conf style key/values, and \@disks
sub parse_ovf {
    my ($ovf, $debug) = @_;

    my $dom = XML::LibXML->load_xml(location => $ovf, no_blanks => 1);

    # register the xml namespaces in a xpath context object
    # 'ovf' is the default namespace so it will prepended to each xml element
    my $xpc = XML::LibXML::XPathContext->new($dom);
    $xpc->registerNs('ovf', 'http://schemas.dmtf.org/ovf/envelope/1');
    $xpc->registerNs('rasd', 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData');
    $xpc->registerNs('vssd', 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData');


    # hash to save qm.conf parameters
    my $qm;

    #array to save a disk list
    my @disks;

    # easy xpath
    # walk down the dom until we find the matching XML element
    my $xpath_find_name = "/ovf:Envelope/ovf:VirtualSystem/ovf:Name";
    my $ovf_name = $xpc->findvalue($xpath_find_name);

    if ($ovf_name) {
	($qm->{name} = $ovf_name) =~ s/[^a-zA-Z0-9\-]//g; # PVE::QemuServer::confdesc requires a valid DNS name
    } else {
	warn "warning: unable to parse the VM name in this OVF manifest, generating a default value\n";
    }

    # middle level xpath
    # element[child] search the elements which have this [child]
    my $processor_id = dtmf_name_to_id('Processor');
    my $xpath_find_vcpu_count = "/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${processor_id}]/rasd:VirtualQuantity";
    $qm->{'cores'} = $xpc->findvalue($xpath_find_vcpu_count);

    my $memory_id = dtmf_name_to_id('Memory');
    my $xpath_find_memory = ("/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${memory_id}]/rasd:VirtualQuantity");
    $qm->{'memory'} = $xpc->findvalue($xpath_find_memory);

    # middle level xpath
    # here we expect multiple results, so we do not read the element value with
    # findvalue() but store multiple elements with findnodes()
    my $disk_id = dtmf_name_to_id('Disk Drive');
    my $xpath_find_disks="/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType=${disk_id}]";
    my @disk_items = $xpc->findnodes($xpath_find_disks);

    # disks metadata is split in four different xml elements:
    # * as an Item node of type DiskDrive in the VirtualHardwareSection
    # * as an Disk node in the DiskSection
    # * as a File node in the References section
    # * each Item node also holds a reference to its owning controller
    #
    # we iterate over the list of Item nodes of type disk drive, and for each item,
    # find the corresponding Disk node, and File node and owning controller
    # when all the nodes has been found out, we copy the relevant information to
    # a $pve_disk hash ref, which we push to @disks;

    foreach my $item_node (@disk_items) {

	my $disk_node;
	my $file_node;
	my $controller_node;
	my $pve_disk;

	print "disk item:\n", $item_node->toString(1), "\n" if $debug;

	# from Item, find corresponding Disk node
	# here the dot means the search should start from the current element in dom
	my $host_resource = $item_node->findvalue('./rasd:HostResource');
	my $disk_section_path;
	my $disk_id;

	# RFC 3986 "2.3.  Unreserved Characters"
	my $valid_uripath_chars = qr/[[:alnum:]]|[\-\._~]/;

	if ($host_resource =~ m|^ovf:/(${valid_uripath_chars}+)/(${valid_uripath_chars}+)$|) {
	    $disk_section_path = $1;
	    $disk_id = $2;
	} else {
	   warn "invalid host ressource $host_resource, skipping\n";
	   next;
	}
	printf "disk section path: $disk_section_path and disk id: $disk_id\n" if $debug;

	# tricky xpath
	# @ means we filter the result query based on a the value of an item attribute ( @ = attribute)
	# @ needs to be escaped to prevent Perl double quote interpolation
	my $xpath_find_fileref = sprintf("/ovf:Envelope/ovf:DiskSection/\
ovf:Disk[\@ovf:diskId='%s']/\@ovf:fileRef", $disk_id);
	my $fileref = $xpc->findvalue($xpath_find_fileref);

	my $valid_url_chars = qr@${valid_uripath_chars}|/@;
	if (!$fileref || $fileref !~ m/^${valid_url_chars}+$/) {
	    warn "invalid host ressource $host_resource, skipping\n";
	    next;
	}

	# from Disk Node, find corresponding filepath
	my $xpath_find_filepath = sprintf("/ovf:Envelope/ovf:References/ovf:File[\@ovf:id='%s']/\@ovf:href", $fileref);
	my $filepath = $xpc->findvalue($xpath_find_filepath);
	if (!$filepath) {
	    warn "invalid file reference $fileref, skipping\n";
	    next;
	}
	print "file path: $filepath\n" if $debug;

	# from Item, find owning Controller type
	my $controller_id = $item_node->findvalue('./rasd:Parent');
	my $xpath_find_parent_type = sprintf("/ovf:Envelope/ovf:VirtualSystem/ovf:VirtualHardwareSection/\
ovf:Item[rasd:InstanceID='%s']/rasd:ResourceType", $controller_id);
	my $controller_type = $xpc->findvalue($xpath_find_parent_type);
	if (!$controller_type) {
	    warn "invalid or missing controller: $controller_type, skipping\n";
	    next;
	}
	print "owning controller type: $controller_type\n" if $debug;

	# extract corresponding Controller node details
	my $adress_on_controller = $item_node->findvalue('./rasd:AddressOnParent');
	my $pve_disk_address = id_to_pve($controller_type) . $adress_on_controller;

	# resolve symlinks and relative path components
	# and die if the diskimage is not somewhere under the $ovf path
	my $ovf_dir = realpath(dirname(File::Spec->rel2abs($ovf)));
	my $backing_file_path = realpath(join ('/', $ovf_dir, $filepath));
	if ($backing_file_path !~ /^\Q${ovf_dir}\E/) {
	    die "error parsing $filepath, are you using a symlink ?";
	}

	my $virtual_size;
	if ( !($virtual_size = PVE::Storage::file_size_info($backing_file_path)) ) {
	    die "error parsing $backing_file_path, size seems to be $virtual_size";
	}

	$pve_disk = {
	    disk_address => $pve_disk_address,
	    backing_file => $backing_file_path,
	    virtual_size => $virtual_size
	};
	push @disks, $pve_disk;

    }

    return {qm => $qm, disks => \@disks};
}

1;
