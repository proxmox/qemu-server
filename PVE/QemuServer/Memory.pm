package PVE::QemuServer::Memory;

use strict;
use warnings;
use PVE::QemuServer;

my $MAX_MEM = 4194304;
my $STATICMEM = 1024;

sub foreach_dimm{
    my ($conf, $vmid, $memory, $sockets, $func) = @_;

    my $dimm_id = 0;
    my $current_size = 1024;
    my $dimm_size = 512;
    return if $current_size == $memory;

    for (my $j = 0; $j < 8; $j++) {
	for (my $i = 0; $i < 32; $i++) {
	    my $name = "dimm${dimm_id}";
	    $dimm_id++;
	    my $numanode = $i % $sockets;
	    $current_size += $dimm_size;
	    &$func($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory);
	    return  $current_size if $current_size >= $memory;
	}
	$dimm_size *= 2;
    }
}

sub foreach_reverse_dimm {
    my ($conf, $vmid, $memory, $sockets, $func) = @_;

    my $dimm_id = 253;
    my $current_size = 4177920;
    my $dimm_size = 65536;
    return if $current_size == $memory;

    for (my $j = 0; $j < 8; $j++) {
	for (my $i = 0; $i < 32; $i++) {
 	    my $name = "dimm${dimm_id}";
 	    $dimm_id--;
 	    my $numanode = $i % $sockets;
 	    $current_size -= $dimm_size;
 	    &$func($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory);
	    return  $current_size if $current_size <= $memory;
	}
	$dimm_size /= 2;
    }
}

sub qemu_memory_hotplug {
    my ($vmid, $conf, $defaults, $opt, $value) = @_;

    return $value if !check_running($vmid);

    my $memory = $conf->{memory} || $defaults->{memory};
    $value = $defaults->{memory} if !$value;
    return $value if $value == $memory;

    my $static_memory = $STATICMEM;
    my $dimm_memory = $memory - $static_memory;

    die "memory can't be lower than $static_memory MB" if $value < $static_memory;
    die "you cannot add more memory than $MAX_MEM MB!\n" if $memory > $MAX_MEM;


    my $sockets = 1;
    $sockets = $conf->{sockets} if $conf->{sockets};

    if($value > $memory) {

    	foreach_dimm($conf, $vmid, $value, $sockets, sub {
	    my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;

		return if $current_size <= $conf->{memory};

		eval { PVE::QemuServer::vm_mon_cmd($vmid, "object-add", 'qom-type' => "memory-backend-ram", id => "mem-$name", props => { size => int($dimm_size*1024*1024) } ) };
		if (my $err = $@) {
		    eval { PVE::QemuServer::qemu_objectdel($vmid, "mem-$name"); };
		    die $err;
		}

		eval { PVE::QemuServer::vm_mon_cmd($vmid, "device_add", driver => "pc-dimm", id => "$name", memdev => "mem-$name", node => $numanode) };
		if (my $err = $@) {
		    eval { PVE::QemuServer::qemu_objectdel($vmid, "mem-$name"); };
		    die $err;
		}
		#update conf after each succesful module hotplug
		$conf->{memory} = $current_size;
		PVE::QemuConfig->write_config($vmid, $conf);
	});

    } else {

    	foreach_reverse_dimm($conf, $vmid, $value, $sockets, sub {
	    my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;

		return if $current_size >= $conf->{memory};
		print "try to unplug memory dimm $name\n";

		my $retry = 0;
	        while (1) {
		    eval { PVE::QemuServer::qemu_devicedel($vmid, $name) };
		    sleep 3;
		    my $dimm_list = qemu_dimm_list($vmid);
		    last if !$dimm_list->{$name};
		    raise_param_exc({ $name => "error unplug memory module" }) if $retry > 5;
		    $retry++;
		}

		#update conf after each succesful module unplug
		$conf->{memory} = $current_size;

		eval { PVE::QemuServer::qemu_objectdel($vmid, "mem-$name"); };
		PVE::QemuConfig->write_config($vmid, $conf);
	});
    }
}

sub qemu_dimm_list {
    my ($vmid) = @_;

    my $dimmarray = PVE::QemuServer::vm_mon_cmd_nocheck($vmid, "query-memory-devices");
    my $dimms = {};

    foreach my $dimm (@$dimmarray) {

        $dimms->{$dimm->{data}->{id}}->{id} = $dimm->{data}->{id};
        $dimms->{$dimm->{data}->{id}}->{node} = $dimm->{data}->{node};
        $dimms->{$dimm->{data}->{id}}->{addr} = $dimm->{data}->{addr};
        $dimms->{$dimm->{data}->{id}}->{size} = $dimm->{data}->{size};
        $dimms->{$dimm->{data}->{id}}->{slot} = $dimm->{data}->{slot};
    }
    return $dimms;
}

1;

