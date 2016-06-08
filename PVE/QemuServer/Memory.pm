package PVE::QemuServer::Memory;

use strict;
use warnings;
use PVE::QemuServer;

my $MAX_NUMA = 8;
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

    return $value if !PVE::QemuServer::check_running($vmid);

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

sub config {
    my ($conf, $vmid, $sockets, $cores, $defaults, $hotplug_features, $cmd) = @_;
    
    my $memory = $conf->{memory} || $defaults->{memory};
    my $static_memory = 0;
    my $dimm_memory = 0;

    if ($hotplug_features->{memory}) {
	die "NUMA need to be enabled for memory hotplug\n" if !$conf->{numa};
	die "Total memory is bigger than ${MAX_MEM}MB\n" if $memory > $MAX_MEM;
	$static_memory = $STATICMEM;
	die "minimum memory must be ${static_memory}MB\n" if($memory < $static_memory);
	$dimm_memory = $memory - $static_memory;
	push @$cmd, '-m', "size=${static_memory},slots=255,maxmem=${MAX_MEM}M";

    } else {

	$static_memory = $memory;
	push @$cmd, '-m', $static_memory;
    }

    if ($conf->{numa}) {

	my $numa_totalmemory = undef;
	for (my $i = 0; $i < $MAX_NUMA; $i++) {
	    next if !$conf->{"numa$i"};
	    my $numa = PVE::QemuServer::parse_numa($conf->{"numa$i"});
	    next if !$numa;
	    # memory
	    die "missing NUMA node$i memory value\n" if !$numa->{memory};
	    my $numa_memory = $numa->{memory};
	    $numa_totalmemory += $numa_memory;
	    my $numa_object = "memory-backend-ram,id=ram-node$i,size=${numa_memory}M";

	    # cpus
	    my $cpulists = $numa->{cpus};
	    die "missing NUMA node$i cpus\n" if !defined($cpulists);
	    my $cpus = join(',', map {
		my ($start, $end) = @$_;
		defined($end) ? "$start-$end" : $start
	    } @$cpulists);

	    # hostnodes
	    my $hostnodelists = $numa->{hostnodes};
	    if (defined($hostnodelists)) {
		my $hostnodes;
		foreach my $hostnoderange (@$hostnodelists) {
		    my ($start, $end) = @$hostnoderange;
		    $hostnodes .= ',' if $hostnodes;
		    $hostnodes .= $start;
		    $hostnodes .= "-$end" if defined($end);
		    $end //= $start;
		    for (my $i = $start; $i <= $end; ++$i ) {
			die "host NUMA node$i don't exist\n" if ! -d "/sys/devices/system/node/node$i/";
		    }
		}

		# policy
		my $policy = $numa->{policy};
		die "you need to define a policy for hostnode $hostnodes\n" if !$policy;
		$numa_object .= ",host-nodes=$hostnodes,policy=$policy";
	    }

	    push @$cmd, '-object', $numa_object;
	    push @$cmd, '-numa', "node,nodeid=$i,cpus=$cpus,memdev=ram-node$i";
	}

	die "total memory for NUMA nodes must be equal to vm static memory\n"
	    if $numa_totalmemory && $numa_totalmemory != $static_memory;

	#if no custom tology, we split memory and cores across numa nodes
	if(!$numa_totalmemory) {

	    my $numa_memory = ($static_memory / $sockets) . "M";

	    for (my $i = 0; $i < $sockets; $i++)  {

		my $cpustart = ($cores * $i);
		my $cpuend = ($cpustart + $cores - 1) if $cores && $cores > 1;
		my $cpus = $cpustart;
		$cpus .= "-$cpuend" if $cpuend;

		push @$cmd, '-object', "memory-backend-ram,size=$numa_memory,id=ram-node$i";
		push @$cmd, '-numa', "node,nodeid=$i,cpus=$cpus,memdev=ram-node$i";
	    }
	}
    }

    if ($hotplug_features->{memory}) {
	foreach_dimm($conf, $vmid, $memory, $sockets, sub {
	    my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;
	    push @$cmd, "-object" , "memory-backend-ram,id=mem-$name,size=${dimm_size}M";
	    push @$cmd, "-device", "pc-dimm,id=$name,memdev=mem-$name,node=$numanode";

	    #if dimm_memory is not aligned to dimm map
	    if($current_size > $memory) {
	         $conf->{memory} = $current_size;
	         PVE::QemuConfig->write_config($vmid, $conf);
	    }
	});
    }
}


1;

