package PVE::QemuServer::Memory;

use strict;
use warnings;

use PVE::JSONSchema qw(parse_property_string);
use PVE::Tools qw(run_command lock_file lock_file_full file_read_firstline dir_glob_foreach);
use PVE::Exception qw(raise raise_param_exc);

use PVE::QemuServer::Helpers qw(parse_number_sets);
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::QMPHelpers qw(qemu_devicedel qemu_objectdel);

use base qw(Exporter);

our @EXPORT_OK = qw(
    get_current_memory
);

our $MAX_NUMA = 8;

my $numa_fmt = {
    cpus => {
        type => "string",
        pattern => qr/\d+(?:-\d+)?(?:;\d+(?:-\d+)?)*/,
        description => "CPUs accessing this NUMA node.",
        format_description => "id[-id];...",
    },
    memory => {
        type => "number",
        description => "Amount of memory this NUMA node provides.",
        optional => 1,
    },
    hostnodes => {
        type => "string",
        pattern => qr/\d+(?:-\d+)?(?:;\d+(?:-\d+)?)*/,
        description => "Host NUMA nodes to use.",
        format_description => "id[-id];...",
        optional => 1,
    },
    policy => {
        type => 'string',
        enum => [qw(preferred bind interleave)],
        description => "NUMA allocation policy.",
        optional => 1,
    },
};
PVE::JSONSchema::register_format('pve-qm-numanode', $numa_fmt);
our $numadesc = {
    optional => 1,
    type => 'string',
    format => $numa_fmt,
    description => "NUMA topology.",
};
PVE::JSONSchema::register_standard_option("pve-qm-numanode", $numadesc);

sub parse_numa {
    my ($data) = @_;

    my $res = parse_property_string($numa_fmt, $data);
    $res->{cpus} = parse_number_sets($res->{cpus}) if defined($res->{cpus});
    $res->{hostnodes} = parse_number_sets($res->{hostnodes}) if defined($res->{hostnodes});
    return $res;
}

my $STATICMEM = 1024;

our $memory_fmt = {
    current => {
        description =>
            "Current amount of online RAM for the VM in MiB. This is the maximum available memory when"
            . " you use the balloon device.",
        type => 'integer',
        default_key => 1,
        minimum => 16,
        default => 512,
    },
};

sub print_memory {
    my $memory = shift;

    return PVE::JSONSchema::print_property_string($memory, $memory_fmt);
}

sub parse_memory {
    my ($value) = @_;

    return { current => $memory_fmt->{current}->{default} } if !defined($value);

    my $res = PVE::JSONSchema::parse_property_string($memory_fmt, $value);

    return $res;
}

my $_host_bits;

sub get_host_phys_address_bits {
    return $_host_bits if defined($_host_bits);

    my $fh = IO::File->new('/proc/cpuinfo', "r") or return;
    while (defined(my $line = <$fh>)) {
        # hopefully we never need to care about mixed (big.LITTLE) archs
        if ($line =~ m/^address sizes\s*:\s*(\d+)\s*bits physical/i) {
            $_host_bits = int($1);
            $fh->close();
            return $_host_bits;
        }
    }
    $fh->close();
    return; # undef, cannot really do anything..
}

my sub get_max_mem {
    my ($conf) = @_;

    my $cpu = {};
    if (my $cpu_prop_str = $conf->{cpu}) {
        $cpu = PVE::JSONSchema::parse_property_string('pve-vm-cpu-conf', $cpu_prop_str)
            or die "Cannot parse cpu description: $cpu_prop_str\n";
    }
    my $bits;
    if (my $phys_bits = $cpu->{'phys-bits'}) {
        if ($phys_bits eq 'host') {
            $bits = get_host_phys_address_bits();
        } elsif ($phys_bits =~ /^(\d+)$/) {
            $bits = int($phys_bits);
        }
    }

    if (!defined($bits)) {
        my $host_bits = get_host_phys_address_bits() // 36; # fixme: what fallback?
        if ($cpu->{cputype} && $cpu->{cputype} =~ /^(host|max)$/) {
            $bits = $host_bits;
        } else {
            $bits = $host_bits > 40 ? 40 : $host_bits; # take the smaller one
        }
    }

    $bits = $bits & ~1; # round down to nearest even as limit is lower with odd bit sizes

    # heuristic: remove 20 bits to get MB and half that as QEMU needs some overhead
    my $bits_to_max_mem = int(1 << ($bits - 21));

    return $bits_to_max_mem > 4 * 1024 * 1024 ? 4 * 1024 * 1024 : $bits_to_max_mem;
}

sub get_current_memory {
    my ($value) = @_;

    my $memory = parse_memory($value);
    return $memory->{current};
}

sub get_numa_node_list {
    my ($conf) = @_;
    my @numa_map;
    for (my $i = 0; $i < $MAX_NUMA; $i++) {
        my $entry = $conf->{"numa$i"} or next;
        my $numa = parse_numa($entry) or next;
        push @numa_map, $i;
    }
    return @numa_map if @numa_map;
    my $sockets = $conf->{sockets} || 1;
    return (0 .. ($sockets - 1));
}

sub host_numanode_exists {
    my ($id) = @_;

    return -d "/sys/devices/system/node/node$id/";
}

# only valid when numa nodes map to a single host node
sub get_numa_guest_to_host_map {
    my ($conf) = @_;
    my $map = {};
    for (my $i = 0; $i < $MAX_NUMA; $i++) {
        my $entry = $conf->{"numa$i"} or next;
        my $numa = parse_numa($entry) or next;
        $map->{$i} = print_numa_hostnodes($numa->{hostnodes});
    }
    return $map if %$map;
    my $sockets = $conf->{sockets} || 1;
    return { map { $_ => $_ } (0 .. ($sockets - 1)) };
}

sub foreach_dimm {
    my ($conf, $vmid, $memory, $static_memory, $func) = @_;

    my $dimm_id = 0;
    my $current_size = $static_memory;
    my $dimm_size = 0;

    if ($conf->{hugepages} && $conf->{hugepages} == 1024) {
        $dimm_size = 1024;
    } else {
        $dimm_size = 512;
    }

    return if $current_size == $memory;

    my @numa_map = get_numa_node_list($conf);

    for (my $j = 0; $j < 8; $j++) {
        for (my $i = 0; $i < 32; $i++) {
            my $name = "dimm${dimm_id}";
            $dimm_id++;
            my $numanode = $numa_map[$i % @numa_map];
            $current_size += $dimm_size;
            &$func($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory);
            return $current_size if $current_size >= $memory;
        }
        $dimm_size *= 2;
    }
}

sub qemu_memory_hotplug {
    my ($vmid, $conf, $value) = @_;

    return $value if !PVE::QemuServer::Helpers::vm_running_locally($vmid);

    my $oldmem = parse_memory($conf->{memory});
    my $newmem = parse_memory($value);

    return $value if $newmem->{current} == $oldmem->{current};

    my $memory = $oldmem->{current};
    $value = $newmem->{current};

    my $sockets = $conf->{sockets} || 1;
    my $static_memory = $STATICMEM;
    $static_memory = $static_memory * $sockets
        if ($conf->{hugepages} && $conf->{hugepages} == 1024);

    die "memory can't be lower than $static_memory MB" if $value < $static_memory;
    my $MAX_MEM = get_max_mem($conf);
    die "you cannot add more memory than max mem $MAX_MEM MB!\n" if $value > $MAX_MEM;

    if ($value > $memory) {

        my $numa_hostmap;

        foreach_dimm(
            $conf,
            $vmid,
            $value,
            $static_memory,
            sub {
                my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;

                return if $current_size <= get_current_memory($conf->{memory});

                if ($conf->{hugepages}) {
                    $numa_hostmap = get_numa_guest_to_host_map($conf) if !$numa_hostmap;

                    my $hugepages_size = hugepages_size($conf, $dimm_size);
                    my $path = hugepages_mount_path($hugepages_size);
                    my $host_numanode = $numa_hostmap->{$numanode};
                    my $hugepages_topology->{$hugepages_size}->{$host_numanode} =
                        hugepages_nr($dimm_size, $hugepages_size);

                    my $code = sub {
                        my $hugepages_host_topology = hugepages_host_topology();
                        hugepages_allocate($hugepages_topology, $hugepages_host_topology);

                        eval {
                            mon_cmd(
                                $vmid, "object-add",
                                'qom-type' => "memory-backend-file",
                                id => "mem-$name",
                                size => int($dimm_size * 1024 * 1024),
                                'mem-path' => $path,
                                share => JSON::true,
                                prealloc => JSON::true,
                            );
                        };
                        if (my $err = $@) {
                            hugepages_reset($hugepages_host_topology);
                            die $err;
                        }

                        hugepages_pre_deallocate($hugepages_topology);
                    };
                    eval { hugepages_update_locked($code); };

                } else {
                    eval {
                        mon_cmd(
                            $vmid, "object-add",
                            'qom-type' => "memory-backend-ram",
                            id => "mem-$name",
                            size => int($dimm_size * 1024 * 1024),
                        );
                    };
                }

                if (my $err = $@) {
                    eval { qemu_objectdel($vmid, "mem-$name"); };
                    die $err;
                }

                eval {
                    mon_cmd(
                        $vmid, "device_add",
                        driver => "pc-dimm",
                        id => "$name",
                        memdev => "mem-$name",
                        node => $numanode,
                    );
                };
                if (my $err = $@) {
                    eval { qemu_objectdel($vmid, "mem-$name"); };
                    die $err;
                }
                # update conf after each successful module hotplug
                $newmem->{current} = $current_size;
                $conf->{memory} = print_memory($newmem);
                PVE::QemuConfig->write_config($vmid, $conf);
            },
        );

    } else {

        my $dimms = qemu_memdevices_list($vmid, 'dimm');

        my $current_size = $memory;
        for my $name (sort { ($b =~ /^dimm(\d+)$/)[0] <=> ($a =~ /^dimm(\d+)$/)[0] } keys %$dimms) {

            my $dimm_size = $dimms->{$name}->{size} / 1024 / 1024;

            last if $current_size <= $value;

            print "try to unplug memory dimm $name\n";

            my $retry = 0;
            while (1) {
                eval { qemu_devicedel($vmid, $name) };
                sleep 3;
                my $dimm_list = qemu_memdevices_list($vmid, 'dimm');
                last if !$dimm_list->{$name};
                raise_param_exc({ $name => "error unplug memory module" }) if $retry > 5;
                $retry++;
            }
            $current_size -= $dimm_size;
            # update conf after each successful module unplug
            $newmem->{current} = $current_size;
            $conf->{memory} = print_memory($newmem);

            eval { qemu_objectdel($vmid, "mem-$name"); };
            PVE::QemuConfig->write_config($vmid, $conf);
        }
    }
    return $conf->{memory};
}

sub qemu_memdevices_list {
    my ($vmid, $type) = @_;

    my $dimmarray = mon_cmd($vmid, "query-memory-devices");
    my $dimms = {};

    foreach my $dimm (@$dimmarray) {
        next if $type && $dimm->{data}->{id} !~ /^$type(\d+)$/;
        $dimms->{ $dimm->{data}->{id} }->{id} = $dimm->{data}->{id};
        $dimms->{ $dimm->{data}->{id} }->{node} = $dimm->{data}->{node};
        $dimms->{ $dimm->{data}->{id} }->{addr} = $dimm->{data}->{addr};
        $dimms->{ $dimm->{data}->{id} }->{size} = $dimm->{data}->{size};
        $dimms->{ $dimm->{data}->{id} }->{slot} = $dimm->{data}->{slot};
    }
    return $dimms;
}

sub config {
    my ($conf, $vmid, $sockets, $cores, $hotplug, $virtiofs_enabled, $cmd, $machine_flags) = @_;

    my $memory = get_current_memory($conf->{memory});
    my $static_memory = 0;

    if ($hotplug) {
        die "NUMA needs to be enabled for memory hotplug\n" if !$conf->{numa};
        my $MAX_MEM = get_max_mem($conf);
        die "Total memory is bigger than ${MAX_MEM}MB\n" if $memory > $MAX_MEM;

        for (my $i = 0; $i < $MAX_NUMA; $i++) {
            die "cannot enable memory hotplugging with custom NUMA topology\n"
                if $conf->{"numa$i"};
        }

        my $sockets = $conf->{sockets} || 1;

        $static_memory = $STATICMEM;
        $static_memory = $static_memory * $sockets
            if ($conf->{hugepages} && $conf->{hugepages} == 1024);

        die "minimum memory must be ${static_memory}MB\n" if ($memory < $static_memory);
        push @$cmd, '-m', "size=${static_memory},slots=255,maxmem=${MAX_MEM}M";

    } else {

        $static_memory = $memory;
        push @$cmd, '-m', $static_memory;
    }

    die "numa needs to be enabled to use hugepages" if $conf->{hugepages} && !$conf->{numa};

    die "Memory hotplug does not work in combination with virtio-fs.\n"
        if $hotplug && $virtiofs_enabled;

    if ($conf->{numa}) {

        my $numa_totalmemory = undef;
        for (my $i = 0; $i < $MAX_NUMA; $i++) {
            next if !$conf->{"numa$i"};
            my $numa = parse_numa($conf->{"numa$i"});
            next if !$numa;
            # memory
            die "missing NUMA node$i memory value\n" if !$numa->{memory};
            my $numa_memory = $numa->{memory};
            $numa_totalmemory += $numa_memory;

            my $memdev = $virtiofs_enabled ? "virtiofs-mem$i" : "ram-node$i";
            my $mem_object = print_mem_object($conf, $memdev, $numa_memory);

            # cpus
            my $cpulists = $numa->{cpus};
            die "missing NUMA node$i cpus\n" if !defined($cpulists);
            my $cpus = join(
                ',cpus=',
                map {
                    my ($start, $end) = @$_;
                    defined($end) ? "$start-$end" : $start
                } @$cpulists,
            );

            # hostnodes
            my $hostnodelists = $numa->{hostnodes};
            if (defined($hostnodelists)) {

                my $hostnodes = print_numa_hostnodes($hostnodelists);

                # policy
                my $policy = $numa->{policy};
                die "you need to define a policy for hostnode $hostnodes\n" if !$policy;
                $mem_object .= ",host-nodes=$hostnodes,policy=$policy";
            } else {
                die "numa hostnodes need to be defined to use hugepages" if $conf->{hugepages};
            }

            push @$cmd, '-object', $mem_object;
            push @$cmd, '-numa', "node,nodeid=$i,cpus=$cpus,memdev=$memdev";
        }

        die "total memory for NUMA nodes must be equal to vm static memory\n"
            if $numa_totalmemory && $numa_totalmemory != $static_memory;

        #if no custom tology, we split memory and cores across numa nodes
        if (!$numa_totalmemory) {
            my $numa_memory = ($static_memory / $sockets);

            for (my $i = 0; $i < $sockets; $i++) {
                die "host NUMA node$i doesn't exist\n"
                    if !host_numanode_exists($i) && $conf->{hugepages};

                my $cpus = ($cores * $i);
                $cpus .= "-" . ($cpus + $cores - 1) if $cores > 1;

                my $memdev = $virtiofs_enabled ? "virtiofs-mem$i" : "ram-node$i";
                my $mem_object = print_mem_object($conf, $memdev, $numa_memory);
                push @$cmd, '-object', $mem_object;
                push @$cmd, '-numa', "node,nodeid=$i,cpus=$cpus,memdev=$memdev";
            }
        }
    } elsif ($virtiofs_enabled) {
        # kvm: '-machine memory-backend' and '-numa memdev' properties are mutually exclusive
        push @$cmd, '-object',
            'memory-backend-memfd,id=virtiofs-mem' . ",size=$conf->{memory}M,share=on";
        push @$machine_flags, 'memory-backend=virtiofs-mem';
    }

    if ($hotplug) {
        foreach_dimm(
            $conf,
            $vmid,
            $memory,
            $static_memory,
            sub {
                my ($conf, $vmid, $name, $dimm_size, $numanode, $current_size, $memory) = @_;

                my $mem_object = print_mem_object($conf, "mem-$name", $dimm_size);

                push @$cmd, "-object", $mem_object;
                push @$cmd, "-device", "pc-dimm,id=$name,memdev=mem-$name,node=$numanode";

                die "memory size ($memory) must be aligned to $dimm_size for hotplugging\n"
                    if $current_size > $memory;
            },
        );
    }
}

sub print_mem_object {
    my ($conf, $id, $size) = @_;

    if ($conf->{hugepages}) {

        my $hugepages_size = hugepages_size($conf, $size);
        my $path = hugepages_mount_path($hugepages_size);

        return "memory-backend-file,id=$id,size=${size}M,mem-path=$path,share=on,prealloc=yes";
    } elsif ($id =~ m/^virtiofs-mem/) {
        return "memory-backend-memfd,id=$id,size=${size}M,share=on";
    } else {
        return "memory-backend-ram,id=$id,size=${size}M";
    }

}

sub print_numa_hostnodes {
    my ($hostnodelists) = @_;

    my $hostnodes;
    foreach my $hostnoderange (@$hostnodelists) {
        my ($start, $end) = @$hostnoderange;
        $hostnodes .= ',' if $hostnodes;
        $hostnodes .= $start;
        $hostnodes .= "-$end" if defined($end);
        $end //= $start;
        for (my $i = $start; $i <= $end; ++$i) {
            die "host NUMA node$i doesn't exist\n" if !host_numanode_exists($i);
        }
    }
    return $hostnodes;
}

sub hugepages_mount {

    my $mountdata = PVE::ProcFSTools::parse_proc_mounts();

    foreach my $size (qw(2048 1048576)) {
        next if (!-d "/sys/kernel/mm/hugepages/hugepages-${size}kB");

        my $path = "/run/hugepages/kvm/${size}kB";

        my $found = grep {
            $_->[2] =~ /^hugetlbfs/
                && $_->[1] eq $path
        } @$mountdata;

        if (!$found) {

            File::Path::make_path($path) if (!-d $path);
            my $cmd =
                ['/bin/mount', '-t', 'hugetlbfs', '-o', "pagesize=${size}k", 'hugetlbfs', $path];
            run_command($cmd, errmsg => "hugepage mount error");
        }
    }
}

sub hugepages_mount_path {
    my ($size) = @_;

    $size = $size * 1024;
    return "/run/hugepages/kvm/${size}kB";

}

sub hugepages_nr {
    my ($size, $hugepages_size) = @_;

    return $size / $hugepages_size;
}

sub hugepages_chunk_size_supported {
    my ($size) = @_;

    return -d "/sys/kernel/mm/hugepages/hugepages-" . ($size * 1024) . "kB";
}

sub hugepages_size {
    my ($conf, $size) = @_;
    die "hugepages option is not enabled" if !$conf->{hugepages};
    die "memory size '$size' is not a positive even integer; cannot use for hugepages\n"
        if $size <= 0 || $size & 1;

    die "your system doesn't support hugepages\n"
        if !hugepages_chunk_size_supported(2) && !hugepages_chunk_size_supported(1024);

    if ($conf->{hugepages} eq 'any') {

        # try to use 1GB if available && memory size is matching
        if (hugepages_chunk_size_supported(1024) && ($size & 1023) == 0) {
            return 1024;
        } elsif (hugepages_chunk_size_supported(2)) {
            return 2;
        } else {
            die
                "host only supports 1024 GB hugepages, but requested size '$size' is not a multiple of 1024 MB\n";
        }
    } else {

        my $hugepagesize = $conf->{hugepages};

        if (!hugepages_chunk_size_supported($hugepagesize)) {
            die "your system doesn't support hugepages of $hugepagesize MB\n";
        } elsif (($size % $hugepagesize) != 0) {
            die
                "Memory size $size is not a multiple of the requested hugepages size $hugepagesize\n";
        }

        return $hugepagesize;
    }
}

sub hugepages_topology {
    my ($conf, $hotplug) = @_;

    my $hugepages_topology = {};

    return if !$conf->{numa};

    my $memory = get_current_memory($conf->{memory});
    my $static_memory = 0;
    my $sockets = $conf->{sockets} || 1;
    my $numa_custom_topology = undef;

    if ($hotplug) {
        $static_memory = $STATICMEM;
        $static_memory = $static_memory * $sockets
            if ($conf->{hugepages} && $conf->{hugepages} == 1024);
    } else {
        $static_memory = $memory;
    }

    #custom numa topology
    for (my $i = 0; $i < $MAX_NUMA; $i++) {
        next if !$conf->{"numa$i"};
        my $numa = parse_numa($conf->{"numa$i"});
        next if !$numa;

        $numa_custom_topology = 1;
        my $numa_memory = $numa->{memory};
        my $hostnodelists = $numa->{hostnodes};
        my $hostnodes = print_numa_hostnodes($hostnodelists);

        die "more than 1 hostnode value in numa node is not supported when hugepages are enabled"
            if $hostnodes !~ m/^(\d)$/;
        my $hugepages_size = hugepages_size($conf, $numa_memory);
        $hugepages_topology->{$hugepages_size}->{$hostnodes} +=
            hugepages_nr($numa_memory, $hugepages_size);

    }

    #if no custom numa tology, we split memory and cores across numa nodes
    if (!$numa_custom_topology) {

        my $numa_memory = ($static_memory / $sockets);

        for (my $i = 0; $i < $sockets; $i++) {

            my $hugepages_size = hugepages_size($conf, $numa_memory);
            $hugepages_topology->{$hugepages_size}->{$i} +=
                hugepages_nr($numa_memory, $hugepages_size);
        }
    }

    if ($hotplug) {
        my $numa_hostmap = get_numa_guest_to_host_map($conf);

        foreach_dimm(
            $conf,
            undef,
            $memory,
            $static_memory,
            sub {
                my ($conf, undef, $name, $dimm_size, $numanode, $current_size, $memory) = @_;

                $numanode = $numa_hostmap->{$numanode};

                my $hugepages_size = hugepages_size($conf, $dimm_size);
                $hugepages_topology->{$hugepages_size}->{$numanode} +=
                    hugepages_nr($dimm_size, $hugepages_size);
            },
        );
    }

    return $hugepages_topology;
}

sub hugepages_host_topology {

    #read host hugepages
    my $hugepages_host_topology = {};

    dir_glob_foreach(
        "/sys/devices/system/node/",
        'node(\d+)',
        sub {
            my ($nodepath, $numanode) = @_;

            dir_glob_foreach(
                "/sys/devices/system/node/$nodepath/hugepages/",
                'hugepages\-(\d+)kB',
                sub {
                    my ($hugepages_path, $hugepages_size) = @_;

                    $hugepages_size = $hugepages_size / 1024;
                    my $hugepages_nr = PVE::Tools::file_read_firstline(
                        "/sys/devices/system/node/$nodepath/hugepages/$hugepages_path/nr_hugepages"
                    );
                    $hugepages_host_topology->{$hugepages_size}->{$numanode} = $hugepages_nr;
                },
            );
        },
    );

    return $hugepages_host_topology;
}

sub hugepages_allocate {
    my ($hugepages_topology, $hugepages_host_topology) = @_;

    #allocate new hupages if needed
    foreach my $size (sort keys %$hugepages_topology) {

        my $nodes = $hugepages_topology->{$size};

        foreach my $numanode (keys %$nodes) {

            my $hugepages_size = $size * 1024;
            my $hugepages_requested = $hugepages_topology->{$size}->{$numanode};
            my $path =
                "/sys/devices/system/node/node${numanode}/hugepages/hugepages-${hugepages_size}kB/";
            my $hugepages_free = PVE::Tools::file_read_firstline($path . "free_hugepages");
            my $hugepages_nr = PVE::Tools::file_read_firstline($path . "nr_hugepages");

            if ($hugepages_requested > $hugepages_free) {
                my $hugepages_needed = $hugepages_requested - $hugepages_free;
                PVE::ProcFSTools::write_proc_entry(
                    $path . "nr_hugepages",
                    $hugepages_nr + $hugepages_needed,
                );
                #verify that is correctly allocated
                $hugepages_free = PVE::Tools::file_read_firstline($path . "free_hugepages");
                if ($hugepages_free < $hugepages_requested) {
                    #rollback to initial host config
                    hugepages_reset($hugepages_host_topology);
                    die "hugepage allocation failed";
                }
            }

        }
    }

}

sub hugepages_default_nr_hugepages {
    my ($size) = @_;

    my $cmdline = PVE::Tools::file_read_firstline("/proc/cmdline");
    my $args = PVE::Tools::split_args($cmdline);

    my $parsed_size = 2; # default is 2M

    foreach my $arg (@$args) {
        if ($arg eq "hugepagesz=2M") {
            $parsed_size = 2;
        } elsif ($arg eq "hugepagesz=1G") {
            $parsed_size = 1024;
        } elsif ($arg =~ m/^hugepages=(\d+)?$/) {
            if ($parsed_size == $size) {
                return $1;
            }
        }
    }

    return 0;
}

sub hugepages_pre_deallocate {
    my ($hugepages_topology) = @_;

    foreach my $size (sort keys %$hugepages_topology) {

        my $hugepages_size = $size * 1024;
        my $path = "/sys/kernel/mm/hugepages/hugepages-${hugepages_size}kB/";
        my $hugepages_nr = hugepages_default_nr_hugepages($size);
        PVE::ProcFSTools::write_proc_entry($path . "nr_hugepages", $hugepages_nr);
    }
}

sub hugepages_reset {
    my ($hugepages_topology) = @_;

    foreach my $size (sort keys %$hugepages_topology) {

        my $nodes = $hugepages_topology->{$size};
        foreach my $numanode (keys %$nodes) {

            my $hugepages_nr = $hugepages_topology->{$size}->{$numanode};
            my $hugepages_size = $size * 1024;
            my $path =
                "/sys/devices/system/node/node${numanode}/hugepages/hugepages-${hugepages_size}kB/";

            PVE::ProcFSTools::write_proc_entry($path . "nr_hugepages", $hugepages_nr);
        }
    }
}

sub hugepages_update_locked {
    my ($code, @param) = @_;

    my $timeout = 60; #could be long if a lot of hugepages need to be allocated

    my $lock_filename = "/var/lock/hugepages.lck";

    my $res = lock_file($lock_filename, $timeout, $code, @param);
    die $@ if $@;

    return $res;
}
1;

