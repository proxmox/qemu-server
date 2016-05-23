package PVE::QemuServer::Memory;

use strict;
use warnings;


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

1;

