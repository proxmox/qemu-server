package PVE::QemuServer::Cloudinit;

use strict;
use warnings;

use File::Path;
use Digest::SHA;
use URI::Escape;

use PVE::Tools qw(run_command file_set_contents);
use PVE::Storage;
use PVE::QemuServer;

sub commit_cloudinit_disk {
    my ($vmid, $conf, $drive, $volname, $storeid, $files, $label) = @_;

    my $path = "/run/pve/cloudinit/$vmid/";
    mkpath $path;
    foreach my $filepath (keys %$files) {
	if ($filepath !~ m@^(.*)\/[^/]+$@) {
	    die "internal error: bad file name in cloud-init image: $filepath\n";
	}
	my $dirname = $1;
	mkpath "$path/$dirname";

	my $contents = $files->{$filepath};
	file_set_contents("$path/$filepath", $contents);
    }

    my $storecfg = PVE::Storage::config();
    my $iso_path = PVE::Storage::path($storecfg, $drive->{file});
    my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
    my $format = PVE::QemuServer::qemu_img_format($scfg, $volname);

    my $size = PVE::Storage::file_size_info($iso_path);

    eval {
	run_command([['genisoimage', '-R', '-V', $label, $path],
		     ['qemu-img', 'dd', '-f', 'raw', '-O', $format,
		      'isize=0', "osize=$size", "of=$iso_path"]]);
    };
    my $err = $@;
    rmtree($path);
    die $err if $err;
}

sub get_cloudinit_format {
    my ($conf) = @_;
    if (defined(my $format = $conf->{citype})) {
	return $format;
    }

    # No format specified, default based on ostype because windows'
    # cloudbased-init only supports configdrivev2, whereas on linux we need
    # to use mac addresses because regular cloudinit doesn't map 'ethX' to
    # the new predicatble network device naming scheme.
    if (defined(my $ostype = $conf->{ostype})) {
	return 'configdrive2'
	    if PVE::QemuServer::windows_version($ostype);
    }

    return 'nocloud';
}

sub get_hostname_fqdn {
    my ($conf) = @_;
    my $hostname = $conf->{name};
    my $fqdn;
    if ($hostname =~ /\./) {
	$fqdn = $hostname;
	$hostname =~ s/\..*$//;
    } elsif (my $search = $conf->{searchdomain}) {
	$fqdn = "$hostname.$search";
    }
    return ($hostname, $fqdn);
}

sub cloudinit_userdata {
    my ($conf) = @_;

    my ($hostname, $fqdn) = get_hostname_fqdn($conf);

    my $content = "#cloud-config\n";
    $content .= "manage_resolv_conf: true\n";

    $content .= "hostname: $hostname\n";
    $content .= "fqdn: $fqdn\n" if defined($fqdn);

    my $username = $conf->{ciuser};
    my $password = $conf->{cipassword};

    $content .= "user: $username\n" if defined($username);
    $content .= "disable_root: False\n" if defined($username) && $username eq 'root';
    $content .= "password: $password\n" if defined($password);

    if (defined(my $keys = $conf->{sshkeys})) {
	$keys = URI::Escape::uri_unescape($keys);
	$keys = [map { chomp $_; $_ } split(/\n/, $keys)];
	$keys = [grep { /\S/ } @$keys];
	$content .= "ssh_authorized_keys:\n";
	foreach my $k (@$keys) {
	    $content .= "  - $k\n";
	}
    }
    $content .= "chpasswd:\n";
    $content .= "  expire: False\n";

    if (!defined($username) || $username ne 'root') {
	$content .= "users:\n";
	$content .= "  - default\n";
    }

    $content .= "package_upgrade: true\n";

    return $content;
}

sub configdrive2_network {
    my ($conf) = @_;

    my $content = "auto lo\n";
    $content .="iface lo inet loopback\n\n";

    my @ifaces = grep(/^net(\d+)$/, keys %$conf);
    foreach my $iface (@ifaces) {
	(my $id = $iface) =~ s/^net//;
	next if !$conf->{"ipconfig$id"};
	my $net = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});
	$id = "eth$id";

	$content .="auto $id\n";
	if ($net->{ip}) {
	    if ($net->{ip} eq 'dhcp') {
		$content .= "iface $id inet dhcp\n";
	    } else {
		my ($addr, $mask) = split('/', $net->{ip});
		$content .= "iface $id inet static\n";
		$content .= "        address $addr\n";
		$content .= "        netmask $PVE::Network::ipv4_reverse_mask->[$mask]\n";
		$content .= "        gateway $net->{gw}\n" if $net->{gw};
	    }
	}
	if ($net->{ip6}) {
	    if ($net->{ip6} =~ /^(auto|dhcp)$/) {
		$content .= "iface $id inet6 $1\n";
	    } else {
		my ($addr, $mask) = split('/', $net->{ip6});
		$content .= "iface $id inet6 static\n";
		$content .= "        address $addr\n";
		$content .= "        netmask $mask\n";
		$content .= "        gateway $net->{gw6}\n" if $net->{gw6};
	    }
	}
    }

    $content .="        dns_nameservers $conf->{nameserver}\n" if $conf->{nameserver};
    $content .="        dns_search $conf->{searchdomain}\n" if $conf->{searchdomain};

    return $content;
}

sub configdrive2_metadata {
    my ($uuid) = @_;
    return <<"EOF";
{
     "uuid": "$uuid",
     "network_config": { "content_path": "/content/0000" }
}
EOF
}

sub generate_configdrive2 {
    my ($conf, $vmid, $drive, $volname, $storeid) = @_;

    my $user_data = cloudinit_userdata($conf);
    my $network_data = configdrive2_network($conf);

    my $digest_data = $user_data . $network_data;
    my $uuid_str = Digest::SHA::sha1_hex($digest_data);

    my $meta_data = configdrive2_metadata($uuid_str);

    my $files = {
	'/openstack/latest/user_data' => $user_data,
	'/openstack/content/0000' => $network_data,
	'/openstack/latest/meta_data.json' => $meta_data
    };
    commit_cloudinit_disk($vmid, $conf, $drive, $volname, $storeid, $files, 'config-2');
}

sub nocloud_network_v2 {
    my ($conf) = @_;

    my $content = '';

    my $head = "version: 2\n"
             . "ethernets:\n";

    my $nameservers_done;

    my @ifaces = grep(/^net(\d+)$/, keys %$conf);
    foreach my $iface (@ifaces) {
	(my $id = $iface) =~ s/^net//;
	next if !$conf->{"ipconfig$id"};

	# indentation - network interfaces are inside an 'ethernets' hash
	my $i = '    ';

	my $net = PVE::QemuServer::parse_net($conf->{$iface});
	my $ipconfig = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});

	my $mac = $net->{macaddr}
	    or die "network interface '$iface' has no mac address\n";

	my $data = "${i}$iface:\n";
	$i .= '    ';
	$data .= "${i}match:\n"
	       . "${i}    macaddress: \"$mac\"\n"
	       . "${i}set-name: eth$id\n";
	my @addresses;
	if (defined(my $ip = $ipconfig->{ip})) {
	    if ($ip eq 'dhcp') {
		$data .= "${i}dhcp4: true\n";
	    } else {
		push @addresses, $ip;
	    }
	}
	if (defined(my $ip = $ipconfig->{ip6})) {
	    if ($ip eq 'dhcp') {
		$data .= "${i}dhcp6: true\n";
	    } else {
		push @addresses, $ip;
	    }
	}
	if (@addresses) {
	    $data .= "${i}addresses:\n";
	    $data .= "${i}- $_\n" foreach @addresses;
	}
	if (defined(my $gw = $ipconfig->{gw})) {
	    $data .= "${i}gateway4: $gw\n";
	}
	if (defined(my $gw = $ipconfig->{gw6})) {
	    $data .= "${i}gateway6: $gw\n";
	}

	if (!$nameservers_done) {
	    $nameservers_done = 1;

	    my $nameserver = $conf->{nameserver} // '';
	    my $searchdomain = $conf->{searchdomain} // '';
	    my @nameservers = PVE::Tools::split_list($nameserver);
	    my @searchdomains = PVE::Tools::split_list($searchdomain);
	    if (@nameservers || @searchdomains) {
		$data .= "${i}nameservers:\n";
		$data .= "${i}    addresses: [".join(',', @nameservers)."]\n"
		    if @nameservers;
		$data .= "${i}    search: [".join(',', @searchdomains)."]\n"
		    if @searchdomains;
	    }
	}


	$content .= $data;
    }

    return $head.$content;
}

sub nocloud_network {
    my ($conf) = @_;

    my $content = "version: 1\n"
                . "config:\n";

    my @ifaces = grep(/^net(\d+)$/, keys %$conf);
    foreach my $iface (@ifaces) {
	(my $id = $iface) =~ s/^net//;
	next if !$conf->{"ipconfig$id"};

	# indentation - network interfaces are inside an 'ethernets' hash
	my $i = '    ';

	my $net = PVE::QemuServer::parse_net($conf->{$iface});
	my $ipconfig = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});

	my $mac = $net->{macaddr}
	    or die "network interface '$iface' has no mac address\n";

	my $data = "${i}- type: physical\n"
	         . "${i}  name: eth$id\n"
	         . "${i}  mac_address: $mac\n"
	         . "${i}  subnets:\n";
	$i .= '  ';
	if (defined(my $ip = $ipconfig->{ip})) {
	    if ($ip eq 'dhcp') {
		$data .= "${i}- type: dhcp4\n";
	    } else {
		$data .= "${i}- type: static\n"
		       . "${i}  address: $ip\n";
		if (defined(my $gw = $ipconfig->{gw})) {
		    $data .= "${i}  gateway: $gw\n";
		}
	    }
	}
	if (defined(my $ip = $ipconfig->{ip6})) {
	    if ($ip eq 'dhcp') {
		$data .= "${i}- type: dhcp6\n";
	    } else {
		$data .= "${i}- type: static6\n"
		       . "${i}  address: $ip\n";
		if (defined(my $gw = $ipconfig->{gw6})) {
		    $data .= "${i}  gateway: $gw\n";
		}
	    }
	}

	$content .= $data;
    }

    my $nameserver = $conf->{nameserver} // '';
    my $searchdomain = $conf->{searchdomain} // '';
    my @nameservers = PVE::Tools::split_list($nameserver);
    my @searchdomains = PVE::Tools::split_list($searchdomain);
    if (@nameservers || @searchdomains) {
	my $i = '    ';
	$content .= "${i}- type: nameserver\n";
	if (@nameservers) {
	    $content .= "${i}  address:\n";
	    $content .= "${i}  - $_\n" foreach @nameservers;
	}
	if (@searchdomains) {
	    $content .= "${i}  search:\n";
	    $content .= "${i}  - $_\n" foreach @searchdomains;
	}
    }

    return $content;
}

sub nocloud_metadata {
    my ($uuid) = @_;
    return "instance-id: $uuid\n";
}

sub generate_nocloud {
    my ($conf, $vmid, $drive, $volname, $storeid) = @_;

    my $user_data = cloudinit_userdata($conf);
    my $network_data = nocloud_network($conf);

    my $digest_data = $user_data . $network_data;
    my $uuid_str = Digest::SHA::sha1_hex($digest_data);

    my $meta_data = nocloud_metadata($uuid_str);

    my $files = {
	'/user-data' => $user_data,
	'/network-config' => $network_data,
	'/meta-data' => $meta_data
    };
    commit_cloudinit_disk($vmid, $conf, $drive, $volname, $storeid, $files, 'cidata');
}

my $cloudinit_methods = {
    configdrive2 => \&generate_configdrive2,
    nocloud => \&generate_nocloud,
};

sub generate_cloudinitconfig {
    my ($conf, $vmid) = @_;

    my $format = get_cloudinit_format($conf);

    PVE::QemuServer::foreach_drive($conf, sub {
        my ($ds, $drive) = @_;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);

	return if !$volname || $volname !~ m/vm-$vmid-cloudinit/;

	my $generator = $cloudinit_methods->{$format}
	    or die "missing cloudinit methods for format '$format'\n";

	$generator->($conf, $vmid, $drive, $volname, $storeid);
    });
}

1;
