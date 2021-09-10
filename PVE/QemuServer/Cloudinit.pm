package PVE::QemuServer::Cloudinit;

use strict;
use warnings;

use File::Path;
use Digest::SHA;
use URI::Escape;
use MIME::Base64 qw(encode_base64);

use PVE::Tools qw(run_command file_set_contents);
use PVE::Storage;
use PVE::QemuServer;

use constant CLOUDINIT_DISK_SIZE => 4 * 1024 * 1024; # 4MiB in bytes

sub commit_cloudinit_disk {
    my ($conf, $vmid, $drive, $volname, $storeid, $files, $label) = @_;

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

    my $size = eval { PVE::Storage::volume_size_info($storecfg, $drive->{file}) };
    if (!defined($size) || $size <= 0) {
	$volname =~ m/(vm-$vmid-cloudinit(.\Q$format\E)?)/;
	my $name = $1;
	$size = 4 * 1024;
	PVE::Storage::vdisk_alloc($storecfg, $storeid, $vmid, $format, $name, $size);
	$size *= 1024; # vdisk alloc takes KB, qemu-img dd's osize takes byte
    }
    my $plugin = PVE::Storage::Plugin->lookup($scfg->{type});
    $plugin->activate_volume($storeid, $scfg, $volname);

    print "generating cloud-init ISO\n";
    eval {
	run_command([
	    ['genisoimage', '-quiet', '-iso-level', '3', '-R', '-V', $label, $path],
	    ['qemu-img', 'dd', '-n', '-f', 'raw', '-O', $format, 'isize=0', "osize=$size", "of=$iso_path"]
	]);
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
    my ($conf, $vmid) = @_;
    my $hostname = $conf->{name} // "VM$vmid";
    my $fqdn;
    if ($hostname =~ /\./) {
	$fqdn = $hostname;
	$hostname =~ s/\..*$//;
    } elsif (my $search = $conf->{searchdomain}) {
	$fqdn = "$hostname.$search";
    }
    return ($hostname, $fqdn);
}

sub get_dns_conf {
    my ($conf) = @_;

    # Same logic as in pve-container, but without the testcase special case
    my $host_resolv_conf = PVE::INotify::read_file('resolvconf');

    my $searchdomains = [
	split(/\s+/, $conf->{searchdomain} // $host_resolv_conf->{search})
    ];

    my $nameserver = $conf->{nameserver};
    if (!defined($nameserver)) {
	$nameserver = [grep { $_ } $host_resolv_conf->@{qw(dns1 dns2 dns3)}];
    } else {
	$nameserver = [split(/\s+/, $nameserver)];
    }

    return ($searchdomains, $nameserver);
}

sub cloudinit_userdata {
    my ($conf, $vmid) = @_;

    my ($hostname, $fqdn) = get_hostname_fqdn($conf, $vmid);

    my $content = "#cloud-config\n";

    $content .= "hostname: $hostname\n";
    $content .= "manage_etc_hosts: true\n";
    $content .= "fqdn: $fqdn\n" if defined($fqdn);

    my $username = $conf->{ciuser};
    my $password = $conf->{cipassword};

    $content .= "user: $username\n" if defined($username);
    $content .= "disable_root: False\n" if defined($username) && $username eq 'root';
    $content .= "password: $password\n" if defined($password);

    if (defined(my $keys = $conf->{sshkeys})) {
	$keys = URI::Escape::uri_unescape($keys);
	$keys = [map { my $key = $_; chomp $key; $key } split(/\n/, $keys)];
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

sub split_ip4 {
    my ($ip) = @_;
    my ($addr, $mask) = split('/', $ip);
    die "not a CIDR: $ip\n" if !defined $mask;
    return ($addr, $PVE::Network::ipv4_reverse_mask->[$mask]);
}

sub configdrive2_network {
    my ($conf) = @_;

    my $content = "auto lo\n";
    $content .= "iface lo inet loopback\n\n";

    my ($searchdomains, $nameservers) = get_dns_conf($conf);
    if ($nameservers && @$nameservers) {
	$nameservers = join(' ', @$nameservers);
	$content .= "        dns_nameservers $nameservers\n";
    }
    if ($searchdomains && @$searchdomains) {
	$searchdomains = join(' ', @$searchdomains);
	$content .= "        dns_search $searchdomains\n";
    }

    my @ifaces = grep { /^net(\d+)$/ } keys %$conf;
    foreach my $iface (sort @ifaces) {
	(my $id = $iface) =~ s/^net//;
	next if !$conf->{"ipconfig$id"};
	my $net = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});
	$id = "eth$id";

	$content .="auto $id\n";
	if ($net->{ip}) {
	    if ($net->{ip} eq 'dhcp') {
		$content .= "iface $id inet dhcp\n";
	    } else {
		my ($addr, $mask) = split_ip4($net->{ip});
		$content .= "iface $id inet static\n";
		$content .= "        address $addr\n";
		$content .= "        netmask $mask\n";
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

    return $content;
}

sub configdrive2_gen_metadata {
    my ($user, $network) = @_;

    my $uuid_str = Digest::SHA::sha1_hex($user.$network);
    return configdrive2_metadata($uuid_str);
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

    my ($user_data, $network_data, $meta_data) = get_custom_cloudinit_files($conf);
    $user_data = cloudinit_userdata($conf, $vmid) if !defined($user_data);
    $network_data = configdrive2_network($conf) if !defined($network_data);

    if (!defined($meta_data)) {
	$meta_data = configdrive2_gen_metadata($user_data, $network_data);
    }
    my $files = {
	'/openstack/latest/user_data' => $user_data,
	'/openstack/content/0000' => $network_data,
	'/openstack/latest/meta_data.json' => $meta_data
    };
    commit_cloudinit_disk($conf, $vmid, $drive, $volname, $storeid, $files, 'config-2');
}

sub generate_opennebula {
    my ($conf, $vmid, $drive, $volname, $storeid) = @_;

    my ($hostname, $fqdn) = get_hostname_fqdn($conf, $vmid);

    my $content = "";

    my $username = $conf->{ciuser} || "root";
    my $password = encode_base64($conf->{cipassword}) if defined($conf->{cipassword});

    $content .= "USERNAME=$username\n" if defined($username);
    $content .= "CRYPTED_PASSWORD_BASE64=$password\n" if defined($password);

    if (defined(my $keys = $conf->{sshkeys})) {
        $keys = URI::Escape::uri_unescape($keys);
        $keys = [map { my $key = $_; chomp $key; $key } split(/\n/, $keys)];
        $keys = [grep { /\S/ } @$keys];
        $content .= "SSH_PUBLIC_KEY=\"";

        foreach my $k (@$keys) {
	     $content .= "$k\n";
        }
        $content .= "\"\n";

    }

    my ($searchdomains, $nameservers) = get_dns_conf($conf);
    if ($nameservers && @$nameservers) {
        $nameservers = join(' ', @$nameservers);
        $content .= "DNS=\"$nameservers\"\n";
    }

    $content .= "SET_HOSTNAME=$hostname\n";

    if ($searchdomains && @$searchdomains) {
        $searchdomains = join(' ', @$searchdomains);
        $content .= "SEARCH_DOMAIN=\"$searchdomains\"\n";
    }

    my $networkenabled = undef;
    my @ifaces = grep { /^net(\d+)$/ } keys %$conf;
    foreach my $iface (sort @ifaces) {
        (my $id = $iface) =~ s/^net//;
	my $net = PVE::QemuServer::parse_net($conf->{$iface});
        next if !$conf->{"ipconfig$id"};
	my $ipconfig = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});
        my $ethid = "ETH$id";

	my $mac = lc $net->{hwaddr};

	if ($ipconfig->{ip}) {
	    $networkenabled = 1;

	    if ($ipconfig->{ip} eq 'dhcp') {
		$content .= $ethid."_DHCP=YES\n";
	    } else {
		my ($addr, $mask) = split_ip4($ipconfig->{ip});
		$content .= $ethid."_IP=$addr\n";
		$content .= $ethid."_MASK=$mask\n";
		$content .= $ethid."_MAC=$mac\n";
		$content .= $ethid."_GATEWAY=$ipconfig->{gw}\n" if $ipconfig->{gw};
	    }
	    $content .= $ethid."_MTU=$net->{mtu}\n" if $net->{mtu};
	}

	if ($ipconfig->{ip6}) {
	    $networkenabled = 1;
	    if ($ipconfig->{ip6} eq 'dhcp') {
		$content .= $ethid."_DHCP6=YES\n";
	    } elsif ($ipconfig->{ip6} eq 'auto') {
		$content .= $ethid."_AUTO6=YES\n";
	    } else {
		my ($addr, $mask) = split('/', $ipconfig->{ip6});
		$content .= $ethid."_IP6=$addr\n";
		$content .= $ethid."_MASK6=$mask\n";
		$content .= $ethid."_MAC6=$mac\n";
		$content .= $ethid."_GATEWAY6=$ipconfig->{gw6}\n" if $ipconfig->{gw6};
	    }
	    $content .= $ethid."_MTU=$net->{mtu}\n" if $net->{mtu};
	}
    }

    $content .= "NETWORK=YES\n" if $networkenabled;

    my $files = {
	'/context.sh' => $content,
    };
    commit_cloudinit_disk($conf, $vmid, $drive, $volname, $storeid, $files, 'CONTEXT');
}

sub nocloud_network_v2 {
    my ($conf) = @_;

    my $content = '';

    my $head = "version: 2\n"
             . "ethernets:\n";

    my $dns_done;

    my @ifaces = grep { /^net(\d+)$/ } keys %$conf;
    foreach my $iface (sort @ifaces) {
	(my $id = $iface) =~ s/^net//;
	next if !$conf->{"ipconfig$id"};

	# indentation - network interfaces are inside an 'ethernets' hash
	my $i = '    ';

	my $net = PVE::QemuServer::parse_net($conf->{$iface});
	my $ipconfig = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});

	my $mac = $net->{macaddr}
	    or die "network interface '$iface' has no mac address\n";

	$content .= "${i}$iface:\n";
	$i .= '    ';
	$content .= "${i}match:\n"
	         . "${i}    macaddress: \"$mac\"\n"
	         . "${i}set-name: eth$id\n";
	my @addresses;
	if (defined(my $ip = $ipconfig->{ip})) {
	    if ($ip eq 'dhcp') {
		$content .= "${i}dhcp4: true\n";
	    } else {
		push @addresses, $ip;
	    }
	}
	if (defined(my $ip = $ipconfig->{ip6})) {
	    if ($ip eq 'dhcp') {
		$content .= "${i}dhcp6: true\n";
	    } else {
		push @addresses, $ip;
	    }
	}
	if (@addresses) {
	    $content .= "${i}addresses:\n";
	    $content .= "${i}- '$_'\n" foreach @addresses;
	}
	if (defined(my $gw = $ipconfig->{gw})) {
	    $content .= "${i}gateway4: '$gw'\n";
	}
	if (defined(my $gw = $ipconfig->{gw6})) {
	    $content .= "${i}gateway6: '$gw'\n";
	}

	next if $dns_done;
	$dns_done = 1;

	my ($searchdomains, $nameservers) = get_dns_conf($conf);
	if ($searchdomains || $nameservers) {
	    $content .= "${i}nameservers:\n";
	    if (defined($nameservers) && @$nameservers) {
		$content .= "${i}  addresses:\n";
		$content .= "${i}  - '$_'\n" foreach @$nameservers;
	    }
	    if (defined($searchdomains) && @$searchdomains) {
		$content .= "${i}  search:\n";
		$content .= "${i}  - '$_'\n" foreach @$searchdomains;
	    }
	}
    }

    return $head.$content;
}

sub nocloud_network {
    my ($conf) = @_;

    my $content = "version: 1\n"
                . "config:\n";

    my @ifaces = grep { /^net(\d+)$/ } keys %$conf;
    foreach my $iface (sort @ifaces) {
	(my $id = $iface) =~ s/^net//;
	next if !$conf->{"ipconfig$id"};

	# indentation - network interfaces are inside an 'ethernets' hash
	my $i = '    ';

	my $net = PVE::QemuServer::parse_net($conf->{$iface});
	my $ipconfig = PVE::QemuServer::parse_ipconfig($conf->{"ipconfig$id"});

	my $mac = lc($net->{macaddr})
	    or die "network interface '$iface' has no mac address\n";

	$content .= "${i}- type: physical\n"
	          . "${i}  name: eth$id\n"
	          . "${i}  mac_address: '$mac'\n"
	          . "${i}  subnets:\n";
	$i .= '  ';
	if (defined(my $ip = $ipconfig->{ip})) {
	    if ($ip eq 'dhcp') {
		$content .= "${i}- type: dhcp4\n";
	    } else {
		my ($addr, $mask) = split_ip4($ip);
		$content .= "${i}- type: static\n"
		          . "${i}  address: '$addr'\n"
		          . "${i}  netmask: '$mask'\n";
		if (defined(my $gw = $ipconfig->{gw})) {
		    $content .= "${i}  gateway: '$gw'\n";
		}
	    }
	}
	if (defined(my $ip = $ipconfig->{ip6})) {
	    if ($ip eq 'dhcp') {
		$content .= "${i}- type: dhcp6\n";
	    } elsif ($ip eq 'auto') {
		# SLAAC is only supported by cloud-init since 19.4
		$content .= "${i}- type: ipv6_slaac\n";
	    } else {
		$content .= "${i}- type: static6\n"
		       . "${i}  address: '$ip'\n";
		if (defined(my $gw = $ipconfig->{gw6})) {
		    $content .= "${i}  gateway: '$gw'\n";
		}
	    }
	}
    }

    my $i = '    ';
    my ($searchdomains, $nameservers) = get_dns_conf($conf);
    if ($searchdomains || $nameservers) {
	$content .= "${i}- type: nameserver\n";
	if (defined($nameservers) && @$nameservers) {
	    $content .= "${i}  address:\n";
	    $content .= "${i}  - '$_'\n" foreach @$nameservers;
	}
	if (defined($searchdomains) && @$searchdomains) {
	    $content .= "${i}  search:\n";
	    $content .= "${i}  - '$_'\n" foreach @$searchdomains;
	}
    }

    return $content;
}

sub nocloud_metadata {
    my ($uuid, $hostname) = @_;
    return "instance-id: $uuid\nhostname: $hostname\n";
}

sub nocloud_gen_metadata {
    my ($user, $network, $hostname) = @_;

    my $uuid_str = Digest::SHA::sha1_hex($user.$network);
    return nocloud_metadata($uuid_str, $hostname);
}

sub generate_nocloud {
    my ($conf, $vmid, $drive, $volname, $storeid) = @_;

    my ($user_data, $network_data, $meta_data) = get_custom_cloudinit_files($conf);
    $user_data = cloudinit_userdata($conf, $vmid) if !defined($user_data);
    $network_data = nocloud_network($conf) if !defined($network_data);

    if (!defined($meta_data)) {
	my ($hostname, $fqdn) = get_hostname_fqdn($conf, $vmid);
	$meta_data = nocloud_gen_metadata($user_data, $network_data, $hostname);
    }

    my $files = {
	'/user-data' => $user_data,
	'/network-config' => $network_data,
	'/meta-data' => $meta_data
    };
    commit_cloudinit_disk($conf, $vmid, $drive, $volname, $storeid, $files, 'cidata');
}

sub get_custom_cloudinit_files {
    my ($conf) = @_;

    my $cicustom = $conf->{cicustom};
    my $files = $cicustom ? PVE::JSONSchema::parse_property_string('pve-qm-cicustom', $cicustom) : {};

    my $network_volid = $files->{network};
    my $user_volid = $files->{user};
    my $meta_volid = $files->{meta};

    my $storage_conf = PVE::Storage::config();

    my $network_data;
    if ($network_volid) {
	$network_data = read_cloudinit_snippets_file($storage_conf, $network_volid);
    }

    my $user_data;
    if ($user_volid) {
	$user_data = read_cloudinit_snippets_file($storage_conf, $user_volid);
    }

    my $meta_data;
    if ($meta_volid) {
	$meta_data = read_cloudinit_snippets_file($storage_conf, $meta_volid);
    }

    return ($user_data, $network_data, $meta_data);
}

sub read_cloudinit_snippets_file {
    my ($storage_conf, $volid) = @_;

    my ($full_path, undef, $type) = PVE::Storage::path($storage_conf, $volid);
    die "$volid is not in the snippets directory\n" if $type ne 'snippets';
    return PVE::Tools::file_get_contents($full_path, 1 * 1024 * 1024);
}

my $cloudinit_methods = {
    configdrive2 => \&generate_configdrive2,
    nocloud => \&generate_nocloud,
    opennebula => \&generate_opennebula,
};

sub generate_cloudinitconfig {
    my ($conf, $vmid) = @_;

    my $format = get_cloudinit_format($conf);

    PVE::QemuConfig->foreach_volume($conf, sub {
        my ($ds, $drive) = @_;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);

	return if !$volname || $volname !~ m/vm-$vmid-cloudinit/;

	my $generator = $cloudinit_methods->{$format}
	    or die "missing cloudinit methods for format '$format'\n";

	$generator->($conf, $vmid, $drive, $volname, $storeid);
    });
}

sub dump_cloudinit_config {
    my ($conf, $vmid, $type) = @_;

    my $format = get_cloudinit_format($conf);

    if ($type eq 'user') {
	return cloudinit_userdata($conf, $vmid);
    } elsif ($type eq 'network') {
	if ($format eq 'nocloud') {
	    return nocloud_network($conf);
	} else {
	    return configdrive2_network($conf);
	}
    } else { # metadata config
	my $user = cloudinit_userdata($conf, $vmid);
	if ($format eq 'nocloud') {
	    my $network = nocloud_network($conf);
	    my ($hostname, $fqdn) = get_hostname_fqdn($conf, $vmid);
	    return nocloud_gen_metadata($user, $network, $hostname);
	} else {
	    my $network = configdrive2_network($conf);
	    return configdrive2_gen_metadata($user, $network);
	}
    }
}

1;
