package PVE::QemuServer::Cloudinit;

use strict;
use warnings;

use File::Path;
use Digest::SHA;
use URI::Escape;

use PVE::Tools qw(run_command file_set_contents);
use PVE::Storage;
use PVE::QemuServer;

sub nbd_stop {
    my ($vmid) = @_;

    PVE::QemuServer::vm_mon_cmd($vmid, 'nbd-server-stop');
}

sub next_free_nbd_dev {
    for(my $i = 0;;$i++) {
	my $dev = "/dev/nbd$i";
	last if ! -b $dev;
	next if -f "/sys/block/nbd$i/pid"; # busy
	return $dev;
    }
    die "unable to find free nbd device\n";
}

sub commit_cloudinit_disk {
    my ($file_path, $iso_path, $format) = @_;

    my $nbd_dev = next_free_nbd_dev();
    run_command(['qemu-nbd', '-c', $nbd_dev, $iso_path, '-f', $format]);

    eval {
	run_command([['genisoimage', '-R', '-V', 'config-2', $file_path],
		     ['dd', "of=$nbd_dev", 'conv=fsync']]);
    };
    my $err = $@;
    eval { run_command(['qemu-nbd', '-d', $nbd_dev]); };
    warn $@ if $@;
    die $err if $err;
}

sub generate_cloudinitconfig {
    my ($conf, $vmid) = @_;

    PVE::QemuServer::foreach_drive($conf, sub {
        my ($ds, $drive) = @_;

	my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);

	return if !$volname || $volname !~ m/vm-$vmid-cloudinit/;

	my $path = "/tmp/cloudinit/$vmid";

	mkdir "/tmp/cloudinit";
	mkdir $path;
	mkdir "$path/drive";
	mkdir "$path/drive/openstack";
	mkdir "$path/drive/openstack/latest";
	mkdir "$path/drive/openstack/content";
	my $digest_data = generate_cloudinit_userdata($conf, $path)
			. generate_cloudinit_network($conf, $path);
	generate_cloudinit_metadata($conf, $path, $digest_data);

	my $storecfg = PVE::Storage::config();
	my $iso_path = PVE::Storage::path($storecfg, $drive->{file});
	my $scfg = PVE::Storage::storage_config($storecfg, $storeid);
	my $format = PVE::QemuServer::qemu_img_format($scfg, $volname);
	#fixme : add meta as drive property to compare
	commit_cloudinit_disk("$path/drive", $iso_path, $format);
	rmtree("$path/drive");
    });
}


sub generate_cloudinit_userdata {
    my ($conf, $path) = @_;

    my $content = "#cloud-config\n";
    my $hostname = $conf->{hostname};
    if (!defined($hostname)) {
	$hostname = $conf->{name};
	if (my $search = $conf->{searchdomain}) {
	    $hostname .= ".$search";
	}
    }
    $content .= "fqdn: $hostname\n";
    $content .= "manage_etc_hosts: true\n";
    $content .= "bootcmd: \n";
    $content .= "  - ifdown -a\n";
    $content .= "  - ifup -a\n";

    my $keys = $conf->{sshkeys};
    if ($keys) {
	$keys = URI::Escape::uri_unescape($keys);
	$keys = [map { chomp $_; $_ } split(/\n/, $keys)];
	$keys = [grep { /\S/ } @$keys];

	$content .= "users:\n";
	$content .= "  - default\n";
	$content .= "  - name: root\n";
	$content .= "    ssh-authorized-keys:\n";
	foreach my $k (@$keys) {
	    $content .= "      - $k\n";
	}
    }

    $content .= "package_upgrade: true\n";

    my $fn = "$path/drive/openstack/latest/user_data";
    file_set_contents($fn, $content);
    return $content;
}

sub generate_cloudinit_metadata {
    my ($conf, $path, $digest_data) = @_;

    my $uuid_str = Digest::SHA::sha1_hex($digest_data);

    my $content = "{\n";
    $content .= "     \"uuid\": \"$uuid_str\",\n";
    $content .= "     \"network_config\" :{ \"content_path\": \"/content/0000\"}\n";
    $content .= "}\n";

    my $fn = "$path/drive/openstack/latest/meta_data.json";

    file_set_contents($fn, $content);
}

sub generate_cloudinit_network {
    my ($conf, $path) = @_;

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

    my $fn = "$path/drive/openstack/content/0000";
    file_set_contents($fn, $content);
    return $content;
}


1;
