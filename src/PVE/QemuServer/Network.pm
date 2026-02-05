package PVE::QemuServer::Network;

use strict;
use warnings;

use PVE::Cluster;
use PVE::Firewall::Helpers;
use PVE::JSONSchema qw(get_standard_option parse_property_string);
use PVE::Network::SDN::Vnets;
use PVE::Network::SDN::Zones;
use PVE::RESTEnvironment qw(log_warn);
use PVE::Tools qw($IPV6RE file_read_firstline);

use PVE::QemuServer::Monitor qw(mon_cmd);

my $nic_model_list = [
    'e1000',
    'e1000-82540em',
    'e1000-82544gc',
    'e1000-82545em',
    'e1000e',
    'i82551',
    'i82557b',
    'i82559er',
    'ne2k_isa',
    'ne2k_pci',
    'pcnet',
    'rtl8139',
    'virtio',
    'vmxnet3',
];

my $net_fmt_bridge_descr = <<__EOD__;
Bridge to attach the network device to. The Proxmox VE standard bridge
is called 'vmbr0'.

If you do not specify a bridge, we create a kvm user (NATed) network
device, which provides DHCP and DNS services. The following addresses
are used:

 10.0.2.2   Gateway
 10.0.2.3   DNS Server
 10.0.2.4   SMB Server

The DHCP server assign addresses to the guest starting from 10.0.2.15.
__EOD__

my $net_fmt = {
    macaddr => get_standard_option(
        'mac-addr',
        {
            description =>
                "MAC address. That address must be unique within your network. This is"
                . " automatically generated if not specified.",
        },
    ),
    model => {
        type => 'string',
        description =>
            "Network Card Model. The 'virtio' model provides the best performance with"
            . " very low CPU overhead. If your guest does not support this driver, it is usually"
            . " best to use 'e1000'.",
        enum => $nic_model_list,
        default_key => 1,
    },
    (map { $_ => { keyAlias => 'model', alias => 'macaddr' } } @$nic_model_list),
    bridge => get_standard_option(
        'pve-bridge-id',
        {
            description => $net_fmt_bridge_descr,
            optional => 1,
        },
    ),
    queues => {
        type => 'integer',
        minimum => 0,
        maximum => 64,
        description => 'Number of packet queues to be used on the device.',
        optional => 1,
    },
    rate => {
        type => 'number',
        minimum => 0,
        description => "Rate limit in mbps (megabytes per second) as floating point number.",
        optional => 1,
    },
    tag => {
        type => 'integer',
        minimum => 1,
        maximum => 4094,
        description => 'VLAN tag to apply to packets on this interface.',
        optional => 1,
    },
    trunks => {
        type => 'string',
        pattern => qr/\d+(?:-\d+)?(?:;\d+(?:-\d+)?)*/,
        description => 'VLAN trunks to pass through this interface.',
        format_description => 'vlanid[;vlanid...]',
        optional => 1,
    },
    firewall => {
        type => 'boolean',
        description => 'Whether this interface should be protected by the firewall.',
        optional => 1,
    },
    link_down => {
        type => 'boolean',
        description => 'Whether this interface should be disconnected (like pulling the plug).',
        optional => 1,
    },
    mtu => {
        type => 'integer',
        minimum => 1,
        maximum => 65520,
        description =>
            "Force MTU of network device (VirtIO only). Setting to '1' or empty will use the bridge MTU",
        optional => 1,
    },
        taprouted => {
              type => 'boolean',
              description => "routed network, just make tap interface and execute routing script",
              optional => 1,
    },
    hostip => {
        type => 'string',
        format => 'ipv4',
        format_description => 'IPv4Format',
        description => 'IPv4 address for the host.',
        optional => 1,
    },
    guestip => {
        type => 'string',
        format => 'ipv4',
        format_description => 'GuestIPv4',
        description => 'IPv4 address for the guest.',
        optional => 1,
    },
};

our $netdesc = {
    optional => 1,
    type => 'string',
    format => $net_fmt,
    description => "Specify network devices.",
};

PVE::JSONSchema::register_standard_option("pve-qm-net", $netdesc);

my $ipconfig_fmt = {
    ip => {
        type => 'string',
        format => 'pve-ipv4-config',
        format_description => 'IPv4Format/CIDR',
        description => 'IPv4 address in CIDR format.',
        optional => 1,
        default => 'dhcp',
    },
    gw => {
        type => 'string',
        format => 'ipv4',
        format_description => 'GatewayIPv4',
        description => 'Default gateway for IPv4 traffic.',
        optional => 1,
        requires => 'ip',
    },
    ip6 => {
        type => 'string',
        format => 'pve-ipv6-config',
        format_description => 'IPv6Format/CIDR',
        description => 'IPv6 address in CIDR format.',
        optional => 1,
        default => 'dhcp',
    },
    gw6 => {
        type => 'string',
        format => 'ipv6',
        format_description => 'GatewayIPv6',
        description => 'Default gateway for IPv6 traffic.',
        optional => 1,
        requires => 'ip6',
    },
};
PVE::JSONSchema::register_format('pve-qm-ipconfig', $ipconfig_fmt);
our $ipconfigdesc = {
    optional => 1,
    type => 'string',
    format => 'pve-qm-ipconfig',
    description => <<'EODESCR',
cloud-init: Specify IP addresses and gateways for the corresponding interface.

IP addresses use CIDR notation, gateways are optional but need an IP of the same type specified.

The special string 'dhcp' can be used for IP addresses to use DHCP, in which case no explicit
gateway should be provided.
For IPv6 the special string 'auto' can be used to use stateless autoconfiguration. This requires
cloud-init 19.4 or newer.

If cloud-init is enabled and neither an IPv4 nor an IPv6 address is specified, it defaults to using
dhcp on IPv4.
EODESCR
};

# netX: e1000=XX:XX:XX:XX:XX:XX,bridge=vmbr0,rate=<mbps>
sub parse_net {
    my ($data, $disable_mac_autogen) = @_;

    my $res = eval { parse_property_string($net_fmt, $data) };
    if ($@) {
        warn $@;
        return;
    }
    if (!defined($res->{macaddr}) && !$disable_mac_autogen) {
        my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
        $res->{macaddr} = PVE::Tools::random_ether_addr($dc->{mac_prefix});
    }
    return $res;
}

# ipconfigX ip=cidr,gw=ip,ip6=cidr,gw6=ip
sub parse_ipconfig {
    my ($data) = @_;

    my $res = eval { parse_property_string($ipconfig_fmt, $data) };
    if ($@) {
        warn $@;
        return;
    }

    if ($res->{gw} && !$res->{ip}) {
        warn 'gateway specified without specifying an IP address';
        return;
    }
    if ($res->{gw6} && !$res->{ip6}) {
        warn 'IPv6 gateway specified without specifying an IPv6 address';
        return;
    }
    if ($res->{gw} && $res->{ip} eq 'dhcp') {
        warn 'gateway specified together with DHCP';
        return;
    }
    if ($res->{gw6} && $res->{ip6} !~ /^$IPV6RE/) {
        # gw6 + auto/dhcp
        warn "IPv6 gateway specified together with $res->{ip6} address";
        return;
    }

    if (!$res->{ip} && !$res->{ip6}) {
        return { ip => 'dhcp', ip6 => 'dhcp' };
    }

    return $res;
}

sub print_net {
    my $net = shift;

    return PVE::JSONSchema::print_property_string($net, $net_fmt);
}

sub add_random_macs {
    my ($settings) = @_;

    foreach my $opt (keys %$settings) {
        next if $opt !~ m/^net(\d+)$/;
        my $net = parse_net($settings->{$opt});
        next if !$net;
        $settings->{$opt} = print_net($net);
    }
}

sub add_nets_bridge_fdb {
    my ($conf, $vmid) = @_;

    for my $opt (keys %$conf) {
        next if $opt !~ m/^net(\d+)$/;
        my $iface = "tap${vmid}i$1";
        # NOTE: expect setups with learning off to *not* use auto-random-generation of MAC on start
        my $net = parse_net($conf->{$opt}, 1) or next;

        my $mac = $net->{macaddr};
        if (!$mac) {
            log_warn(
                "MAC learning disabled, but vNIC '$iface' has no static MAC to add to forwarding DB!"
            ) if !file_read_firstline("/sys/class/net/$iface/brport/learning");
            next;
        }

        my $bridge = $net->{bridge};
        if (!$bridge) {
            log_warn("Interface '$iface' not attached to any bridge.");
            next;
        }
        PVE::Network::SDN::Zones::add_bridge_fdb($iface, $mac, $bridge);
    }
}

sub del_nets_bridge_fdb {
    my ($conf, $vmid) = @_;

    for my $opt (keys %$conf) {
        next if $opt !~ m/^net(\d+)$/;
        my $iface = "tap${vmid}i$1";

        my $net = parse_net($conf->{$opt}) or next;
        my $mac = $net->{macaddr} or next;

        my $bridge = $net->{bridge};
        PVE::Network::SDN::Zones::del_bridge_fdb($iface, $mac, $bridge);
    }
}

sub create_ifaces_ipams_ips {
    my ($conf, $vmid) = @_;

    foreach my $opt (keys %$conf) {
        if ($opt =~ m/^net(\d+)$/) {
            my $value = $conf->{$opt};
            my $net = parse_net($value);
            eval {
                PVE::Network::SDN::Vnets::add_next_free_cidr(
                    $net->{bridge}, $conf->{name}, $net->{macaddr}, $vmid, undef, 1,
                );
            };
            warn $@ if $@;
        }
    }
}

sub delete_ifaces_ipams_ips {
    my ($conf, $vmid) = @_;

    foreach my $opt (keys %$conf) {
        if ($opt =~ m/^net(\d+)$/) {
            my $net = parse_net($conf->{$opt});
            eval {
                PVE::Network::SDN::Vnets::del_ips_from_mac(
                    $net->{bridge},
                    $net->{macaddr},
                    $conf->{name},
                );
            };
            warn $@ if $@;
        }
    }
}

sub tap_plug {
    my ($iface, $bridge, $tag, $firewall, $trunks, $rate) = @_;

    $firewall = $firewall && PVE::Firewall::Helpers::needs_fwbr($bridge);
    PVE::Network::SDN::Zones::tap_plug($iface, $bridge, $tag, $firewall, $trunks, $rate);
}

sub get_nets_host_mtu {
    my ($vmid, $conf) = @_;

    my $nets_host_mtu = [];
    for my $opt (sort keys $conf->%*) {
        next if $opt !~ m/^net(\d+)$/;
        my $net = parse_net($conf->{$opt});
        next if $net->{model} ne 'virtio';

        my $host_mtu = eval {
            mon_cmd(
                $vmid, 'qom-get',
                path => "/machine/peripheral/$opt",
                property => 'host_mtu',
            );
        };
        if (my $err = $@) {
            log_warn("$opt: could not query host_mtu - $err");
        } elsif (defined($host_mtu)) {
            push $nets_host_mtu->@*, "${opt}=${host_mtu}";
        } else {
            log_warn("$opt: got undefined value when querying host_mtu");
        }
    }
    return join(',', $nets_host_mtu->@*);
}

1;
