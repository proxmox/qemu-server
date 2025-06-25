package PVE::QemuMigrate::Helpers;

use strict;
use warnings;

use JSON;

use PVE::Cluster;
use PVE::JSONSchema qw(parse_property_string);
use PVE::Mapping::Dir;
use PVE::Mapping::PCI;
use PVE::Mapping::USB;

use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::QemuServer::Virtiofs;

sub check_non_migratable_resources {
    my ($conf, $state, $noerr) = @_;

    my @blockers = ();
    if ($state) {
        push @blockers, "amd-sev" if $conf->{"amd-sev"};
        push @blockers, "virtiofs" if PVE::QemuServer::Virtiofs::virtiofs_enabled($conf);
    }

    if (scalar(@blockers) && !$noerr) {
        die "Cannot live-migrate, snapshot (with RAM), or hibernate a VM with: "
            . join(', ', @blockers) . "\n";
    }

    return @blockers;
}

# test if VM uses local resources (to prevent migration)
sub check_local_resources {
    my ($conf, $state, $noerr) = @_;

    my @loc_res = ();
    my $mapped_res = {};

    my @non_migratable_resources = check_non_migratable_resources($conf, $state, $noerr);
    push(@loc_res, @non_migratable_resources);

    my $nodelist = PVE::Cluster::get_nodelist();
    my $pci_map = PVE::Mapping::PCI::config();
    my $usb_map = PVE::Mapping::USB::config();
    my $dir_map = PVE::Mapping::Dir::config();

    my $missing_mappings_by_node = { map { $_ => [] } @$nodelist };

    my $add_missing_mapping = sub {
        my ($type, $key, $id) = @_;
        for my $node (@$nodelist) {
            my $entry;
            if ($type eq 'pci') {
                $entry = PVE::Mapping::PCI::get_node_mapping($pci_map, $id, $node);
            } elsif ($type eq 'usb') {
                $entry = PVE::Mapping::USB::get_node_mapping($usb_map, $id, $node);
            } elsif ($type eq 'dir') {
                $entry = PVE::Mapping::Dir::get_node_mapping($dir_map, $id, $node);
            }
            if (!scalar($entry->@*)) {
                push @{ $missing_mappings_by_node->{$node} }, $key;
            }
        }
    };

    push @loc_res, "hostusb" if $conf->{hostusb}; # old syntax
    push @loc_res, "hostpci" if $conf->{hostpci}; # old syntax

    push @loc_res, "ivshmem" if $conf->{ivshmem};

    foreach my $k (keys %$conf) {
        if ($k =~ m/^usb/) {
            my $entry = parse_property_string('pve-qm-usb', $conf->{$k});
            next if $entry->{host} && $entry->{host} =~ m/^spice$/i;
            if (my $name = $entry->{mapping}) {
                $add_missing_mapping->('usb', $k, $name);
                $mapped_res->{$k} = { name => $name };
            }
        }
        if ($k =~ m/^hostpci/) {
            my $entry = parse_property_string('pve-qm-hostpci', $conf->{$k});
            if (my $name = $entry->{mapping}) {
                $add_missing_mapping->('pci', $k, $name);
                my $mapped_device = { name => $name };
                $mapped_res->{$k} = $mapped_device;

                if ($pci_map->{ids}->{$name}->{'live-migration-capable'}) {
                    $mapped_device->{'live-migration'} = 1;
                    # don't add mapped device with live migration as blocker
                    next;
                }

                # don't add mapped devices as blocker for offline migration but still iterate over
                # all mappings above to collect on which nodes they are available.
                next if !$state;
            }
        }
        if ($k =~ m/^virtiofs/) {
            my $entry = parse_property_string('pve-qm-virtiofs', $conf->{$k});
            $add_missing_mapping->('dir', $k, $entry->{dirid});
            $mapped_res->{$k} = { name => $entry->{dirid} };
        }
        # sockets are safe: they will recreated be on the target side post-migrate
        next if $k =~ m/^serial/ && ($conf->{$k} eq 'socket');
        push @loc_res, $k if $k =~ m/^(usb|hostpci|serial|parallel|virtiofs)\d+$/;
    }

    die "VM uses local resources\n" if scalar @loc_res && !$noerr;

    return wantarray ? (\@loc_res, $mapped_res, $missing_mappings_by_node) : \@loc_res;
}

sub set_migration_caps {
    my ($vmid, $savevm) = @_;

    my $qemu_support = eval { mon_cmd($vmid, "query-proxmox-support") };

    my $bitmap_prop = $savevm ? 'pbs-dirty-bitmap-savevm' : 'pbs-dirty-bitmap-migration';
    my $dirty_bitmaps = $qemu_support->{$bitmap_prop} ? 1 : 0;

    my $cap_ref = [];

    my $enabled_cap = {
        "auto-converge" => 1,
        "xbzrle" => 1,
        "dirty-bitmaps" => $dirty_bitmaps,
    };

    my $supported_capabilities = mon_cmd($vmid, "query-migrate-capabilities");

    for my $supported_capability (@$supported_capabilities) {
        push @$cap_ref,
            {
                capability => $supported_capability->{capability},
                state => $enabled_cap->{ $supported_capability->{capability} }
                ? JSON::true
                : JSON::false,
            };
    }

    mon_cmd($vmid, "migrate-set-capabilities", capabilities => $cap_ref);
}

1;
