#!/usr/bin/perl

# Regression tests for applying pending changes to a running VM via hotplug.
#
# Each test is a VM config in 'hotplug/*.conf' with the changes to apply in a [PENDING] section. The
# monitor of the VM is mocked with a minimal model of a running QEMU instance, that tracks the
# present devices, buses, block nodes, backends and QOM objects and enforces the constraints between
# them. Every monitor command and every host-side action (network, SDN, storage, cgroup) that is
# issued while applying the pending changes is recorded. Afterwards, the model is compared to the
# model of a VM freshly started with the resulting config, which is what the target of a live
# migration is, to detect deviations like differing PCI addresses or left-over devices. The
# recordings are compared to the corresponding 'hotplug/*.conf.expected' file. If that file does not
# exist yet, it is generated and needs to be manually verified. Tests are given via a directory as
# parameter (default 'hotplug').

use v5.36;

use lib qw(.. .);

# hmp does not return an error for us, just strings so we use verify afterwards to check if
# it worked. The helpers then wait between retries when verifying (un)plugged devices. Overwrite
# `sleep` behavior so tests do not wait around.
BEGIN {
    *CORE::GLOBAL::sleep = sub { return 0; };
}

use JSON;
use Storable qw(dclone);
use Test::More;
use Test::MockModule;

use PVE::File qw(file_get_contents file_set_contents);

use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Blockdev;
use PVE::QemuServer::CGroup;
use PVE::QemuServer::CPUConfig;
use PVE::QemuServer::Drive;
use PVE::QemuServer::DriveDevice;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Machine;
use PVE::QemuServer::Monitor;
use PVE::QemuServer::Network;
use PVE::Storage;

# the mocks for generating the command line of a VM, shared with the cfg2cmd tests
use QemuServerTest::CommandLineMocks qw(get_storage_config get_test_qemu_version set_test_env);
use QemuServerTest::Utils qw(diff);

my $vmid = 8006;
my $fake_config_fn = "hotplug/qemu-server/$vmid.conf";

my $storecfg = get_storage_config();

my $current_test; # = {
#   testname => 'file name and description',
#   description => 'Test description', # if available
#   qemu_version => '10.1',
#   host_arch => 'x86_64',
#   fail_device_add => { deviceid => 1 },
#   fail_device_del => { deviceid => 1 },
#   fail_command => { command => 1 },
#   config => { config hash },
# };

# The model of the running QEMU instance, set up from the command line that config_to_command()
# generates for the config. The number of online vCPUs and the present memory DIMMs are derived
# from the 'cpuN' and 'dimmN' devices. Buses are derived from the machine type and the present
# bridges and controllers.
my $vm_state; # = {
#   machine => 'pc-i440fx-10.1+pve0', # the machine type of the running VM
#   buses => { bus => 1 }, # buses provided by the machine itself
#   devices => { qdev_id => { device options referencing buses and backends } },
#   hotplugged => { qdev_id => 1 }, # devices that were added during the test
#   netdevs => { netdev_id => 1 },
#   chardevs => { chardev_id => 1 },
#   drives => { drive_id => 1 }, # legacy '-drive' backends (machine version < 10.0)
#   blocknodes => { node_name => 1 }, # explicitly added block nodes (machine version >= 10.0)
#   objects => { object_id => { arguments of object-add } }, # QOM objects
# };

my $recorded_actions = [];

# use the config description to describe the test and the state of the running VM, fields are:
#   TEST: A single line describing the test, gets outputted
#   QEMU_VERSION: \d+\.\d+(\.\d+)? version of the running QEMU binary (defaults to current version)
#   HOST_ARCH: x86_64 | aarch64 (default to x86_64, to make tests stable)
#   FAIL_DEVICE_ADD: <id> QEMU accepts 'device_add' for this device, but it never shows up
#   FAIL_DEVICE_DEL: <id> QEMU accepts 'device_del' for this device, but it never goes away
#   FAIL_COMMAND: <name> the QMP or HMP command with this name fails
#   EXPECTED_ERROR: <msg> the expected error message(s)
#   STAYS_PENDING: bool
# all fields are optional, FAIL_* and EXPECTED_ERROR comments can be specified multiple times
sub parse_test($config_fn) {
    $current_test = {
        fail_device_add => {},
        fail_device_del => {},
        fail_command => {},
        expected_errors => [],
    };

    my $config_raw = file_get_contents($config_fn);
    my $config = PVE::QemuServer::parse_vm_config($fake_config_fn, $config_raw);

    $current_test->{config} = $config;

    my $description = $config->{description} // '';

    while ($description =~ /^\h*(.*?)\h*$/gm) {
        my $line = $1;
        next if !$line || $line =~ /^#/;

        if ($line =~ /^TEST:\s*(.*)\s*$/) {
            $current_test->{description} = "$1";
        } elsif ($line =~ /^QEMU_VERSION:\s*(.*)\s*$/) {
            $current_test->{qemu_version} = "$1";
        } elsif ($line =~ /^HOST_ARCH:\s*(.*)\s*$/) {
            $current_test->{host_arch} = "$1";
        } elsif ($line =~ /^FAIL_DEVICE_ADD:\s*(\S+)\s*$/) {
            $current_test->{fail_device_add}->{$1} = 1;
        } elsif ($line =~ /^FAIL_DEVICE_DEL:\s*(\S+)\s*$/) {
            $current_test->{fail_device_del}->{$1} = 1;
        } elsif ($line =~ /^FAIL_COMMAND:\s*(\S+)\s*$/) {
            $current_test->{fail_command}->{$1} = 1;
        } elsif ($line =~ /^EXPECTED_ERROR:\s*(.*)$/) {
            push $current_test->{expected_errors}->@*, $1;
        } elsif ($line =~ /^STAYS_PENDING:\s*(.*)$/) {
            $current_test->{stays_pending} = $1;
        } else {
            die "invalid test configuration\n";
        }
    }

    # the description only describes the test and is not part of the resulting config
    delete $config->{description};

    $config_fn =~ /([^\/]+)$/;
    my $testname = "$1";
    if (my $desc = $current_test->{description}) {
        $testname = "'$testname' - $desc";
    }
    $current_test->{testname} = $testname;

    set_test_env($current_test);

    # the 'host' CPU model is registered for the host architecture of the current test
    PVE::QemuServer::CPUConfig::initialize_cpu_models();
}

# The buses a machine provides on its own. Everything else (PCI bridges, SCSI and USB controllers)
# comes from devices on the command line or from the config files read via -readconfig.
sub default_buses_for_machine($conf, $machine) {
    return { map { $_ => 1 } qw(pcie.0) } if $machine =~ m/^virt/;
    return { map { $_ => 1 } ('pcie.0', map { "ide.$_" } 0 .. 5) }
        if PVE::QemuServer::Machine::machine_type_is_q35($conf);
    return { map { $_ => 1 } qw(pci.0 ide.0 ide.1) };
}

# Parse a comma separated option string like 'driver,id=x,bus=y' into a hash. A leading value
# without key is stored under $first_key.
sub parse_options($string, $first_key = undef) {
    my $options = {};
    for my $part (split(/,/, $string)) {
        if ($part =~ m/^([^=]+)=(.*)$/) {
            $options->{$1} = $2;
        } elsif (defined($first_key)) {
            $options->{$first_key} = $part;
        } else {
            die "no key, and no first key given\n";
        }
    }
    return $options;
}

# Parse the devices from a QEMU config file (-readconfig), which is shipped in 'usr/' of the repo.
sub parse_readconfig($path) {
    my ($name) = $path =~ m|([^/]+)$|;
    my $devices = {};
    my $current;
    for my $line (split(/\n/, file_get_contents("../usr/$name"))) {
        if ($line =~ m/^\[device "([^"]+)"\]/) {
            $current = $devices->{$1} = { id => $1 };
        } elsif ($line =~ m/^\[/) {
            $current = undef;
        } elsif ($current && $line =~ m/^\s*(\S+)\s*=\s*"([^"]*)"/) {
            $current->{$1} = $2;
        }
    }
    return $devices;
}

# Resolve the full final machine version, even for values like 'pc' or 'q35'.
sub resolve_machine_alias($machine) {
    my ($type, $pve_version) = split(/\+/, $machine, 2);

    die "no +pveX version set\n" if !defined($pve_version);

    if ($type && $type !~ m/^(?:pc|q35|virt)$/) {
        return $machine;
    }

    my ($pin_version) = get_test_qemu_version() =~ m/^(\d+\.\d+)/;
    my $new_machine = PVE::QemuServer::Machine::expand_basic_machine_type($type, $pin_version);

    return $new_machine . "+$pve_version";
}

# Returns the model of a VM freshly started with the given config, derived from the command line
# that config_to_command() generates for it.
sub vm_state_from_config($conf) {
    my $cmd = PVE::QemuServer::config_to_command(
        $storecfg, $vmid, dclone($conf), PVE::QemuServer::load_defaults(), {},
    );

    my $state = {
        machine => '',
        devices => {},
        hotplugged => {},
        netdevs => {},
        chardevs => {},
        drives => {},
        blocknodes => {},
        objects => {},
    };

    for (my $i = 0; $i < scalar($cmd->@*) - 1; $i++) {
        my ($opt, $arg) = $cmd->@[$i, $i + 1];
        if ($opt eq '-machine') {
            $state->{machine} = resolve_machine_alias(parse_options($arg)->{type});
        } elsif ($opt eq '-device') {
            my $device = parse_options($arg, 'driver');
            $state->{devices}->{ $device->{id} } = $device if $device->{id};
        } elsif ($opt eq '-readconfig') {
            my $devices = parse_readconfig($arg);
            $state->{devices}->{$_} = $devices->{$_} for keys $devices->%*;
        } elsif ($opt eq '-netdev') {
            $state->{netdevs}->{ parse_options($arg)->{id} } = 1;
        } elsif ($opt eq '-chardev') {
            $state->{chardevs}->{ parse_options($arg, 'backend')->{id} } = 1;
        } elsif ($opt eq '-drive') {
            $state->{drives}->{ parse_options($arg)->{id} } = 1;
        } elsif ($opt eq '-blockdev') {
            $state->{blocknodes}->{ decode_json($arg)->{'node-name'} } = 1;
        } elsif ($opt eq '-object') {
            my $object = $arg =~ m/^\{/ ? decode_json($arg) : parse_options($arg, 'qom-type');
            # sizes on the command line have a unit, QMP uses bytes
            if (defined($object->{size}) && $object->{size} =~ m/^(\d+)([KMGT])$/i) {
                my ($size, $unit) = ($1, $2);
                my $exponent = index("KMGT", uc($unit)) + 1;
                $object->{size} = $size * 1024**$exponent;
            }
            $state->{objects}->{ $object->{id} } = $object;
        }
    }

    die "no machine set\n" if $state->{machine} eq '';

    $state->{buses} = default_buses_for_machine($conf, $state->{machine});

    return $state;
}

sub setup_vm_state($conf) {
    $vm_state = vm_state_from_config($conf);
}

# Throttle limits set via QMP contain all properties, while the throttle group generated for the
# command line only contains the configured ones. Drop the defaults to make them comparable.
sub normalized_object($object) {
    $object = dclone($object);
    if (($object->{'qom-type'} // '') eq 'throttle-group' && $object->{limits}) {
        my $limits = $object->{limits};
        my $is_default = sub { $limits->{ $_[0] } == ($_[0] =~ m/-max-length$/ ? 1 : 0) };
        $object->{limits} =
            { map { $_ => $limits->{$_} } grep { !$is_default->($_) } keys %$limits };
    }
    return to_json($object, { canonical => 1 });
}

# Compare the model of the running VM with the model of a VM freshly started with the resulting
# config, like the target of a live migration is. Returns a list of the differences. The boot index
# is not compared, as hotplugged devices are added without one.
sub compare_with_fresh_vm($conf) {
    my $running = $vm_state;
    my $fresh = vm_state_from_config($conf);
    my $differences = [];

    my $compare_ids = sub($kind, $running_ids, $fresh_ids) {
        my $all_keys = [keys $running_ids->%*, keys $fresh_ids->%*];
        for my $key ($all_keys->@*) {
            push $differences->@*, "$kind: $key: only present in running VM"
                if !$fresh_ids->{$key};
            push $differences->@*, "$kind: $key: only present in freshly started VM"
                if !$running_ids->{$key};
        }
    };

    push $differences->@*, "machine: running '$running->{machine}' vs fresh '$fresh->{machine}'"
        if $running->{machine} ne $fresh->{machine};

    $compare_ids->('device', $running->{devices}, $fresh->{devices});
    for my $id (sort grep { $fresh->{devices}->{$_} } keys $running->{devices}->%*) {
        my $running_device = $running->{devices}->{$id};
        my $fresh_device = $fresh->{devices}->{$id};
        my %options = map { $_ => 1 } keys $running_device->%*, keys $fresh_device->%*;
        # hotplugged devices are not added with a bootindex
        delete $options{bootindex};
        for my $option (sort keys %options) {
            my $running_value = $running_device->{$option} // '<undef>';
            my $fresh_value = $fresh_device->{$option} // '<undef>';
            if ("$running_value" ne "$fresh_value") {
                push $differences->@*,
                    "device $id option $option: running '$running_value' vs fresh '$fresh_value'";
            }
        }
    }

    $compare_ids->('object', $running->{objects}, $fresh->{objects});
    for my $id (sort grep { $fresh->{objects}->{$_} } keys $running->{objects}->%*) {
        my $running_object = normalized_object($running->{objects}->{$id});
        my $fresh_object = normalized_object($fresh->{objects}->{$id});
        push $differences->@*, "object $id: running $running_object vs fresh $fresh_object"
            if $running_object ne $fresh_object;
    }

    for my $kind (qw(netdev chardev drive blocknode)) {
        $compare_ids->($kind, $running->{"${kind}s"}, $fresh->{"${kind}s"});
    }

    return $differences;
}

# Record an action with its arguments. HMP commands are recorded as the full command line. Arguments
# of QMP commands are recorded as they are.
sub record_action($layer, $action, @args) {
    my $line = "$layer $action";
    $line .= ' ' . to_json([@args], { canonical => 1 }) if scalar(@args);
    push $recorded_actions->@*, $line;
}

sub record_qmp_action($action, $args) {
    my $line = "qmp $action";
    $line .= ' ' . to_json($args, { canonical => 1 });
    push $recorded_actions->@*, $line;
}

sub sorted_devices($regex = qr/./) {
    my @list = sort grep { $_ =~ $regex } keys $vm_state->{devices}->%*;
    return @list;
}

sub bus_exists_in_vm_state($bus) {
    return 1 if $vm_state->{buses}->{$bus};
    return 1 if $bus =~ m/^pci\.\d+$/ && $vm_state->{devices}->{$bus}; # PCI bridge
    return 1 if $bus =~ m/^(.+)\.0$/ && $vm_state->{devices}->{$1}; # SCSI and USB controllers
    return 0;
}

# Check the constraints for adding the device with the given options. Returns an error message if
# the device cannot be added, otherwise adds it and returns nothing.
sub add_device($options) {
    my $id = $options->{id} or die "device_add without ID\n";
    my $driver = $options->{driver};

    return "Duplicate device ID '$id'" if $vm_state->{devices}->{$id};
    return "simulated failure adding device '$id'" if $current_test->{fail_device_add}->{$id};

    if (my $bus = $options->{bus}) {
        return "Bus '$bus' does not support hotplugging" if $bus =~ m/^(ide\.\d+|ahci\d+\.\d+)$/;
        # devices cannot be hotplugged into a PCI bridge that was itself hotplugged, as the guest
        # firmware did not assign any resources to it
        return "Bus '$bus' does not support hotplugging" if $vm_state->{hotplugged}->{$bus};
        return "Bus '$bus' not found" if !bus_exists_in_vm_state($bus);
    }

    my $backends = {
        netdev => $vm_state->{netdevs},
        chardev => $vm_state->{chardevs},
        drive => { $vm_state->{drives}->%*, $vm_state->{blocknodes}->%* },
        iothread => $vm_state->{objects},
        memdev => $vm_state->{objects},
    };
    for my $option (sort keys $backends->%*) {
        my $value = $options->{$option} or next;
        return "Property '$driver.$option' can't find value '$value'"
            if !$backends->{$option}->{$value};
    }

    $vm_state->{devices}->{$id} = $options;
    $vm_state->{hotplugged}->{$id} = 1;
    return;
}

# Handle QMP commands querying the state of the VM. Returns nothing for other commands.
sub mocked_qmp_query($execute, $arguments) {
    if ($execute eq 'query-version') {
        my ($major, $minor, $micro) = get_test_qemu_version() =~ m/^(\d+)\.(\d+)(?:\.(\d+))?/;
        return { qemu => { major => $major, minor => $minor, micro => $micro // 0 } };
    } elsif ($execute eq 'query-machines') {
        my ($name, $pve_version) = split(/\+/, $vm_state->{machine}, 2);
        my $machine = { name => $name, 'is-current' => JSON::true };
        $machine->{'pve-version'} = $pve_version if $pve_version;
        return [$machine];
    } elsif ($execute eq 'query-pci') {
        # everything that is not a disk or memory DIMM is reported as a PCI device with the qdev ID
        my @devices =
            map { { qdev_id => $_ } }
            grep { !PVE::QemuServer::Drive::is_valid_drivename($_) && $_ !~ m/^dimm\d+$/ }
            grep { $_ ne 'tablet' && $_ ne 'keyboard' } sorted_devices();
        return [{ bus => 0, devices => \@devices }];
    } elsif ($execute eq 'query-block') {
        my @blocks = ();
        for my $id (grep { PVE::QemuServer::Drive::is_valid_drivename($_) } sorted_devices()) {
            my $qdev = $id =~ m/^virtio\d+$/ ? "/machine/peripheral/$id/virtio-backend" : $id;
            push @blocks, { device => '', qdev => $qdev };
        }
        return \@blocks;
    } elsif ($execute eq 'query-mice') {
        return [{ name => 'QEMU HID Tablet' }] if $vm_state->{devices}->{tablet};
        return [{ name => 'QEMU PS/2 Mouse' }];
    } elsif ($execute eq 'qom-list') {
        die "unexpected qom-list path '$arguments->{path}'\n"
            if $arguments->{path} ne '/machine/peripheral';
        return [map { { name => $_ } } sorted_devices()];
    } elsif ($execute eq 'query-iothreads') {
        my $objects = $vm_state->{objects};
        return [
            map { { id => $_, 'thread-id' => 1 } }
            sort grep { $objects->{$_}->{'qom-type'} eq 'iothread' } keys $objects->%*
        ];
    } elsif ($execute eq 'query-cpus-fast') {
        # the first vCPU is always present, the others are 'cpuN' devices
        my @hotplugged_cpus = sorted_devices(qr/^cpu\d+$/);
        return [map { { 'cpu-index' => $_ } } (0 .. scalar(@hotplugged_cpus))];
    } elsif ($execute eq 'query-memory-devices') {
        my $objects = $vm_state->{objects};
        return [
            map { {
                type => 'dimm',
                data => { id => $_, size => $objects->{"mem-$_"}->{size} },
            } } sorted_devices(qr/^dimm\d+$/)
        ];
    } elsif ($execute eq 'query-named-block-nodes') {
        return [
            map { { 'node-name' => $_, children => [] } }
            sort keys $vm_state->{blocknodes}->%*
        ];
    }

    return;
}

# Handle commands issued via the human monitor. Errors are reported as text output like QEMU does.
sub mocked_hmp_cmd($cmdline) {
    record_action('hmp', $cmdline);

    my ($command, $args) = $cmdline =~ m/^(\S+)\s+(.*)$/;
    return "Error: simulated failure of HMP command '$command'"
        if $current_test->{fail_command}->{$command};

    if ($command eq 'device_add') {
        my $options = { map { split(/=/, $_, 2) } split(/,/, $args) };
        return "Error: Parameter 'driver' is missing" if !$options->{driver};
        my $err = add_device($options);
        return $err ? "Error: $err" : '';
    } elsif ($command eq 'device_del') {
        my $id = $args;
        return "Error: Device '$id' not found" if !$vm_state->{devices}->{$id};
        # the guest never releases the device
        return '' if $current_test->{fail_device_del}->{$id};
        my $device = delete $vm_state->{devices}->{$id};
        # usb-redir deletes its chardev when it is unrealized, see usbredir_unrealize() in QEMU
        delete $vm_state->{chardevs}->{ $device->{chardev} }
            if ($device->{driver} // '') eq 'usb-redir' && $device->{chardev};
        return '';
    } elsif ($command eq 'drive_add') {
        my ($id) = $args =~ m/,id=([^,"]+)/ or die "drive_add without ID: $cmdline\n";
        return "Error: Duplicate ID '$id' for drive" if $vm_state->{drives}->{$id};
        $vm_state->{drives}->{$id} = 1;
        return 'OK';
    } elsif ($command eq 'drive_del') {
        my $id = $args;
        return "Error: Device '$id' not found" if !delete $vm_state->{drives}->{$id};
        return '';
    }

    die "unexpected HMP command: '$cmdline'\n";
}

my $qmp_command_does_not_change_state = {
    balloon => 1,
    block_set_io_throttle => 1,
    'blockdev-change-medium' => 1,
    'blockdev-close-tray' => 1,
    'blockdev-open-tray' => 1,
    eject => 1,
};

sub assert_backend_not_in_use($type, $id) {
    my $devices = $vm_state->{devices};
    for my $key (keys $devices->%*) {
        if (($devices->{$key}->{$type} // '') eq $id) {
            die "$type $id is in use by device $key";
        }
    }
}

# Replacement for PVE::QemuServer::Monitor::qmp_cmd, handling all monitor communication with the VM.
my sub qmp_command($execute, %arguments) {
    die "simulated failure of QMP command '$execute'"
        if $current_test->{fail_command}->{$execute};

    return {} if $qmp_command_does_not_change_state->{$execute};

    my $id = $arguments{id};
    my $node_name = $arguments{'node-name'};
    my $devices = $vm_state->{devices};

    if ($execute eq 'device_add') {
        my $err = add_device(\%arguments);
        die $err if $err;
    } elsif ($execute eq 'netdev_add') {
        die "Duplicate ID '$id' for netdev" if $vm_state->{netdevs}->{$id};
        $vm_state->{netdevs}->{$id} = 1;
    } elsif ($execute eq 'netdev_del') {
        die "Device '$id' not found" if !$vm_state->{netdevs}->{$id};
        assert_backend_not_in_use('netdev', $id);
        delete $vm_state->{netdevs}->{$id};
    } elsif ($execute eq 'set_link') {
        my $name = $arguments{name};
        die "Device '$name' not found"
            if !$devices->{$name} && !$vm_state->{netdevs}->{$name};
    } elsif ($execute eq 'chardev-add') {
        die "Duplicate ID '$id' for chardev" if $vm_state->{chardevs}->{$id};
        $vm_state->{chardevs}->{$id} = 1;
    } elsif ($execute eq 'object-add') {
        die "Duplicate object ID '$id'" if $vm_state->{objects}->{$id};
        $vm_state->{objects}->{$id} = \%arguments;
    } elsif ($execute eq 'object-del') {
        die "Object '$id' not found" if !$vm_state->{objects}->{$id};
        assert_backend_not_in_use('iothread', $id);
        assert_backend_not_in_use('memdev', $id);
        # the top block node of a drive uses the throttle group with the same name
        if (my ($node) = $id =~ m/^throttle-(drive-.+)$/) {
            die "Object '$id' is in use by node '$node'"
                if $vm_state->{blocknodes}->{$node};
        }
        delete $vm_state->{objects}->{$id};
    } elsif ($execute eq 'qom-set') {
        my $object = $vm_state->{objects}->{ $arguments{path} };
        die "Object '$arguments{path}' not found" if !$object;
        $object->{ $arguments{property} } = $arguments{value};
    } elsif ($execute eq 'blockdev-add') {
        die "Duplicate nodes with node-name='$node_name'"
            if $vm_state->{blocknodes}->{$node_name};
        $vm_state->{blocknodes}->{$node_name} = 1;
    } elsif ($execute eq 'blockdev-del') {
        die "Failed to find node with node-name='$node_name'"
            if !$vm_state->{blocknodes}->{$node_name};
        assert_backend_not_in_use('drive', $node_name);
        delete $vm_state->{blocknodes}->{$node_name};
    } elsif ($execute eq 'blockdev-remove-medium') {
        die "Device '$id' not found" if !$devices->{$id};
        delete $devices->{$id}->{drive};
    } elsif ($execute eq 'blockdev-insert-medium') {
        die "Device '$id' not found" if !$devices->{$id};
        die "Node '$node_name' not found" if !$vm_state->{blocknodes}->{$node_name};
        $devices->{$id}->{drive} = $node_name;
    } else {
        die "unexpected QMP command: '$execute'\n";
    }

    return {};
}

# wraps qmp_command and decides if errors should be bubbled or returned as string
sub mocked_qmp_cmd($peer, $execute, %arguments) {

    die "unexpected QMP peer '$peer->{name}' of type '$peer->{type}'\n"
        if $peer->{type} ne 'qmp' || $peer->{id} != $vmid;

    delete $arguments{timeout};
    my $noerr = delete $arguments{noerr};

    return mocked_hmp_cmd($arguments{'command-line'}) if $execute eq 'human-monitor-command';

    # queries do not change the state of the VM and are not recorded
    if (my $result = mocked_qmp_query($execute, \%arguments)) {
        return $result;
    }

    record_qmp_action($execute, \%arguments);

    my $res = eval { qmp_command($execute, %arguments) };
    if (my $err = $@) {
        return { error => $err } if $noerr;
        die $err;
    }

    return $res;
}

my $monitor_module = Test::MockModule->new('PVE::QemuServer::Monitor');
$monitor_module->mock(qmp_cmd => \&mocked_qmp_cmd);

# qmp_cmd is imported by these modules, so the imported copies need to be replaced too
my $qemu_server_module = Test::MockModule->new('PVE::QemuServer');
$qemu_server_module->mock(qmp_cmd => \&mocked_qmp_cmd);

my $blockdev_module = Test::MockModule->new('PVE::QemuServer::Blockdev');
$blockdev_module->mock(qmp_cmd => \&mocked_qmp_cmd);

# the machine type of the running VM is derived from the QEMU version, so it has to be the mocked
# one everywhere, not only for the imported copy in PVE::QemuServer
my $qemu_server_helpers = Test::MockModule->new('PVE::QemuServer::Helpers');
$qemu_server_helpers->mock(
    kvm_user_version => \&get_test_qemu_version,
    vm_running_locally => sub {
        return 1;
    },
);

my $drive_device_module = Test::MockModule->new('PVE::QemuServer::DriveDevice');
$drive_device_module->mock(kvm_user_version => \&get_test_qemu_version);

my $qemu_server_config = Test::MockModule->new('PVE::QemuConfig');
$qemu_server_config->mock(
    write_config => sub {
        my ($class, $vmid, $conf) = @_;
        return;
    },
    load_config => sub {
        die "config was reloaded unexpectedly";
    },
);

my $pve_cluster_module = Test::MockModule->new('PVE::Cluster');
$pve_cluster_module->mock(
    cfs_read_file => sub {
        my ($file) = @_;

        if ($file eq 'datacenter.cfg') {
            return {};
        } else {
            die "'cfs_read_file' called for '$file' - missing mock?\n";
        }
    },
);

# returns a mock that records the call with all its arguments as an action of the given layer
my sub recorder($layer, $action) {
    return sub {
        record_action($layer, $action, @_);
        return;
    };
}

my $pve_common_network = Test::MockModule->new('PVE::Network');
$pve_common_network->mock(
    tap_unplug => recorder('net', 'tap_unplug'),
    tap_rate_limit => recorder('net', 'tap_rate_limit'),
);

my $qemu_network_module = Test::MockModule->new('PVE::QemuServer::Network');
$qemu_network_module->mock(tap_plug => recorder('net', 'tap_plug'));

my $sdn_vnets_module = Test::MockModule->new('PVE::Network::SDN::Vnets');
$sdn_vnets_module->mock(
    add_next_free_cidr => recorder('sdn', 'add_next_free_cidr'),
    add_dhcp_mapping => recorder('sdn', 'add_dhcp_mapping'),
    del_ips_from_mac => recorder('sdn', 'del_ips_from_mac'),
);

# the shared mocks turn these into no-ops, but here they are actions worth recording
my $storage_module = Test::MockModule->new('PVE::Storage');
$storage_module->mock(
    activate_volumes => sub {
        my ($cfg, $vollist) = @_;
        record_action('storage', 'activate_volumes', $vollist->@*);
        return;
    },
    vdisk_free => sub {
        my ($cfg, $volid) = @_;
        record_action('storage', 'vdisk_free', $volid);
        return;
    },
);

# detaching a disk checks permissions via the RPC environment, which is not initialized in tests
my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
$rpcenv_module->mock(
    get => sub {
        return bless({}, 'PVE::RPCEnvironment');
    },
    get_user => sub {
        return 'root@pam';
    },
    check => sub {
        return 1;
    },
    check_vm_perm => sub {
        return 1;
    },
);

my $cgroup_module = Test::MockModule->new('PVE::QemuServer::CGroup');
$cgroup_module->mock(
    change_cpu_shares => sub {
        my ($self, $shares) = @_;
        record_action('cgroup', 'change_cpu_shares', $shares);
        return;
    },
    change_cpu_quota => sub {
        my ($self, $quota, $period) = @_;
        record_action('cgroup', 'change_cpu_quota', $quota, $period);
        return;
    },
);

sub cleanup_error_message($msg) {
    chomp $msg;
    $msg =~ s/ at \S+ line \d+\.?$/ at X line Y/;
    return $msg;
}

# warnings are part of the expected outcome, e.g. when cleaning up after a failed hotplug
$SIG{__WARN__} = sub {
    my $warning = shift;
    $warning = cleanup_error_message($warning);
    record_action('warn', $warning);
};

sub do_test($config_fn) {
    die "no such input test config: $config_fn\n" if !-f $config_fn;

    $recorded_actions = []; # also record warnings while parsing the config
    parse_test($config_fn);

    my $testname = $current_test->{testname};
    my $conf = $current_test->{config};

    my $errors = {};
    eval {
        setup_vm_state($conf);
        PVE::QemuServer::vmconfig_hotplug_pending($vmid, $conf, $storecfg, undef, $errors);
    };
    if (my $err = $@) {
        $errors->{died} = $err;
    }

    # error messages without trailing newline contain the source location, which changes too often
    my $clean_error = sub {
        my ($key, $msg) = @_;
        my $cleaned = cleanup_error_message($msg);
        return "$key: $cleaned";
    };

    my $result = "";
    $result .= "$_\n" for $recorded_actions->@*;

    my $expected_errors = $current_test->{expected_errors};
    if (scalar($expected_errors->@*) || scalar($errors->%*)) {
        my $expected = join("\n", $expected_errors->@*);
        my $got = join("\n", map { $clean_error->($_, $errors->{$_}) } sort keys $errors->%*);

        if ($expected ne $got) {
            note("unexpected error output:");
            note("got: $got");
            note("expected: $expected");
            fail($testname);
            return;
        }
    }

    # the target of a live migration is started with the resulting config, so it must match
    my $differences = eval { compare_with_fresh_vm($conf) };
    if (my $err = $@) {
        push $differences->@*,
            "failed to start a VM with the resulting config: " . $clean_error->('start', $err);
    }

    if (scalar($differences->@*) > 0) {
        note("there are differences to freshly started vm:");
        for my $diff (sort $differences->@*) {
            note($diff);
        }
        fail("$testname");
        return;
    }

    if (scalar($conf->{pending}->%*) > 0 && !$current_test->{stays_pending}) {
        note("could not hotplug (unexpectedly): " . join(',', keys $conf->{pending}->%*));
        fail("$testname");
        return;
    }

    if ($current_test->{stays_pending} && scalar($conf->{pending}->%*) == 0) {
        note("hotplug unexpectedly works");
        fail("$testname");
        return;
    }

    my $expected_fn = "$config_fn.expected";

    if (!-f $expected_fn) {
        file_set_contents($expected_fn, $result);
        pass("$testname (generated expected output)");
        return;
    }

    my $expected = file_get_contents($expected_fn);
    if (my $diff = diff($expected, $result)) {
        note("files differ:\n$diff");
        fail("$testname");
    } else {
        pass("$testname");
    }
}

print "testing hotplug of pending changes\n";

# exec tests
my $test_target = shift // 'hotplug';

if (-f $test_target) {
    do_test($test_target);
} elsif (-d $test_target) {
    PVE::File::dir_glob_foreach(
        $test_target,
        qr/.+\.conf/,
        sub {
            my ($file) = @_;

            do_test("${test_target}/${file}");
        },
    );
} else {
    die "test target '$test_target' is neither file nor directory, cannot proceed\n";
}

done_testing();
