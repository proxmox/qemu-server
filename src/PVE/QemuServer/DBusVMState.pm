package PVE::QemuServer::DBusVMState;

use strict;
use warnings;

use Net::DBus;
use Net::DBus::RemoteService;

use PVE::SafeSyslog;
use PVE::Systemd;
use PVE::Tools;

use PVE::QemuServer::Helpers;

use constant {
    DBUS_VMSTATE_EXE => '/usr/libexec/qemu-server/dbus-vmstate',
};

# Call a method for an object from a specific interface name.
# In contrast to calling the method directly by using $obj->Method(), this
# actually respects the owner of the object and thus can be used for interfaces
# with might have multiple (queued) owners on the DBus.
my sub dbus_call_method {
    my ($obj, $interface, $method, $params, $timeout) = @_;

    $timeout = 10 if !$timeout;

    my $con = $obj->{service}->get_bus()->get_connection();

    my $call = $con->make_method_call_message(
        $obj->{service}->get_service_name(),
        $obj->{object_path},
        $interface,
        $method,
    );

    $call->set_destination($obj->get_service()->get_owner_name());
    $call->append_args_list($params->@*) if $params;

    return $con->send_with_reply_and_block($call, $timeout * 1000)->get_args_list();
}

# Retrieves a property from an object from a specific interface name.
# In contrast to accessing the property directly by using $obj->Property, this
# actually respects the owner of the object and thus can be used for interfaces
# with might have multiple (queued) owners on the DBus.
my sub dbus_get_property {
    my ($obj, $interface, $name) = @_;

    my @reply =
        dbus_call_method($obj, 'org.freedesktop.DBus.Properties', 'Get', [$interface, $name]);
    return $reply[0];
}

# Starts the dbus-vmstate helper D-Bus service daemon and adds the needed
# object to the appropriate QEMU instance for the specified VM.
sub qemu_add_dbus_vmstate {
    my ($vmid) = @_;

    if (!PVE::QemuServer::Helpers::vm_running_locally($vmid)) {
        die "VM $vmid must be running locally\n";
    }

    # In case some leftover, previous instance is running, stop it. Otherwise
    # we run into errors, as a systemd service instance is unique.
    if (defined(qemu_del_dbus_vmstate($vmid, quiet => 1))) {
        warn "stopped previously running dbus-vmstate helper for VM $vmid\n";
    }

    # Start the actual service, which will then register itself with QEMU.
    eval { PVE::Tools::run_command(['systemctl', 'start', "pve-dbus-vmstate\@$vmid"]) };
    if (my $err = $@) {
        die "failed to start DBus VMState service for VM $vmid: $err\n";
    }
}

# Stops the dbus-vmstate helper D-Bus service daemon and removes the associated
# object from QEMU for the specified VM.
#
# Returns the number of migrated conntrack entries, or undef in case of error.
sub qemu_del_dbus_vmstate {
    my ($vmid, %params) = @_;

    my $num_entries = undef;
    my $dbus = eval { Net::DBus->system(); };
    if (my $err = $@) {
        # log fundamental error even if $params{quiet} is set
        syslog('warn', "failed to connect to DBus system bus: $err");
        return undef;
    }

    my $dbus_obj = eval { $dbus->get_bus_object(); };
    if (my $err = $@) {
        # log fundamental error even if $params{quiet} is set
        syslog('warn', "failed to get DBus bus object: $err");
        return undef;
    }

    my $owners = eval { $dbus_obj->ListQueuedOwners('org.qemu.VMState1') };
    if (my $err = $@) {
        syslog('warn', "failed to retrieve org.qemu.VMState1 owners: $err\n")
            if !$params{quiet};
        return undef;
    }

    # Iterate through all name owners for 'org.qemu.VMState1' and compare
    # the ID. If we found the corresponding one for $vmid, retrieve the
    # `NumMigratedEntries` property and call the `Quit()` method on it.
    # Any D-Bus interaction might die/croak, so try to be careful here and
    # swallow any hard errors.
    foreach my $owner (@$owners) {
        my $service = eval { Net::DBus::RemoteService->new($dbus, $owner, 'org.qemu.VMState1') };
        if (my $err = $@) {
            syslog('warn', "failed to get org.qemu.VMState1 service from D-Bus $owner: $err\n")
                if !$params{quiet};
            next;
        }

        my $object = eval { $service->get_object('/org/qemu/VMState1') };
        if (my $err = $@) {
            syslog('warn', "failed to get /org/qemu/VMState1 object from D-Bus $owner: $err\n")
                if !$params{quiet};
            next;
        }

        my $id = eval { dbus_get_property($object, 'org.qemu.VMState1', 'Id') };
        if (defined($id) && $id eq "pve-vmstate-$vmid") {
            my $helperobj =
                eval { $service->get_object('/org/qemu/VMState1', 'com.proxmox.VMStateHelper') };
            if (my $err = $@) {
                syslog(
                    'warn',
                    "found dbus-vmstate helper, but does not implement com.proxmox.VMStateHelper? ($err)\n",
                ) if !$params{quiet};
                last;
            }

            $num_entries = eval {
                dbus_get_property($object, 'com.proxmox.VMStateHelper', 'NumMigratedEntries');
            };
            # Quit() does QMP object-del which has a timeout of 60 seconds
            eval { dbus_call_method($object, 'com.proxmox.VMStateHelper', 'Quit', [], 70); };
            if (my $err = $@) {
                syslog('warn', "failed to call quit on dbus-vmstate for VM $vmid: $err\n")
                    if !$params{quiet};
            }

            last;
        }
    }

    return $num_entries;
}

1;
