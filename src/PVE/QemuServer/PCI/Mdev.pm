package PVE::QemuServer::PCI::Mdev;

use v5.36;

use File::Basename;

use PVE::RS::NVML;
use PVE::SysFSTools;
use PVE::File qw(file_read_first_line dir_glob_foreach file_get_contents);

my $pcisysfs = "/sys/bus/pci";

# Returns the PCI bus id of the physical function (IOW, parent device) of the
# given device. If the device does not have a parent physical function, returns
# the given ID unchanged.
my sub pci_dev_physfn_id($id) {
    $id = PVE::SysFSTools::normalize_pci_id($id);
    my $devpath = "$pcisysfs/devices/$id";

    if (-d "$devpath/physfn") {
        return basename(readlink("$devpath/physfn"));
    } else {
        return $id;
    }
}

sub generate_mdev_uuid($vmid, $index) {
    return sprintf("%08d-0000-0000-0000-%012d", $index, $vmid);
}

#
# return format:
# [
#     {
#         type => 'FooType_1',
#         description => "a longer description with custom format\nand newlines",
#         available => 5,
#         name => "human readable name for the type",
#     },
#     ...
# ]
#
sub get_mdev_types($id) {
    $id = PVE::SysFSTools::normalize_pci_id($id);

    my $types = [];

    my $dev_path = "$pcisysfs/devices/$id";
    my $mdev_path = "$dev_path/mdev_supported_types";
    my $nvidia_path = "$dev_path/nvidia/creatable_vgpu_types";
    if (-d $mdev_path) {
        dir_glob_foreach(
            $mdev_path,
            '[^\.].*',
            sub {
                my ($type) = @_;

                my $type_path = "$mdev_path/$type";

                my $available = int(file_read_first_line("$type_path/available_instances"));
                my $description = file_get_contents("$type_path/description");

                my $entry = {
                    type => $type,
                    description => $description,
                    available => $available,
                };

                my $name = file_read_first_line("$type_path/name");
                $entry->{name} = $name if defined($name);

                push @$types, $entry;
            },
        );
    } elsif (-f $nvidia_path) {
        my $physfn = pci_dev_physfn_id($id);
        my $creatable = eval { PVE::RS::NVML::creatable_vgpu_types_for_dev($physfn) };
        die "failed to query NVIDIA vGPU types for $id - $@\n" if $@;

        for my $type ($creatable->@*) {
            my $nvidia_id = $type->{id};
            my $name = $type->{name};
            push $types->@*,
                {
                    type => "nvidia-$nvidia_id",
                    description => $type->{description},
                    available => 1,
                    name => $name,
                };
        }
    }

    return $types;
}

sub pci_create_mdev_device($pciid, $uuid, $type) {
    $pciid = PVE::SysFSTools::normalize_pci_id($pciid);

    my $basedir = "$pcisysfs/devices/$pciid";
    my $mdev_dir = "$basedir/mdev_supported_types";

    die "pci device '$pciid' does not support mediated devices \n"
        if !-d $mdev_dir;

    die "pci device '$pciid' has no type '$type'\n"
        if !-d "$mdev_dir/$type";

    if (-d "$basedir/$uuid") {
        # it already exists, checking type
        my $typelink = readlink("$basedir/$uuid/mdev_type");
        my ($existingtype) = $typelink =~ m|/([^/]+)$|;
        die "mdev instance '$uuid' already exists, but type is not '$type'\n"
            if $type ne $existingtype;

        # instance exists, so use it but warn the user
        warn "mdev instance '$uuid' already existed, using it.\n";
        return undef;
    }

    my $instances = file_read_first_line("$mdev_dir/$type/available_instances");
    my ($avail) = $instances =~ m/^(\d+)$/;
    die "pci device '$pciid' has no available instances of '$type'\n"
        if $avail < 1;

    die "could not create '$type' for pci devices '$pciid'\n"
        if !PVE::SysFSTools::file_write("$mdev_dir/$type/create", $uuid);

    return undef;
}

# set vgpu type of a vf of an nvidia gpu with kernel 6.8 or newer
sub create_nvidia_device($id, $model) {
    $id = PVE::SysFSTools::normalize_pci_id($id);

    my $creation = "$pcisysfs/devices/$id/nvidia/current_vgpu_type";

    die "no nvidia sysfs api for '$id'\n" if !-f $creation;

    my $current = file_read_first_line($creation);
    if ($current ne "0") {
        return 1 if $current eq $model;
        # reset vgpu type so we can see all available and set the real device
        die "unable to reset vgpu type for '$id'\n" if !PVE::SysFSTools::file_write($creation, "0");
    }

    my $types = get_mdev_types($id);
    my $selected;
    for my $type_definition ($types->@*) {
        next if $type_definition->{type} ne "nvidia-$model";
        $selected = $type_definition;
    }

    if (!defined($selected) || $selected->{available} < 1) {
        die "vgpu type '$model' not available for '$id'\n";
    }

    if (!PVE::SysFSTools::file_write($creation, $model)) {
        die "could not set vgpu type to '$model' for '$id'\n";
    }

    return 1;
}

1;
