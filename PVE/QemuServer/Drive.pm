package PVE::QemuServer::Drive;

use strict;
use warnings;

use PVE::Storage;
use PVE::JSONSchema qw(get_standard_option);

use base qw(Exporter);

our @EXPORT_OK = qw(
is_valid_drivename
drive_is_cloudinit
drive_is_cdrom
parse_drive
print_drive
foreach_drive
foreach_volid
);

our $QEMU_FORMAT_RE = qr/raw|cow|qcow|qcow2|qed|vmdk|cloop/;

PVE::JSONSchema::register_standard_option('pve-qm-image-format', {
    type => 'string',
    enum => [qw(raw cow qcow qed qcow2 vmdk cloop)],
    description => "The drive's backing file's data format.",
    optional => 1,
});

my $MAX_IDE_DISKS = 4;
my $MAX_SCSI_DISKS = 31;
my $MAX_VIRTIO_DISKS = 16;
our $MAX_SATA_DISKS = 6;
our $MAX_UNUSED_DISKS = 256;

our $drivedesc_hash;

my %drivedesc_base = (
    volume => { alias => 'file' },
    file => {
	type => 'string',
	format => 'pve-volume-id-or-qm-path',
	default_key => 1,
	format_description => 'volume',
	description => "The drive's backing volume.",
    },
    media => {
	type => 'string',
	enum => [qw(cdrom disk)],
	description => "The drive's media type.",
	default => 'disk',
	optional => 1
    },
    cyls => {
	type => 'integer',
	description => "Force the drive's physical geometry to have a specific cylinder count.",
	optional => 1
    },
    heads => {
	type => 'integer',
	description => "Force the drive's physical geometry to have a specific head count.",
	optional => 1
    },
    secs => {
	type => 'integer',
	description => "Force the drive's physical geometry to have a specific sector count.",
	optional => 1
    },
    trans => {
	type => 'string',
	enum => [qw(none lba auto)],
	description => "Force disk geometry bios translation mode.",
	optional => 1,
    },
    snapshot => {
	type => 'boolean',
	description => "Controls qemu's snapshot mode feature."
	    . " If activated, changes made to the disk are temporary and will"
	    . " be discarded when the VM is shutdown.",
	optional => 1,
    },
    cache => {
	type => 'string',
	enum => [qw(none writethrough writeback unsafe directsync)],
	description => "The drive's cache mode",
	optional => 1,
    },
    format => get_standard_option('pve-qm-image-format'),
    size => {
	type => 'string',
	format => 'disk-size',
	format_description => 'DiskSize',
	description => "Disk size. This is purely informational and has no effect.",
	optional => 1,
    },
    backup => {
	type => 'boolean',
	description => "Whether the drive should be included when making backups.",
	optional => 1,
    },
    replicate => {
	type => 'boolean',
	description => 'Whether the drive should considered for replication jobs.',
	optional => 1,
	default => 1,
    },
    rerror => {
	type => 'string',
	enum => [qw(ignore report stop)],
	description => 'Read error action.',
	optional => 1,
    },
    werror => {
	type => 'string',
	enum => [qw(enospc ignore report stop)],
	description => 'Write error action.',
	optional => 1,
    },
    aio => {
	type => 'string',
	enum => [qw(native threads)],
	description => 'AIO type to use.',
	optional => 1,
    },
    discard => {
	type => 'string',
	enum => [qw(ignore on)],
	description => 'Controls whether to pass discard/trim requests to the underlying storage.',
	optional => 1,
    },
    detect_zeroes => {
	type => 'boolean',
	description => 'Controls whether to detect and try to optimize writes of zeroes.',
	optional => 1,
    },
    serial => {
	type => 'string',
	format => 'urlencoded',
	format_description => 'serial',
	maxLength => 20*3, # *3 since it's %xx url enoded
	description => "The drive's reported serial number, url-encoded, up to 20 bytes long.",
	optional => 1,
    },
    shared => {
	type => 'boolean',
	description => 'Mark this locally-managed volume as available on all nodes',
	verbose_description => "Mark this locally-managed volume as available on all nodes.\n\nWARNING: This option does not share the volume automatically, it assumes it is shared already!",
	optional => 1,
	default => 0,
    }
);

my %iothread_fmt = ( iothread => {
	type => 'boolean',
	description => "Whether to use iothreads for this drive",
	optional => 1,
});

my %model_fmt = (
    model => {
	type => 'string',
	format => 'urlencoded',
	format_description => 'model',
	maxLength => 40*3, # *3 since it's %xx url enoded
	description => "The drive's reported model name, url-encoded, up to 40 bytes long.",
	optional => 1,
    },
);

my %queues_fmt = (
    queues => {
	type => 'integer',
	description => "Number of queues.",
	minimum => 2,
	optional => 1
    }
);

my %scsiblock_fmt = (
    scsiblock => {
	type => 'boolean',
	description => "whether to use scsi-block for full passthrough of host block device\n\nWARNING: can lead to I/O errors in combination with low memory or high memory fragmentation on host",
	optional => 1,
	default => 0,
    },
);

my %ssd_fmt = (
    ssd => {
	type => 'boolean',
	description => "Whether to expose this drive as an SSD, rather than a rotational hard disk.",
	optional => 1,
    },
);

my %wwn_fmt = (
    wwn => {
	type => 'string',
	pattern => qr/^(0x)[0-9a-fA-F]{16}/,
	format_description => 'wwn',
	description => "The drive's worldwide name, encoded as 16 bytes hex string, prefixed by '0x'.",
	optional => 1,
    },
);

my $add_throttle_desc = sub {
    my ($key, $type, $what, $unit, $longunit, $minimum) = @_;
    my $d = {
	type => $type,
	format_description => $unit,
	description => "Maximum $what in $longunit.",
	optional => 1,
    };
    $d->{minimum} = $minimum if defined($minimum);
    $drivedesc_base{$key} = $d;
};
# throughput: (leaky bucket)
$add_throttle_desc->('bps',     'integer', 'r/w speed',   'bps',  'bytes per second');
$add_throttle_desc->('bps_rd',  'integer', 'read speed',  'bps',  'bytes per second');
$add_throttle_desc->('bps_wr',  'integer', 'write speed', 'bps',  'bytes per second');
$add_throttle_desc->('mbps',    'number',  'r/w speed',   'mbps', 'megabytes per second');
$add_throttle_desc->('mbps_rd', 'number',  'read speed',  'mbps', 'megabytes per second');
$add_throttle_desc->('mbps_wr', 'number',  'write speed', 'mbps', 'megabytes per second');
$add_throttle_desc->('iops',    'integer', 'r/w I/O',     'iops', 'operations per second');
$add_throttle_desc->('iops_rd', 'integer', 'read I/O',    'iops', 'operations per second');
$add_throttle_desc->('iops_wr', 'integer', 'write I/O',   'iops', 'operations per second');

# pools: (pool of IO before throttling starts taking effect)
$add_throttle_desc->('mbps_max',    'number',  'unthrottled r/w pool',       'mbps', 'megabytes per second');
$add_throttle_desc->('mbps_rd_max', 'number',  'unthrottled read pool',      'mbps', 'megabytes per second');
$add_throttle_desc->('mbps_wr_max', 'number',  'unthrottled write pool',     'mbps', 'megabytes per second');
$add_throttle_desc->('iops_max',    'integer', 'unthrottled r/w I/O pool',   'iops', 'operations per second');
$add_throttle_desc->('iops_rd_max', 'integer', 'unthrottled read I/O pool',  'iops', 'operations per second');
$add_throttle_desc->('iops_wr_max', 'integer', 'unthrottled write I/O pool', 'iops', 'operations per second');

# burst lengths
$add_throttle_desc->('bps_max_length',     'integer', 'length of I/O bursts',       'seconds', 'seconds', 1);
$add_throttle_desc->('bps_rd_max_length',  'integer', 'length of read I/O bursts',  'seconds', 'seconds', 1);
$add_throttle_desc->('bps_wr_max_length',  'integer', 'length of write I/O bursts', 'seconds', 'seconds', 1);
$add_throttle_desc->('iops_max_length',    'integer', 'length of I/O bursts',       'seconds', 'seconds', 1);
$add_throttle_desc->('iops_rd_max_length', 'integer', 'length of read I/O bursts',  'seconds', 'seconds', 1);
$add_throttle_desc->('iops_wr_max_length', 'integer', 'length of write I/O bursts', 'seconds', 'seconds', 1);

# legacy support
$drivedesc_base{'bps_rd_length'} = { alias => 'bps_rd_max_length' };
$drivedesc_base{'bps_wr_length'} = { alias => 'bps_wr_max_length' };
$drivedesc_base{'iops_rd_length'} = { alias => 'iops_rd_max_length' };
$drivedesc_base{'iops_wr_length'} = { alias => 'iops_wr_max_length' };

my $ide_fmt = {
    %drivedesc_base,
    %model_fmt,
    %ssd_fmt,
    %wwn_fmt,
};
PVE::JSONSchema::register_format("pve-qm-ide", $ide_fmt);

my $idedesc = {
    optional => 1,
    type => 'string', format => $ide_fmt,
    description => "Use volume as IDE hard disk or CD-ROM (n is 0 to " .($MAX_IDE_DISKS -1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-ide", $idedesc);

my $scsi_fmt = {
    %drivedesc_base,
    %iothread_fmt,
    %queues_fmt,
    %scsiblock_fmt,
    %ssd_fmt,
    %wwn_fmt,
};
my $scsidesc = {
    optional => 1,
    type => 'string', format => $scsi_fmt,
    description => "Use volume as SCSI hard disk or CD-ROM (n is 0 to " . ($MAX_SCSI_DISKS - 1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-scsi", $scsidesc);

my $sata_fmt = {
    %drivedesc_base,
    %ssd_fmt,
    %wwn_fmt,
};
my $satadesc = {
    optional => 1,
    type => 'string', format => $sata_fmt,
    description => "Use volume as SATA hard disk or CD-ROM (n is 0 to " . ($MAX_SATA_DISKS - 1). ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-sata", $satadesc);

my $virtio_fmt = {
    %drivedesc_base,
    %iothread_fmt,
};
my $virtiodesc = {
    optional => 1,
    type => 'string', format => $virtio_fmt,
    description => "Use volume as VIRTIO hard disk (n is 0 to " . ($MAX_VIRTIO_DISKS - 1) . ").",
};
PVE::JSONSchema::register_standard_option("pve-qm-virtio", $virtiodesc);

my $alldrive_fmt = {
    %drivedesc_base,
    %iothread_fmt,
    %model_fmt,
    %queues_fmt,
    %scsiblock_fmt,
    %ssd_fmt,
    %wwn_fmt,
};

my $efidisk_fmt = {
    volume => { alias => 'file' },
    file => {
	type => 'string',
	format => 'pve-volume-id-or-qm-path',
	default_key => 1,
	format_description => 'volume',
	description => "The drive's backing volume.",
    },
    format => get_standard_option('pve-qm-image-format'),
    size => {
	type => 'string',
	format => 'disk-size',
	format_description => 'DiskSize',
	description => "Disk size. This is purely informational and has no effect.",
	optional => 1,
    },
};

my $efidisk_desc = {
    optional => 1,
    type => 'string', format => $efidisk_fmt,
    description => "Configure a Disk for storing EFI vars",
};

PVE::JSONSchema::register_standard_option("pve-qm-efidisk", $efidisk_desc);

for (my $i = 0; $i < $MAX_IDE_DISKS; $i++)  {
    $drivedesc_hash->{"ide$i"} = $idedesc;
}

for (my $i = 0; $i < $MAX_SATA_DISKS; $i++)  {
    $drivedesc_hash->{"sata$i"} = $satadesc;
}

for (my $i = 0; $i < $MAX_SCSI_DISKS; $i++)  {
    $drivedesc_hash->{"scsi$i"} = $scsidesc;
}

for (my $i = 0; $i < $MAX_VIRTIO_DISKS; $i++)  {
    $drivedesc_hash->{"virtio$i"} = $virtiodesc;
}

$drivedesc_hash->{efidisk0} = $efidisk_desc;

our $unuseddesc = {
    optional => 1,
    type => 'string', format => 'pve-volume-id',
    description => "Reference to unused volumes. This is used internally, and should not be modified manually.",
};

sub valid_drive_names {
    # order is important - used to autoselect boot disk
    return ((map { "ide$_" } (0 .. ($MAX_IDE_DISKS - 1))),
            (map { "scsi$_" } (0 .. ($MAX_SCSI_DISKS - 1))),
            (map { "virtio$_" } (0 .. ($MAX_VIRTIO_DISKS - 1))),
            (map { "sata$_" } (0 .. ($MAX_SATA_DISKS - 1))),
            'efidisk0');
}

sub is_valid_drivename {
    my $dev = shift;

    return defined($drivedesc_hash->{$dev});
}

PVE::JSONSchema::register_format('pve-qm-bootdisk', \&verify_bootdisk);
sub verify_bootdisk {
    my ($value, $noerr) = @_;

    return $value if is_valid_drivename($value);

    return undef if $noerr;

    die "invalid boot disk '$value'\n";
}

sub drive_is_cloudinit {
    my ($drive) = @_;
    return $drive->{file} =~ m@[:/]vm-\d+-cloudinit(?:\.$QEMU_FORMAT_RE)?$@;
}

sub drive_is_cdrom {
    my ($drive, $exclude_cloudinit) = @_;

    return 0 if $exclude_cloudinit && drive_is_cloudinit($drive);

    return $drive && $drive->{media} && ($drive->{media} eq 'cdrom');
}

# ideX = [volume=]volume-id[,media=d][,cyls=c,heads=h,secs=s[,trans=t]]
#        [,snapshot=on|off][,cache=on|off][,format=f][,backup=yes|no]
#        [,rerror=ignore|report|stop][,werror=enospc|ignore|report|stop]
#        [,aio=native|threads][,discard=ignore|on][,detect_zeroes=on|off]
#        [,iothread=on][,serial=serial][,model=model]

sub parse_drive {
    my ($key, $data) = @_;

    my ($interface, $index);

    if ($key =~ m/^([^\d]+)(\d+)$/) {
	$interface = $1;
	$index = $2;
    } else {
	return undef;
    }

    my $desc = $key =~ /^unused\d+$/ ? $alldrive_fmt
                                     : $drivedesc_hash->{$key}->{format};
    if (!$desc) {
	warn "invalid drive key: $key\n";
	return undef;
    }
    my $res = eval { PVE::JSONSchema::parse_property_string($desc, $data) };
    return undef if !$res;
    $res->{interface} = $interface;
    $res->{index} = $index;

    my $error = 0;
    foreach my $opt (qw(bps bps_rd bps_wr)) {
	if (my $bps = defined(delete $res->{$opt})) {
	    if (defined($res->{"m$opt"})) {
		warn "both $opt and m$opt specified\n";
		++$error;
		next;
	    }
	    $res->{"m$opt"} = sprintf("%.3f", $bps / (1024*1024.0));
	}
    }

    # can't use the schema's 'requires' because of the mbps* => bps* "transforming aliases"
    for my $requirement (
	[mbps_max => 'mbps'],
	[mbps_rd_max => 'mbps_rd'],
	[mbps_wr_max => 'mbps_wr'],
	[miops_max => 'miops'],
	[miops_rd_max => 'miops_rd'],
	[miops_wr_max => 'miops_wr'],
	[bps_max_length => 'mbps_max'],
	[bps_rd_max_length => 'mbps_rd_max'],
	[bps_wr_max_length => 'mbps_wr_max'],
	[iops_max_length => 'iops_max'],
	[iops_rd_max_length => 'iops_rd_max'],
	[iops_wr_max_length => 'iops_wr_max']) {
	my ($option, $requires) = @$requirement;
	if ($res->{$option} && !$res->{$requires}) {
	    warn "$option requires $requires\n";
	    ++$error;
	}
    }

    return undef if $error;

    return undef if $res->{mbps_rd} && $res->{mbps};
    return undef if $res->{mbps_wr} && $res->{mbps};
    return undef if $res->{iops_rd} && $res->{iops};
    return undef if $res->{iops_wr} && $res->{iops};

    if ($res->{media} && ($res->{media} eq 'cdrom')) {
	return undef if $res->{snapshot} || $res->{trans} || $res->{format};
	return undef if $res->{heads} || $res->{secs} || $res->{cyls};
	return undef if $res->{interface} eq 'virtio';
    }

    if (my $size = $res->{size}) {
	return undef if !defined($res->{size} = PVE::JSONSchema::parse_size($size));
    }

    return $res;
}

sub print_drive {
    my ($drive) = @_;
    my $skip = [ 'index', 'interface' ];
    return PVE::JSONSchema::print_property_string($drive, $alldrive_fmt, $skip);
}

sub foreach_drive {
    my ($conf, $func, @param) = @_;

    foreach my $ds (valid_drive_names()) {
	next if !defined($conf->{$ds});

	my $drive = parse_drive($ds, $conf->{$ds});
	next if !$drive;

	&$func($ds, $drive, @param);
    }
}

sub foreach_volid {
    my ($conf, $func, @param) = @_;

    my $volhash = {};

    my $test_volid = sub {
	my ($volid, $is_cdrom, $replicate, $shared, $snapname, $size) = @_;

	return if !$volid;

	$volhash->{$volid}->{cdrom} //= 1;
	$volhash->{$volid}->{cdrom} = 0 if !$is_cdrom;

	$volhash->{$volid}->{replicate} //= 0;
	$volhash->{$volid}->{replicate} = 1 if $replicate;

	$volhash->{$volid}->{shared} //= 0;
	$volhash->{$volid}->{shared} = 1 if $shared;

	$volhash->{$volid}->{referenced_in_config} //= 0;
	$volhash->{$volid}->{referenced_in_config} = 1 if !defined($snapname);

	$volhash->{$volid}->{referenced_in_snapshot}->{$snapname} = 1
	    if defined($snapname);
	$volhash->{$volid}->{size} = $size if $size;
    };

    foreach_drive($conf, sub {
	my ($ds, $drive) = @_;
	$test_volid->($drive->{file}, drive_is_cdrom($drive), $drive->{replicate} // 1, $drive->{shared}, undef, $drive->{size});
    });

    foreach my $snapname (keys %{$conf->{snapshots}}) {
	my $snap = $conf->{snapshots}->{$snapname};
	$test_volid->($snap->{vmstate}, 0, 1, $snapname);
	foreach_drive($snap, sub {
	    my ($ds, $drive) = @_;
	    $test_volid->($drive->{file}, drive_is_cdrom($drive), $drive->{replicate} // 1, $drive->{shared}, $snapname);
        });
    }

    foreach my $volid (keys %$volhash) {
	&$func($volid, $volhash->{$volid}, @param);
    }
}

sub disksize {
    my ($storecfg, $conf) = @_;

    my $bootdisk = $conf->{bootdisk};
    return undef if !$bootdisk;
    return undef if !is_valid_drivename($bootdisk);

    return undef if !$conf->{$bootdisk};

    my $drive = parse_drive($bootdisk, $conf->{$bootdisk});
    return undef if !defined($drive);

    return undef if drive_is_cdrom($drive);

    my $volid = $drive->{file};
    return undef if !$volid;

    return $drive->{size};
}

sub update_disksize {
    my ($drive, $volid_hash) = @_;

    my $volid = $drive->{file};
    return undef if !defined($volid);

    my $oldsize = $drive->{size};
    my $newsize = $volid_hash->{$volid}->{size};

    if (defined($newsize) && defined($oldsize) && $newsize != $oldsize) {
	$drive->{size} = $newsize;

	my $old_fmt = PVE::JSONSchema::format_size($oldsize);
	my $new_fmt = PVE::JSONSchema::format_size($newsize);

	return wantarray ? ($drive, $old_fmt, $new_fmt) : $drive;
    }

    return undef;
}

sub is_volume_in_use {
    my ($storecfg, $conf, $skip_drive, $volid) = @_;

    my $path = PVE::Storage::path($storecfg, $volid);

    my $scan_config = sub {
	my ($cref, $snapname) = @_;

	foreach my $key (keys %$cref) {
	    my $value = $cref->{$key};
	    if (is_valid_drivename($key)) {
		next if $skip_drive && $key eq $skip_drive;
		my $drive = parse_drive($key, $value);
		next if !$drive || !$drive->{file} || drive_is_cdrom($drive);
		return 1 if $volid eq $drive->{file};
		if ($drive->{file} =~ m!^/!) {
		    return 1 if $drive->{file} eq $path;
		} else {
		    my ($storeid, $volname) = PVE::Storage::parse_volume_id($drive->{file}, 1);
		    next if !$storeid;
		    my $scfg = PVE::Storage::storage_config($storecfg, $storeid, 1);
		    next if !$scfg;
		    return 1 if $path eq PVE::Storage::path($storecfg, $drive->{file}, $snapname);
		}
	    }
	}

	return 0;
    };

    return 1 if &$scan_config($conf);

    undef $skip_drive;

    foreach my $snapname (keys %{$conf->{snapshots}}) {
	return 1 if &$scan_config($conf->{snapshots}->{$snapname}, $snapname);
    }

    return 0;
}

sub resolve_first_disk {
    my $conf = shift;
    my @disks = valid_drive_names();
    my $firstdisk;
    foreach my $ds (reverse @disks) {
	next if !$conf->{$ds};
	my $disk = parse_drive($ds, $conf->{$ds});
	next if drive_is_cdrom($disk);
	$firstdisk = $ds;
    }
    return $firstdisk;
}

1;
