#!/usr/bin/perl

# this is some experimental code to test pci pass through

use strict;
use warnings;
use IO::Dir;
use IO::File;
use Time::HiRes qw(usleep);
use Data::Dumper;

# linux/Documentation/filesystems/sysfs-pci.txt
# linux/DocumentationABI/testing/sysfs-bus-pci

use constant {
    PCI_STATUS => 0x06,
    PCI_CONF_HEADER_LEN => 0x40,
    PCI_STATUS_CAP_LIST => 0x10,
    PCI_CAPABILITY_LIST => 0x34, 
    PCI_CAP_ID_PM => 0x01,
    PCI_PM_CTRL => 0x04,
    PCI_PM_CTRL_STATE_MASK => 0x03,
    PCI_PM_CTRL_STATE_D0 => 0x00,
    PCI_PM_CTRL_STATE_D3hot => 0x03,
    PCI_PM_CTRL_NO_SOFT_RESET => 0x08,
};

my $pcisysfs = "/sys/bus/pci";

sub file_read_firstline {
    my ($filename) = @_;

    my $fh = IO::File->new ($filename, "r");
    return undef if !$fh;
    my $res = <$fh>;
    chomp $res;
    $fh->close;
    return $res;
}

sub file_read {
    my ($filename) = @_;

    my $fh = IO::File->new ($filename, "r");
    return undef if !$fh;

    local $/ = undef; # enable slurp mode
    my $content = <$fh>;
    $fh->close();

    return $content;
}

sub file_write {
    my ($filename, $buf) = @_;

    my $fh = IO::File->new ($filename, "w");
    return undef if !$fh;

    my $res = print $fh $buf;

    $fh->close();

    return $res;
}

sub read_pci_config {
    my $name = shift;

    return file_read ("$pcisysfs/devices/$name/config");
}

sub pci_config_write {
    my ($name, $pos, $buf) = @_;

    my $filename = "$pcisysfs/devices/$name/config";

    my $fh = IO::File->new ($filename, "w");
    return undef if !$fh;

    if (sysseek($fh, $pos, 0) != $pos) {
	print "PCI WRITE seek failed\n";
	return undef;
    }

    my $res = syswrite ($fh, $buf);
    print "PCI WRITE $res\n";

    $fh->close();

    return $res;
}

sub pci_config_read {
    my ($conf, $pos, $fmt) = @_;

    my $len;
    if ($fmt eq 'C') {
	$len = 1;
    } elsif ($fmt eq 'S') {
	$len = 2;
    } elsif ($fmt eq 'L') {
	$len = 4;
    } else {
	return undef;
    }
    return undef if (($pos < 0) || (($pos + $len) > length($conf)));

    return unpack($fmt, substr($conf, $pos, $len));
}


sub pci_device_list {

    my $res = {};

    my $dh = IO::Dir->new ("$pcisysfs/devices") || return $res;

    my $used_irqs;

    if ($dh) {
	while (defined(my $name = $dh->read)) {
	    if ($name =~ m/^([a-f0-9]{4}):([a-f0-9]{2}):([a-f0-9]{2})\.([a-f0-9])$/i) {
		my ($domain, $bus, $slot, $func) = ($1, $2, $3, $4);

		my $irq = file_read_firstline("$pcisysfs/devices/$name/irq");
		next if $irq !~ m/^\d+$/;

		my $irq_is_shared = defined($used_irqs->{$irq}) || 0;
		$used_irqs->{$irq} = 1;

		my $vendor = file_read_firstline("$pcisysfs/devices/$name/vendor");
		next if $vendor !~ s/^0x//;
		my $product = file_read_firstline("$pcisysfs/devices/$name/device");
		next if $product !~ s/^0x//;

		my $conf = read_pci_config ($name);
		next if !$conf;

		$res->{$name} = {
		    vendor => $vendor,
		    product => $product,
		    domain => $domain,
		    bus => $bus,
		    slot => $slot,
		    func => $func,
		    irq => $irq,
		    irq_is_shared => $irq_is_shared,
		    has_fl_reset => -f "$pcisysfs/devices/$name/reset" || 0,
		};


		my $status = pci_config_read ($conf, PCI_STATUS, 'S');
		next if !defined ($status) || (!($status & PCI_STATUS_CAP_LIST));

		my $pos = pci_config_read ($conf, PCI_CAPABILITY_LIST, 'C');
		while ($pos && $pos > PCI_CONF_HEADER_LEN && $pos != 0xff) {
		    my $capid = pci_config_read ($conf, $pos, 'C');
		    last if !defined ($capid);
		    $res->{$name}->{cap}->{$capid} = $pos;
		    $pos = pci_config_read ($conf, $pos + 1, 'C');
		}

		#print Dumper($res->{$name});
		my $capid = PCI_CAP_ID_PM;
		if (my $pm_cap_off = $res->{$name}->{cap}->{$capid}) {
		    # require the NO_SOFT_RESET bit is clear
		    my $ctl = pci_config_read ($conf, $pm_cap_off + PCI_PM_CTRL, 'L');
		    if (defined ($ctl) && !($ctl & PCI_PM_CTRL_NO_SOFT_RESET)) {
			$res->{$name}->{has_pm_reset} = 1;
		    } 
		}
	    }
	}
    }

    return $res;
}

sub pci_pm_reset {
    my ($list, $name) = @_;

    print "trying to reset $name\n";

    my $dev = $list->{$name} || die "no such pci device '$name";
    
    my $capid = PCI_CAP_ID_PM;
    my $pm_cap_off = $list->{$name}->{cap}->{$capid};

    return undef if !defined ($pm_cap_off);
    return undef if !$dev->{has_pm_reset};

    my $conf = read_pci_config ($name) || die "cant read pci config";

    my $ctl = pci_config_read ($conf, $pm_cap_off + PCI_PM_CTRL, 'L');
    return undef if !defined ($ctl);

    $ctl = $ctl & ~PCI_PM_CTRL_STATE_MASK;

    pci_config_write($name, $pm_cap_off + PCI_PM_CTRL, 
		     pack ('L', $ctl|PCI_PM_CTRL_STATE_D3hot));
 
    usleep(10000); # 10ms

    pci_config_write($name, $pm_cap_off + PCI_PM_CTRL, 
		     pack ('L', $ctl|PCI_PM_CTRL_STATE_D0));

    usleep(10000); # 10ms

    return pci_config_write($name, 0, $conf);
}

sub pci_dev_reset {
    my ($list, $name) = @_;

    print "trying to reset $name\n";

    my $dev = $list->{$name} || die "no such pci device '$name";

    my $fn = "$pcisysfs/devices/$name/reset";

    return file_write ($fn, "1");
}


sub pci_dev_bind_to_stub {
    my ($list, $name) = @_;

    my $dev = $list->{$name} || die "no such pci device '$name";

    #return undef if $dev->{irq_is_shared};

    my $testdir = "$pcisysfs/drivers/pci-stub/$name";
    return 1 if -d $testdir;

    my $data = "$dev->{vendor} $dev->{product}";
    return undef if !file_write ("$pcisysfs/drivers/pci-stub/new_id", $data);

    my $fn = "$pcisysfs/devices/$name/driver/unbind";
    if (!file_write ($fn, $name)) {
	return undef if -f $fn;
    }

    $fn = "$pcisysfs/drivers/pci-stub/bind";
    if (! -d $testdir) {
	return undef if !file_write ($fn, $name);
    }

    return -d $testdir;
}

sub pci_dev_unbind_from_stub {
    my ($list, $name) = @_;

    my $dev = $list->{$name} || die "no such pci device '$name";

    #return undef if $dev->{irq_is_shared};

    my $testdir = "$pcisysfs/drivers/pci-stub/$name";
    return 1 if ! -d $testdir;

    my $data = "$dev->{vendor} $dev->{product}";
    file_write ("$pcisysfs/drivers/pci-stub/remove_id", $data);

    return undef if !file_write ("$pcisysfs/drivers/pci-stub/unbind", $name);

    return ! -d $testdir;
}

my $devlist = pci_device_list();
print Dumper($devlist);

my $name = $ARGV[0] || exit 0;

if (!pci_dev_bind_to_stub($devlist, $name)) {
    print "failed\n";
    exit (-1);
}
if (!pci_dev_unbind_from_stub($devlist, $name)) {
    print "failed\n";
    exit (-1);
}

#pci_pm_reset ($devlist, $name);

if (!pci_dev_reset ($devlist, $name)) {
    print "reset failed\n";
    exit (-1);
}


exit 0;
