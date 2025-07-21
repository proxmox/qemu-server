package PVE::API2::Qemu::HMPPerms;

use strict;
use warnings;

# List of monitor commands and associated required permission. Listed explicitly to be future-proof.
#
# Currently permissions are:
# 'root' - for root-only commands
# 'Sys.Modify' - commands that can be issued with 'Sys.Modify' on '/'
# 'none' - no permissions required (i.e. help and info)
our $hmp_command_perms = {
    help => 'none', # show the help
    '?' => 'none', # short-form of 'help'
    info => 'none', # show various information about the system state

    # root-only: backup to arbitrary target file (although currently, not overwriting existing file)
    backup => 'root', # create a VM backup (VMA format).
    # root-only: requires the stream source in the backing chain currently, but better be safe
    block_stream => 'root', # copy data from a backing file into a block device
    # root-only: allows changing the path a removable medium points to
    change => 'root', # change a removable medium
    # root-only: among others, there is a 'file' driver
    'chardev-add' => 'root', # add chardev
    # root-only: among others, there is a 'file' driver (e.g. modify backend for serial device)
    'chardev-change' => 'root', # change chardev
    # root-only: because chardev-add is
    'chardev-remove' => 'root', # remove chardev
    # root-only: after migration SPICE client will attempt to connect to arbitrarily set host
    client_migrate_info => 'root', # set migration information for remote display
    # root-only: like '-device' on the commandline
    device_add => 'root', # add device, like -device on the command line
    # root-only: because device_add is
    device_del => 'root', # remove device
    # root-only: like '-drive' on the commandline
    drive_add => 'root', # add drive to PCI storage controller
    # root-only: backup to arbitrary target file
    drive_backup => 'root', # initiates a point-in-time copy for a device.
    # root-only: because drive_add is
    drive_del => 'root', # remove host block device
    # root-only: mirror to arbitrary target file
    drive_mirror => 'root', # initiates live storage migration for a device.
    # root-only: dump guest memory into arbitrary target file
    'dump-guest-memory' => 'root', # dump guest memory into file 'filename'.
    # root-only: dumps into arbitrary target file
    dumpdtb => 'root', # dump the FDT in dtb format to 'filename'
    # root-only: starts GDB server on the host
    gdbserver => 'root', # start gdbserver on given device (default 'tcp::1234'), stop with 'none'
    # root-only: host information leak
    gpa2hpa => 'Sys.Modify', # print the host physical address corresponding to a guest physical address
    # root-only: host information leak
    gpa2hva => 'Sys.Modify', # print the host virtual address corresponding to a guest physical address
    # root-only: redirect TCP or UDP connections from host to guest
    hostfwd_add => 'root', # redirect TCP or UDP connections from host to guest (requires -net user)
    # root-only: because hostfwd_add is
    hostfwd_remove => 'root', # remove host-to-guest TCP or UDP redirection
    # root-only: read from IO adress space (e.g. PCI devices)
    i => 'Sys.Modify', # I/O port read
    # root-only: log to arbitrary target file
    logfile => 'root', # output logs to 'filename'
    # root-only: no guarantee there are no KVM bugs that could afffect the real CPU
    mce => 'root', # inject a MCE on the given CPU [and broadcast to other CPUs with -b option]
    # root-only: allows to save to arbitrary file
    memsave => 'root', # save to disk virtual memory dump starting at 'addr' of size 'size'
    # root-only: could specify arbitrary host, also there is 'exec' and 'file' migrations
    migrate => 'root', # migrate to URI (using -d to not wait for completion)
    # root-only: allows setting arbitrary URI
    migrate_incoming => 'root', # Continue an incoming migration from an -incoming defer
    # root-only: allows setting arbitrary URI
    migrate_recover => 'root', # Continue a paused incoming postcopy migration
    # root-only: because nbd_server_start is
    nbd_server_add => 'root', # export a block device via NBD
    # root-only: because nbd_server_start is
    nbd_server_remove => 'root', # remove an export previously exposed via NBD
    # root-only: start NBD server on the host
    nbd_server_start => 'root', # serve block devices on the given host and port
    # root-only: because nbd_server_start is
    nbd_server_stop => 'root', # stop serving block devices using the NBD protocol
    # root-only: add host network device
    netdev_add => 'root', # add host network device
    # root-only: because netdev_add is
    netdev_del => 'root', # remove host network device
    # root-only: no guarantee there are no KVM bugs that could afffect the real CPU
    nmi => 'root', # inject an NMI
    # root-only: write to IO adress space (e.g. PCI devices)
    o => 'root', # I/O port write
    # root-only: create arbitrary objects, e.g. serial
    object_add => 'root', # create QOM object
    # root-only: because object_del is
    object_del => 'root', # destroy QOM object
    # root-only: inject error on PCIe devices
    pcie_aer_inject_error => 'root', # inject pcie aer error
    # root-only: save to arbitrary file
    pmemsave => 'root', # save to disk physical memory dump starting at 'addr' of size 'size'
    # root-only: modify arbitrary object properties
    'qom-set' => 'root', # set QOM property.
    # root-only: because savevm-start is
    'savevm-end' => 'root', # Resume VM after snaphot.
    # root-only: save VM state to arbitrary target file
    'savevm-start' => 'root', # Prepare for snapshot and halt VM. Save VM state to statefile.
    # root-only: dump to arbitrary target file
    screendump => 'root', # save screen
    # root-only: allows specifying arbitrary target file
    snapshot_blkdev => 'root', # initiates a live snapshot of device
    # root-only: allows inject-nmi
    watchdog_action => 'root', # change watchdog action
    # root-only: saves to arbitrary target file
    wavcapture => 'root', # capture audio to a wave file
    # root-only: not relevant for Proxmox VE
    'xen-event-inject' => 'root', # inject event channel
    # root-only: not relevant for Proxmox VE
    'xen-event-list' => 'root', # list event channel state

    announce_self => 'Sys.Modify', # Trigger GARP/RARP announcements
    backup_cancel => 'Sys.Modify', # cancel the current VM backup
    balloon => 'Sys.Modify', # request VM to change its memory allocation (in MB)
    block_job_cancel => 'Sys.Modify', # stop an active background block operation
    block_job_complete => 'Sys.Modify', # stop an active background block operation
    block_job_pause => 'Sys.Modify', # pause an active background block operation
    block_job_resume => 'Sys.Modify', # resume a paused background block operation
    block_job_set_speed => 'Sys.Modify', # set maximum speed for a background block operation
    block_resize => 'Sys.Modify', # resize a block image
    block_set_io_throttle => 'Sys.Modify', # change I/O throttle limits for a block drive
    boot_set => 'Sys.Modify', # define new values for the boot device list
    calc_dirty_rate => 'Sys.Modify', # start a round of guest dirty rate measurement
    cancel_vcpu_dirty_limit => 'Sys.Modify', # cancel dirty page rate limit
    'chardev-send-break' => 'Sys.Modify', # send a break on chardev
    closefd => 'Sys.Modify', # close a file descriptor previously passed via SCM rights
    commit => 'Sys.Modify', # commit changes to the disk images or backing files
    cont => 'Sys.Modify', # resume emulation
    c => 'Sys.Modify', # short-form of 'cont'
    cpu => 'Sys.Modify', # set the default CPU
    delvm => 'Sys.Modify', # delete a VM snapshot from its tag
    eject => 'Sys.Modify', # eject a removable medium (use -f to force it)
    exit_preconfig => 'Sys.Modify', # exit the preconfig state
    expire_password => 'Sys.Modify', # set spice/vnc password expire-time
    getfd => 'Sys.Modify', # receive a file descriptor via SCM rights and assign it a name
    gva2gpa => 'Sys.Modify', # print the guest physical address corresponding to a guest virtual address
    loadvm => 'Sys.Modify', # restore a VM snapshot from its tag
    log => 'Sys.Modify', # activate logging of the specified items
    migrate_cancel => 'Sys.Modify', # cancel the current VM migration
    migrate_continue => 'Sys.Modify', # Continue migration from the given paused state
    migrate_pause => 'Sys.Modify', # Pause an ongoing migration (postcopy-only)
    migrate_set_capability => 'Sys.Modify', # Enable/Disable the usage of a capability for migration
    migrate_set_parameter => 'Sys.Modify', # Set the parameter for migration
    migrate_start_postcopy => 'Sys.Modify', # Switch the migration to postcopy mode.
    mouse_button => 'Sys.Modify', # change mouse button state (1=L, 2=M, 4=R)
    mouse_move => 'Sys.Modify', # send mouse move events
    mouse_set => 'Sys.Modify', # set which mouse device receives events
    'one-insn-per-tb' => 'Sys.Modify', # run emulation with one guest instruction per translation block
    print => 'Sys.Modify', # print expression value (use $reg for CPU register access)
    p => 'Sys.Modify', # alias for 'print'
    'qemu-io' => 'Sys.Modify', # run a qemu-io command on a block device
    # decidedly not root-only even if qom-set ist, because it is just too useful
    'qom-get' => 'Sys.Modify', # print QOM property
    'qom-list' => 'Sys.Modify', # list QOM properties
    quit => 'Sys.Modify', # quit the emulator
    q => 'Sys.Modify', # short-form of 'quit'
    replay_break => 'Sys.Modify', # set breakpoint at the specified instruction count
    replay_delete_break => 'Sys.Modify', # remove replay breakpoint
    replay_seek => 'Sys.Modify', # replay execution to the specified instruction count
    ringbuf_read => 'Sys.Modify', # Read from a ring buffer character device
    ringbuf_write => 'Sys.Modify', # Write to a ring buffer character device
    savevm => 'Sys.Modify', # save a VM snapshot. If no tag is provided, a new snapshot is created
    sendkey => 'Sys.Modify', # send keys to the VM
    set_link => 'Sys.Modify', # change the link status of a network adapter
    set_password => 'Sys.Modify', # set spice/vnc password
    set_vcpu_dirty_limit => 'Sys.Modify', # set dirty page rate limit
    snapshot_blkdev_internal => 'Sys.Modify', # take an internal snapshot of device.
    snapshot_delete_blkdev_internal => 'Sys.Modify', # delete an internal snapshot of device.
    stopcapture => 'Sys.Modify', # stop capture
    stop => 'Sys.Modify', # stop emulation
    s => 'Sys.Modify', # short-form of 'stop'
    sum => 'Sys.Modify', # compute the checksum of a memory region
    'sync-profile' => 'Sys.Modify', # enable, disable or reset synchronization profiling.
    system_powerdown => 'Sys.Modify', # send system power down event
    system_reset => 'Sys.Modify', # reset the system
    system_wakeup => 'Sys.Modify', # wakeup guest from suspend
    'trace-event' => 'Sys.Modify', # changes status of a specific trace event
    x => 'Sys.Modify', # virtual memory dump starting at 'addr'
    x_colo_lost_heartbeat => 'Sys.Modify', # Tell COLO that heartbeat is lost
    xp => 'Sys.Modify', # physical memory dump starting at 'addr'
};

sub generate_description {
    my $cmd_by_priv = {};
    for my $cmd (sort keys $hmp_command_perms->%*) {
        my $priv = $hmp_command_perms->{$cmd};
        $cmd_by_priv->{$priv} = [] if !exists($cmd_by_priv->{$priv});

        push $cmd_by_priv->{$priv}->@*, $cmd;
    }
    my $none_cmds = delete($cmd_by_priv->{none})
        or die "internal error - no commands for 'none' found";
    my $root_only_cmds = delete($cmd_by_priv->{'root'})
        or die "internal error no commands for 'root' found";

    my $text = '';
    $text .= "The following commands do not require any additional privilege: "
        . join(', ', $none_cmds->@*) . "\n\n";

    for my $priv (sort keys $cmd_by_priv->%*) {
        $text .= "The following commands require '$priv': "
            . join(', ', $cmd_by_priv->{$priv}->@*) . "\n\n";
    }

    $text .= "The following commands are root-only: " . join(', ', $root_only_cmds->@*) . "\n";
}

1;
