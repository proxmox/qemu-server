#! /bin/sh

### BEGIN INIT INFO
# Provides:          qemu-server
# Required-Start:    +iscsi pve-cluster cman clvm $network $local_fs $remote_fs
# Required-Stop:     +iscsi pve-cluster cman clvm $network $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: start all qemu/kvm virtual machines
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin
PROG=/usr/sbin/qm
DESC="Qemu Server"

test -x $PROG || exit 0

set -e

case "$1" in
  start)
	(egrep '^flags.*svm' /proc/cpuinfo >/dev/null && modprobe -q kvm-amd) || 
	(egrep '^flags.*vmx' /proc/cpuinfo >/dev/null && modprobe -q kvm-intel) || 
	echo "unable to load kvm module"

	modprobe -q vhost_net || true

	# recent distributions use tmpfs for /var/run
	# and /var/lock to avoid to clean it up on every boot.
	# they also assume that init scripts will create
	# required subdirectories for proper operations
	mkdir -p /var/run/qemu-server
	mkdir -p /var/lock/qemu-server

	;;
  stop)
        # nothing to do, because we are no real daemon
	;;
  force-reload)
	;;
  restart)
        # nothing to do, because we are no real daemon
	;;
esac

exit 0
