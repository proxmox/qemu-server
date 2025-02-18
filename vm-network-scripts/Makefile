DESTDIR=
LIBEXECDIR=$(DESTDIR)/usr/libexec/qemu-server
# Remove with version 9
VARLIBDIR=$(DESTDIR)/var/lib/qemu-server

.PHONY: install
install: pve-bridge pve-bridge-hotplug pve-bridgedown
	install -d ${LIBEXECDIR}
	install -m 0755 pve-bridge ${LIBEXECDIR}/pve-bridge
	install -m 0755 pve-bridge-hotplug ${LIBEXECDIR}/pve-bridge-hotplug
	install -m 0755 pve-bridgedown ${LIBEXECDIR}/pve-bridgedown
	install -d ${VARLIBDIR}
	install -m 0755 pve-bridge ${VARLIBDIR}/pve-bridge
	install -m 0755 pve-bridge-hotplug ${VARLIBDIR}/pve-bridge-hotplug
	install -m 0755 pve-bridgedown ${VARLIBDIR}/pve-bridgedown

.PHONY: clean
clean:
