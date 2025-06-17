PACKAGE ?= qemu-server
DESTDIR=
PREFIX=/usr
LIBDIR=$(DESTDIR)/$(PREFIX)/lib
LIBEXECDIR=$(DESTDIR)/$(PREFIX)/libexec/$(PACKAGE)
SHAREDIR=$(DESTDIR)/$(PREFIX)/share/$(PACKAGE)

.PHONY: install
install: pve-usb.cfg pve-q35.cfg pve-q35-4.0.cfg bootsplash.jpg modules-load.conf pve-bridge pve-bridge-hotplug pve-bridgedown
	install -d $(SHAREDIR)
	install -m 0644 pve-usb.cfg $(SHAREDIR)
	install -m 0644 pve-q35.cfg $(SHAREDIR)
	install -m 0644 pve-q35-4.0.cfg $(SHAREDIR)
	install -m 0644 -D bootsplash.jpg $(SHAREDIR)
	install -D -m 0644 modules-load.conf $(LIBDIR)/modules-load.d/qemu-server.conf
	install -d $(LIBEXECDIR)
	install -m 0755 pve-bridge $(LIBEXECDIR)/pve-bridge
	install -m 0755 pve-bridge-hotplug $(LIBEXECDIR)/pve-bridge-hotplug
	install -m 0755 pve-bridgedown $(LIBEXECDIR)/pve-bridgedown

.PHONY: clean
clean:
