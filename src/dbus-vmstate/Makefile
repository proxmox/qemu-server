export LIBEXECDIR := $(DESTDIR)/usr/libexec/$(PACKAGE)
export LIBSYSTEMDDIR := $(DESTDIR)/usr/lib/systemd
export DBUSDIR := $(DESTDIR)/usr/share/dbus-1

all:

.PHONY: install
install:
	install -D -m 0755 dbus-vmstate $(LIBEXECDIR)/dbus-vmstate
	install -D -m 0644 pve-dbus-vmstate@.service $(LIBSYSTEMDDIR)/system/pve-dbus-vmstate@.service
	install -D -m 0644 org.qemu.VMState1.conf $(DBUSDIR)/system.d/org.qemu.VMState1.conf
