DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

SOURCES=Agent.pm CPU.pm HMPPerms.pm Machine.pm

.PHONY: install
install:
	install -d -m 0755 $(DESTDIR)$(PERLDIR)/PVE/API2/Qemu
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/API2/Qemu/$$i; done
