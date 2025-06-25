DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

SOURCES=Helpers.pm

.PHONY: install
install: $(SOURCES)
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/QemuMigrate/$$i; done
