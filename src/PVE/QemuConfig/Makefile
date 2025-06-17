DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

SOURCES=NoWrite.pm

.PHONY: install
install: $(SOURCES)
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/QemuConfig/$$i; done
