DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

SOURCES=qm.pm qmrestore.pm

.PHONY: install
install: $(SOURCES)
	install -d -m 0755 $(DESTDIR)$(PERLDIR)/PVE/CLI
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/CLI/$$i; done


