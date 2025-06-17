DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

PERLSOURCE = 			\
	QemuServer.pm		\
	QemuMigrate.pm		\
	QMPClient.pm		\
	QemuConfig.pm

.PHONY: install
install:
	install -d $(DESTDIR)$(PERLDIR)/PVE
	install -m 0644 $(PERLSOURCE) $(DESTDIR)$(PERLDIR)/PVE/
	$(MAKE) -C VZDump install
	$(MAKE) -C API2 install
	$(MAKE) -C CLI install
	$(MAKE) -C QemuConfig install
	$(MAKE) -C QemuServer install
