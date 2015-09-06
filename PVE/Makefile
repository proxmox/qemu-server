PERLSOURCE = 			\
	QemuServer.pm		\
	QemuMigrate.pm		\
	QMPClient.pm

.PHONY: install
install:
	install -d ${DESTDIR}${PERLDIR}/PVE
	install -m 0644 ${PERLSOURCE} ${DESTDIR}${PERLDIR}/PVE/
	make -C VZDump install
	make -C API2 install
	make -C CLI install
