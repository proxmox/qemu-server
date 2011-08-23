
.PHONY: install
install:
	install -D -m 0644 QemuServer.pm ${DESTDIR}${PERLDIR}/PVE/QemuServer.pm
	make -C VZDump install
	make -C API2 install