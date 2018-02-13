.PHONY: install
install:
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE/API2
	install -D -m 0644 Qemu.pm ${DESTDIR}${PERLDIR}/PVE/API2/Qemu.pm
	make -C Qemu install
