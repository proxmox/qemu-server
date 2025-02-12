SOURCES=NoWrite.pm

.PHONY: install
install: ${SOURCES}
	for i in ${SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/QemuConfig/$$i; done
