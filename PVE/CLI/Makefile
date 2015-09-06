SOURCES=qm.pm

.PHONY: install
install: ${SOURCES}
	install -d -m 0755 ${PERLDIR}/PVE/CLI
	for i in ${SOURCES}; do install -D -m 0644 $$i ${PERLDIR}/PVE/CLI/$$i; done


