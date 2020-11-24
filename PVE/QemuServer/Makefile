SOURCES=PCI.pm		\
	USB.pm		\
	Memory.pm	\
	ImportDisk.pm	\
	OVF.pm		\
	Cloudinit.pm	\
	Agent.pm	\
	Helpers.pm	\
	Monitor.pm	\
	Machine.pm	\
	CPUConfig.pm	\
	CGroup.pm	\
	Drive.pm	\

.PHONY: install
install: ${SOURCES}
	for i in ${SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/QemuServer/$$i; done
