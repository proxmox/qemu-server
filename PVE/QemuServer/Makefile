SOURCES=PCI.pm		\
	RNG.pm		\
	USB.pm		\
	Memory.pm	\
	ImportDisk.pm	\
	Cloudinit.pm	\
	Agent.pm	\
	Helpers.pm	\
	Monitor.pm	\
	Machine.pm	\
	MetaInfo.pm	\
	CPUConfig.pm	\
	CGroup.pm	\
	Drive.pm	\
	QMPHelpers.pm

.PHONY: install
install: ${SOURCES}
	for i in ${SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/QemuServer/$$i; done
