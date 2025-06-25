DESTDIR=
PREFIX=/usr
PERLDIR=$(PREFIX)/share/perl5

SOURCES=Agent.pm	\
	Blockdev.pm	\
	BlockJob.pm	\
	CGroup.pm	\
	Cloudinit.pm	\
	CPUConfig.pm	\
	Drive.pm	\
	Helpers.pm	\
	ImportDisk.pm	\
	Machine.pm	\
	Memory.pm	\
	MetaInfo.pm	\
	Monitor.pm	\
	Network.pm	\
	OVMF.pm		\
	PCI.pm		\
	QemuImage.pm	\
	QMPHelpers.pm	\
	RNG.pm		\
	RunState.pm	\
	StateFile.pm	\
	USB.pm		\
	Virtiofs.pm

.PHONY: install
install: $(SOURCES)
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/QemuServer/$$i; done
