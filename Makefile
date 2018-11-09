VERSION=5.0
PACKAGE=qemu-server
PKGREL=39

CFLAGS= -O2 -Werror -Wall -Wtype-limits -Wl,-z,relro 

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
BINDIR=${PREFIX}/bin
LIBDIR=${PREFIX}/lib/${PACKAGE}
VARLIBDIR=/var/lib/${PACKAGE}
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
MAN1DIR=${MANDIR}/man1/
MAN5DIR=${MANDIR}/man5/
BASHCOMPLDIR=${PREFIX}/share/bash-completion/completions/
export PERLDIR=${PREFIX}/share/perl5
PERLINCDIR=${PERLDIR}/asm-x86_64

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

# this requires package pve-doc-generator
export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

export SOURCE_DATE_EPOCH ?= $(shell dpkg-parsechangelog -STimestamp)

all:

.PHONY: dinstall
dinstall: deb
	dpkg -i ${DEB}

qm.bash-completion:
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::qm; PVE::CLI::qm->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

qmrestore.bash-completion:
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::qmrestore; PVE::CLI::qmrestore->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

PKGSOURCES=qm qm.1 qmrestore qmrestore.1 qmextract qm.conf.5 qm.bash-completion qmrestore.bash-completion

.PHONY: install
install: ${PKGSOURCES}
	install -d ${DESTDIR}/${SBINDIR}
	install -d ${DESTDIR}${LIBDIR}
	install -d ${DESTDIR}${VARLIBDIR}
	install -d ${DESTDIR}/${MAN1DIR}
	install -d ${DESTDIR}/${MAN5DIR}
	install -d ${DESTDIR}/usr/share/man/man5
	install -d ${DESTDIR}/usr/share/${PACKAGE}
	install -m 0644 pve-usb.cfg ${DESTDIR}/usr/share/${PACKAGE}
	install -m 0644 pve-q35.cfg ${DESTDIR}/usr/share/${PACKAGE}
	install -m 0644 -D qm.bash-completion ${DESTDIR}/${BASHCOMPLDIR}/qm
	install -m 0644 -D qmrestore.bash-completion ${DESTDIR}/${BASHCOMPLDIR}/qmrestore
	install -m 0644 -D bootsplash.jpg ${DESTDIR}/usr/share/${PACKAGE}
	make -C PVE install
	install -m 0755 qm ${DESTDIR}${SBINDIR}
	install -m 0755 qmrestore ${DESTDIR}${SBINDIR}
	install -m 0755 pve-bridge ${DESTDIR}${VARLIBDIR}/pve-bridge
	install -m 0755 pve-bridge-hotplug ${DESTDIR}${VARLIBDIR}/pve-bridge-hotplug
	install -m 0755 pve-bridgedown ${DESTDIR}${VARLIBDIR}/pve-bridgedown
	install -D -m 0644 modules-load.conf ${DESTDIR}/etc/modules-load.d/qemu-server.conf
	install -m 0755 qmextract ${DESTDIR}${LIBDIR}
	install -m 0644 qm.1 ${DESTDIR}/${MAN1DIR}
	gzip -9 -n -f ${DESTDIR}/${MAN1DIR}/qm.1
	install -m 0644 qmrestore.1 ${DESTDIR}/${MAN1DIR}
	gzip -9 -n -f ${DESTDIR}/${MAN1DIR}/qmrestore.1
	install -m 0644 qm.conf.5 ${DESTDIR}/${MAN5DIR}
	gzip -9 -n -f ${DESTDIR}/${MAN5DIR}/qm.conf.5
	cd ${DESTDIR}/${MAN5DIR}; ln -s -f qm.conf.5.gz vm.conf.5.gz

.PHONY: deb
deb: ${DEB}
${DEB}:
	rm -rf build
	rsync -a * build
	echo "git clone git://git.proxmox.com/git/qemu-server.git\\ngit checkout ${GITVERSION}" > build/debian/SOURCE
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

.PHONY: test
test:
	PVE_GENERATING_DOCS=1 perl -I. ./qm verifyapi
	make -C test

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com upload --product pve --dist stretch

.PHONY: clean
clean:
	make cleanup-docgen
	rm -rf build *.deb *.buildinfo *.changes
	find . -name '*~' -exec rm {} ';'


.PHONY: distclean
distclean: clean
