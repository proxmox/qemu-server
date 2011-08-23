RELEASE=2.0

VERSION=2.0
PACKAGE=qemu-server
PKGREL=1

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
BINDIR=${PREFIX}/bin
LIBDIR=${PREFIX}/lib/${PACKAGE}
VARLIBDIR=/var/lib/${PACKAGE}
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
PODDIR=${PREFIX}/share/doc/${PACKAGE}/pod
MAN1DIR=${MANDIR}/man1/
export PERLDIR=${PREFIX}/share/perl5
PERLINCDIR=${PERLDIR}/asm-x86_64

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

CDATE:=$(shell date +%F)
SNAP=${PACKAGE}-${VERSION}-${CDATE}.tar.gz

all: ${DEB}

.PHONY: dinstall
dinstall: deb
	dpkg -i ${DEB}

control: control.in
	sed -e s/@@VERSION@@/${VERSION}/ -e s/@@PKGRELEASE@@/${PKGREL}/ -e s/@@ARCH@@/${ARCH}/<$< >$@


vzsyscalls.ph: vzsyscalls.h
	 h2ph -d . vzsyscalls.h

vmtar: vmtar.c utils.c
	gcc -O2 -Wall -o vmtar vmtar.c

sparsecp: sparsecp.c utils.c
	gcc -O2 -Wall -o sparsecp sparsecp.c

%.1.gz: %.1.pod
	rm -f $@
	cat $<|pod2man -n $* -s 1 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

%.5.gz: %.5.pod
	rm -f $@
	cat $<|pod2man -n $* -s 5 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

%.1.pod: %
	podselect $*>$@

qm.1.pod: qm PVE/QemuServer.pm
	perl -I. ./qm printmanpod >$@

vm.conf.5.pod: gen-vmconf-pod.pl PVE/QemuServer.pm 
	perl -I. ./gen-vmconf-pod.pl >$@

PKGSOURCES=qm qm.1.gz qm.1.pod qmigrate qmigrate.1.gz qmrestore qmrestore.1.gz sparsecp vmtar qemu.init.d qmupdate control vm.conf.5.pod vm.conf.5.gz

.PHONY: install
install: ${PKGSOURCES}
	install -d ${DESTDIR}/${SBINDIR}
	install -d ${DESTDIR}/etc/${PACKAGE}
	install -d ${DESTDIR}${LIBDIR}
	install -d ${DESTDIR}${VARLIBDIR}
	install -d ${DESTDIR}${PODDIR}
	install -d ${DESTDIR}/usr/share/man/man1
	install -d ${DESTDIR}/usr/share/man/man5
	install -d ${DESTDIR}/usr/share/${PACKAGE}
	install -m 0644 pve-usb.cfg ${DESTDIR}/usr/share/${PACKAGE}
	make -C PVE install
	install -m 0755 qm ${DESTDIR}${SBINDIR}
	install -m 0755 qmigrate ${DESTDIR}${SBINDIR}
	install -m 0755 qmrestore ${DESTDIR}${SBINDIR}
	install -D -m 0755 qmupdate ${DESTDIR}${VARLIBDIR}/qmupdate
	install -D -m 0755 qemu.init.d ${DESTDIR}/etc/init.d/${PACKAGE}
	install -m 0755 pve-bridge ${DESTDIR}${VARLIBDIR}/pve-bridge
	install -s -m 0755 vmtar ${DESTDIR}${LIBDIR}
	install -s -m 0755 sparsecp ${DESTDIR}${LIBDIR}
#	pod2man -n qemu-server -s 1 -r "proxmox 1.0" -c "Proxmox Documentation" <qemu-server.pod | gzip -9 > ${DESTDIR}/usr/share/man/man1/qemu-server.1.gz
	install -m 0644 qm.1.gz ${DESTDIR}/usr/share/man/man1/
	install -m 0644 qm.1.pod ${DESTDIR}/${PODDIR}
	install -m 0644 qmigrate.1.gz ${DESTDIR}/usr/share/man/man1/
	install -m 0644 qmrestore.1.gz ${DESTDIR}/usr/share/man/man1/
	install -m 0644 vm.conf.5.pod ${DESTDIR}/${PODDIR}
	install -m 0644 vm.conf.5.gz ${DESTDIR}/usr/share/man/man5/

.PHONY: deb ${DEB}
deb ${DEB}: ${PKGSOURCES}
	rm -rf debian
	mkdir debian
	make DESTDIR=${CURDIR}/debian install
	perl -I. ./qm verifyapi
	install -d -m 0755 debian/DEBIAN
	install -m 0644 control debian/DEBIAN
	install -m 0755 postinst debian/DEBIAN
	install -m 0755 postrm debian/DEBIAN
	echo "/etc/init.d/${PACKAGE}" >>debian/DEBIAN/conffiles
	install -D -m 0644 copyright debian/${DOCDIR}/${PACKAGE}/copyright
	install -m 0644 changelog.Debian debian/${DOCDIR}/${PACKAGE}/
	gzip -9 debian/${DOCDIR}/${PACKAGE}/changelog.Debian
	dpkg-deb --build debian	
	mv debian.deb ${DEB}
	rm -rf debian
	-lintian ${DEB}

.PHONY: upload
upload:
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o rw 
	mkdir -p /pve/${RELEASE}/extra
	rm -rf /pve/${RELEASE}/extra/${PACKAGE}_*.deb
	rm -rf /pve/${RELEASE}/extra/Packages*
	cp ${DEB} /pve/${RELEASE}/extra
	cd /pve/${RELEASE}/extra; dpkg-scanpackages . /dev/null > Packages; gzip -9c Packages > Packages.gz
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o ro

.PHONY: clean
clean: 	
	rm -rf debian *.deb qm.1.gz control vzsyscalls.ph _h2ph_pre.ph ${PACKAGE}-*.tar.gz dist *.1,gz *.pod
	find . -name '*~' -exec rm {} ';'


.PHONY: distclean
distclean: clean

.PHONY: dist
${SNAP} dist: distclean
	rm -rf ${SNAP} dist/qemu-server
	mkdir -p dist/${PACKAGE}
	svn co svn://proxdev/server/svn/qemu-server/trunc dist/${PACKAGE}
	tar cvzf ${SNAP} -C dist --exclude .svn ${PACKAGE}
	rm -rf dist

.PHONY:
uploaddist: ${SNAP}
	scp ${SNAP} pve.proxmox.com:/home/ftp/sources/
