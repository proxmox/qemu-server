include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=qemu-server

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
LIBDIR=${PREFIX}/lib/${PACKAGE}
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
MAN1DIR=${MANDIR}/man1/
MAN5DIR=${MANDIR}/man5/
MAN8DIR=${MANDIR}/man8/
BASHCOMPLDIR=${PREFIX}/share/bash-completion/completions/
ZSHCOMPLDIR=${PREFIX}/share/zsh/vendor-completions/
export PERLDIR=${PREFIX}/share/perl5
PERLINCDIR=${PERLDIR}/asm-x86_64

GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_${DEB_BUILD_ARCH}.deb
DBG_DEB=${PACKAGE}-dbgsym_${DEB_VERSION_UPSTREAM_REVISION}_${DEB_BUILD_ARCH}.deb

DEBS=${DEB} ${DBG_DEB}

# this requires package pve-doc-generator
export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

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

qm.zsh-completion:
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::qm; PVE::CLI::qm->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

qmrestore.zsh-completion:
	PVE_GENERATING_DOCS=1 perl -I. -T -e "use PVE::CLI::qmrestore; PVE::CLI::qmrestore->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

PKGSOURCES=qm qm.1 qmrestore qmrestore.1 qmextract qm.conf.5 qm.bash-completion qmrestore.bash-completion \
	    qm.zsh-completion qmrestore.zsh-completion

.PHONY: install
install: ${PKGSOURCES}
	install -d ${DESTDIR}/${SBINDIR}
	install -d ${DESTDIR}${LIBDIR}
	install -d ${DESTDIR}/${MAN1DIR}
	install -d ${DESTDIR}/${MAN5DIR}
	install -d ${DESTDIR}/${MAN8DIR}
	install -d ${DESTDIR}/usr/share/man/man5
	install -d ${DESTDIR}/usr/share/${PACKAGE}
	install -m 0644 -D qm.bash-completion ${DESTDIR}/${BASHCOMPLDIR}/qm
	install -m 0644 -D qmrestore.bash-completion ${DESTDIR}/${BASHCOMPLDIR}/qmrestore
	install -m 0644 -D qm.zsh-completion ${DESTDIR}/${ZSHCOMPLDIR}/_qm
	install -m 0644 -D qmrestore.zsh-completion ${DESTDIR}/${ZSHCOMPLDIR}/_qmrestore
	install -m 0644 -D bootsplash.jpg ${DESTDIR}/usr/share/${PACKAGE}
	$(MAKE) -C PVE install
	$(MAKE) -C qmeventd install
	$(MAKE) -C qemu-configs install
	$(MAKE) -C vm-network-scripts install
	install -m 0755 qm ${DESTDIR}${SBINDIR}
	install -m 0755 qmrestore ${DESTDIR}${SBINDIR}
	install -D -m 0644 modules-load.conf ${DESTDIR}/etc/modules-load.d/qemu-server.conf
	install -m 0755 qmextract ${DESTDIR}${LIBDIR}
	install -m 0644 qm.1 ${DESTDIR}/${MAN1DIR}
	install -m 0644 qmrestore.1 ${DESTDIR}/${MAN1DIR}
	install -m 0644 qm.conf.5 ${DESTDIR}/${MAN5DIR}
	cd ${DESTDIR}/${MAN5DIR}; ln -s -f qm.conf.5.gz vm.conf.5.gz

.PHONY: deb
deb: ${DEBS}
${DBG_DEB}: ${DEB}
${DEB}:
	rm -rf build
	rsync -a * build
	echo "git clone git://git.proxmox.com/git/qemu-server.git\\ngit checkout ${GITVERSION}" > build/debian/SOURCE
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEBS}

.PHONY: test
test:
	PVE_GENERATING_DOCS=1 perl -I. ./qm verifyapi
	$(MAKE) -C test

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEBS} | ssh repoman@repo.proxmox.com upload --product pve --dist buster

.PHONY: clean
clean:
	$(MAKE) cleanup-docgen
	rm -rf build *.deb *.buildinfo *.changes
	find . -name '*~' -exec rm {} ';'


.PHONY: distclean
distclean: clean
