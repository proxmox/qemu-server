PACKAGE ?= qemu-server

DESTDIR=
PREFIX=/usr
SBINDIR=$(PREFIX)/sbin
LIBDIR=$(PREFIX)/lib/$(PACKAGE)
MANDIR=$(PREFIX)/share/man
MAN1DIR=$(MANDIR)/man1/
MAN5DIR=$(MANDIR)/man5/
BASHCOMPLDIR=$(PREFIX)/share/bash-completion/completions/
ZSHCOMPLDIR=$(PREFIX)/share/zsh/vendor-completions/

PERL_DOC_INC_DIRS=..
-include /usr/share/pve-doc-generator/pve-doc-generator.mk

all:


qm.bash-completion:
	PVE_GENERATING_DOCS=1 perl -I.. -T -e "use PVE::CLI::qm; PVE::CLI::qm->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

qmrestore.bash-completion:
	PVE_GENERATING_DOCS=1 perl -I.. -T -e "use PVE::CLI::qmrestore; PVE::CLI::qmrestore->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

qm.zsh-completion:
	PVE_GENERATING_DOCS=1 perl -I.. -T -e "use PVE::CLI::qm; PVE::CLI::qm->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

qmrestore.zsh-completion:
	PVE_GENERATING_DOCS=1 perl -I.. -T -e "use PVE::CLI::qmrestore; PVE::CLI::qmrestore->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

PKGSOURCES=qm qm.1 qmrestore qmrestore.1 qmextract qm.conf.5 qm.bash-completion qmrestore.bash-completion \
	    qm.zsh-completion qmrestore.zsh-completion cpu-models.conf.5

.PHONY: install
install: $(PKGSOURCES)
	install -d $(DESTDIR)/$(SBINDIR)
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)/$(MAN1DIR)
	install -d $(DESTDIR)/$(MAN5DIR)
	install -d $(DESTDIR)/usr/share/$(PACKAGE)
	install -m 0644 -D qm.bash-completion $(DESTDIR)/$(BASHCOMPLDIR)/qm
	install -m 0644 -D qmrestore.bash-completion $(DESTDIR)/$(BASHCOMPLDIR)/qmrestore
	install -m 0644 -D qm.zsh-completion $(DESTDIR)/$(ZSHCOMPLDIR)/_qm
	install -m 0644 -D qmrestore.zsh-completion $(DESTDIR)/$(ZSHCOMPLDIR)/_qmrestore
	install -m 0755 qm $(DESTDIR)$(SBINDIR)
	install -m 0755 qmrestore $(DESTDIR)$(SBINDIR)
	install -m 0755 qmextract $(DESTDIR)$(LIBDIR)
	install -m 0644 qm.1 $(DESTDIR)/$(MAN1DIR)
	install -m 0644 qmrestore.1 $(DESTDIR)/$(MAN1DIR)
	install -m 0644 cpu-models.conf.5 $(DESTDIR)/$(MAN5DIR)
	install -m 0644 qm.conf.5 $(DESTDIR)/$(MAN5DIR)
	cd $(DESTDIR)/$(MAN5DIR); ln -s -f qm.conf.5.gz vm.conf.5.gz

.PHONY: test
test:
	PVE_GENERATING_DOCS=1 perl -I.. ./qm verifyapi

.PHONY: clean
clean:
	rm -f *.xml.tmp *.1 *.5 *.8 *{synopsis,opts}.adoc docinfo.xml

.PHONY: distclean
distclean: clean
