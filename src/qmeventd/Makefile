DESTDIR=
PREFIX=/usr
SBINDIR=$(PREFIX)/sbin
SERVICEDIR=$(PREFIX)/lib/systemd/system
MANDIR=$(PREFIX)/share/man

-include /usr/share/pve-doc-generator/pve-doc-generator.mk

CC ?= gcc
CFLAGS += -O2 -Werror -Wall -Wextra -Wpedantic -Wtype-limits -Wl,-z,relro -std=gnu11
CFLAGS += $(shell pkgconf --cflags json-c glib-2.0)
LDFLAGS += $(shell pkgconf --libs json-c glib-2.0)

qmeventd: qmeventd.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

docs: qmeventd.8

.PHONY: install
install: qmeventd docs
	install -d $(DESTDIR)/$(SBINDIR)
	install -m 0755 qmeventd $(DESTDIR)/$(SBINDIR)
	install -d $(DESTDIR)/$(SERVICEDIR)
	install -m 0644 qmeventd.service $(DESTDIR)/$(SERVICEDIR)
	install -d $(DESTDIR)/$(MANDIR)/man8
	install -m 0644 qmeventd.8 $(DESTDIR)/$(MANDIR)/man8

.PHONY: clean
clean:
	$(MAKE) cleanup-docgen
	rm -rf qmeventd
