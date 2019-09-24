DESTDIR=
PREFIX=/usr
SBINDIR=${PREFIX}/sbin
SERVICEDIR=/lib/systemd/system
MANDIR=${PREFIX}/share/man

export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

CC ?= gcc
CFLAGS += -O2 -Werror -Wall -Wextra -Wpedantic -Wtype-limits -Wl,-z,relro -std=gnu11
CFLAGS += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs json-c)

qmeventd: qmeventd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

docs: qmeventd.8

.PHONY: install
install: qmeventd docs
	install -d ${DESTDIR}/${SBINDIR}
	install -d ${DESTDIR}${SERVICEDIR}
	install -m 0644 qmeventd.service ${DESTDIR}${SERVICEDIR}
	install -m 0755 qmeventd ${DESTDIR}${SBINDIR}
	install -m 0644 qmeventd.8 ${DESTDIR}/${MANDIR}/man8

.PHONY: clean
clean:
	$(MAKE) cleanup-docgen
	rm -rf qmeventd
