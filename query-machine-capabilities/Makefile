DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/libexec/qemu-server

CC ?= gcc
CFLAGS += -O2 -fanalyzer -Werror -Wall -Wextra -Wpedantic -Wtype-limits -Wl,-z,relro -std=gnu11

query-machine-capabilities: query-machine-capabilities.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: install
install: query-machine-capabilities
	install -d ${DESTDIR}/${BINDIR}
	install -m 0755 query-machine-capabilities ${DESTDIR}${BINDIR}

.PHONY: clean
clean:
	rm -f query-machine-capabilities
