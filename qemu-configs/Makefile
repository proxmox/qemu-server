DESTDIR=
USRSHAREDIR=$(DESTDIR)/usr/share/qemu-server

.PHONY: install
install: pve-usb.cfg pve-q35.cfg pve-q35-4.0.cfg
	install -d $(USRSHAREDIR)
	install -m 0644 pve-usb.cfg $(USRSHAREDIR)
	install -m 0644 pve-q35.cfg $(USRSHAREDIR)
	install -m 0644 pve-q35-4.0.cfg $(USRSHAREDIR)

.PHONY: clean
clean:
