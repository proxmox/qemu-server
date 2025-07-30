all:

.PHONY: install
install:
	$(MAKE) -C PVE install
	$(MAKE) -C bin install
	$(MAKE) -C qmeventd install
	$(MAKE) -C query-machine-capabilities install
	$(MAKE) -C dbus-vmstate install
	$(MAKE) -C usr install

.PHONY: test
test:
	$(MAKE) -C test
	$(MAKE) -C bin $@

.PHONY: clean
clean:
	$(MAKE) -C test $@
	$(MAKE) -C bin $@

.PHONY: distclean
distclean: clean
