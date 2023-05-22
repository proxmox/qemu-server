all: test

test: test_snapshot test_ovf test_cfg_to_cmd test_pci_addr_conflicts test_qemu_img_convert test_migration test_restore_config

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl
	./test_get_replicatable_volumes.pl

test_ovf: run_ovf_tests.pl
	./run_ovf_tests.pl

test_cfg_to_cmd: run_config2command_tests.pl cfg2cmd/*.conf
	perl -I../ ./run_config2command_tests.pl

test_qemu_img_convert: run_qemu_img_convert_tests.pl
	perl -I../ ./run_qemu_img_convert_tests.pl

test_pci_addr_conflicts: run_pci_addr_checks.pl
	./run_pci_addr_checks.pl

MIGRATION_TEST_TARGETS := $(addprefix test_migration_,$(shell perl -ne 'print "$$1 " if /^\s*name\s*=>\s*["'\'']([^\s"'\'']+)["'\'']\s*,\s*$$/; END { print "\n" }' run_qemu_migrate_tests.pl))

test_migration: run_qemu_migrate_tests.pl MigrationTest/*.pm $(MIGRATION_TEST_TARGETS)

$(MIGRATION_TEST_TARGETS):
	./run_qemu_migrate_tests.pl $(@:test_migration_%=%)

test_restore_config: run_qemu_restore_config_tests.pl
	./run_qemu_restore_config_tests.pl

.PHONY: clean
clean:
	rm -rf MigrationTest/run
