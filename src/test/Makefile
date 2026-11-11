all: test

test: test_snapshot test_cfg_to_cmd test_cfg_to_cmd_aarch64 test_hotplug test_hotplug_aarch64 test_pci_addr_conflicts test_pci_reservation test_qemu_img_convert test_migration test_restore_config test_parse_config test_memory test_agent test_raw_config_write test_api test_api_cloudinit_dump test_mtunnel test_guest_identity

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl
	./test_get_replicatable_volumes.pl
	./test_vmstate_storage.pl

test_cfg_to_cmd: run_config2command_tests.pl QemuServerTest/*.pm cfg2cmd/*.conf
	perl -I../ ./run_config2command_tests.pl

test_cfg_to_cmd_aarch64: run_config2command_tests.pl QemuServerTest/*.pm cfg2cmd/aarch64/*.conf
	perl -I../ ./run_config2command_tests.pl cfg2cmd/aarch64

test_hotplug: run_hotplug_tests.pl QemuServerTest/*.pm hotplug/*.conf
	perl -I../ ./run_hotplug_tests.pl

test_hotplug_aarch64: run_hotplug_tests.pl QemuServerTest/*.pm hotplug/aarch64/*.conf
	perl -I../ ./run_hotplug_tests.pl hotplug/aarch64

test_qemu_img_convert: run_qemu_img_convert_tests.pl
	perl -I../ ./run_qemu_img_convert_tests.pl

test_pci_addr_conflicts: run_pci_addr_checks.pl
	./run_pci_addr_checks.pl

test_pci_reservation: run_pci_reservation_tests.pl
	./run_pci_reservation_tests.pl

MIGRATION_TEST_TARGETS := $(addprefix test_migration_,$(shell perl -ne 'print "$$1 " if /^\s*name\s*=>\s*["'\'']([^\s"'\'']+)["'\'']\s*,\s*$$/; END { print "\n" }' run_qemu_migrate_tests.pl))

test_migration: run_qemu_migrate_tests.pl MigrationTest/*.pm $(MIGRATION_TEST_TARGETS)

$(MIGRATION_TEST_TARGETS):
	./run_qemu_migrate_tests.pl $(@:test_migration_%=%)

test_restore_config: run_qemu_restore_config_tests.pl run_qemu_restore_permission_tests.pl
	./run_qemu_restore_config_tests.pl
	./run_qemu_restore_permission_tests.pl

test_parse_config: run_parse_config_tests.pl QemuServerTest/Utils.pm
	./run_parse_config_tests.pl

test_memory: run_memory_tests.pl
	./run_memory_tests.pl

test_agent: run_agent_tests.pl
	./run_agent_tests.pl

test_raw_config_write: run_raw_config_write_tests.pl
	./run_raw_config_write_tests.pl

test_api: run_api_tests.pl
	./run_api_tests.pl

test_api_cloudinit_dump: run_api_cloudinit_dump_tests.pl
	./run_api_cloudinit_dump_tests.pl

test_mtunnel: run_mtunnel_tests.pl QemuServerTest/FakeCFS.pm QemuServerTest/MTunnel.pm
	./run_mtunnel_tests.pl

test_guest_identity: run_guest_identity_tests.pl QemuServerTest/FakeCFS.pm
	./run_guest_identity_tests.pl

.PHONY: clean
clean:
	rm -rf MigrationTest/run
