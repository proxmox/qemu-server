all: test

test: test_snapshot test_ovf test_cfg_to_cmd test_pci_addr_conflicts

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl
	./test_get_replicatable_volumes.pl

test_ovf: run_ovf_tests.pl
	./run_ovf_tests.pl

test_cfg_to_cmd: run_config2command_tests.pl cfg2cmd/*.conf
	perl -I../ ./run_config2command_tests.pl

test_pci_addr_conflicts: run_pci_addr_checks.pl
	./run_pci_addr_checks.pl
