all: test

test: test_snapshot test_ovf

test_snapshot: run_snapshot_tests.pl
	./run_snapshot_tests.pl
	./test_get_replicatable_volumes.pl

test_ovf: run_ovf_tests.pl
	./run_ovf_tests.pl
