.PHONY: install test smoke full clean

install:
	./install_termux.sh

test:
	./scripts/run_tests.sh

smoke:
	./scripts/run_smoke_tests.sh

full:
	./scripts/run_full_test_suite.sh

clean:
	rm -rf .pytest_cache .ruff_cache reports/junit reports/coverage reports/smoke
