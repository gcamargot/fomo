.PHONY: test lint test-integration forge-sim

test:
	pytest -q

lint:
	ruff check .

test-integration:
	pytest -q -m integration

forge-sim:
	cd simulations && forge test -v
