.PHONY: lint test test-sandbox

lint:
	ruff check .
	ruff format --check .

# Portable suites: no execution account or macOS sandbox needed.
test:
	python3 -B -m unittest discover -s tests -p test_dossier.py
	python3 -B -m unittest discover -s jobsearch/tests

# The pipeline's suites that build and test as the _arcexec account (macOS; see exec-user/README.md first).
SANDBOX_SUITES = test_pipeline test_build test_evaluate test_broker test_passkey
test-sandbox: test
	for s in $(SANDBOX_SUITES); do python3 -B -m unittest discover -s tests -p "$$s.py" || exit 1; done
