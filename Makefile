SHELL := env PATH=$(PATH) /bin/bash
PIP := pip3
PYTHON := python3
APPLICATION := attestation
APPLICATION_FOLDER := ./application/$(APPLICATION)
OUTFILE := e2e_outfile.json

# Run all unit tests enclosed in application
unit_test:
	source .venv/bin/activate && pytest -o log_cli=true ${APPLICATION_FOLDER}/enclave/tests

# Run all e2e test cases
integration_tests:
	source .venv/bin/activate && $(APPLICATION_FOLDER)/tests/integration/run_e2e_test.sh $(OUTFILE)

# create virtual env
venv:
	rm -rf .venv
	$(PYTHON) -m venv .venv
	source .venv/bin/activate;\
		$(PIP) install --upgrade pip
		$(PIP) install -r requirements.txt;\
		$(PIP)  install -r requirements-test.txt
	@echo "Activate the virtual env: source .venv/bin/activate"
	@echo "Deactivate when done: deactivate"


 # Auto-format to pep8
format:
	source .venv/bin/activate && $(PYTHON) -m black $(APPLICATION_FOLDER)
	source .venv/bin/activate && $(PYTHON) -m isort $(APPLICATION_FOLDER)


lint:
	source .venv/bin/activate && $(PYTHON) -m flake8 $(APPLICATION_FOLDER) --config $(APPLICATION_FOLDER)/.flake8
	source .venv/bin/activate && $(PYTHON) -m bandit -r $(APPLICATION_FOLDER)/enclave $(APPLICATION_FOLDER)/scripts $(APPLICATION_FOLDER)/watchdog -c application/attestation/bandit.yaml
