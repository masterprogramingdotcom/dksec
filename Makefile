.PHONY: help install demo scan pr-check ui test clean

PYTHON ?= python3

help:
	@echo "DKSec - Enterprise Product Security Lifecycle Platform"
	@echo "Available commands:"
	@echo "  make install   Install DKSec locally in editable mode"
	@echo "  make demo      Run one-click complete 9-stage demo audit"
	@echo "  make scan      Run full scan on sample app"
	@echo "  make pr-check  Run fast PR gate (Stages 1, 3, 8)"
	@echo "  make ui        Launch interactive Web GUI dashboard on port 8080"
	@echo "  make test      Run automated unit & integration test suite"
	@echo "  make clean     Remove temporary reports and Python caches"

install:
	$(PYTHON) -m pip install -e .

demo:
	./dksec-cli demo

scan:
	./dksec-cli scan -p "DKSec Demo Audit" -t samples/app -o reports/demo

pr-check:
	./dksec-cli scan -t samples/app --preset pr -o reports/pr_gate

ui:
	./dksec-cli ui --port 8080

test:
	$(PYTHON) -m unittest discover tests

clean:
	rm -rf reports __pycache__ dksec/__pycache__ dksec/*/__pycache__ tests/__pycache__ *.egg-info
