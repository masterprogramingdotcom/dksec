.PHONY: help install scan selective ui test clean

PYTHON ?= python3

help:
	@echo "OmniSec - Unified Product Security Lifecycle Suite"
	@echo "Available commands:"
	@echo "  make install    Install OmniSec locally"
	@echo "  make scan       Run full 9-stage audit on sample app"
	@echo "  make selective  Run selective stages (1, 3, 8)"
	@echo "  make ui         Start interactive Web Dashboard on port 8080"
	@echo "  make test       Run automated test suite"
	@echo "  make clean      Remove generated reports and caches"

install:
	$(PYTHON) -m pip install -e .

scan:
	./omnisec_cli.py scan -p "Fintech Core Demo" -t samples/app -o reports/demo

selective:
	./omnisec_cli.py scan -p "Fintech Selective" -t samples/app -s 1,3,8 -o reports/selective

ui:
	./omnisec_cli.py ui --port 8080

test:
	$(PYTHON) -m unittest discover tests

clean:
	rm -rf reports __pycache__ omnisec/__pycache__ omnisec/*/__pycache__ *.egg-info
