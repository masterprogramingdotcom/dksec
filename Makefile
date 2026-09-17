# ==============================================================================
# DKSec - Unified Enterprise Product Security Lifecycle Platform
# Makefile for Easy Setup, Testing, and Pipeline Execution
# ==============================================================================

PYTHON ?= python3
PIP    ?= pip3
PORT   ?= 8080
TARGET ?= samples/app
OUTPUT ?= reports/run
PRESET ?= full
PROJECT ?= "DKSec Security Review"

# Terminal Colors
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
BOLD   := \033[1m
RESET  := \033[0m

.PHONY: help setup venv install quickstart demo wizard ui live-scan scan pr-check test clean docker-build docker-run

# ------------------------------------------------------------------------------
# 1. Help Menu (Default)
# ------------------------------------------------------------------------------
help:
	@echo ""
	@echo "$(CYAN)$(BOLD)  ____  _  ______           $(RESET)"
	@echo "$(CYAN)$(BOLD) |  _ \| |/ / ___|          $(RESET)"
	@echo "$(CYAN)$(BOLD) | | | | ' /| (___   ___  ___ $(RESET)"
	@echo "$(CYAN)$(BOLD) | | | |  <  \___ \ / _ \/ __|$(RESET)"
	@echo "$(CYAN)$(BOLD) | |_| | . \ ____) |  __/ (__ $(RESET)"
	@echo "$(CYAN)$(BOLD) |____/|_|\_\_____/ \___|\___|$(RESET)"
	@echo "$(BOLD) Unified Enterprise Product Security Lifecycle Platform$(RESET)"
	@echo ""
	@echo "$(BOLD)⚡ QUICK START COMMANDS:$(RESET)"
	@echo "  $(GREEN)make setup$(RESET)        Install all dependencies & configure DKSec locally"
	@echo "  $(GREEN)make quickstart$(RESET)   Run one-click complete 9-stage demo and view reports"
	@echo "  $(GREEN)make wizard$(RESET)       Launch interactive step-by-step terminal audit wizard"
	@echo "  $(GREEN)make ui$(RESET)           Start the interactive Web GUI dashboard on http://127.0.0.1:8080"
	@echo "  $(GREEN)make live-scan$(RESET)    Run live authenticated scan against sample microservice"
	@echo ""
	@echo "$(BOLD)🔧 AUDIT & CI/CD COMMANDS:$(RESET)"
	@echo "  $(YELLOW)make scan$(RESET)         Run scan on TARGET (e.g. make scan TARGET=./my-app PRESET=full)"
	@echo "  $(YELLOW)make pr-check$(RESET)     Run fast pull request gate (Stages 1, 3, 8 with --fail-on-gate)"
	@echo "  $(YELLOW)make test$(RESET)         Execute automated 20-test unit and integration test suite"
	@echo ""
	@echo "$(BOLD)🐳 DOCKER & MAINTENANCE:$(RESET)"
	@echo "  $(CYAN)make docker-build$(RESET) Build minimal DKSec Docker image"
	@echo "  $(CYAN)make docker-run$(RESET)   Run DKSec Web Dashboard in Docker container"
	@echo "  $(CYAN)make clean$(RESET)        Remove temporary reports, test caches, and build artifacts"
	@echo ""

# ------------------------------------------------------------------------------
# 2. Easy Setup & Virtual Environment
# ------------------------------------------------------------------------------
setup: install
	@chmod +x dksec-cli dksec.py dksec_cli.py
	@echo ""
	@echo "$(GREEN)$(BOLD)✔ DKSec setup successfully completed!$(RESET)"
	@echo "  You can now run:"
	@echo "    • $(CYAN)./dksec-cli wizard$(RESET)     (Interactive terminal wizard)"
	@echo "    • $(CYAN)make ui$(RESET)                 (Browser GUI on http://127.0.0.1:8080)"
	@echo "    • $(CYAN)make demo$(RESET)               (One-click sample audit)"
	@echo ""

install:
	@echo "$(BOLD)Installing DKSec dependencies...$(RESET)"
	@$(PIP) install -r requirements.txt || $(PYTHON) -m pip install -r requirements.txt || true
	@$(PIP) install -e . || $(PYTHON) -m pip install -e . || true

venv:
	@echo "$(BOLD)Setting up Python virtual environment in .venv...$(RESET)"
	@$(PYTHON) -m venv .venv
	@.venv/bin/pip install --upgrade pip
	@.venv/bin/pip install -r requirements.txt
	@.venv/bin/pip install -e .
	@echo "$(GREEN)✔ Virtual environment created. Activate with: source .venv/bin/activate$(RESET)"

# ------------------------------------------------------------------------------
# 3. Workflows & Execution
# ------------------------------------------------------------------------------
quickstart: demo

demo:
	@./dksec-cli demo

wizard:
	@./dksec-cli wizard

ui:
	@echo "$(GREEN)$(BOLD)Starting DKSec Web Dashboard on port $(PORT)...$(RESET)"
	@./dksec-cli ui --port $(PORT)

dashboard: ui

live-scan:
	@echo "$(BOLD)Starting sample fintech microservice in background...$(RESET)"
	@$(PYTHON) samples/app/server.py & SERVER_PID=$$!; \
	sleep 1; \
	echo "$(GREEN)✔ Service online. Launching authenticated DKSec audit...$(RESET)"; \
	./dksec-cli scan \
		-p "Live Authenticated Scan" \
		-t samples/app \
		-u http://127.0.0.1:5000 \
		--login-url http://127.0.0.1:5000/api/v1/login \
		--username admin \
		--password AdminSecretPassword99! \
		-o reports/live_scan; \
	kill $$SERVER_PID 2>/dev/null || true
	@echo "$(GREEN)$(BOLD)✔ Live authenticated audit complete! View: reports/live_scan/dksec-report.html$(RESET)"

scan:
	@./dksec-cli scan -p $(PROJECT) -t $(TARGET) --preset $(PRESET) -o $(OUTPUT)

pr-check:
	@echo "$(BOLD)Executing Fast Pull Request Security Gate (Stages 1, 3, 8)...$(RESET)"
	@./dksec-cli scan -t $(TARGET) --preset pr --fail-on-gate -o reports/pr_gate

# ------------------------------------------------------------------------------
# 4. Testing & Quality Assurance
# ------------------------------------------------------------------------------
test:
	@echo "$(BOLD)Running DKSec Automated Test Suite...$(RESET)"
	@$(PYTHON) -m unittest discover tests

# ------------------------------------------------------------------------------
# 5. Docker Containers
# ------------------------------------------------------------------------------
docker-build:
	@docker build -t dksec:latest .

docker-run:
	@echo "$(GREEN)Running DKSec Web Dashboard in Docker on http://127.0.0.1:8080...$(RESET)"
	@docker run --rm -p 8080:8080 -v $$(pwd)/reports:/app/reports dksec:latest ui --host 0.0.0.0 --port 8080

# ------------------------------------------------------------------------------
# 6. Housekeeping & Cleanup
# ------------------------------------------------------------------------------
clean:
	@echo "$(YELLOW)Cleaning temporary test reports, cache files, and builds...$(RESET)"
	@rm -rf reports/run reports/live_scan reports/cli_test reports/live_auth_test reports/pr_gate reports/web_audit
	@rm -rf __pycache__ dksec/__pycache__ dksec/*/__pycache__ tests/__pycache__ samples/*/__pycache__
	@rm -rf *.egg-info build dist .pytest_cache
	@echo "$(GREEN)✔ Cleanup complete.$(RESET)"
