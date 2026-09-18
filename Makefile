# ==============================================================================
# DKSec - Unified Enterprise Product Security Lifecycle Platform
# Makefile for Setup, Testing, Single/Multi-Stage Audits & CI/CD Pipelines
# ==============================================================================

PYTHON     ?= python3
PIP        ?= $(PYTHON) -m pip
PORT       ?= 8080
TARGET     ?= samples/app
URL        ?=
OUTPUT     ?= reports/run
PRESET     ?= full
STAGES     ?=
PROJECT    ?= "DKSec Security Review"
EXTRA_ARGS ?=

# Terminal Colors
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
BOLD   := \033[1m
RESET  := \033[0m

.PHONY: help setup venv install quickstart demo wizard ui dashboard live-scan \
        scan pr-check test clean docker-build docker-run \
        vapt pentest sast threat threat-model asvs dast wstg defectdojo dojo signoff scorecard wazuh siem \
        api-audit code-audit supply-chain

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
	@echo "  $(GREEN)make setup$(RESET)                 Install dependencies and configure DKSec locally"
	@echo "  $(GREEN)make quickstart$(RESET)            Run one-click 9-stage demo and view reports"
	@echo "  $(GREEN)make wizard$(RESET)                Launch interactive step-by-step terminal wizard"
	@echo "  $(GREEN)make ui$(RESET)                    Start Web GUI dashboard on http://127.0.0.1:8080"
	@echo "  $(GREEN)make live-scan$(RESET)             Run live authenticated scan against sample microservice"
	@echo ""
	@echo "$(BOLD)🎯 SINGLE-STAGE AUDITS (Run Specific Stage Only):$(RESET)"
	@echo "  $(YELLOW)make vapt$(RESET)                  [Stage 6] Penetration Test & Attack Surface Discovery"
	@echo "  $(YELLOW)make sast$(RESET)                  [Stage 3] Static Code Analysis, SCA & Secret Scanning"
	@echo "  $(YELLOW)make threat$(RESET)                [Stage 1] STRIDE Threat Model & OWASP Threat Dragon DFD"
	@echo "  $(YELLOW)make asvs$(RESET)                  [Stage 2] OWASP ASVS 4.0.3 Security Requirements & Verification"
	@echo "  $(YELLOW)make dast$(RESET)                  [Stage 4] Dynamic Application & API Security Fuzzing"
	@echo "  $(YELLOW)make wstg$(RESET)                  [Stage 5] OWASP Web Security Testing Guide (WSTG v4.2)"
	@echo "  $(YELLOW)make defectdojo$(RESET)            [Stage 7] DefectDojo Vulnerability Tracking & Retest Sync"
	@echo "  $(YELLOW)make signoff$(RESET)               [Stage 8] OpenSSF Scorecard & Cryptographic Release Gate"
	@echo "  $(YELLOW)make wazuh$(RESET)                 [Stage 9] Wazuh SIEM XML Rules & Sigma Detection Engine"
	@echo ""
	@echo "$(BOLD)🔀 MULTI-STAGE & CUSTOM PIPELINES:$(RESET)"
	@echo "  $(CYAN)make scan STAGES=sast,vapt$(RESET) Run custom combination of named stages"
	@echo "  $(CYAN)make scan STAGES=1,3,6$(RESET)     Run custom combination by stage IDs"
	@echo "  $(CYAN)make scan PRESET=pr$(RESET)        Run fast PR gate preset (Stages 1, 3, 8)"
	@echo "  $(CYAN)make scan PRESET=api$(RESET)       Run API/dynamic preset (Stages 4, 5, 6)"
	@echo "  $(CYAN)make code-audit$(RESET)            Combined Threat Model + SAST + Secrets (Stages 1, 3)"
	@echo "  $(CYAN)make api-audit$(RESET)             Combined Live DAST + WSTG + VAPT (Stages 4, 5, 6)"
	@echo "  $(CYAN)make supply-chain$(RESET)          Combined ASVS + CycloneDX SBOM + OpenSSF (Stages 2, 3, 8)"
	@echo ""
	@echo "$(BOLD)🔧 CUSTOMIZATION PARAMETERS:$(RESET)"
	@echo "  TARGET=<dir>              Target source code directory (default: samples/app)"
	@echo "  URL=<http://...>          Target live URL / API endpoint for DAST/VAPT"
	@echo "  OUTPUT=<dir>              Output directory for reports (default: reports/run)"
	@echo "  EXTRA_ARGS=\"<flags>\"      Additional CLI flags (e.g. EXTRA_ARGS=\"--llm --token abc\")"
	@echo ""
	@echo "$(BOLD)🧪 TESTING & CI/CD:$(RESET)"
	@echo "  $(GREEN)make test$(RESET)                  Run complete unit & integration test suite"
	@echo "  $(GREEN)make pr-check$(RESET)              Run fast PR gate with --fail-on-gate"
	@echo "  $(CYAN)make clean$(RESET)                 Clean temporary reports, cache files, and builds"
	@echo "  $(CYAN)make docker-build$(RESET)          Build minimal DKSec Docker image"
	@echo "  $(CYAN)make docker-run$(RESET)            Run DKSec Web Dashboard in Docker container"
	@echo ""

# ------------------------------------------------------------------------------
# 2. Setup & Virtual Environment
# ------------------------------------------------------------------------------
# OS detection
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
else
    DETECTED_OS := $(shell uname -s)
endif

setup:
	@echo "$(BOLD)Setting up DKSec for $(DETECTED_OS)...$(RESET)"
ifeq ($(DETECTED_OS),Linux)
	@echo "Detected Linux. Please ensure python3, python3-pip, and python3-venv are installed."
	@echo "If not, run: sudo apt-get install python3 python3-pip python3-venv"
	@$(MAKE) venv
else ifeq ($(DETECTED_OS),Darwin)
	@echo "Detected macOS. Please ensure python3 is installed via Homebrew (brew install python3)."
	@$(MAKE) venv
else ifeq ($(DETECTED_OS),Windows)
	@echo "Detected Windows. Setting up..."
	@python -m venv .venv
	@.venv\Scripts\pip install --upgrade pip
	@.venv\Scripts\pip install -r requirements.txt
	@.venv\Scripts\pip install -e .
	@echo "$(GREEN)✔ Windows setup complete. Activate with: .venv\Scripts\activate$(RESET)"
else
	@echo "Unknown OS. Attempting standard generic setup..."
	@$(MAKE) venv
endif
	@echo ""
	@echo "$(GREEN)$(BOLD)✔ DKSec setup successfully completed!$(RESET)"
	@echo "  Activate your environment:"
	@echo "    Linux/macOS: $(CYAN)source .venv/bin/activate$(RESET)"
	@echo "    Windows:     $(CYAN).venv\Scripts\activate$(RESET)"
	@echo "  You can now run:"
	@echo "    • $(CYAN)python3 dksec.py wizard$(RESET)     (Interactive terminal wizard)"
	@echo "    • $(CYAN)make ui$(RESET)                   (Browser GUI on http://127.0.0.1:8080)"
	@echo ""

install:
	@echo "$(BOLD)Installing DKSec dependencies...$(RESET)"
	@$(PYTHON) -m pip install -r requirements.txt || true
	@$(PYTHON) -m pip install -e . || true

venv:
	@echo "$(BOLD)Setting up Python virtual environment in .venv...$(RESET)"
	@$(PYTHON) -m venv .venv
	@.venv/bin/pip install --upgrade pip
	@.venv/bin/pip install -r requirements.txt
	@.venv/bin/pip install -e .
	@echo "$(GREEN)✔ Virtual environment created. Activate with: source .venv/bin/activate$(RESET)"
# ------------------------------------------------------------------------------
# 3. Interactive Tools & Demonstration
# ------------------------------------------------------------------------------
quickstart: demo

demo:
	@$(PYTHON) python3 dksec.py demo

wizard:
	@$(PYTHON) python3 dksec.py wizard

interactive: wizard

ui:
	@echo "$(GREEN)$(BOLD)Starting DKSec Web Dashboard on port $(PORT)...$(RESET)"
	@$(PYTHON) python3 dksec.py ui --port $(PORT)

dashboard: ui

live-scan:
	@echo "$(BOLD)Starting sample fintech microservice in background...$(RESET)"
	@$(PYTHON) samples/app/server.py & SERVER_PID=$$!; \
	sleep 1; \
	echo "$(GREEN)✔ Service online. Launching authenticated DKSec audit...$(RESET)"; \
	$(PYTHON) python3 dksec.py scan \
		-p "Live Authenticated Scan" \
		-t samples/app \
		-u http://127.0.0.1:5000 \
		--login-url http://127.0.0.1:5000/api/v1/login \
		--username admin \
		--password AdminSecretPassword99! \
		-o reports/live_scan; \
	kill $$SERVER_PID 2>/dev/null || true
	@echo "$(GREEN)$(BOLD)✔ Live authenticated audit complete! View: reports/live_scan/dksec-report.html$(RESET)"

# ------------------------------------------------------------------------------
# 4. Single-Stage Audit Targets
# ------------------------------------------------------------------------------
vapt pentest:
	@echo "$(BOLD)🎯 Executing Stage 6: Penetration Testing & Attack Surface Discovery...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		$$(if [ -n "$(URL)" ]; then echo "-u $(URL)"; fi) \
		-s vapt \
		-o $(OUTPUT) $(EXTRA_ARGS)

sast:
	@echo "$(BOLD)🔍 Executing Stage 3: SAST, SCA & Secret Scanning...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		-s sast \
		-o $(OUTPUT) $(EXTRA_ARGS)

threat threat-model:
	@echo "$(BOLD)📐 Executing Stage 1: Architecture & STRIDE Threat Modeling...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		-s threat \
		-o $(OUTPUT) $(EXTRA_ARGS)

asvs:
	@echo "$(BOLD)📋 Executing Stage 2: OWASP ASVS 4.0.3 Security Requirements & Verification...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		-s asvs \
		-o $(OUTPUT) $(EXTRA_ARGS)

dast:
	@echo "$(BOLD)⚡ Executing Stage 4: DAST & API Security Fuzzing...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		$$(if [ -n "$(URL)" ]; then echo "-u $(URL)"; fi) \
		-s dast \
		-o $(OUTPUT) $(EXTRA_ARGS)

wstg:
	@echo "$(BOLD)📑 Executing Stage 5: OWASP Web Security Testing Guide (WSTG v4.2)...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		$$(if [ -n "$(URL)" ]; then echo "-u $(URL)"; fi) \
		-s wstg \
		-o $(OUTPUT) $(EXTRA_ARGS)

defectdojo dojo:
	@echo "$(BOLD)🎯 Executing Stage 7: DefectDojo Vulnerability Tracking & Retest Sync...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		-s defectdojo \
		-o $(OUTPUT) $(EXTRA_ARGS)

signoff scorecard:
	@echo "$(BOLD)🛡️ Executing Stage 8: OpenSSF Scorecard & Cryptographic Release Gate...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		-s signoff \
		-o $(OUTPUT) $(EXTRA_ARGS)

wazuh siem:
	@echo "$(BOLD)🚨 Executing Stage 9: Wazuh SIEM XML Rules & Sigma Detection Engine...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		-s wazuh \
		-o $(OUTPUT) $(EXTRA_ARGS)

# ------------------------------------------------------------------------------
# 5. Multi-Stage Combinations & Workflows
# ------------------------------------------------------------------------------
scan:
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		$$(if [ -n "$(URL)" ]; then echo "-u $(URL)"; fi) \
		$$(if [ -n "$(STAGES)" ]; then echo "-s $(STAGES)"; else echo "--preset $(PRESET)"; fi) \
		-o $(OUTPUT) $(EXTRA_ARGS)

code-audit:
	@echo "$(BOLD)🔍 Running Code & Architecture Audit (Threat Model + SAST + Secrets)...$(RESET)"
	@$(PYTHON) python3 dksec.py scan -p $(PROJECT) -t $(TARGET) -s "1,3" -o $(OUTPUT) $(EXTRA_ARGS)

api-audit:
	@echo "$(BOLD)⚡ Running Dynamic Web & API Penetration Audit (DAST + WSTG + VAPT)...$(RESET)"
	@$(PYTHON) python3 dksec.py scan \
		-p $(PROJECT) \
		-t $(TARGET) \
		$$(if [ -n "$(URL)" ]; then echo "-u $(URL)"; fi) \
		-s "4,5,6" \
		-o $(OUTPUT) $(EXTRA_ARGS)

supply-chain:
	@echo "$(BOLD)📦 Running Supply Chain & Compliance Audit (ASVS + SBOM + OpenSSF)...$(RESET)"
	@$(PYTHON) python3 dksec.py scan -p $(PROJECT) -t $(TARGET) -s "2,3,8" -o $(OUTPUT) $(EXTRA_ARGS)

pr-check:
	@echo "$(BOLD)Executing Fast Pull Request Security Gate (Stages 1, 3, 8)...$(RESET)"
	@$(PYTHON) python3 dksec.py scan -t $(TARGET) --preset pr --fail-on-gate -o reports/pr_gate $(EXTRA_ARGS)

# ------------------------------------------------------------------------------
# 6. Testing & Quality Assurance
# ------------------------------------------------------------------------------
test:
	@echo "$(BOLD)Running DKSec Automated Test Suite...$(RESET)"
	@$(PYTHON) -m unittest discover tests

# ------------------------------------------------------------------------------
# 7. Docker Containers
# ------------------------------------------------------------------------------
docker-build:
	@docker build -t dksec:latest .

docker-run:
	@echo "$(GREEN)Running DKSec Web Dashboard in Docker on http://127.0.0.1:8080...$(RESET)"
	@docker run --rm -p 8080:8080 -v $$(pwd)/reports:/app/reports dksec:latest ui --host 0.0.0.0 --port 8080

# ------------------------------------------------------------------------------
# 8. Housekeeping & Cleanup
# ------------------------------------------------------------------------------
clean:
	@echo "$(YELLOW)Cleaning temporary test reports, cache files, and builds...$(RESET)"
	@rm -rf reports/run reports/live_scan reports/cli_test reports/live_auth_test reports/pr_gate reports/web_audit
	@rm -rf __pycache__ dksec/__pycache__ dksec/*/__pycache__ tests/__pycache__ samples/*/__pycache__
	@rm -rf *.egg-info build dist .pytest_cache
	@echo "$(GREEN)✔ Cleanup complete.$(RESET)"
