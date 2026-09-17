# 🛡️ DKSec — Enterprise Product Security Lifecycle Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![SARIF 2.1.0](https://img.shields.io/badge/OASIS-SARIF_2.1.0-purple.svg)](https://sarifweb.azurewebsites.net)
[![CycloneDX 1.5](https://img.shields.io/badge/SBOM-CycloneDX_1.5-orange.svg)](https://cyclonedx.org)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard_18_Checks-blue.svg)](https://securityscorecards.dev)

> **DKSec** is a unified, all-in-one Product Security platform that executes and orchestrates all 9 stages of the DevSecOps lifecycle at once. It supports **static source analysis, live authenticated dynamic scanning (behind login URLs, JWTs, and cookies), penetration testing, vulnerability management, and SIEM monitoring** — generating executive and technical reports in standard formats.

---

## ⚡ Quick Start (Up & Running in 30 Seconds)

### 1. One-Command Setup
```bash
# Clone and configure everything with a single command
make setup
```

### 2. Choose How You Want to Use DKSec

| Method | Command | Best For |
| :--- | :--- | :--- |
| **🌐 Interactive Web GUI** | `make ui` | Visual dashboard on `http://127.0.0.1:8080` with Light/Dark theme & live session testing |
| **🎯 Single-Stage VAPT** | `make vapt` | Run penetration testing & attack surface discovery only (Stage 6) |
| **🔍 Single-Stage SAST** | `make sast` | Run static code analysis, SCA & secret scanning only (Stage 3) |
| **🔀 Custom Multi-Stage** | `make scan STAGES=sast,vapt` | Run any combination of stages (by name or ID) |
| **🧙 Terminal Wizard** | `make wizard` | Step-by-step interactive CLI wizard with workflow presets |
| **⚡ One-Click Demo** | `make quickstart` | Instant full 9-stage audit against built-in vulnerable fintech app |
| **🔐 Live Authenticated Scan** | `make live-scan` | Automated live scan with background app, login session, & token audit |
| **🚀 Fast PR Gate** | `make pr-check` | Rapid CI/CD check (Threat Model, SAST, Secrets, Signoff with `--fail-on-gate`) |

---

## 📋 Complete 9-Stage Product Security Workflow

DKSec replaces 10+ disjointed security tools with a single unified engine:

```
               PRODUCT / APPLICATION / API / REPO
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 1. Architecture & Threat Model               │  OWASP Threat Dragon
        │    (STRIDE / LINDDUN / DFD & Mermaid Visual) │  https://github.com/OWASP/threat-dragon
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 2. Security Requirements                     │  OWASP ASVS v4.0.3
        │    (Level 1, 2, 3 Verification Matrix)       │  https://github.com/OWASP/ASVS
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 3. SAST + SCA + Secret Scanning              │  Semgrep + Trivy + Gitleaks
        │    (AST Analysis + CycloneDX 1.5 SBOM)       │  https://github.com/semgrep/semgrep
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 4. DAST + API Security Testing               │  OWASP ZAP + OWASP API Security
        │    (Live Authenticated Dynamic Probing)      │  https://github.com/zaproxy/zaproxy
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 5. Manual Security Testing                   │  OWASP WSTG v4.2
        │    (12 Domains Heuristic Correlation Engine) │  https://github.com/OWASP/wstg
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 6. Penetration Test / VAPT                   │  OWASP WSTG + Nuclei + Amass
        │    (Active Fuzzing & Auth Bypass Probes)     │  https://github.com/projectdiscovery/nuclei
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 7. Fix & Retest                              │  OWASP DefectDojo
        │    (SLA Deadlines, Jira, Regression Engine)  │  https://github.com/DefectDojo/django-DefectDojo
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 8. Security Signoff                          │  OpenSSF Scorecard (18 Checks)
        │    (SLSA Levels + SHA-256 Gate Stamp Hash)   │  https://github.com/ossf/scorecard
        └──────────────────────┬───────────────────────┘
                               ▼
                     PRODUCTION RELEASE
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │ 9. Monitoring & Incident Response            │  Wazuh SIEM/XDR + Sigma Rules
        │    (MITRE ATT&CK + NIST IR Playbook)         │  https://github.com/wazuh/wazuh
        └──────────────────────────────────────────────┘
```

---

## 🎯 Running Single-Stage Audits (Targeted Security Testing)

You can run **any of the 9 stages independently** using either **Makefile shortcuts** or the **`./dksec-cli`** command line tool without running prior stages.

### Stage 6: Penetration Testing & Attack Surface (VAPT)
Audits live target URLs or source directories for exposed sensitive endpoints, administrative consoles, debug interfaces, weak TLS, and attack surface:
```bash
# Via Makefile
make vapt TARGET=./my-app
make vapt URL=http://127.0.0.1:5000

# Via CLI (using stage name alias or number)
./dksec-cli scan -s vapt -t samples/app
./dksec-cli scan -s 6 -u http://127.0.0.1:5000
./dksec-cli scan --preset vapt -u http://127.0.0.1:5000
```

### Stage 3: Static Code Analysis (SAST, SCA & Secret Scanning)
Performs static AST rule checks (SQLi, SSRF, Command Injection), detects leaked hardcoded API keys/passwords/private keys, and compiles a CycloneDX 1.5 SBOM of third-party dependencies:
```bash
# Via Makefile
make sast TARGET=./my-app

# Via CLI
./dksec-cli scan -s sast -t samples/app
./dksec-cli scan -s 3 -t samples/app
./dksec-cli scan --preset sast -t samples/app
```

### Stage 1: Architecture & STRIDE Threat Modeling
Parses system boundaries, generates an OWASP Threat Dragon v2 data flow model, visualizes trust zones in Mermaid, and identifies STRIDE/LINDDUN threats:
```bash
# Via Makefile
make threat TARGET=./my-app

# Via CLI
./dksec-cli scan -s threat -t samples/app
./dksec-cli scan -s 1 -t samples/app
```

### Stage 2: Security Requirements & Verification (OWASP ASVS 4.0.3)
Maps the target against Level 1, 2, and 3 verification requirements across 14 ASVS domains:
```bash
# Via Makefile
make asvs TARGET=./my-app

# Via CLI
./dksec-cli scan -s asvs -t samples/app
./dksec-cli scan -s 2 -t samples/app
```

### Stage 4: Dynamic Application & API Security (DAST)
Probes live REST and GraphQL endpoints for OWASP API Top 10 vulnerabilities (BOLA/IDOR, BFLA, Mass Assignment, rate limiting, and JWT flaws):
```bash
# Via Makefile
make dast URL=http://127.0.0.1:5000

# Via CLI
./dksec-cli scan -s dast -u http://127.0.0.1:5000
./dksec-cli scan -s 4 -u http://127.0.0.1:5000
```

### Stage 5: Manual Security Testing Guide (OWASP WSTG v4.2)
Verifies 12 testing domains including authentication mechanisms, session fixation, input sanitization heuristics, and access control matrices:
```bash
# Via Makefile
make wstg TARGET=./my-app URL=http://127.0.0.1:5000

# Via CLI
./dksec-cli scan -s wstg -t samples/app -u http://127.0.0.1:5000
```

### Stage 7: Vulnerability Management, Fix & Retest (OWASP DefectDojo)
Generates DefectDojo generic findings, tracks remediation SLAs, produces Jira tickets, and verifies resolved issues:
```bash
# Via Makefile
make defectdojo TARGET=./my-app

# Via CLI
./dksec-cli scan -s defectdojo -t samples/app
./dksec-cli scan -s 7 -t samples/app
```

### Stage 8: Security Signoff & Cryptographic Release Gate (OpenSSF Scorecard)
Evaluates 18 OpenSSF supply-chain security checks, SLSA security levels, and issues a SHA-256 digital release certificate:
```bash
# Via Makefile
make signoff TARGET=./my-app

# Via CLI
./dksec-cli scan -s signoff -t samples/app
./dksec-cli scan -s 8 -t samples/app
```

### Stage 9: SIEM Rules & Sigma Detection Engine (Wazuh & Sigma)
Automatically synthesizes Wazuh XML rules, Sigma YAML detection rules, and NIST SP 800-61 incident response runbooks based on detected vulnerabilities:
```bash
# Via Makefile
make wazuh TARGET=./my-app

# Via CLI
./dksec-cli scan -s wazuh -t samples/app
./dksec-cli scan -s 9 -t samples/app
```

---

## 🔀 Running Multi-Stage Audits & Custom Combinations

You can execute **any combination** of stages in a single pass using comma-separated stage names or stage numbers:

```bash
# Run SAST + Penetration Testing (Stages 3 & 6)
make scan STAGES=sast,vapt TARGET=./my-app
./dksec-cli scan -s sast,vapt -t samples/app

# Run Threat Modeling + SAST + OpenSSF Signoff (Stages 1, 3, 8)
make scan STAGES=1,3,8 TARGET=./my-app
./dksec-cli scan -s 1,3,8 -t samples/app

# Run DAST + WSTG + VAPT with live endpoint authentication
make scan STAGES=dast,wstg,vapt URL=http://127.0.0.1:5000 TARGET=samples/app

# Pre-packaged multi-stage workflow recipes:
make code-audit     # Runs Stages 1 & 3 (Threat Model + Code SAST + Secrets)
make api-audit      # Runs Stages 4, 5 & 6 (DAST + WSTG + VAPT)
make supply-chain   # Runs Stages 2, 3 & 8 (ASVS + CycloneDX SBOM + OpenSSF)
make pr-check       # Fast PR check (Stages 1, 3, 8 with --fail-on-gate)
```

---

## 🔐 Live URL & Authenticated Application Testing

DKSec features a built-in **Session Manager** (`dksec/auth.py`) to test endpoints **behind logins**:

### 1. Automated Login URL (JSON / Form POST)
DKSec logs in, captures `Set-Cookie` headers, extracts the Bearer token, and audits protected routes:
```bash
./dksec-cli scan \
  --project "Fintech Core" \
  --target samples/app \
  --url http://127.0.0.1:5000 \
  --login-url http://127.0.0.1:5000/api/v1/login \
  --username admin \
  --password AdminSecretPassword99!
```

### 2. Bearer Token / JWT
```bash
./dksec-cli scan \
  --target samples/app \
  --url https://api.staging.company.com \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI..."
```

### 3. Session Cookies
```bash
./dksec-cli scan \
  --url https://app.company.com \
  --cookie "session=abc123xyz; role=admin"
```

### 4. Custom API Key / Header
```bash
./dksec-cli scan \
  --url https://api.company.com \
  --header "X-API-Key: production_secret_token_123"
```

### 🛡️ What DKSec Audits Behind the Login:
- **JWT Hygiene**: Checks for `alg: none` unsigned token forgery (CWE-345), missing expiration (`exp`), and leaked passwords/credentials in unencrypted base64 payloads.
- **Session Cookie Flags**: Audits for missing `HttpOnly` (XSS theft), missing `Secure` (cleartext transmission), and missing `SameSite` (CSRF risk).
- **BOLA / IDOR**: Tests object ID manipulation (`/api/v1/users/1` vs `/api/v1/users/2`).
- **BFLA (Privilege Escalation)**: Probes administrative routes (`/admin`, `/api/v1/admin/debug`) using standard user sessions.
- **Response Data Leakage**: Flags API responses leaking database credentials (`db_pass`), private keys, or API secrets.
- **Brute-Force Rate Limiting**: Sends rapid failed logins to verify HTTP 429 Too Many Requests or account lockout enforcement (WSTG-ATHN-03).

---

## 🎯 Workflow Presets

You can run predefined workflow profiles for common engineering use cases:

| Preset | Name | Stages Included | Typical Use Case |
| :---: | :--- | :--- | :--- |
| `full` / `all` | **Full 9-Stage DevSecOps** | `1, 2, 3, 4, 5, 6, 7, 8, 9` | Complete application security review & release signoff |
| `pr` | **Fast CI / PR Gate** | `1, 3, 8` | Pull request validation (Threat Model, SAST, Secrets, Signoff) |
| `api` / `web` | **Web & API Pentest** | `4, 5, 6` | Dynamic vulnerability assessment & attack-surface fuzzing |
| `sbom` | **Supply Chain Audit** | `2, 3, 8` | ASVS requirements, SCA vulnerabilities, and CycloneDX SBOM |
| `vapt` | **Penetration Test Only** | `6` | Quick attack-surface discovery & sensitive endpoint exposure |
| `sast` | **Static Analysis Only** | `3` | Fast AST code scanning, secret detection & CycloneDX SBOM |
| `threat` | **Threat Modeling Only** | `1` | Architecture STRIDE threat modeling & OWASP Threat Dragon DFD |

Example:
```bash
# Run VAPT only via preset
./dksec-cli scan --preset vapt -u http://127.0.0.1:5000

# Fast PR gate that fails if critical/high bugs exist
./dksec-cli scan --preset pr --fail-on-gate

# Dynamic API penetration test against a running service
./dksec-cli scan --preset api --url http://127.0.0.1:5000
```

---

## 🖥️ Interactive Web Dashboard (Light & Dark Theme)

DKSec includes a built-in, lightweight web GUI that requires zero Node.js/npm dependencies:

```bash
make ui
# or: ./dksec-cli ui --port 8080
```
Visit **`http://127.0.0.1:8080`** in your browser.

### Key Web Dashboard Features:
- **🌓 Dynamic Light & Dark Theme**: Toggle instantly between a modern high-contrast Light Theme (ideal for day-to-day work and reports) and an executive Dark Theme. Preference is saved automatically in `localStorage`.
- **🎯 One-Click Stage Presets**: Instantly toggle **Full 9-Stage Audit**, **Fast PR Gate**, **API Pentest**, **VAPT Only**, **SAST Only**, or **Threat Model Only**.
- **🔐 Session Connection Tester**: Test automated logins, Bearer JWTs, session cookies, and custom headers live against your target application before initiating full scans.
- **🤖 AI Engine Verification**: Verify API keys and test connectivity to OpenAI, Gemini, Claude, or local Ollama with a single click.
- **📡 Real-Time Telemetry & Progress**: Watch stages execute live with streaming logs and dynamic progress bars.
- **📦 Direct Artifact Downloads**: Instantly open or download generated HTML reports, CycloneDX 1.5 SBOM, SARIF 2.1.0, DefectDojo JSON, Threat Dragon models, and Wazuh/Sigma SIEM rules.

---

## 🤖 Dynamic AI / LLM Security Assistant (Optional)

DKSec includes an autonomous, zero-dependency **Smart LLM Security Engine** (`dksec/llm.py`) that empowers security teams with generative AI intelligence:

- **Autonomous False-Positive Reduction**: Evaluates code context and AST signals to classify findings as `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `SUSPICIOUS` with confidence ratings.
- **Contextual Remediation Patches**: Generates unified git diff patches (`--- a/app.py / +++ b/app.py`) for instantaneous developer remediations.
- **Executive CISO Briefings**: Synthesizes cross-stage audit telemetry into board-ready executive summaries in both interactive HTML and Markdown.
- **Multi-Provider Support**:
  - 🌐 **OpenAI**: `gpt-4o`, `gpt-4o-mini` (uses `$OPENAI_API_KEY`)
  - 💎 **Google Gemini**: `gemini-1.5-pro`, `gemini-1.5-flash` (uses `$GEMINI_API_KEY`)
  - 🧠 **Anthropic Claude**: `claude-3-5-sonnet` (uses `$ANTHROPIC_API_KEY`)
  - 🦙 **Ollama Local / Private**: `llama3`, `mistral`, `codellama` (100% private, zero telemetry, no cloud keys needed)
  - ⚡ **Custom OpenAI-Compatible**: vLLM, LocalAI, or self-hosted enterprise model gateways
- **Graceful Fallback**: If offline or if no API keys are supplied, DKSec automatically activates a built-in high-confidence heuristic rule engine with zero pipeline disruptions.

### Enabling Dynamic AI via CLI
```bash
# Enable with OpenAI
./dksec-cli scan --llm --llm-provider openai --llm-model gpt-4o

# Enable with Local Ollama (Zero Telemetry, 100% On-Premise)
./dksec-cli scan --llm --llm-provider ollama --llm-model llama3 --llm-url http://localhost:11434/v1

# Enable with Google Gemini
./dksec-cli scan --llm --llm-provider gemini --llm-model gemini-1.5-pro --llm-key $GEMINI_API_KEY
```

---

## 🛠️ Makefile Command Reference

The provided [Makefile](Makefile) gives you intuitive shortcuts for all operations:

### Quick Start & Exploration
```bash
make help          # View interactive color menu of all commands
make setup         # Install dependencies & set executable permissions
make venv          # Create an isolated Python virtual environment in .venv
make quickstart    # Run complete 9-stage demo audit immediately
make wizard        # Launch step-by-step interactive terminal wizard
make ui            # Start the web dashboard on http://127.0.0.1:8080 (Light/Dark theme)
make live-scan     # Launch sample app & run authenticated live scan
```

### Targeted Single-Stage Audits
```bash
make vapt          # [Stage 6] Penetration test & attack surface discovery
make sast          # [Stage 3] Static code analysis, SCA & secret scanning
make threat        # [Stage 1] STRIDE threat model & Threat Dragon DFD
make asvs          # [Stage 2] OWASP ASVS 4.0.3 requirements verification
make dast          # [Stage 4] Dynamic application & API security fuzzing
make wstg          # [Stage 5] OWASP Web Security Testing Guide checklist
make defectdojo    # [Stage 7] DefectDojo vulnerability tracking & retest
make signoff       # [Stage 8] OpenSSF Scorecard & cryptographic release gate
make wazuh         # [Stage 9] Wazuh SIEM XML rules & Sigma detection engine
```

### Multi-Stage & Custom Pipelines
```bash
make scan STAGES=sast,vapt        # Run custom combination of named stages
make scan STAGES=1,3,6 TARGET=... # Run custom combination by stage IDs
make scan PRESET=pr               # Run fast PR gate preset (Stages 1, 3, 8)
make code-audit                   # Combined Threat Model + SAST + Secrets (1, 3)
make api-audit                    # Combined Live DAST + WSTG + VAPT (4, 5, 6)
make supply-chain                 # Combined ASVS + SBOM + OpenSSF (2, 3, 8)
make pr-check                     # Run fast PR gate with --fail-on-gate
```

### Testing, Containers & Housekeeping
```bash
make test          # Run automated 31-test unit & integration test suite
make clean         # Delete temporary scan reports and python caches
make docker-build  # Build Docker container image
make docker-run    # Run Web Dashboard in Docker container
```

---

## ⚙️ Configuration File (`dksec.yml`)

You can define all targets, authentication parameters, LLM preferences, and gating criteria in `dksec.yml`:

```yaml
project_name: "Fintech Core Banking API"
target_path: "samples/app"
target_url: "http://127.0.0.1:5000"
output_dir: "./reports"

# Dynamic AI / LLM Security Assistant
llm:
  enabled: true
  provider: "openai"       # "openai", "gemini", "anthropic", "ollama", "custom"
  model: "gpt-4o"
  api_key: null            # Reads from OPENAI_API_KEY if null
  api_base_url: null       # Set for Ollama (e.g. http://localhost:11434/v1)
  triage_findings: true
  auto_generate_patches: true
  generate_executive_summary: true

# Live Authentication
auth:
  enabled: true
  auth_type: "login" # "login", "bearer", "cookie", or "header"
  login_url: "http://127.0.0.1:5000/api/v1/login"
  username: "admin"
  password: "AdminSecretPassword99!"
  payload_type: "json"
  token_json_path: "token"

signoff:
  max_critical: 0 # Zero-tolerance gate for critical vulnerabilities
  max_high: 0 # Zero-tolerance gate for high vulnerabilities
  min_score: 75.0 # Minimum score required for release approval (0-100)

stages:
  1: { enabled: true } # Architecture & Threat Model (STRIDE)
  2: { enabled: true } # Security Requirements (OWASP ASVS)
  3: { enabled: true } # SAST + SCA + Secrets (Semgrep, Trivy, Gitleaks)
  4: { enabled: true } # DAST + API Security (ZAP, API Top 10)
  5: { enabled: true } # Manual Security Testing (OWASP WSTG)
  6: { enabled: true } # Penetration Test / VAPT (Nuclei, Amass)
  7: { enabled: true } # Fix & Retest (DefectDojo, Jira)
  8: { enabled: true } # Security Signoff (OpenSSF Scorecard)
  9: { enabled: true } # Monitoring & Incident Response (Wazuh, Sigma)
```

Run with:
```bash
./dksec-cli scan -c dksec.yml
```

---

## 📦 Generated Industry-Standard Artifacts

Every DKSec run outputs industry-standard files into your output directory:

| Artifact | Format / Standard | Purpose |
| :--- | :--- | :--- |
| **`dksec-report.html`** | Interactive HTML5 Dashboard | Executive KPI cards, rendered Mermaid DFD, patch diffs, auth status badges, and print-ready PDF styling |
| **`cyclonedx-sbom.json`** | CycloneDX v1.5 JSON | Software Bill of Materials (SBOM) with purls, licenses, and dependencies |
| **`dksec-results.sarif`** | OASIS SARIF v2.1.0 | Native integration for GitHub / GitLab Code Scanning alerts & IDEs |
| **`defectdojo-findings.json`** | OWASP DefectDojo Generic Finding | One-click import format for enterprise vulnerability management |
| **`threat-dragon-model.json`** | OWASP Threat Dragon v2 Schema | Architecture threat model importable into Threat Dragon GUI |
| **`wazuh-local_rules.xml`** | Wazuh SIEM XML Rules | Application-tailored detection rules for Wazuh SIEM/XDR |
| **`sigma-rules.yml`** | Sigma YAML | Vendor-neutral detection rules for Splunk, Elastic, Sentinel, and QRadar |
| **`incident-response-runbook.md`** | NIST SP 800-61r2 Playbook | Step-by-step incident response procedures and classification criteria |
| **`jira-issues.json`** | Atlassian Jira Bulk Issue Import | Pre-formatted tickets ready for Jira remediation tracking |
| **`dksec-report.md`** | GitHub Flavored Markdown | Clean summary for Pull Request comments and Release notes |

---

## 🔄 CI/CD Pipeline Integration Example

### GitHub Actions (`.github/workflows/security.yml`)
```yaml
name: DKSec Product Security Gate

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install DKSec
        run: make setup

      - name: Execute Security Gate
        run: ./dksec-cli scan --preset pr --fail-on-gate --output ./reports

      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/dksec-results.sarif

      - name: Archive Security Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: dksec-security-reports
          path: reports/
```

---

## 🧪 Testing & Verification

Run the complete 31-test automated suite:
```bash
make test
```
All tests run with zero external network dependencies in **~1.8 seconds**.
