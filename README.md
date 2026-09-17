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
| **🌐 Interactive Web GUI** | `make ui` | Visual dashboard on `http://127.0.0.1:8080` with instant session connection testing |
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
| `full` | **Full 9-Stage DevSecOps** | `1, 2, 3, 4, 5, 6, 7, 8, 9` | Complete application security review & release signoff |
| `pr` | **Fast CI / PR Gate** | `1, 3, 8` | Pull request validation (Threat Model, SAST, Secrets, Signoff) |
| `api` | **Web & API Pentest** | `4, 5, 6` | Dynamic vulnerability assessment & attack-surface fuzzing |
| `sbom` | **Supply Chain Audit** | `2, 3, 8` | ASVS requirements, SCA vulnerabilities, and CycloneDX SBOM |

Example:
```bash
# Fast PR gate that fails if critical/high bugs exist
./dksec-cli scan --preset pr --fail-on-gate

# Dynamic API penetration test against a running service
./dksec-cli scan --preset api --url http://127.0.0.1:5000
```

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

The provided [Makefile](Makefile) gives you one-word shortcuts for all operations:

```bash
make help          # View beautiful interactive menu
make setup         # Install dependencies & set executable permissions
make venv          # Create an isolated Python virtual environment in .venv
make quickstart    # Run complete 9-stage demo audit immediately
make wizard        # Launch step-by-step interactive terminal wizard
make ui            # Start the web dashboard on http://127.0.0.1:8080
make live-scan     # Launch sample app & run authenticated live scan
make scan          # Run scan on default target (customize with TARGET=... PRESET=...)
make pr-check      # Run fast PR gate with --fail-on-gate
make test          # Run automated 28-test unit & integration test suite
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

Run the complete 28-test automated suite:
```bash
make test
```
All tests run with zero external network dependencies in **~1.4 seconds**.
