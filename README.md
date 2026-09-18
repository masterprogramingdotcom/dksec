# 🛡️ DKSec — Enterprise Product Security Lifecycle Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![SARIF 2.1.0](https://img.shields.io/badge/OASIS-SARIF_2.1.0-purple.svg)](https://sarifweb.azurewebsites.net)
[![CycloneDX 1.5](https://img.shields.io/badge/SBOM-CycloneDX_1.5-orange.svg)](https://cyclonedx.org)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard_18_Checks-blue.svg)](https://securityscorecards.dev)

> **DKSec** is a unified, all-in-one Product Security platform that orchestrates all 9 stages of the DevSecOps lifecycle at once. It supports **static source analysis, live authenticated dynamic scanning, active API fuzzing, automated dual-session RBAC testing, auto-remediation patching, and SIEM monitoring** — generating executive and technical reports in standard formats.

---

## ⚡ What's New in Enterprise v2.0
We've added a powerful suite of 7 massive enterprise-grade features to automate the most complex parts of application security:

1. 🎯 **OpenAPI-Driven Active Parameter Fuzzing:** Automatically extracts OpenAPI/Swagger schemas and actively fuzzes dynamic parameters (injecting SQLi, XSS, and Path Traversal payloads).
2. 🎭 **Multi-Role RBAC / BOLA Matrix Auditor:** Supports dual-session testing (`--user-b-token`) to automatically detect Broken Object Level Authorization (BOLA) and IDOR vulnerabilities between Admin and Low-Privilege users.
3. 💾 **Auto-Remediation & Git Diff Generator:** Analyzes findings and generates ready-to-merge Unified Git Diff patches (`dksec-diff.json`) to instantly fix vulnerable code.
4. 📈 **Delta / Regression Scanning:** Tracks vulnerability regressions over time. Pass `--diff-against previous-report.json` to generate delta summaries (New Regressions vs. Resolved Findings).
5. 🔔 **Webhook Alerts & Notifications:** Dispatch beautiful, formatted JSON telemetry payloads directly to Slack, Microsoft Teams, or Discord using `--webhook-url`.
6. 💻 **Interactive cURL PoC UI:** The generated HTML dashboard now renders fully interactive "Proof-of-Concept" (PoC) blocks, including `raw_request`, `raw_response`, and copy-pasteable `curl` payloads to reproduce vulnerabilities instantly.
7. 📡 **Real-Time Web UI Streaming:** The `dksec ui` web dashboard now uses Server-Sent Events (SSE) to stream live scan telemetry and execution logs directly to your browser without freezing!

---

## ⚡ Quick Start (Up & Running in 30 Seconds)

### 1. OS-Aware Setup
DKSec ships with an intelligent setup script that automatically detects your OS (Linux, macOS, or Windows) and configures the environment.

**Linux & macOS:**
```bash
# This will automatically create a .venv and install dependencies
make setup

# Activate the virtual environment
source .venv/bin/activate
```

**Windows:**
If you have `make` installed (via MSYS2/Git Bash), you can run `make setup`. Otherwise, set up the environment natively:
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 2. Choose How You Want to Use DKSec

| Method | Command | Best For |
| :--- | :--- | :--- |
| **🌐 Interactive Web GUI** | `make ui` | Visual dashboard on `http://127.0.0.1:8080` with Light/Dark theme & live session streaming |
| **🎯 Delta Scan (Regression)** | `python3 dksec.py scan -s 4 --diff-against old.json` | Compare a new scan against a baseline to find regressions |
| **🔔 CI/CD with Webhooks** | `python3 dksec.py scan --preset pr --webhook-url http://...` | Run a fast PR gate and dispatch results to Slack/Teams |
| **🔐 Live Authenticated Scan** | `python3 dksec.py scan --url https://target --token "jwt_here"` | Automated live scan with background app, login session, & token audit |
| **🎭 Dual-Session BOLA Test** | `python3 dksec.py scan --url https://target --token "admin" --user-b-token "low_priv"` | Tests APIs for BOLA/IDOR by swapping session contexts |
| **🧙 Terminal Wizard** | `make wizard` | Step-by-step interactive CLI wizard with workflow presets |

---

## 📋 Complete 9-Stage Product Security Workflow

DKSec replaces 10+ disjointed security tools with a single unified engine:

1. **Architecture & Threat Model:** Generates OWASP Threat Dragon components, mitigates STRIDE risks, and maps them to MITRE ATT&CK.
2. **Security Requirements (ASVS):** Verifies code against the OWASP ASVS v4.0.3 requirements matrix.
3. **SAST / SCA / Secrets:** Scans code using 35+ custom rules for Hardcoded Secrets, SQL Injection, RCE, and generates a full CycloneDX 1.5 SBOM.
4. **DAST & API Security:** Probes live APIs for JWT bypass, CORS misconfigurations, SSRF, active fuzzing, and BOLA matrix validation.
5. **WSTG Manual Tests:** Maps out test plans for OWASP Web Security Testing Guide elements.
6. **VAPT & Attack Surface:** Discovers active attack vectors like Cloud Metadata SSRF, Subdomain Takeover, and active port scanning.
7. **DefectDojo SLA:** Generates bug tracker issues mapped to SLA requirements.
8. **OpenSSF Scorecard:** Verifies CI/CD pipelines against the 18 SLSA scorecard checks.
9. **Wazuh/Sigma SIEM:** Synthesizes custom Wazuh XML and Sigma YAML detection rules based on the identified threats!

---

## 🤖 Dynamic AI Smart Triage (LLM Assistant)
DKSec integrates seamlessly with leading Large Language Models (LLMs) to automatically filter false positives and generate **CISO-ready Executive Briefings**.

```bash
# Analyze a live target using OpenAI GPT-4o for intelligent triage
python3 dksec.py scan --url https://campaignmitra.com --llm --llm-provider openai
```

**Supported Providers:**
* `openai` (GPT-4o, GPT-4o-mini)
* `gemini` (Google Gemini 1.5 Pro / Flash)
* `anthropic` (Claude 3.5 Sonnet)
* `ollama` (Local Llama3 / Mistral — **Zero Cloud Telemetry!**)

---

## 📄 Output Artifacts
DKSec generates a complete suite of industry-standard artifacts in the `./reports/` directory:
* `dksec-report.html`: Beautiful, interactive Web Dashboard (with cURL PoCs and diffs).
* `dksec-report.json`: Machine-readable master report.
* `dksec-diff.json`: Delta regression report (if `--diff-against` is used).
* `dksec-results.sarif`: OASIS SARIF 2.1.0 (for GitHub Advanced Security / GitLab integration).
* `cyclonedx-sbom.json`: CycloneDX 1.5 Software Bill of Materials.
* `sigma-rules.yml`: Custom Sigma detection signatures.
* `wazuh-local_rules.xml`: Custom Wazuh SIEM alerts.

---

## 🛡️ License
Released under the MIT License. Built for Modern DevSecOps Teams.
