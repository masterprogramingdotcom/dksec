# 🛡️ OmniSec — Unified Product Security Lifecycle Platform

> **An all-in-one security orchestrator that runs all 9 Product Security phases at once, lets users selectively decide what stages to execute, and generates a unified executive & technical audit report.**

---

## 📌 Complete 9-Stage Product Security Workflow

```
               PRODUCT
                  │
                  ▼
       ┌────────────────────────┐
       │ 1. Architecture        │  OWASP Threat Dragon
       │    & Threat Model      │  (STRIDE / LINDDUN / DFD)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 2. Security            │  OWASP ASVS v4.0
       │    Requirements        │  (Design & Runtime Verification)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 3. SAST + SCA +        │  Semgrep + Trivy + Gitleaks
       │    Secret Scanning     │  (Code, Dependencies & Secrets)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 4. DAST + API          │  OWASP ZAP + OWASP API Security
       │    Security Testing    │  (Dynamic API Fuzzing & Headers)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 5. Manual Security     │  OWASP WSTG v4.2
       │    Testing             │  (Testing Methodology & Checklists)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 6. Penetration Test    │  OWASP WSTG + Nuclei + Amass
       │    / VAPT              │  (Surface Discovery & Exploit Probing)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 7. Fix & Retest        │  OWASP DefectDojo
       │                        │  (Triage, SLAs & Verification)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 8. Security Signoff    │  OpenSSF Scorecard
       │                        │  (Release Gating & Audit Stamp)
       └──────────┬─────────────┘
                  ▼
               RELEASE
                  │
                  ▼
       ┌────────────────────────┐
       │ 9. Monitoring &        │  Wazuh SIEM / XDR
       │    Incident Response   │  (FIM, Live Rules & IR Playbook)
       └────────────────────────┘
```

---

## 🎯 Coverage & Recommended GitHub Repositories

| # | Stage / Task | Recommended GitHub Repository | What OmniSec Covers & Automates |
| :-: | :--- | :--- | :--- |
| **1** | **Architecture & Threat Model** | [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) | Data-flow diagrams, component identification, automated STRIDE threat matrix, and Threat Dragon v2 schema generation (`threat-dragon-model.json`). |
| **2** | **Security Requirements** | [OWASP/ASVS](https://github.com/OWASP/ASVS) | ASVS v4.0 compliance scoring across V1-V14 chapters (Levels 1, 2, 3), automated password/cookie/crypto checks, and gap analysis. |
| **3** | **SAST + SCA + Secret Scanning** | [semgrep/semgrep](https://github.com/semgrep/semgrep)<br>[aquasecurity/trivy](https://github.com/aquasecurity/trivy)<br>[gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | Multi-language source code analysis, dependency CVE matching (`package.json`, `requirements.txt`), and high-entropy secret detection with line numbers and snippets. |
| **4** | **DAST + API Security Testing** | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)<br>[OWASP/API-Security](https://github.com/OWASP/API-Security) | Dynamic endpoint audit for missing security headers (HSTS, CSP, X-Frame-Options), CORS misconfigurations, server leaks, and API Top 10 vulnerabilities. |
| **5** | **Manual Security Testing** | [OWASP/wstg](https://github.com/OWASP/wstg) | Comprehensive WSTG v4.2 verification checklist with automated heuristic correlation from SAST/DAST results. |
| **6** | **Penetration Test / VAPT** | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)<br>[owasp-amass/amass](https://github.com/owasp-amass/amass) | Attack-surface discovery, open port scanning, sensitive file fuzzing (`.env`, `.git`, `/actuator`, backup files), and RFC 9116 `security.txt` check. |
| **7** | **Fix & Retest** | [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Cross-stage finding deduplication, remediation SLA deadlines (Critical 7d, High 14d, Med 30d), DefectDojo API push, and `defectdojo-findings.json` export. |
| **8** | **Security Signoff** | [ossf/scorecard](https://github.com/ossf/scorecard) | Automated repository posture check (branch protection, dangerous GitHub Actions, licenses, binary artifacts) and Release Gating verdict with digital SHA-256 stamp. |
| **9** | **Monitoring & Incident Response** | [wazuh/wazuh](https://github.com/wazuh/wazuh) | FIM & telemetry audit, automated generation of custom Wazuh SIEM detection rules (`wazuh-local_rules.xml`), and a tailored Incident Response Playbook. |

---

## 🚀 Quickstart & 3 Ways to Run

### 1. Interactive Terminal Wizard
Simply launch the tool without arguments or with `interactive` to enter a guided terminal interface:
```bash
./omnisec_cli.py interactive
```
*Prompts for Project Name, Target Code, Optional Live URL, and displays an interactive multi-select menu to select any subset or all 9 stages.*

---

### 2. Direct CLI Pipeline Execution
Run all 9 stages or select specific stages directly from the command line:

```bash
# Run ALL 9 stages against target code & live API
./omnisec_cli.py scan \
  --project "Core Banking API" \
  --target ./samples/app \
  --url http://127.0.0.1:5000 \
  --output ./reports/audit

# Run SELECTIVE stages (e.g. Stage 1: Threat Model, Stage 3: SAST/SCA/Secrets, Stage 8: Signoff)
./omnisec_cli.py scan \
  --project "Quick PR Check" \
  --target ./samples/app \
  --stages 1,3,8 \
  --output ./reports/pr_check
```

---

### 3. Interactive Web GUI Dashboard
Launch the built-in browser UI (zero external web frameworks needed):
```bash
./omnisec_cli.py ui --port 8080
```
Open **`http://127.0.0.1:8080`** in your browser to:
- Select/deselect any of the 9 stages with toggle switches.
- Configure target paths and target URLs.
- Watch real-time execution progress bars and streaming logs.
- Instantly view and download interactive reports.

---

## 📊 Generated Artifacts & Unified Reporting

Every audit run generates a complete suite of artifacts in the designated output directory:

| Generated File | Purpose | Target Audience / Tool |
| :--- | :--- | :--- |
| **`omnisec-report.html`** | Standalone interactive dashboard with live filtering by severity, stage tabs, search bar, and print-to-PDF formatting. | CISO, Tech Leads, Auditors |
| **`omnisec-report.md`** | Clean GitHub/GitLab markdown summary with status badges, KPI tables, and remediation instructions. | PR Comments, Jira, CI/CD Summaries |
| **`omnisec-report.json`** | Machine-readable full audit data schema. | DevSecOps automation, SIEM pipelines |
| **`defectdojo-findings.json`** | Standard OWASP DefectDojo Generic Finding format. | One-click import into DefectDojo |
| **`threat-dragon-model.json`** | OWASP Threat Dragon v2 schema model. | Open in OWASP Threat Dragon GUI |
| **`wazuh-local_rules.xml`** | Custom Wazuh SIEM XML detection rules tailored to app findings. | Deploy to `/var/ossec/etc/rules/` |
| **`incident-response-runbook.md`** | Tailored Incident Response playbook with triage SLAs. | SOC / Incident Response Team |

---

## ⚙️ Configuration (`omnisec.yml`)

You can define standard organization security profiles using `omnisec.yml`:

```yaml
project_name: "My Enterprise App"
target_path: "./src"
target_url: "https://api.mycompany.com"
output_dir: "./reports"

# Release Gate thresholds
signoff:
  max_critical: 0
  max_high: 0
  min_score: 80.0

# Optional integration credentials
defectdojo:
  url: "https://defectdojo.company.internal"
  api_key: "${DEFECTDOJO_API_KEY}"
  product_id: 1

wazuh:
  url: "https://wazuh.company.internal:55000"
  user: "wazuh-api"
  password: "${WAZUH_PASSWORD}"

stages:
  1: { enabled: true }  # Threat Model
  2: { enabled: true }  # ASVS
  3: { enabled: true }  # SAST/SCA/Secrets
  4: { enabled: true }  # DAST/API
  5: { enabled: true }  # WSTG Manual
  6: { enabled: true }  # VAPT
  7: { enabled: true }  # DefectDojo
  8: { enabled: true }  # Signoff
  9: { enabled: true }  # Wazuh
```

---

## 🐳 Docker Deployment

Run with Docker Compose:
```bash
docker-compose up -d
```
Access the dashboard at `http://localhost:8080`.

---

## 🧪 Testing

Run the automated test suite covering all 9 stages, reporters, and CLI commands:
```bash
make test
```
