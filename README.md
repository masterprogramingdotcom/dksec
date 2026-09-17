# 🛡️ OmniSec — Enterprise Product Security Lifecycle Platform

> **An all-in-one, enterprise-grade Product Security platform that executes, audits, and orchestrates all 9 phases of the DevSecOps lifecycle at once, allows granular stage selection, and generates unified executive & technical reports compliant with OASIS SARIF v2.1.0, CycloneDX v1.5 SBOM, OWASP ASVS v4.0, OpenSSF Scorecard, and NIST SP 800-61r2.**

---

## 📌 Complete 9-Stage Product Security Workflow

```
               PRODUCT
                  │
                  ▼
       ┌────────────────────────┐
       │ 1. Architecture        │  OWASP Threat Dragon
       │    & Threat Model      │  (STRIDE / LINDDUN / DFD & Mermaid)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 2. Security            │  OWASP ASVS v4.0.3
       │    Requirements        │  (Levels 1, 2, 3 Verification)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 3. SAST + SCA +        │  Semgrep (AST) + Trivy + Gitleaks
       │    Secret Scanning     │  (CycloneDX 1.5 SBOM + Patch Diffs)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 4. DAST + API          │  OWASP ZAP + OWASP API Security
       │    Security Testing    │  (TLS Handshake, OpenAPI 3.0 Audit)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 5. Manual Security     │  OWASP WSTG v4.2
       │    Testing             │  (12 Testing Domains & Correlation)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 6. Penetration Test    │  OWASP WSTG + Nuclei + Amass
       │    / VAPT              │  (DNS Posture & 50+ Asset Fuzzers)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 7. Fix & Retest        │  OWASP DefectDojo
       │                        │  (SLA Deadlines, Jira, Baseline Retest)
       └──────────┬─────────────┘
                  ▼
       ┌────────────────────────┐
       │ 8. Security Signoff    │  OpenSSF Scorecard (All 18 Checks)
       │                        │  (SLSA Levels + SHA-256 Gate Stamp)
       └──────────┬─────────────┘
                  ▼
               RELEASE
                  │
                  ▼
       ┌────────────────────────┐
       │ 9. Monitoring &        │  Wazuh SIEM/XDR + Sigma Rules
       │    Incident Response   │  (MITRE ATT&CK + NIST IR Playbook)
       └────────────────────────┘
```

---

## 🔬 Deep Technical Capabilities by Stage

### Stage 1: Architecture & Threat Model ([OWASP Threat Dragon](https://github.com/OWASP/threat-dragon))
- **Automatic Boundary & Component Discovery**: Auto-detects Actors, DMZ Ingress Proxies, Application APIs, Databases (SQL/NoSQL), Object Stores (S3), and Third-Party APIs.
- **STRIDE & LINDDUN Matrix**: Maps threats against Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- **Visual Mermaid DFD**: Produces rendered Data Flow Diagrams in HTML and Markdown reports.
- **Threat Dragon v2 Schema**: Exports valid JSON ready to load into OWASP Threat Dragon GUI (`threat-dragon-model.json`).

### Stage 2: Security Requirements ([OWASP ASVS v4.0.3](https://github.com/OWASP/ASVS))
- **Comprehensive Chapter Coverage**: V1 Architecture, V2 Authentication, V3 Session, V4 Access Control, V5 Input Validation, V6 Cryptography, V7 Logging/Error, V8 Data Protection, V9 Communications, V10 Malicious Code, V11 Business Logic, V12 Files, V13 API, V14 Configuration.
- **Three-Tier Compliance Scoring**: Independent scoring and gap analysis for Level 1 (Baseline), Level 2 (Standard Enterprise), and Level 3 (High Assurance).

### Stage 3: SAST + SCA + Secret Scanning ([Semgrep](https://github.com/semgrep/semgrep) + [Trivy](https://github.com/aquasecurity/trivy) + [Gitleaks](https://github.com/gitleaks/gitleaks))
- **Python Abstract Syntax Tree (AST) Taint Analysis**: Parses code into Python AST nodes to identify dynamic SQL execution (`cursor.execute(f"...")`), unsafe `pickle.loads()`, `yaml.load()` without SafeLoader, and `subprocess(shell=True)`.
- **Automated Unified Remediation Diffs**: Generates drop-in code fix patches for discovered SAST bugs.
- **CycloneDX v1.5 SBOM**: Catalogs dependencies with Package URLs (`pkg:pypi/...`, `pkg:npm/...`), licenses, and CVE vulnerability ratings.
- **High-Entropy Secret Detection**: Detects AWS Access & Secret keys, GitHub PATs, Stripe live keys, Slack tokens, private RSA/EC keys, and plaintext database URIs.

### Stage 4: DAST + API Security Testing ([OWASP ZAP](https://github.com/zaproxy/zaproxy) + [OWASP API Security](https://github.com/OWASP/API-Security))
- **OpenAPI 2.0 & 3.0 Spec Audit**: Analyzes Swagger/OpenAPI files for missing `securitySchemes`, unauthenticated sensitive endpoints, and broken access controls.
- **Transport Security & TLS Handshake**: Inspects certificate expiration, protocol negotiation (TLS 1.2/1.3), and deprecated cipher suites.
- **Header & CORS Dynamic Probes**: Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and detects wildcard CORS origins paired with credentials.

### Stage 5: Manual Security Testing ([OWASP WSTG v4.2](https://github.com/OWASP/wstg))
- **12 Testing Domains**: INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT, and APIT.
- **Automated Heuristic Correlation**: Connects SAST and DAST findings directly to WSTG test cases, automatically updating test statuses and evidence.

### Stage 6: Penetration Test / VAPT ([Nuclei](https://github.com/projectdiscovery/nuclei) + [OWASP Amass](https://github.com/owasp-amass/amass))
- **Attack Surface Discovery**: Port scanning and service fingerprinting across standard web, API, database, and cache ports.
- **50+ High-Value Asset Fuzzers**: Fuzzes for exposed `.git`, `.env`, backup SQL dumps, database binaries, and Spring Boot `/actuator`.
- **RFC 9116 security.txt**: Validates vulnerability disclosure policies and contact vectors.

### Stage 7: Fix & Retest ([OWASP DefectDojo](https://github.com/DefectDojo/django-DefectDojo))
- **Cryptographic Fingerprint Deduplication**: Hashes finding attributes to merge duplicate alerts.
- **Remediation SLA Engine**: Enforces exact calendar due dates (Critical: 7d, High: 14d, Medium: 30d, Low: 90d).
- **OWASP DefectDojo API Client & JSON**: One-click import format (`defectdojo-findings.json`) + direct REST API sync.
- **Jira Bulk Ticket Exporter**: Generates `jira-issues.json` ready for Jira issue import.
- **Retest Regression Engine**: Tracks fixed vulnerabilities vs. newly introduced regressions against `omnisec-baseline.json`.

### Stage 8: Security Signoff ([OpenSSF Scorecard](https://github.com/ossf/scorecard))
- **All 18 OpenSSF Checks Implemented**: Binary-Artifacts, Branch-Protection, CI-Tests, CII-Best-Practices, Code-Review, Contributors, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing, License, Maintained, Packaging, Pinned-Dependencies, SAST, Security-Policy, Signed-Releases, Token-Permissions, and Vulnerabilities.
- **SLSA Provenance Evaluation**: Assigns SLSA Level 0, 1, or 2 rating.
- **Cryptographic Release Gate**: Evaluates Critical/High thresholds and issues an immutable SHA-256 certificate stamp (`APPROVED`, `CONDITIONAL_APPROVAL`, `BLOCKED`).

### Stage 9: Monitoring & Incident Response ([Wazuh](https://github.com/wazuh/wazuh) + [Sigma](https://github.com/SigmaHQ/sigma))
- **Wazuh XML SIEM Rules**: Generates application-specific `wazuh-local_rules.xml`.
- **Sigma YAML Detection Signatures**: Generates vendor-neutral `sigma-rules.yml` for Splunk, Elastic, Sentinel, and QRadar.
- **MITRE ATT&CK Matrix**: Maps findings to ATT&CK techniques (T1190, T1059, T1552, T1595, T1078, T1195).
- **NIST SP 800-61r2 Incident Response Playbook**: Generates custom classification criteria and containment runbooks (`incident-response-runbook.md`).

---

## 🚀 How to Run

### 1. Interactive Terminal Wizard
```bash
./omnisec_cli.py interactive
```

### 2. Direct CLI Command (All 9 Stages or Selected Stages)
```bash
# Run all 9 stages
./omnisec_cli.py scan --project "Core Banking" --target ./samples/app --url http://127.0.0.1:5000 --output ./reports

# Run selective stages (e.g. Stage 1, 3, 8)
./omnisec_cli.py scan --target ./samples/app --stages 1,3,8 --output ./reports/quick

# CI/CD Gate Mode (Exits with code 1 if release is blocked)
./omnisec_cli.py scan --target ./samples/app --fail-on-gate
```

### 3. Interactive Web GUI Dashboard
```bash
./omnisec_cli.py ui --port 8080
```
Open `http://127.0.0.1:8080` in your browser.

---

## 📦 Output Artifacts Generated on Every Run

1. **`omnisec-report.html`**: Interactive dark-mode dashboard with Mermaid DFD, filterable findings, patch diffs, and PDF styling.
2. **`cyclonedx-sbom.json`**: Official CycloneDX v1.5 JSON Software Bill of Materials (SBOM).
3. **`omnisec-results.sarif`**: Official OASIS SARIF v2.1.0 for GitHub / GitLab Code Scanning alerts.
4. **`defectdojo-findings.json`**: OWASP DefectDojo Generic Finding format.
5. **`threat-dragon-model.json`**: OWASP Threat Dragon v2 schema file.
6. **`wazuh-local_rules.xml`**: Custom Wazuh SIEM XML rules.
7. **`sigma-rules.yml`**: Generic Sigma YAML detection rules.
8. **`incident-response-runbook.md`**: NIST SP 800-61r2 Incident Response Playbook.
9. **`jira-issues.json`**: Jira bulk issue import file.
10. **`omnisec-report.md`**: Clean markdown summary for PRs.
