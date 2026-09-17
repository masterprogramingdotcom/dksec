# 🛡️ DKSec — Enterprise Product Security Lifecycle Platform

> **The unified, enterprise-grade Product Security platform that executes, audits, and orchestrates all 9 phases of the DevSecOps lifecycle at once, supports authenticated live URL & API penetration testing, and generates executive & technical reports compliant with OASIS SARIF v2.1.0, CycloneDX v1.5 SBOM, OWASP ASVS v4.0.3, OWASP WSTG v4.2, OWASP API Security Top 10, OpenSSF Scorecard, and NIST SP 800-61r2.**

---

## 📌 Complete 9-Stage Product Security Workflow

```
               PRODUCT / APPLICATION / API
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │ 1. Architecture & Threat Model       │  OWASP Threat Dragon
        │    (STRIDE / LINDDUN / DFD & Mermaid)│  https://github.com/OWASP/threat-dragon
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 2. Security Requirements             │  OWASP ASVS v4.0.3
        │    (Levels 1, 2, 3 Verification)     │  https://github.com/OWASP/ASVS
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 3. SAST + SCA + Secret Scanning      │  Semgrep + Trivy + Gitleaks
        │    (AST Analysis + CycloneDX SBOM)   │  https://github.com/semgrep/semgrep
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 4. DAST + API Security Testing       │  OWASP ZAP + OWASP API Security
        │    (Live Authenticated Dynamic Audit)│  https://github.com/zaproxy/zaproxy
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 5. Manual Security Testing           │  OWASP WSTG v4.2
        │    (12 Domains Heuristic Correlation)│  https://github.com/OWASP/wstg
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 6. Penetration Test / VAPT           │  OWASP WSTG + Nuclei + Amass
        │    (Active Fuzzing & Auth Bypass)    │  https://github.com/projectdiscovery/nuclei
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 7. Fix & Retest                      │  OWASP DefectDojo
        │    (SLA Deadlines, Jira, Retest Diff)│  https://github.com/DefectDojo/django-DefectDojo
        └──────────────────┬───────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ 8. Security Signoff                  │  OpenSSF Scorecard (18 Checks)
        │    (SLSA Levels + Gate Stamp Hash)   │  https://github.com/ossf/scorecard
        └──────────────────┬───────────────────┘
                           ▼
                 PRODUCTION RELEASE
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │ 9. Monitoring & Incident Response    │  Wazuh SIEM/XDR + Sigma Rules
        │    (MITRE ATT&CK + NIST Playbook)    │  https://github.com/wazuh/wazuh
        └──────────────────────────────────────┘
```

---

## 🔐 Advanced Live URL & Authenticated Testing Capabilities

DKSec features a state-of-the-art **Authentication & Live Session Engine** (`dksec/auth.py`) capable of auditing protected enterprise web applications and microservices behind login walls:

1. **Automated Login & Session Handling**:
   - Executes automated JSON or Form-based POST requests to your login endpoints (e.g. `/api/v1/login`, `/oauth/token`).
   - Automatically parses `Set-Cookie` headers into a persistent HTTP session jar.
   - Automatically extracts access tokens (`token`, `access_token`, `jwt`, `bearer`, or custom paths like `data.token`) and injects them as `Authorization: Bearer <token>`.
2. **JWT Security Audit**:
   - Checks for dangerous `alg: "none"` acceptance allowing unsigned token forgery (CWE-345).
   - Verifies expiration claims (`exp`) to detect perpetual session tokens (CWE-613).
   - Flags sensitive information leakage inside unencrypted base64 JWT payloads (e.g. database credentials, API keys, passwords) (CWE-312).
   - Detects symmetric algorithm risks (`HS256`).
3. **Session Cookie Security Auditing**:
   - Inspects session cookies for missing `HttpOnly` flags (XSS cookie theft risk, CWE-1004).
   - Enforces `Secure` attributes across HTTPS targets (CWE-614).
   - Verifies `SameSite` flags (`Lax` / `Strict`) to safeguard against Cross-Site Request Forgery (CSRF, CWE-1275).
4. **Broken Object & Function Level Authorization (BOLA / BFLA)**:
   - Evaluates endpoints under both **unauthenticated** and **authenticated** states.
   - Flags administrative controllers (e.g. `/api/v1/admin/debug`, `/admin`, `/manage`) accessible by standard authenticated user roles (CWE-285 / OWASP API5:2023).
   - Probes for Object Level Authorization (IDOR) on entity endpoints (e.g. `/api/v1/users/1` vs `/api/v1/users/2`).
5. **Sensitive Data Exposure in API Responses**:
   - Real-time heuristic scanning of API JSON responses for exposed database passwords (`db_pass`), private keys, or API tokens (CWE-200 / OWASP API3:2023).
6. **Authentication Brute-Force & Rate Limiting Verification**:
   - Rapidly probes login endpoints with failed attempts to ensure HTTP 429 Too Many Requests or account lockout mechanisms are actively enforced (WSTG-ATHN-03 / OWASP API4:2023).

---

## 🔬 Deep Technical Capabilities by Stage

### Stage 1: Architecture & Threat Model ([OWASP Threat Dragon](https://github.com/OWASP/threat-dragon))
- **Automatic Boundary & Component Discovery**: Auto-detects Actors, DMZ Ingress Proxies, Application APIs, Databases (SQL/NoSQL), Object Stores (S3), and Third-Party APIs.
- **STRIDE & LINDDUN Matrix**: Maps threats against Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- **Rendered Mermaid DFD**: Produces rendered Data Flow Diagrams in HTML and Markdown reports.
- **Threat Dragon v2 Schema**: Exports valid JSON ready to load into OWASP Threat Dragon GUI (`threat-dragon-model.json`).

### Stage 2: Security Requirements ([OWASP ASVS v4.0.3](https://github.com/OWASP/ASVS))
- **Comprehensive Chapter Coverage**: V1 Architecture, V2 Authentication, V3 Session, V4 Access Control, V5 Input Validation, V6 Cryptography, V7 Logging/Error, V8 Data Protection, V9 Communications, V10 Malicious Code, V11 Business Logic, V12 Files, V13 API, V14 Configuration.
- **Three-Tier Compliance Scoring**: Independent scoring and gap analysis for Level 1 (Baseline), Level 2 (Standard Enterprise), and Level 3 (High Assurance).

### Stage 3: SAST + SCA + Secret Scanning ([Semgrep](https://github.com/semgrep/semgrep) + [Trivy](https://github.com/aquasecurity/trivy) + [Gitleaks](https://github.com/gitleaks/gitleaks))
- **Python AST Taint Analysis**: Analyzes Python Abstract Syntax Trees for dynamic SQL formatting (`cursor.execute(f"...")`), unsafe `pickle.loads()`, `yaml.load()` without SafeLoader, and command execution.
- **Unified Code Remediation Diffs**: Generates drop-in diff patches for identified SAST issues.
- **CycloneDX v1.5 SBOM**: Generates complete dependency manifests with Package URLs (`pkg:pypi/...`, `pkg:npm/...`), licenses, and CVE vulnerability ratings.
- **High-Entropy Secret Detection**: Detects AWS Access & Secret keys, GitHub PATs, Stripe live keys, Slack tokens, private RSA/EC keys, and plaintext database URIs.

### Stage 4: DAST + API Security Testing ([OWASP ZAP](https://github.com/zaproxy/zaproxy) + [OWASP API Security](https://github.com/OWASP/API-Security))
- **OpenAPI 2.0 & 3.0 Spec Audit**: Analyzes Swagger/OpenAPI specifications for missing `securitySchemes`, unauthenticated sensitive endpoints, and broken access controls.
- **Live Authenticated Session Testing**: Authenticates via login forms, Bearer JWTs, or session cookies to audit protected APIs.
- **Transport Security & TLS Handshake**: Validates certificate validity, protocol negotiation (TLS 1.2/1.3), and deprecated cipher suites.
- **Header & CORS Dynamic Probes**: Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and detects wildcard CORS origins paired with credentials.

### Stage 5: Manual Security Testing ([OWASP WSTG v4.2](https://github.com/OWASP/wstg))
- **12 Testing Domains**: INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT, and APIT.
- **Automated Heuristic Correlation**: Connects SAST, DAST, and live session findings directly to WSTG test cases, automatically updating test statuses and evidence.

### Stage 6: Penetration Test / VAPT ([Nuclei](https://github.com/projectdiscovery/nuclei) + [OWASP Amass](https://github.com/owasp-amass/amass))
- **Authenticated Nuclei Probing**: Injects authentication headers (`-H "Authorization: ..."` / `-H "Cookie: ..."`) into native Nuclei scans when installed.
- **Attack Surface Discovery**: Port scanning and service fingerprinting across standard web, API, database, and cache ports.
- **50+ High-Value Asset Fuzzers**: Fuzzes for exposed `.git`, `.env`, backup SQL dumps, database binaries, and Spring Boot `/actuator`.
- **Active Injection & Path Normalization**: Detects path traversal and access-control bypass via URL normalization (`/api/v1/../admin/debug`).

### Stage 7: Fix & Retest ([OWASP DefectDojo](https://github.com/DefectDojo/django-DefectDojo))
- **Cryptographic Fingerprint Deduplication**: Hashes finding attributes to merge duplicate alerts across tools.
- **Remediation SLA Engine**: Enforces exact calendar due dates (Critical: 7d, High: 14d, Medium: 30d, Low: 90d).
- **OWASP DefectDojo Client**: Generates one-click import format (`defectdojo-findings.json`) + direct REST API sync.
- **Jira Bulk Ticket Exporter**: Generates `jira-issues.json` ready for Jira issue import.
- **Retest Regression Engine**: Tracks fixed vulnerabilities vs. newly introduced regressions against `dksec-baseline.json`.

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
./dksec-cli wizard
# or
./dksec-cli interactive
```
The wizard guides you step-by-step through preset workflow selection, target repository, live URL, and authentication settings.

### 2. Live Authenticated Scans (CLI)

#### Automated Login URL (JSON / Form POST)
```bash
./dksec-cli scan   --project "Fintech Core"   --target ./samples/app   --url http://127.0.0.1:5000   --login-url http://127.0.0.1:5000/api/v1/login   --username admin   --password AdminSecretPassword99!   --output ./reports
```

#### Direct Bearer Token / JWT
```bash
./dksec-cli scan   --target ./samples/app   --url https://api.staging.internal   --token "eyJhbGciOiJIUzI1NiIsInR5cCI..."   --output ./reports
```

#### Session Cookies
```bash
./dksec-cli scan   --url https://app.example.com   --cookie "session=abc123xyz; role=admin"
```

#### Custom Authorization Header / API Key
```bash
./dksec-cli scan   --url https://api.example.com   --header "X-API-Key: production_secret_token_123"
```

### 3. Workflow Presets
```bash
# Full 9-stage DevSecOps lifecycle (Stages 1-9)
./dksec-cli scan --preset full

# Fast PR / CI Gate (Threat Model, SAST, Secrets, Signoff - Stages 1, 3, 8)
./dksec-cli scan --preset pr --fail-on-gate

# Dynamic Web & API Pentest (DAST, API Fuzzing, WSTG, VAPT - Stages 4, 5, 6)
./dksec-cli scan --preset api -u http://127.0.0.1:5000

# Supply Chain & SBOM Audit (ASVS, SCA, CycloneDX SBOM, OpenSSF - Stages 2, 3, 8)
./dksec-cli scan --preset sbom
```

### 4. Interactive Web GUI Dashboard
```bash
./dksec-cli ui --port 8080
```
Open **`http://127.0.0.1:8080`** in any web browser to access:
- Live Target & Authentication configuration with instant session validation (`⚡ Test Session Connection`).
- Preset workflow selectors and stage checkboxes.
- Real-time progress tracker and console telemetry stream.
- One-click artifact downloads and interactive report viewer.

---

## 📦 Output Artifacts Generated on Every Run

1. **`dksec-report.html`**: Interactive executive & technical dashboard with Mermaid DFDs, filterable findings, patch diffs, authentication badges, and printable styling.
2. **`cyclonedx-sbom.json`**: Official CycloneDX v1.5 JSON Software Bill of Materials (SBOM).
3. **`dksec-results.sarif`**: Official OASIS SARIF v2.1.0 format for GitHub Code Scanning and IDEs.
4. **`defectdojo-findings.json`**: OWASP DefectDojo Generic Finding format.
5. **`threat-dragon-model.json`**: OWASP Threat Dragon v2 schema file.
6. **`wazuh-local_rules.xml`**: Application-specific Wazuh SIEM XML detection rules.
7. **`sigma-rules.yml`**: Vendor-neutral Sigma YAML detection rules.
8. **`incident-response-runbook.md`**: NIST SP 800-61r2 Incident Response Playbook.
9. **`jira-issues.json`**: Jira bulk issue import file.
10. **`dksec-report.md`**: Clean markdown summary for pull request comments and Git releases.

---

## 🧪 Running the Test Suite
```bash
python3 -m unittest discover tests
```
