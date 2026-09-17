# Incident Response (IR) Runbook: Fintech Core Banking
Generated automatically by OmniSec Unified Product Security Platform.

## 1. Triage & Incident Classification
- **P1 (Critical)**: Active breach, compromised credentials, or confirmed RCE/SQLi exploitation.
  - SLA: 15-minute response, 2-hour containment.
- **P2 (High)**: Exploitable vulnerability discovered in production without confirmed breach.
  - SLA: 1-hour response, 12-hour containment.
- **P3 (Medium)**: Misconfiguration or policy deviation.
  - SLA: 24-hour response.

## 2. Wazuh SIEM Alert Triage Flow
1. **Detection**: Wazuh agent triggers Rule `100002` (Reconnaissance) or `100003` (Injection).
2. **Isolation**: Trigger Wazuh Active Response `firewall-drop` script for attacker IP.
3. **Investigation**:
   - Inspect web server access logs around timestamp.
   - Query Wazuh syscheck FIM for modified files in application directory.
   - Check database audit logs for unauthorized record access.
4. **Remediation**:
   - Apply hotfix using patches generated in OmniSec Stage 7 Fix & Retest.
   - Invalidate compromised JWT sessions or API tokens.

## 3. Product-Specific Security Hotspots
Currently identified open risks in this product:
- Critical Findings requiring immediate monitoring: 7
- Review `defectdojo-findings.json` for detailed line numbers and vulnerability vectors.
