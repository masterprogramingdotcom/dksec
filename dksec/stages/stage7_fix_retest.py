"""
Stage 7: Fix & Retest (Advanced Enterprise Edition)
Recommended Repo: OWASP DefectDojo (https://github.com/DefectDojo/django-DefectDojo)
What it covers: Vulnerability/finding management, DefectDojo sync, Jira ticket export, remediation SLAs, and retest regression tracking
"""

import os
import json
import datetime
import hashlib
from typing import List, Dict, Any, Tuple
import requests
from dksec.stages.base import BaseStage
from dksec.models import Finding, Severity, FindingStatus
from dksec.config import DKSecConfig


class Stage7FixRetest(BaseStage):
    def __init__(self):
        super().__init__(7)

    def run(self, config: DKSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        self.log("Synthesizing all lifecycle findings into OWASP DefectDojo & Triage Retest Tracker")

        # 1. Aggregate findings from all preceding stages
        raw_findings: List[Finding] = []
        for stage_id, s_res in context.get("stage_results", {}).items():
            raw_findings.extend(s_res.findings)

        # 2. Cryptographic Fingerprint Deduplication
        deduped = self._deduplicate_findings(raw_findings)
        self.log(f"Deduplicated {len(raw_findings)} raw observations into {len(deduped)} distinct vulnerability issues.")

        # 3. Compute Remediation Action Plan & SLAs
        remediation_plan = self._generate_remediation_plan(deduped)

        # 4. Generate OWASP DefectDojo Generic Finding Format
        defectdojo_payload = self._build_defectdojo_export(config.project_name, deduped)
        dojo_path = os.path.join(config.output_dir, "defectdojo-findings.json")
        try:
            os.makedirs(config.output_dir, exist_ok=True)
            with open(dojo_path, "w", encoding="utf-8") as f:
                json.dump(defectdojo_payload, f, indent=2)
            self.log(f"Exported OWASP DefectDojo artifact: {dojo_path}")
        except Exception as e:
            self.log(f"Error writing DefectDojo file: {e}")

        # 5. Generate Jira Ticket Bulk Import Artifact
        jira_payload = self._build_jira_export(config.project_name, deduped)
        jira_path = os.path.join(config.output_dir, "jira-issues.json")
        try:
            with open(jira_path, "w", encoding="utf-8") as f:
                json.dump(jira_payload, f, indent=2)
            self.log(f"Exported Jira bulk ticket artifact: {jira_path}")
        except Exception as e:
            pass

        # 6. Push to DefectDojo API if credentials provided
        api_status = "Not configured"
        if config.defectdojo_url and config.defectdojo_api_key:
            api_status = self._push_to_defectdojo(config, dojo_path)

        # 7. Retest & Regression Tracker against baseline
        baseline_path = os.path.join(config.output_dir, "dksec-baseline.json")
        retest_data = self._evaluate_retest_and_regressions(deduped, baseline_path)

        # Update baseline for next execution
        try:
            with open(baseline_path, "w", encoding="utf-8") as f:
                json.dump([f.to_dict() for f in deduped], f, indent=2)
        except Exception:
            pass

        metrics = {
            "total_deduplicated_findings": len(deduped),
            "critical_sla_count": len([f for f in deduped if f.severity == Severity.CRITICAL]),
            "high_sla_count": len([f for f in deduped if f.severity == Severity.HIGH]),
            "defectdojo_export_file": dojo_path,
            "jira_export_file": jira_path,
            "defectdojo_api_status": api_status,
            "retest_regressions": retest_data.get("new_regressions_count", 0),
            "fixed_and_retested": retest_data.get("fixed_vulnerabilities_count", 0)
        }

        details = {
            "remediation_plan": remediation_plan,
            "retest_summary": retest_data,
            "defectdojo_sync": api_status
        }

        context["deduped_findings"] = deduped
        context["remediation_plan"] = remediation_plan
        return [], metrics, details

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = {}
        unique = []
        for f in findings:
            key = f"{f.title.strip()}|{f.cwe}|{f.file_path or f.target}"
            h = hashlib.sha256(key.encode()).hexdigest()
            if h not in seen:
                seen[h] = True
                unique.append(f)
        return unique

    def _generate_remediation_plan(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        now = datetime.datetime.now(datetime.timezone.utc)
        plan = []
        for f in findings:
            due = now + datetime.timedelta(days=f.sla_days)
            plan.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "tool": f.tool,
                "stage": f.stage_name,
                "sla_days": f.sla_days,
                "target_due_date": due.strftime("%Y-%m-%d"),
                "remediation": f.remediation,
                "remediation_diff": f.remediation_diff,
                "status": f.status.value,
                "mitre_attack": f.mitre_attack or "N/A"
            })
        return sorted(plan, key=lambda x: Severity[x["severity"]].weight, reverse=True)

    def _build_defectdojo_export(self, project_name: str, findings: List[Finding]) -> Dict[str, Any]:
        dojo_findings = []
        for f in findings:
            dojo_findings.append({
                "title": f.title,
                "severity": f.severity.value.capitalize(),
                "description": f.description,
                "mitigation": f.remediation,
                "cwe": int(f.cwe.replace("CWE-", "")) if f.cwe and f.cwe.startswith("CWE-") and f.cwe[4:].isdigit() else 20,
                "active": True,
                "verified": True,
                "false_p": f.status == FindingStatus.FALSE_POSITIVE,
                "duplicate": False,
                "out_of_scope": False,
                "impact": f"Risk Rating: {f.severity.value}. Remediate within {f.sla_days} days.",
                "references": "\n".join(f.references),
                "file_path": f.file_path or f.target or "N/A",
                "line": f.line_number or 1,
                "date": f.discovered_at[:10]
            })

        return {
            "findings": dojo_findings,
            "scan_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "scan_type": "DKSec Unified Pipeline",
            "product_name": project_name
        }

    def _build_jira_export(self, project_name: str, findings: List[Finding]) -> Dict[str, Any]:
        issues = []
        for f in findings:
            issues.append({
                "fields": {
                    "project": {"key": "SEC"},
                    "summary": f"[{f.severity.value}] {f.title}",
                    "description": f"{f.description}\n\n*Target:* {f.file_path or f.target}\n*Remediation:* {f.remediation}",
                    "issuetype": {"name": "Security Vulnerability"},
                    "priority": {"name": "Highest" if f.severity == Severity.CRITICAL else ("High" if f.severity == Severity.HIGH else "Medium")},
                    "labels": ["dksec", f"stage-{f.stage_id}", f.tool.lower().replace(" ", "-")]
                }
            })
        return {"issues": issues}

    def _push_to_defectdojo(self, config: DKSecConfig, file_path: str) -> str:
        try:
            url = f"{config.defectdojo_url.rstrip('/')}/api/v2/import-scan/"
            headers = {"Authorization": f"Token {config.defectdojo_api_key}"}
            with open(file_path, "rb") as fl:
                files = {"file": fl}
                data = {
                    "scan_type": "Generic Findings Import",
                    "product_name": config.project_name,
                    "engagement_name": "Continuous Product Security Audit",
                    "active": True,
                    "verified": True,
                    "auto_create_context": True
                }
                r = requests.post(url, headers=headers, data=data, files=files, timeout=25)
                if r.status_code in (200, 201):
                    return f"Successfully uploaded {len(files)} findings to DefectDojo API."
                return f"DefectDojo API returned status {r.status_code}: {r.text[:100]}"
        except Exception as e:
            return f"DefectDojo sync failed: {str(e)}"

    def _evaluate_retest_and_regressions(self, current: List[Finding], baseline_file: str) -> Dict[str, Any]:
        if not os.path.exists(baseline_file):
            return {
                "first_scan": True,
                "new_regressions_count": 0,
                "fixed_vulnerabilities_count": 0
            }

        try:
            with open(baseline_file, "r") as f:
                baseline = json.load(f)
            baseline_titles = {b["title"] for b in baseline}
            current_titles = {c.title for c in current}

            fixed = baseline_titles - current_titles
            new_regressions = current_titles - baseline_titles

            return {
                "first_scan": False,
                "new_regressions_count": len(new_regressions),
                "fixed_vulnerabilities_count": len(fixed),
                "fixed_titles": list(fixed)[:10],
                "new_regression_titles": list(new_regressions)[:10]
            }
        except Exception:
            return {"first_scan": True}
