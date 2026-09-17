"""
Stage 7: Fix & Retest
Recommended Repo: OWASP DefectDojo (https://github.com/DefectDojo/django-DefectDojo)
What it covers: Vulnerability/finding management, remediation tracking, verification and retesting
"""

import os
import json
import datetime
import hashlib
from typing import List, Dict, Any, Tuple
import requests
from omnisec.stages.base import BaseStage
from omnisec.models import Finding, Severity, FindingStatus
from omnisec.config import OmniSecConfig


class Stage7FixRetest(BaseStage):
    def __init__(self):
        super().__init__(7)

    def run(self, config: OmniSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        self.log("Consolidating findings into OWASP DefectDojo Vulnerability Management Engine")

        # 1. Aggregate findings from all preceding stages
        raw_findings: List[Finding] = []
        for stage_id, s_res in context.get("stage_results", {}).items():
            raw_findings.extend(s_res.findings)

        self.log(f"Aggregated {len(raw_findings)} raw findings from stages 1-6.")

        # 2. Deduplicate findings
        deduped_findings = self._deduplicate_findings(raw_findings)
        self.log(f"Deduplicated to {len(deduped_findings)} unique findings.")

        # 3. Calculate Remediation SLAs and Action Plans
        remediation_plan = self._generate_remediation_plan(deduped_findings)

        # 4. Generate OWASP DefectDojo Generic Finding Format
        defectdojo_payload = self._build_defectdojo_export(config.project_name, deduped_findings)
        dojo_export_path = os.path.join(config.output_dir, "defectdojo-findings.json")
        try:
            os.makedirs(config.output_dir, exist_ok=True)
            with open(dojo_export_path, "w", encoding="utf-8") as f:
                json.dump(defectdojo_payload, f, indent=2)
            self.log(f"Exported DefectDojo import artifact: {dojo_export_path}")
        except Exception as e:
            self.log(f"Error writing DefectDojo artifact: {e}")

        # 5. Push to DefectDojo API if credentials provided
        api_sync_status = "Not configured"
        if config.defectdojo_url and config.defectdojo_api_key:
            api_sync_status = self._push_to_defectdojo(config, dojo_export_path)

        # 6. Retest & Verification Tracker
        # Check against previous baseline if exists
        baseline_file = os.path.join(config.output_dir, "omnisec-baseline.json")
        retest_metrics = self._evaluate_retest_status(deduped_findings, baseline_file)

        # Save current findings as updated baseline for next run
        try:
            with open(baseline_file, "w", encoding="utf-8") as f:
                json.dump([f.to_dict() for f in deduped_findings], f, indent=2)
        except Exception:
            pass

        metrics = {
            "total_deduplicated_findings": len(deduped_findings),
            "critical_sla_count": len([f for f in deduped_findings if f.severity == Severity.CRITICAL]),
            "high_sla_count": len([f for f in deduped_findings if f.severity == Severity.HIGH]),
            "defectdojo_export_file": dojo_export_path,
            "defectdojo_api_status": api_sync_status,
            "retest_status": retest_metrics
        }

        details = {
            "remediation_plan": remediation_plan,
            "retest_summary": retest_metrics,
            "defectdojo_sync": api_sync_status
        }

        context["deduped_findings"] = deduped_findings
        context["remediation_plan"] = remediation_plan

        # Stage 7 returns no new findings itself, it manages and triages all prior findings
        return [], metrics, details

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = {}
        unique = []
        for f in findings:
            key = f"{f.title.strip()}|{f.cwe}|{f.file_path or f.target}"
            key_hash = hashlib.md5(key.encode()).hexdigest()
            if key_hash not in seen:
                seen[key_hash] = True
                unique.append(f)
        return unique

    def _generate_remediation_plan(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        now = datetime.datetime.now(datetime.timezone.utc)
        plan = []
        for f in findings:
            due_date = now + datetime.timedelta(days=f.sla_days)
            plan.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "tool": f.tool,
                "stage": f.stage_name,
                "sla_days": f.sla_days,
                "due_date": due_date.strftime("%Y-%m-%d"),
                "remediation": f.remediation,
                "status": f.status.value
            })
        return sorted(plan, key=lambda x: Severity[x["severity"]].weight, reverse=True)

    def _build_defectdojo_export(self, project_name: str, findings: List[Finding]) -> Dict[str, Any]:
        """OWASP DefectDojo Generic Finding JSON format."""
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
                "impact": f"Risk rating: {f.severity.value}. Requires remediation per SLA within {f.sla_days} days.",
                "references": "\n".join(f.references),
                "file_path": f.file_path or f.target or "N/A",
                "line": f.line_number or 1,
                "date": f.discovered_at[:10]
            })

        return {
            "findings": dojo_findings,
            "scan_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "scan_type": "OmniSec Unified Pipeline",
            "product_name": project_name
        }

    def _push_to_defectdojo(self, config: OmniSecConfig, file_path: str) -> str:
        try:
            url = f"{config.defectdojo_url.rstrip('/')}/api/v2/import-scan/"
            headers = {"Authorization": f"Token {config.defectdojo_api_key}"}
            with open(file_path, "rb") as f:
                files = {"file": f}
                data = {
                    "scan_type": "Generic Findings Import",
                    "product_name": config.project_name,
                    "engagement_name": "OmniSec Continuous Security Verification",
                    "active": True,
                    "verified": True,
                    "auto_create_context": True
                }
                resp = requests.post(url, headers=headers, data=data, files=files, timeout=30)
                if resp.status_code in [200, 201]:
                    return f"Successfully imported {os.path.basename(file_path)} to DefectDojo"
                return f"DefectDojo returned status {resp.status_code}: {resp.text[:100]}"
        except Exception as e:
            return f"Failed to push to DefectDojo: {str(e)}"

    def _evaluate_retest_status(self, current: List[Finding], baseline_file: str) -> Dict[str, Any]:
        if not os.path.exists(baseline_file):
            return {
                "first_scan": True,
                "new_vulnerabilities": len(current),
                "fixed_vulnerabilities": 0,
                "retested_and_verified": 0
            }

        try:
            with open(baseline_file, "r") as f:
                baseline = json.load(f)
            baseline_titles = {b["title"] for b in baseline}
            current_titles = {c.title for c in current}

            fixed = baseline_titles - current_titles
            new_vulns = current_titles - baseline_titles

            return {
                "first_scan": False,
                "new_vulnerabilities": len(new_vulns),
                "fixed_vulnerabilities": len(fixed),
                "retested_and_verified": len(fixed),
                "fixed_titles": list(fixed)
            }
        except Exception:
            return {"first_scan": True}
