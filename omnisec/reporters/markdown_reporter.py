"""
Markdown Report Generator for OmniSec.
Ideal for CI/CD Job Summaries, GitHub Pull Request comments, and issue trackers.
"""

import os
from omnisec.models import OmniSecReport, Severity


class MarkdownReporter:
    @staticmethod
    def generate(report: OmniSecReport, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        verdict_badge = {
            "APPROVED": "🟢 **RELEASE APPROVED**",
            "CONDITIONAL_APPROVAL": "🟡 **CONDITIONAL APPROVAL**",
            "BLOCKED": "🔴 **RELEASE BLOCKED**"
        }.get(report.gate_verdict.status, report.gate_verdict.status)

        md = []
        md.append(f"# 🛡️ OmniSec Product Security Audit Report: {report.project_name}")
        md.append(f"*Generated on {report.timestamp} | Audit Duration: {report.duration_seconds:.2f}s*")
        md.append("")
        md.append("## 📋 Executive Summary & Release Gate")
        md.append(f"| Metric | Status / Value |")
        md.append(f"| :--- | :--- |")
        md.append(f"| **Gate Verdict** | {verdict_badge} |")
        md.append(f"| **Security Posture Score** | **{report.overall_score:.1f} / 100** |")
        md.append(f"| **Critical Findings** | `{report.severity_counts.get('CRITICAL', 0)}` (Target: 0) |")
        md.append(f"| **High Findings** | `{report.severity_counts.get('HIGH', 0)}` (Target: 0) |")
        md.append(f"| **Medium Findings** | `{report.severity_counts.get('MEDIUM', 0)}` |")
        md.append(f"| **Low / Info Findings** | `{report.severity_counts.get('LOW', 0) + report.severity_counts.get('INFO', 0)}` |")
        md.append(f"| **Signoff Audit Hash** | `{report.gate_verdict.signoff_hash[:16]}...` |")
        md.append("")

        if report.gate_verdict.reasons:
            md.append("### Release Gate Notes:")
            for reason in report.gate_verdict.reasons:
                md.append(f"- {reason}")
            md.append("")

        md.append("## 🔄 9-Stage Product Security Lifecycle Breakdown")
        md.append("| # | Stage Name | Recommended Tool(s) | Status | Findings | Time |")
        md.append("| :-: | :--- | :--- | :-: | :-: | -: |")

        for stage_id in sorted(report.stages_executed):
            s_res = report.stage_results.get(stage_id)
            if s_res:
                status_icon = "✅ Pass" if s_res.success and len([f for f in s_res.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]) == 0 else ("⚠️ Review" if s_res.success else "❌ Failed")
                md.append(f"| {stage_id} | {s_res.stage_name} | `{s_res.recommended_tools}` | {status_icon} | {len(s_res.findings)} | {s_res.execution_time_seconds:.1f}s |")
        md.append("")

        md.append("## 🔍 Detailed Security Findings & Action Plan")
        if not report.all_findings:
            md.append("🎉 *No security vulnerabilities discovered across audited stages.*")
        else:
            md.append("| ID | Severity | Stage | Tool | Title | CWE | SLA |")
            md.append("| :--- | :-: | :--- | :--- | :--- | :-: | :-: |")
            for f in sorted(report.all_findings, key=lambda x: x.severity.weight, reverse=True):
                sev_icon = {
                    Severity.CRITICAL: "🔴 CRITICAL",
                    Severity.HIGH: "🟠 HIGH",
                    Severity.MEDIUM: "🟡 MEDIUM",
                    Severity.LOW: "🔵 LOW",
                    Severity.INFO: "⚪ INFO"
                }.get(f.severity, f.severity.value)
                md.append(f"| `{f.id}` | {sev_icon} | Stage {f.stage_id} | {f.tool} | **{f.title}** | `{f.cwe or 'N/A'}` | {f.sla_days}d |")
            md.append("")

            md.append("### Detailed Remediation Guidance")
            for f in sorted(report.all_findings, key=lambda x: x.severity.weight, reverse=True)[:10]:
                md.append(f"#### [{f.severity.value}] {f.title} (`{f.id}`)")
                md.append(f"- **Target / File:** `{f.file_path or f.target or 'N/A'}`" + (f":{f.line_number}" if f.line_number else ""))
                md.append(f"- **Description:** {f.description}")
                if f.code_snippet:
                    md.append(f"```text\n{f.code_snippet}\n```")
                md.append(f"- **Remediation:** {f.remediation}")
                md.append("")

        md.append("---")
        md.append("*OmniSec Product Security Engine — Integrating Threat Dragon, ASVS, Semgrep, Trivy, Gitleaks, ZAP, WSTG, Nuclei, Amass, DefectDojo, OpenSSF Scorecard, and Wazuh.*")

        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
