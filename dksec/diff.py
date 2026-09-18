"""
Delta and Regression Analysis Engine for DKSec.
Compares scan reports to track newly introduced regressions, resolved vulnerabilities,
and posture score trends across CI/CD pipeline runs.
"""

import json
import os
import logging
from typing import Dict, Any, List, Optional
from dksec.models import DKSecReport, Finding, Severity

logger = logging.getLogger("dksec.diff")


def _finding_fingerprint(f_dict: Dict[str, Any]) -> str:
    """Creates a consistent fingerprint for finding comparison across scans."""
    title = f_dict.get("title", "").strip().lower()
    cwe = (f_dict.get("cwe") or "").strip().lower()
    target = (f_dict.get("target") or f_dict.get("file_path") or "").strip().lower()
    return f"{cwe}:{title}:{target}"


def compare_reports(current_report: DKSecReport, previous_report_path: str) -> Optional[Dict[str, Any]]:
    """
    Compares the current scan report with a previous JSON report.
    Returns delta analytics: new, resolved, persistent findings, and score trends.
    """
    if not os.path.exists(previous_report_path):
        logger.warning(f"Previous report not found at {previous_report_path}")
        return None

    try:
        with open(previous_report_path, "r", encoding="utf-8") as f:
            prev_data = json.load(f)
    except Exception as e:
        logger.warning(f"Failed to read previous report JSON: {e}")
        return None

    prev_findings = prev_data.get("findings", [])
    curr_findings = [f.to_dict() for f in current_report.all_findings]

    prev_map = {_finding_fingerprint(f): f for f in prev_findings}
    curr_map = {_finding_fingerprint(f): f for f in curr_findings}

    new_keys = set(curr_map.keys()) - set(prev_map.keys())
    resolved_keys = set(prev_map.keys()) - set(curr_map.keys())
    persistent_keys = set(curr_map.keys()) & set(prev_map.keys())

    new_findings = [curr_map[k] for k in new_keys]
    resolved_findings = [prev_map[k] for k in resolved_keys]
    persistent_findings = [curr_map[k] for k in persistent_keys]

    prev_score = prev_data.get("security_posture_score")
    curr_score = current_report.security_posture_score
    score_delta = (curr_score - prev_score) if (curr_score is not None and prev_score is not None) else None

    diff_summary = {
        "previous_report_path": previous_report_path,
        "previous_generated_at": prev_data.get("generated_at"),
        "previous_score": prev_score,
        "current_score": curr_score,
        "score_delta": score_delta,
        "previous_gate": prev_data.get("gate_verdict", {}).get("status", "UNKNOWN"),
        "current_gate": current_report.gate_verdict.status,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "persistent_count": len(persistent_findings),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings,
    }

    return diff_summary


def format_terminal_diff(diff_summary: Dict[str, Any]) -> str:
    """Formats the delta summary for CLI display."""
    lines = [
        "============================================================================",
        "📊  DKSEC DELTA & REGRESSION SCAN ANALYSIS",
        f"    Baseline Report: {diff_summary.get('previous_report_path')}",
    ]

    delta = diff_summary.get("score_delta")
    if delta is not None:
        delta_str = f"+{delta:.1f}" if delta >= 0 else f"{delta:.1f}"
        lines.append(f"    Posture Trend:   {diff_summary.get('previous_score', 0):.1f} ➔ {diff_summary.get('current_score', 0):.1f} ({delta_str})")
    
    lines.extend([
        f"    🔴 New Regressions:     {diff_summary.get('new_count', 0)}",
        f"    🟢 Resolved Issues:     {diff_summary.get('resolved_count', 0)}",
        f"    ⚪ Unresolved Debt:     {diff_summary.get('persistent_count', 0)}",
        "============================================================================",
    ])

    if diff_summary.get("resolved_findings"):
        lines.append("  🎉 Recently Resolved Vulnerabilities:")
        for rf in diff_summary["resolved_findings"][:5]:
            lines.append(f"     ✔ [{rf.get('severity')}] {rf.get('title')}")

    if diff_summary.get("new_findings"):
        lines.append("  🚨 Newly Introduced Regressions:")
        for nf in diff_summary["new_findings"][:5]:
            lines.append(f"     ✖ [{nf.get('severity')}] {nf.get('title')}")

    return "\n".join(lines)
