"""
Notification and Alert Dispatcher for DKSec Security Platform.
Supports Slack, Microsoft Teams, Discord, and Generic JSON Webhooks.
"""

import os
import json
import logging
from typing import Optional, Dict, Any
import requests

from dksec.models import DKSecReport, GateVerdict

logger = logging.getLogger("dksec.notifications")


def dispatch_webhook(
    report: DKSecReport,
    webhook_url: Optional[str] = None,
    custom_message: Optional[str] = None
) -> bool:
    url = webhook_url or os.environ.get("DKSEC_WEBHOOK_URL")
    if not url:
        return False

    approved = report.gate_verdict.approved
    status = report.gate_verdict.status
    score = report.overall_score
    crit_count = report.severity_counts.get("CRITICAL", 0)
    high_count = report.severity_counts.get("HIGH", 0)
    med_count = report.severity_counts.get("MEDIUM", 0)
    low_count = report.severity_counts.get("LOW", 0)

    target_name = report.target_url or report.target_path or "Target Application"
    color = "#10b981" if approved else "#ef4444"
    status_emoji = "✅" if approved else "🚨"
    score_str = f"{score:.1f}" if score is not None else "N/A"

    url_lower = url.lower()

    try:
        if "slack.com" in url_lower:
            payload = {
                "text": f"{status_emoji} *DKSec Release Gate: {status}* for `{target_name}` (Score: {score_str}/100)",
                "attachments": [
                    {
                        "color": color,
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*Target:* `{target_name}`\n*Decision:* *{status}* | *Score:* `{score_str}/100`\n"\
                                            f"🔴 *Critical:* {crit_count} | 🟠 *High:* {high_count} | 🟡 *Medium:* {med_count} | 🔵 *Low:* {low_count}"
                                }
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"Scanned by DKSec Enterprise Orchestrator • {len(report.all_findings)} Total Issues Identified"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        elif "discord.com" in url_lower:
            dec_color = int(color.lstrip("#"), 16)
            payload = {
                "content": f"{status_emoji} **DKSec Security Scan Completed for {target_name}**",
                "embeds": [
                    {
                        "title": f"Security Release Gate: {status}",
                        "description": f"Target: `{target_name}`\nSecurity Posture Score: **{score_str}/100**",
                        "color": dec_color,
                        "fields": [
                            {"name": "Critical", "value": str(crit_count), "inline": True},
                            {"name": "High", "value": str(high_count), "inline": True},
                            {"name": "Medium", "value": str(med_count), "inline": True},
                            {"name": "Low", "value": str(low_count), "inline": True},
                            {"name": "Total Issues", "value": str(len(report.all_findings)), "inline": True}
                        ],
                        "footer": {"text": "DKSec Application Security Platform"}
                    }
                ]
            }
        elif "office.com" in url_lower or "webhook.office" in url_lower:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color.lstrip("#"),
                "summary": f"DKSec Scan: {status}",
                "sections": [
                    {
                        "activityTitle": f"{status_emoji} DKSec Release Gate: {status}",
                        "activitySubtitle": f"Target: {target_name}",
                        "facts": [
                            {"name": "Security Score", "value": f"{score_str} / 100"},
                            {"name": "Critical Issues", "value": str(crit_count)},
                            {"name": "High Issues", "value": str(high_count)},
                            {"name": "Medium Issues", "value": str(med_count)},
                            {"name": "Total Findings", "value": str(len(report.all_findings))}
                        ],
                        "markdown": True
                    }
                ]
            }
        else:
            payload = {
                "event": "dksec.scan.completed",
                "timestamp": report.generated_at,
                "target": target_name,
                "gate_status": status,
                "gate_approved": approved,
                "security_score": score,
                "counts": {
                    "critical": crit_count,
                    "high": high_count,
                    "medium": med_count,
                    "low": low_count,
                    "total": len(report.all_findings)
                },
                "reasons": report.gate_verdict.reasons,
                "top_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "cwe": f.cwe,
                        "tool": f.tool
                    }
                    for f in report.all_findings[:5]
                ]
            }

        headers = {"Content-Type": "application/json"}
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        return resp.status_code in (200, 201, 204)
    except Exception as e:
        logger.warning(f"Failed to dispatch security notification webhook: {e}")
        return False
