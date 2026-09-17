"""
OASIS SARIF v2.1.0 Standard Exporter for OmniSec.
Generates compliant SARIF for GitHub Code Scanning, GitLab Security Dashboard, and SonarQube.
"""

import os
import json
from typing import Dict, Any
from omnisec.models import OmniSecReport


class SarifReporter:
    @staticmethod
    def generate(report: OmniSecReport, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        rules = []
        rule_indices = {}
        results = []

        for idx, f in enumerate(report.all_findings):
            rule_id = f.cwe or f"SEC-{f.id}"
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.title[:64],
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "helpUri": f.references[0] if f.references else "https://owasp.org",
                    "help": {
                        "text": f"Remediation: {f.remediation}",
                        "markdown": f"### Remediation Guidance\n{f.remediation}\n\n*References:*\n" + "\n".join(f"- {r}" for r in f.references)
                    },
                    "properties": {
                        "tags": ["security", f"stage-{f.stage_id}", f.tool.lower()],
                        "security-severity": str(round(f.severity.weight, 1))
                    }
                })

            result_entry: Dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": f.severity.sarif_level,
                "message": {
                    "text": f"{f.title}: {f.description}"
                },
                "locations": []
            }

            if f.file_path:
                result_entry["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": f.line_number or 1,
                            "snippet": {
                                "text": f.code_snippet or ""
                            }
                        }
                    }
                })

            results.append(result_entry)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "OmniSec Unified Product Security Platform",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/OWASP",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

        with open(output_path, "w", encoding="utf-8") as fl:
            json.dump(sarif_doc, fl, indent=2)

        return output_path
