"""
CycloneDX v1.5 JSON Software Bill of Materials (SBOM) Exporter for DKSec.
Complies with NTIA / CISA minimum elements and CycloneDX 1.5 schema.
"""

import os
import json
import uuid
import datetime
from typing import List
from dksec.models import DKSecReport, SBOMComponent, Severity


class CycloneDXReporter:
    @staticmethod
    def generate(report: DKSecReport, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        components_json = []
        for comp in report.sbom_components:
            components_json.append(comp.to_cyclonedx())

        # Map discovered SCA vulnerabilities to CycloneDX format
        vulnerabilities_json = []
        for f in report.all_findings:
            if f.stage_id == 3 and f.id.startswith("SCA-"):
                cve_id = f.id.replace("SCA-", "")
                vulnerabilities_json.append({
                    "id": cve_id,
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                    "ratings": [
                        {
                            "severity": f.severity.value.lower(),
                            "score": 9.8 if f.severity == Severity.CRITICAL else (7.5 if f.severity == Severity.HIGH else 5.0),
                            "method": "CVSSv3"
                        }
                    ],
                    "description": f.description,
                    "recommendation": f.remediation,
                    "affects": [{"ref": f"pkg:generic/{f.title.split()[2]}" if len(f.title.split()) > 2 else "pkg:generic/unknown"}]
                })

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "DKSec",
                        "name": "DKSec Unified Product Security Platform",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": report.project_name,
                    "version": "1.0.0"
                }
            },
            "components": components_json,
            "vulnerabilities": vulnerabilities_json
        }

        with open(output_path, "w", encoding="utf-8") as fl:
            json.dump(bom, fl, indent=2)

        return output_path
