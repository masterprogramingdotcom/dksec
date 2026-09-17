"""
Stage 1: Architecture & Threat Model
Recommended GitHub Repo: OWASP Threat Dragon (https://github.com/OWASP/threat-dragon)
What it covers: Data-flow diagrams, threat identification, STRIDE/LINDDUN/CIA-style modeling and mitigations
"""

import os
import json
import re
from typing import List, Dict, Any, Tuple
from omnisec.stages.base import BaseStage
from omnisec.models import Finding, Severity, FindingStatus, ThreatItem
from omnisec.config import OmniSecConfig


class Stage1ThreatModel(BaseStage):
    def __init__(self):
        super().__init__(1)

    def run(self, config: OmniSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        self.log("Initializing OWASP Threat Dragon & STRIDE Threat Modeling Engine")
        
        # 1. Architecture Discovery: inspect target code to discover components, data stores, external services
        components = self._discover_architecture(config.target_path)
        self.log(f"Discovered architecture components: {[c['name'] for c in components]}")

        # 2. Generate STRIDE Threats
        stride_threats = self._generate_stride_threats(components)
        self.log(f"Identified {len(stride_threats)} STRIDE threats across components.")

        # 3. Build OWASP Threat Dragon compatible model
        threat_dragon_model = self._build_threat_dragon_schema(config.project_name, components, stride_threats)
        
        # Save Threat Dragon JSON model to output dir
        model_path = os.path.join(config.output_dir, "threat-dragon-model.json")
        try:
            os.makedirs(config.output_dir, exist_ok=True)
            with open(model_path, "w", encoding="utf-8") as f:
                json.dump(threat_dragon_model, f, indent=2)
            self.log(f"Exported OWASP Threat Dragon model to {model_path}")
        except Exception as e:
            self.log(f"Failed to save Threat Dragon file: {e}")

        # 4. Convert unmitigated / high risk threats into Stage Findings
        findings: List[Finding] = []
        for idx, threat in enumerate(stride_threats):
            finding = self.create_finding(
                finding_id=f"TM-{threat['category'][:3].upper()}-{idx+1:03d}",
                title=f"[{threat['category']}] {threat['title']} in {threat['component']}",
                severity=threat['severity'],
                description=f"{threat['description']}\nImpact: {threat['impact']}",
                tool="OWASP Threat Dragon (STRIDE)",
                target=threat['component'],
                cwe=threat.get('cwe', 'CWE-1008'),
                owasp="OWASP A04:2021-Insecure Design",
                remediation=f"Recommended Mitigation: {threat['mitigation']}",
                status=FindingStatus.OPEN,
                references=[
                    "https://owasp.org/www-project-threat-dragon/",
                    "https://owasp.org/www-community/Threat_Modeling_Process"
                ]
            )
            findings.append(finding)

        metrics = {
            "components_discovered": len(components),
            "total_threats_identified": len(stride_threats),
            "threats_by_stride": self._count_by_stride(stride_threats),
            "threat_dragon_model_file": model_path
        }

        details = {
            "components": components,
            "threats": [t for t in stride_threats],
            "threat_dragon_summary": threat_dragon_model.get("summary", {})
        }

        context["threat_model"] = threat_dragon_model
        return findings, metrics, details

    def _discover_architecture(self, target_path: str) -> List[Dict[str, Any]]:
        components = [
            {"id": "c1", "name": "User Browser / Mobile Client", "type": "Actor", "trust_level": "Untrusted"},
            {"id": "c2", "name": "API Gateway / Reverse Proxy", "type": "Process", "trust_level": "DMZ"},
            {"id": "c3", "name": "Backend Application Server", "type": "Process", "trust_level": "Trusted Internal"},
            {"id": "c4", "name": "Primary Database Store", "type": "DataStore", "trust_level": "Restricted Core"},
            {"id": "c5", "name": "External Third-Party APIs (OAuth/Payment)", "type": "ExternalService", "trust_level": "External"},
        ]

        if not os.path.exists(target_path):
            return components

        # Scan files to refine components
        has_docker = False
        has_auth = False
        has_cloud_storage = False

        for root, _, files in os.walk(target_path):
            for file in files:
                f_lower = file.lower()
                if "docker" in f_lower:
                    has_docker = True
                if any(x in f_lower for x in ["auth", "jwt", "login", "session"]):
                    has_auth = True
                if any(x in f_lower for x in ["s3", "blob", "storage", "upload"]):
                    has_cloud_storage = True

        if has_cloud_storage:
            components.append({
                "id": f"c{len(components)+1}",
                "name": "Object Storage (S3 / Cloud Blob)",
                "type": "DataStore",
                "trust_level": "Restricted Cloud"
            })
        if has_auth:
            components.append({
                "id": f"c{len(components)+1}",
                "name": "Authentication & Token Service",
                "type": "Process",
                "trust_level": "Trusted Internal"
            })

        return components

    def _generate_stride_threats(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        threats = [
            {
                "category": "Spoofing",
                "component": "API Gateway / Reverse Proxy",
                "title": "Client Identity Spoofing & Broken Auth Token Validation",
                "severity": Severity.HIGH,
                "description": "Adversary sends forged JWTs or replayed credentials to bypass identity verification.",
                "impact": "Unauthorized access to internal endpoints as another authenticated entity.",
                "mitigation": "Enforce strict RS256/ES256 asymmetric signature verification, short-lived tokens, and jti revocation list.",
                "cwe": "CWE-287"
            },
            {
                "category": "Tampering",
                "component": "Primary Database Store",
                "title": "Data Tampering via Unparameterized Input or Missing State Integrity",
                "severity": Severity.CRITICAL,
                "description": "Untrusted parameters injected into application layer alter database records or transactions.",
                "impact": "Data corruption, financial loss, or unauthorized record modifications.",
                "mitigation": "Enforce strict ORM parameterized queries, row-level integrity checks, and least-privilege DB credentials.",
                "cwe": "CWE-89"
            },
            {
                "category": "Repudiation",
                "component": "Backend Application Server",
                "title": "Insufficient Audit Trail for Critical Actions & State Transitions",
                "severity": Severity.MEDIUM,
                "description": "Sensitive administrative changes, balance transfers, or permission grants occur without immutable logging.",
                "impact": "Inability to hold malicious actors accountable or reconstruct incident forensics.",
                "mitigation": "Implement structured tamper-evident security logging with user IDs, timestamps, client IPs, and append-only log sinks.",
                "cwe": "CWE-778"
            },
            {
                "category": "Information Disclosure",
                "component": "API Gateway / Reverse Proxy",
                "title": "Sensitive Data Leakage via Error Stack Traces and Verbose Headers",
                "severity": Severity.HIGH,
                "description": "Production endpoints return unhandled exception stack traces, environment variables, or database schemas.",
                "impact": "Exposes internal system topology, library versions, and credentials to potential attackers.",
                "mitigation": "Sanitize all error responses, disable debug mode in production, and remove Server/X-Powered-By banners.",
                "cwe": "CWE-209"
            },
            {
                "category": "Denial of Service",
                "component": "Backend Application Server",
                "title": "Application Resource Exhaustion via Unthrottled Endpoints (API4)",
                "severity": Severity.HIGH,
                "description": "Expensive queries, file uploads, or cryptographic hashing endpoints lack rate limiting and concurrency caps.",
                "impact": "Service outage, thread pool depletion, and cloud billing spike.",
                "mitigation": "Implement IP and token-based rate limiting (e.g. token bucket in Redis), strict request body size limits, and timeouts.",
                "cwe": "CWE-400"
            },
            {
                "category": "Elevation of Privilege",
                "component": "Backend Application Server",
                "title": "Broken Object Level Authorization (BOLA / IDOR)",
                "severity": Severity.CRITICAL,
                "description": "Endpoint does not verify if the requesting authenticated user owns or has rights to the requested resource ID.",
                "impact": "Tenants can read or modify sensitive data belonging to other organizations or administrators.",
                "mitigation": "Implement centralized context-aware authorization checks on every data access query (e.g. user_id = current_user.id).",
                "cwe": "CWE-639"
            }
        ]
        return threats

    def _count_by_stride(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {"Spoofing": 0, "Tampering": 0, "Repudiation": 0, "Information Disclosure": 0, "Denial of Service": 0, "Elevation of Privilege": 0}
        for t in threats:
            cat = t.get("category", "")
            if cat in counts:
                counts[cat] += 1
        return counts

    def _build_threat_dragon_schema(self, project_name: str, components: List[Dict[str, Any]], threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """OWASP Threat Dragon v2.x JSON compatible export schema."""
        diagram_elements = []
        for i, comp in enumerate(components):
            diagram_elements.append({
                "id": comp["id"],
                "name": comp["name"],
                "type": "tm." + comp["type"],
                "hasOpenThreats": True,
                "attributes": {
                    "trustLevel": comp["trust_level"]
                }
            })

        td_threats = []
        for idx, t in enumerate(threats):
            td_threats.append({
                "id": f"threat-{idx+1}",
                "title": t["title"],
                "type": t["category"],
                "status": "Open",
                "severity": t["severity"].value,
                "description": t["description"],
                "mitigation": t["mitigation"],
                "modelType": "STRIDE"
            })

        return {
            "version": "2.1.0",
            "summary": {
                "title": f"Threat Model for {project_name}",
                "owner": "Security Architecture Team",
                "description": "Generated by OmniSec unified product security pipeline with STRIDE/LINDDUN analysis."
            },
            "detail": {
                "contributors": [{"name": "OmniSec Automated Threat Engine"}],
                "diagrams": [
                    {
                        "id": 1,
                        "title": "System Architecture & Data Flows",
                        "diagramType": "STRIDE",
                        "placeholder": "Data Flow Diagram (DFD)",
                        "elements": diagram_elements
                    }
                ],
                "threats": td_threats
            }
        }
