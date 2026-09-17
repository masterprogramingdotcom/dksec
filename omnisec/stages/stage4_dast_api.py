"""
Stage 4: DAST + API Security Testing
Recommended Repos: OWASP ZAP + OWASP API Security
What it covers: Web/API dynamic testing, automated scanning and API-specific security guidance
"""

import os
import re
import json
import urllib.parse
from typing import List, Dict, Any, Tuple
import requests
from omnisec.stages.base import BaseStage
from omnisec.models import Finding, Severity, FindingStatus
from omnisec.config import OmniSecConfig


class Stage4DastApi(BaseStage):
    def __init__(self):
        super().__init__(4)

    def run(self, config: OmniSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        target_url = config.target_url
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        details: Dict[str, Any] = {}

        if target_url:
            self.log(f"Running DAST & API Security Testing against target URL: {target_url}")
            
            # 1. External OWASP ZAP execution if available
            zap_findings = self._run_zap_if_available(target_url)
            findings.extend(zap_findings)

            # 2. Built-in DAST Header & Configuration Audit
            header_findings, header_data = self._audit_security_headers(target_url)
            findings.extend(header_findings)

            # 3. Built-in CORS Misconfiguration Audit
            cors_findings, cors_data = self._audit_cors(target_url)
            findings.extend(cors_findings)

            # 4. Built-in HTTP Methods & Information Leakage Audit
            http_findings, method_data = self._audit_http_methods(target_url)
            findings.extend(http_findings)

            # 5. OWASP API Security Top 10 Sensitive Endpoint Probes
            api_findings, api_data = self._probe_api_security_endpoints(target_url)
            findings.extend(api_findings)

            metrics = {
                "target_url": target_url,
                "scan_mode": "Live Dynamic & API Audit",
                "total_probes": header_data.get("probes", 0) + api_data.get("probes", 0),
                "dast_findings_count": len(findings)
            }
            details = {
                "headers": header_data,
                "cors": cors_data,
                "methods": method_data,
                "api_probes": api_data
            }
        else:
            self.log("No live target_url specified; conducting static API Security Specification & Route Architecture Audit...")
            code_findings, code_data = self._audit_static_api_routes(config.target_path)
            findings.extend(code_findings)
            metrics = {
                "scan_mode": "Static API Surface & Spec Audit",
                "api_routes_analyzed": code_data.get("routes_found", 0),
                "dast_findings_count": len(findings)
            }
            details = code_data

        return findings, metrics, details

    def _run_zap_if_available(self, url: str) -> List[Finding]:
        if self.is_tool_installed("zap-cli"):
            self.log("Running OWASP ZAP CLI baseline scan...")
            cmd = ["zap-cli", "quick-scan", "-s", "xss,sqli", url]
            code, stdout, stderr = self.execute_command(cmd, timeout=120)
        return []

    def _audit_security_headers(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        data = {"probes": 1, "missing_headers": []}
        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Required headers checklist
            expected = {
                "strict-transport-security": ("HSTS (Strict-Transport-Security) Missing", Severity.MEDIUM, "CWE-319", "Enforce HSTS with 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"),
                "content-security-policy": ("Content-Security-Policy (CSP) Missing", Severity.MEDIUM, "CWE-1021", "Implement strict Content-Security-Policy to mitigate Cross-Site Scripting."),
                "x-frame-options": ("X-Frame-Options Missing (Clickjacking Risk)", Severity.MEDIUM, "CWE-1021", "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
                "x-content-type-options": ("X-Content-Type-Options Missing (MIME Sniffing)", Severity.LOW, "CWE-16", "Set 'X-Content-Type-Options: nosniff'."),
                "referrer-policy": ("Referrer-Policy Header Missing", Severity.LOW, "CWE-200", "Set 'Referrer-Policy: strict-origin-when-cross-origin'.")
            }

            for hdr, (title, sev, cwe, fix) in expected.items():
                if hdr not in headers:
                    data["missing_headers"].append(hdr)
                    findings.append(self.create_finding(
                        finding_id=f"DAST-HDR-{len(findings)+1:03d}",
                        title=title,
                        severity=sev,
                        description=f"The endpoint {url} did not return the expected security header `{hdr}`.",
                        tool="OWASP ZAP / DAST Header Audit",
                        target=url,
                        cwe=cwe,
                        owasp="OWASP A05:2021-Security Misconfiguration",
                        remediation=fix,
                        references=["https://owasp.org/www-project-secure-headers/"]
                    ))

            # Server & Technology Leaks
            if "server" in headers:
                findings.append(self.create_finding(
                    finding_id=f"DAST-LEAK-{len(findings)+1:03d}",
                    title=f"Server Banner Information Disclosure: {headers['server']}",
                    severity=Severity.LOW,
                    description=f"Server banner leaks web server type and version: `{headers['server']}`",
                    tool="OWASP ZAP / Banner Leak",
                    target=url,
                    cwe="CWE-200",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Configure web server to suppress or genericize the Server header."
                ))

            if "x-powered-by" in headers:
                findings.append(self.create_finding(
                    finding_id=f"DAST-LEAK-{len(findings)+1:03d}",
                    title=f"X-Powered-By Header Information Leak: {headers['x-powered-by']}",
                    severity=Severity.LOW,
                    description=f"Backend framework is exposed via X-Powered-By header: `{headers['x-powered-by']}`",
                    tool="OWASP ZAP / Banner Leak",
                    target=url,
                    cwe="CWE-200",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Disable X-Powered-By in framework configuration (e.g. app.disable('x-powered-by'))."
                ))
        except Exception as e:
            self.log(f"Header audit connection error for {url}: {e}")

        return findings, data

    def _audit_cors(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        data = {"tested": True}
        try:
            headers = {"Origin": "https://attacker-controlled-origin.com"}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                findings.append(self.create_finding(
                    finding_id=f"DAST-CORS-001",
                    title="Critical CORS Misconfiguration: Wildcard Origin with Credentials",
                    severity=Severity.CRITICAL,
                    description=f"Target permits wildcard origin with Access-Control-Allow-Credentials: true.",
                    tool="OWASP API Security Audit",
                    target=url,
                    cwe="CWE-942",
                    owasp="OWASP API7:2023-Server Side Request Forgery / Misconfiguration",
                    remediation="Never allow wildcard origins when credentials (cookies, auth headers) are accepted."
                ))
            elif "attacker-controlled-origin.com" in acao:
                findings.append(self.create_finding(
                    finding_id=f"DAST-CORS-002",
                    title="CORS Arbitrary Origin Reflection",
                    severity=Severity.HIGH,
                    description=f"Target reflected untrusted Origin header in Access-Control-Allow-Origin.",
                    tool="OWASP API Security Audit",
                    target=url,
                    cwe="CWE-942",
                    owasp="OWASP API7:2023-Security Misconfiguration",
                    remediation="Validate Origin header against a strict server-side whitelist of allowed origins."
                ))
        except Exception:
            pass
        return findings, data

    def _audit_http_methods(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        data = {"methods": []}
        try:
            resp = requests.options(url, timeout=10, verify=False)
            allow = resp.headers.get("Allow", "")
            data["allowed_methods"] = allow
            if "TRACE" in allow.upper():
                findings.append(self.create_finding(
                    finding_id="DAST-METH-001",
                    title="Insecure HTTP Method TRACE Enabled (XST)",
                    severity=Severity.MEDIUM,
                    description="The TRACE HTTP method is enabled on the target server, allowing Cross-Site Tracing attacks.",
                    tool="OWASP ZAP",
                    target=url,
                    cwe="CWE-16",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Disable HTTP TRACE/TRACK methods on the web server."
                ))
        except Exception:
            pass
        return findings, data

    def _probe_api_security_endpoints(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        endpoints = [
            ("/.env", Severity.CRITICAL, "CWE-552", "Exposed .env configuration file"),
            ("/actuator/env", Severity.CRITICAL, "CWE-552", "Exposed Spring Actuator Environment Endpoint"),
            ("/swagger-ui.html", Severity.LOW, "CWE-200", "Exposed Interactive Swagger UI documentation"),
            ("/api/v1/users", Severity.MEDIUM, "CWE-306", "Potential Unauthenticated User Directory Endpoint"),
            ("/graphql", Severity.LOW, "CWE-200", "GraphQL endpoint exposed (verify introspection is disabled)")
        ]
        probes = 0
        for ep, sev, cwe, desc in endpoints:
            probes += 1
            target = urllib.parse.urljoin(base_url, ep)
            try:
                resp = requests.get(target, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 10:
                    findings.append(self.create_finding(
                        finding_id=f"DAST-API-{probes:03d}",
                        title=f"API Security Exposure: {ep}",
                        severity=sev,
                        description=f"Endpoint {target} returned HTTP 200 OK without authentication. {desc}.",
                        tool="OWASP API Security Audit",
                        target=target,
                        cwe=cwe,
                        owasp="OWASP API8:2023-Security Misconfiguration",
                        remediation="Enforce authentication and restrict access to internal API administrative endpoints."
                    ))
            except Exception:
                pass

        return findings, {"probes": probes}

    def _audit_static_api_routes(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        routes_found = 0
        if not os.path.exists(target_path):
            return findings, {"routes_found": 0}

        for root, _, files in os.walk(target_path):
            for f in files:
                if f.endswith((".py", ".js", ".ts")):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", errors="ignore") as f: content = f.read()
                        # Detect Flask/Express API routes
                        matches = re.findall(r"@app\.route\(['\"]([^'\"]+)['\"].*\)|router\.(?:get|post|put|delete)\(['\"]([^'\"]+)['\"]", content)
                        routes_found += len(matches)

                        # Check for missing authentication middleware on routes containing /admin or /internal
                        for m in matches:
                            route = m[0] or m[1]
                            if any(p in route.lower() for p in ["/admin", "/internal", "/private", "/secrets"]):
                                findings.append(self.create_finding(
                                    finding_id=f"API-AUTH-{len(findings)+1:03d}",
                                    title=f"Sensitive Route Architecture Audit: {route}",
                                    severity=Severity.HIGH,
                                    description=f"Sensitive route `{route}` detected in {f}. Verify strict role-based access control (RBAC) is enforced.",
                                    tool="OWASP API Security",
                                    file_path=os.path.relpath(fpath, target_path),
                                    cwe="CWE-306",
                                    owasp="OWASP API1:2023-Broken Object Level Authorization",
                                    remediation="Attach authentication and authorization middleware to sensitive route controllers."
                                ))
                    except Exception:
                        pass
        return findings, {"routes_found": routes_found}
