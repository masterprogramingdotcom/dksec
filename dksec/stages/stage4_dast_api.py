"""
Stage 4: DAST + API Security Testing (Advanced Enterprise Edition)
Recommended Repos: OWASP ZAP + OWASP API Security
What it covers: Web/API dynamic testing, TLS audit, OpenAPI/Swagger 2.0/3.0 security audit
"""

import os
import re
import json
import socket
import ssl
import urllib.parse
from typing import List, Dict, Any, Tuple
import requests
import yaml
from dksec.stages.base import BaseStage
from dksec.models import Finding, Severity, FindingStatus
from dksec.config import DKSecConfig


class Stage4DastApi(BaseStage):
    def __init__(self):
        super().__init__(4)

    def run(self, config: DKSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        target_url = config.target_url
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        details: Dict[str, Any] = {}

        # 1. OpenAPI / Swagger Specification Security Audit (Static & Dynamic)
        spec_findings, spec_data = self._audit_openapi_specifications(config.target_path)
        findings.extend(spec_findings)
        details["openapi_spec"] = spec_data

        if target_url:
            self.log(f"Running Advanced Dynamic API & DAST Audit against target URL: {target_url}")

            # 2. TLS/SSL Security & Certificate Validation
            tls_findings, tls_data = self._audit_tls_security(target_url)
            findings.extend(tls_findings)
            details["tls"] = tls_data

            # 3. HTTP Security Headers
            header_findings, header_data = self._audit_security_headers(target_url)
            findings.extend(header_findings)
            details["headers"] = header_data

            # 4. CORS Misconfiguration Audit
            cors_findings, cors_data = self._audit_cors(target_url)
            findings.extend(cors_findings)
            details["cors"] = cors_data

            # 5. Dangerous HTTP Methods
            http_findings, method_data = self._audit_http_methods(target_url)
            findings.extend(http_findings)
            details["methods"] = method_data

            # 6. OWASP API Top 10 Sensitive Exposure Probes
            api_findings, api_data = self._probe_api_endpoints(target_url)
            findings.extend(api_findings)
            details["api_probes"] = api_data

            metrics = {
                "target_url": target_url,
                "tls_protocol": tls_data.get("protocol", "N/A"),
                "openapi_endpoints_audited": spec_data.get("endpoints_found", 0),
                "total_probes_sent": header_data.get("probes", 0) + api_data.get("probes", 0),
                "dast_findings_count": len(findings)
            }
        else:
            self.log("No live target_url provided; auditing static API route definitions & OpenAPI surface...")
            route_findings, route_data = self._audit_static_routes(config.target_path)
            findings.extend(route_findings)
            metrics = {
                "scan_mode": "Static API Surface & Spec Audit",
                "openapi_endpoints_audited": spec_data.get("endpoints_found", 0),
                "code_routes_audited": route_data.get("routes_found", 0),
                "dast_findings_count": len(findings)
            }
            details["static_routes"] = route_data

        return findings, metrics, details

    def _audit_openapi_specifications(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        endpoints_found = 0
        spec_candidates = [
            "openapi.json", "openapi.yaml", "openapi.yml",
            "swagger.json", "swagger.yaml", "swagger.yml"
        ]

        if not os.path.exists(target_path):
            return findings, {"endpoints_found": 0}

        for root, _, files in os.walk(target_path):
            for f in files:
                if f.lower() in spec_candidates:
                    fpath = os.path.join(root, f)
                    rel_path = os.path.relpath(fpath, target_path)
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            if f.endswith(".json"):
                                spec = json.load(fl)
                            else:
                                spec = yaml.safe_load(fl)

                        paths = spec.get("paths", {})
                        endpoints_found += len(paths)
                        security_defs = spec.get("components", {}).get("securitySchemes", {}) or spec.get("securityDefinitions", {})

                        # Check 1: Missing Global or Defined Security Scheme
                        if not security_defs:
                            findings.append(self.create_finding(
                                finding_id=f"API-SPEC-NOSEC",
                                title="OpenAPI Spec: Missing SecuritySchemes Definition",
                                severity=Severity.HIGH,
                                description=f"The API specification {rel_path} contains no security schemes (OAuth2, Bearer, ApiKey).",
                                tool="OWASP API Security Analyzer",
                                file_path=rel_path,
                                cwe="CWE-306",
                                owasp="OWASP API2:2023-Broken Authentication",
                                remediation="Define global securitySchemes (e.g. Bearer JWT / OAuth2) in your OpenAPI document."
                            ))

                        # Check 2: Sensitive admin endpoints without security
                        for path, methods in paths.items():
                            if any(k in path.lower() for k in ["/admin", "/internal", "/private", "/users", "/keys"]):
                                for method, m_data in methods.items():
                                    if method.lower() in ("get", "post", "put", "delete"):
                                        if not m_data.get("security") and not spec.get("security"):
                                            findings.append(self.create_finding(
                                                finding_id=f"API-SPEC-UNAUTH-{path.replace('/', '_')}",
                                                title=f"OpenAPI Spec: Sensitive Route Without Authentication ({method.upper()} {path})",
                                                severity=Severity.HIGH,
                                                description=f"Route `{method.upper()} {path}` is marked unauthenticated in {rel_path}.",
                                                tool="OWASP API Security Analyzer",
                                                file_path=rel_path,
                                                cwe="CWE-306",
                                                owasp="OWASP API1:2023-Broken Object Level Authorization",
                                                remediation="Attach a security requirement to sensitive route definitions in OpenAPI."
                                            ))
                    except Exception:
                        pass

        return findings, {"endpoints_found": endpoints_found}

    def _audit_tls_security(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        data = {"protocol": "N/A"}
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            findings.append(self.create_finding(
                finding_id="DAST-TLS-CLEARTEXT",
                title="Cleartext HTTP Scheme Enforced (Missing Transport Encryption)",
                severity=Severity.HIGH,
                description=f"The target URL {url} uses unencrypted HTTP protocol.",
                tool="OWASP ZAP / Transport Security",
                target=url,
                cwe="CWE-319",
                owasp="OWASP A02:2021-Cryptographic Failures",
                remediation="Enforce HTTPS/TLS 1.3 across all production endpoints and redirect HTTP to HTTPS."
            ))
            return findings, data

        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ver = ssock.version()
                    cipher = ssock.cipher()
                    data["protocol"] = ver
                    data["cipher"] = cipher[0] if cipher else "Unknown"

                    if ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(self.create_finding(
                            finding_id="DAST-TLS-LEGACY",
                            title=f"Insecure Legacy TLS Protocol Supported: {ver}",
                            severity=Severity.HIGH,
                            description=f"Target negotiated deprecated protocol {ver}.",
                            tool="OWASP ZAP / SSL Audit",
                            target=url,
                            cwe="CWE-326",
                            owasp="OWASP A02:2021-Cryptographic Failures",
                            remediation="Disable TLS 1.0/1.1; enforce TLS 1.2+ with forward secrecy ciphers."
                        ))
        except Exception:
            pass
        return findings, data

    def _audit_security_headers(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        data = {"probes": 1, "missing": []}
        try:
            r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            rules = [
                ("strict-transport-security", "HSTS Header Missing", Severity.MEDIUM, "CWE-319", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"),
                ("content-security-policy", "Content-Security-Policy (CSP) Missing", Severity.MEDIUM, "CWE-1021", "Implement strict CSP to prevent XSS."),
                ("x-frame-options", "X-Frame-Options Header Missing (Clickjacking Risk)", Severity.MEDIUM, "CWE-1021", "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
                ("x-content-type-options", "X-Content-Type-Options Missing (MIME Sniffing)", Severity.LOW, "CWE-16", "Set 'X-Content-Type-Options: nosniff'."),
                ("referrer-policy", "Referrer-Policy Header Missing", Severity.LOW, "CWE-200", "Set 'Referrer-Policy: strict-origin-when-cross-origin'.")
            ]

            for hdr, title, sev, cwe, fix in rules:
                if hdr not in hdrs:
                    data["missing"].append(hdr)
                    findings.append(self.create_finding(
                        finding_id=f"DAST-HDR-{len(findings)+1:03d}",
                        title=title,
                        severity=sev,
                        description=f"Endpoint {url} did not return the standard security header `{hdr}`.",
                        tool="OWASP ZAP / Header Audit",
                        target=url,
                        cwe=cwe,
                        owasp="OWASP A05:2021-Security Misconfiguration",
                        remediation=fix,
                        references=["https://owasp.org/www-project-secure-headers/"]
                    ))

            if "server" in hdrs:
                findings.append(self.create_finding(
                    finding_id="DAST-BANNER-SERVER",
                    title=f"Server Banner Information Leak: {hdrs['server']}",
                    severity=Severity.LOW,
                    description=f"Web server version exposed: `{hdrs['server']}`",
                    tool="OWASP ZAP",
                    target=url,
                    cwe="CWE-200",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Suppress the Server response header."
                ))

            if "x-powered-by" in hdrs:
                findings.append(self.create_finding(
                    finding_id="DAST-BANNER-XPOWERED",
                    title=f"X-Powered-By Header Information Leak: {hdrs['x-powered-by']}",
                    severity=Severity.LOW,
                    description=f"Backend framework exposed: `{hdrs['x-powered-by']}`",
                    tool="OWASP ZAP",
                    target=url,
                    cwe="CWE-200",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Disable X-Powered-By header in web framework."
                ))
        except Exception:
            pass
        return findings, data

    def _audit_cors(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        try:
            r = requests.get(url, headers={"Origin": "https://attacker.example.com"}, timeout=5, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                findings.append(self.create_finding(
                    finding_id="DAST-CORS-CRIT",
                    title="Critical CORS Misconfiguration: Wildcard Origin With Credentials",
                    severity=Severity.CRITICAL,
                    description="Target permits wildcard Access-Control-Allow-Origin: * while allowing credentials.",
                    tool="OWASP API Security Audit",
                    target=url,
                    cwe="CWE-942",
                    owasp="OWASP API7:2023-Security Misconfiguration",
                    remediation="Never pair Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
                ))
            elif "attacker.example.com" in acao:
                findings.append(self.create_finding(
                    finding_id="DAST-CORS-REFLECT",
                    title="CORS Origin Reflection Vulnerability",
                    severity=Severity.HIGH,
                    description="Target reflects untrusted Origin header without server-side allowlist validation.",
                    tool="OWASP API Security Audit",
                    target=url,
                    cwe="CWE-942",
                    owasp="OWASP API7:2023-Security Misconfiguration",
                    remediation="Validate Origin header strictly against an explicit server-side allowlist."
                ))
        except Exception:
            pass
        return findings, {"audited": True}

    def _audit_http_methods(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        try:
            r = requests.options(url, timeout=5, verify=False)
            allowed = r.headers.get("Allow", "")
            if "TRACE" in allowed.upper():
                findings.append(self.create_finding(
                    finding_id="DAST-METHOD-TRACE",
                    title="Dangerous HTTP Method Enabled: TRACE (Cross-Site Tracing Risk)",
                    severity=Severity.MEDIUM,
                    description="The TRACE method is enabled on web server.",
                    tool="OWASP ZAP",
                    target=url,
                    cwe="CWE-16",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Disable HTTP TRACE and TRACK methods on the web server."
                ))
        except Exception:
            pass
        return findings, {}

    def _probe_api_endpoints(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        probes = [
            ("/.env", Severity.CRITICAL, "CWE-552", "Exposed .env Configuration File (Credentials Theft)"),
            ("/actuator/metrics", Severity.MEDIUM, "CWE-200", "Exposed Spring Actuator Metrics"),
            ("/swagger-ui.html", Severity.LOW, "CWE-200", "Exposed Swagger UI Interactive Portal"),
            ("/api/v1/users", Severity.MEDIUM, "CWE-306", "Potential Unauthenticated User Directory Endpoint"),
            ("/graphql", Severity.LOW, "CWE-200", "Exposed GraphQL Endpoint (Verify Introspection Disabled)")
        ]
        count = 0
        for ep, sev, cwe, desc in probes:
            count += 1
            target = urllib.parse.urljoin(base_url, ep)
            try:
                r = requests.get(target, timeout=4, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 10:
                    findings.append(self.create_finding(
                        finding_id=f"DAST-EXPOSE-{count:03d}",
                        title=f"API Security Exposure: {desc}",
                        severity=sev,
                        description=f"Endpoint {target} returned HTTP 200 OK without authentication.",
                        tool="OWASP API Security Prober",
                        target=target,
                        cwe=cwe,
                        owasp="OWASP API8:2023-Security Misconfiguration",
                        remediation="Apply authentication middleware and block external access to management endpoints."
                    ))
            except Exception:
                pass
        return findings, {"probes": count}

    def _audit_static_routes(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        routes = 0
        if not os.path.exists(target_path):
            return findings, {"routes_found": 0}

        for root, _, files in os.walk(target_path):
            for f in files:
                if f.endswith((".py", ".js", ".ts")):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()
                            matches = re.findall(r"@app\.route\(['\"]([^'\"]+)['\"].*\)|router\.(?:get|post|put|delete)\(['\"]([^'\"]+)['\"]", content)
                            routes += len(matches)
                            for m in matches:
                                route = m[0] or m[1]
                                if any(x in route.lower() for x in ["/admin", "/internal", "/debug", "/keys"]):
                                    findings.append(self.create_finding(
                                        finding_id=f"API-ROUTE-SENSITIVE-{len(findings)+1:03d}",
                                        title=f"Sensitive Administrative API Route: {route}",
                                        severity=Severity.HIGH,
                                        description=f"Administrative endpoint `{route}` declared in {f}. Verify explicit RBAC guards.",
                                        tool="OWASP API Security",
                                        file_path=os.path.relpath(fpath, target_path),
                                        cwe="CWE-306",
                                        owasp="OWASP API5:2023-Broken Function Level Authorization",
                                        remediation="Ensure role-based authorization decorator / middleware wraps this controller."
                                    ))
                    except Exception:
                        pass
        return findings, {"routes_found": routes}
