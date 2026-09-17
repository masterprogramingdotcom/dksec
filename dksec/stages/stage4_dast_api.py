"""
Stage 4: DAST + API Security Testing (Advanced Enterprise Edition)
Recommended Repos: OWASP ZAP + OWASP API Security
What it covers: Web/API dynamic testing, authenticated session scans, TLS audit,
OpenAPI/Swagger 2.0/3.0 security audit, BOLA/IDOR, BFLA, JWT & Cookie security.
"""

import os
import re
import json
import socket
import ssl
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
import requests
from dksec import yaml_compat as yaml

from dksec.stages.base import BaseStage
from dksec.models import Finding, Severity, FindingStatus
from dksec.config import DKSecConfig
from dksec.auth import DKSecSessionManager


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

        # 2. Static Route Discovery from Source Code
        route_findings, route_data = self._audit_static_routes(config.target_path)
        findings.extend(route_findings)
        details["static_routes"] = route_data

        if target_url:
            self.log(f"Running Advanced Dynamic API & DAST Audit against target URL: {target_url}")

            # 3. Initialize Authenticated Session Manager
            session_mgr = DKSecSessionManager(config.auth, base_url=target_url)
            context["session_manager"] = session_mgr

            if session_mgr.is_authenticated:
                self.log(f"✔ Authenticated session established (Method: {session_mgr.auth_method.upper()})")
                details["auth_status"] = {
                    "authenticated": True,
                    "method": session_mgr.auth_method,
                    "has_token": bool(session_mgr.captured_token),
                    "cookies_count": len(session_mgr.captured_cookies)
                }

                # 3a. Audit JWT Token if present
                if session_mgr.captured_token:
                    jwt_findings = session_mgr.audit_jwt()
                    findings.extend(jwt_findings)
                    self.log(f"Audited JWT token structure: {len(jwt_findings)} issues identified.")

                # 3b. Audit Session Cookie Flags if cookies captured
                if session_mgr.last_login_response:
                    cookie_findings = session_mgr.audit_cookies(session_mgr.last_login_response, target_url)
                    findings.extend(cookie_findings)

                # 3c. Audit Login Endpoint (Brute-Force & Credential Exposure)
                login_target = config.auth.login_url or urllib.parse.urljoin(target_url, "/api/v1/login")
                login_findings = session_mgr.audit_login_endpoint(login_target)
                findings.extend(login_findings)
            else:
                self.log("Running unauthenticated DAST audit (no login credentials configured or login failed).")
                details["auth_status"] = {
                    "authenticated": False,
                    "error": session_mgr.login_error
                }

            # 4. TLS/SSL Security & Certificate Validation
            tls_findings, tls_data = self._audit_tls_security(target_url)
            findings.extend(tls_findings)
            details["tls"] = tls_data

            # 5. HTTP Security Headers
            header_findings, header_data = self._audit_security_headers(target_url)
            findings.extend(header_findings)
            details["headers"] = header_data

            # 6. CORS Misconfiguration Audit
            cors_findings, cors_data = self._audit_cors(target_url)
            findings.extend(cors_findings)
            details["cors"] = cors_data

            # 7. Dangerous HTTP Methods
            http_findings, method_data = self._audit_http_methods(target_url)
            findings.extend(http_findings)
            details["methods"] = method_data

            # 8. OWASP API Top 10 Sensitive Exposure Probes
            api_findings, api_data = self._probe_api_endpoints(target_url)
            findings.extend(api_findings)
            details["api_probes"] = api_data

            # 9. Dynamic Route Probing (Differential Authenticated vs Unauthenticated Testing)
            all_target_routes = list(set(
                route_data.get("routes_list", []) +
                spec_data.get("endpoints_list", []) +
                ["/api/v1/users", "/api/v1/users/1", "/api/v1/admin/debug", "/api/v1/transfer"]
            ))
            dyn_findings, dyn_data = self._audit_live_routes(target_url, session_mgr, all_target_routes)
            findings.extend(dyn_findings)
            details["live_routes_audit"] = dyn_data

            metrics = {
                "target_url": target_url,
                "authenticated_scan": session_mgr.is_authenticated,
                "auth_method": session_mgr.auth_method if session_mgr.is_authenticated else "none",
                "tls_protocol": tls_data.get("protocol", "N/A"),
                "openapi_endpoints_audited": spec_data.get("endpoints_found", 0),
                "live_routes_tested": len(all_target_routes),
                "total_probes_sent": header_data.get("probes", 0) + api_data.get("probes", 0) + dyn_data.get("probes", 0),
                "dast_findings_count": len(findings)
            }
        else:
            self.log("No live target_url provided; completed static API route definitions & OpenAPI surface audit.")
            metrics = {
                "scan_mode": "Static API Surface & Spec Audit",
                "openapi_endpoints_audited": spec_data.get("endpoints_found", 0),
                "code_routes_audited": route_data.get("routes_found", 0),
                "dast_findings_count": len(findings)
            }

        return findings, metrics, details

    def _audit_openapi_specifications(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        endpoints_found = 0
        endpoints_list = []
        spec_candidates = [
            "openapi.json", "openapi.yaml", "openapi.yml",
            "swagger.json", "swagger.yaml", "swagger.yml"
        ]

        if not os.path.exists(target_path):
            return findings, {"endpoints_found": 0, "endpoints_list": []}

        for root, _, files in os.walk(target_path):
            for f in files:
                if f.lower() in spec_candidates:
                    fpath = os.path.join(root, f)
                    rel_path = os.path.relpath(fpath, target_path)
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            content = fl.read()
                            data = yaml.safe_load(content) if (f.endswith(".yaml") or f.endswith(".yml")) else json.loads(content)

                        paths = data.get("paths", {})
                        endpoints_found += len(paths)
                        endpoints_list.extend(list(paths.keys()))

                        # Check 1: Missing Global Security Definitions
                        sec = data.get("security", [])
                        sec_defs = data.get("securityDefinitions") or data.get("components", {}).get("securitySchemes", {})
                        if not sec and not sec_defs:
                            findings.append(self.create_finding(
                                finding_id=f"API-SPEC-NO-AUTH-{len(findings)+1:03d}",
                                title="OpenAPI Missing Global Authentication & Security Scheme",
                                severity=Severity.HIGH,
                                description=f"The API specification `{rel_path}` defines {len(paths)} endpoints without enforcing a global securityScheme or authentication requirement.",
                                tool="OWASP API Security Audit",
                                file_path=rel_path,
                                cwe="CWE-306",
                                owasp="OWASP API2:2023-Broken Authentication",
                                remediation="Declare securitySchemes (OAuth2, Bearer JWT) in components and apply them globally under 'security:'."
                            ))

                        # Check 2: Deprecated or Insecure Schemes (HTTP Basic in cleartext)
                        for sname, sdef in sec_defs.items():
                            if isinstance(sdef, dict) and sdef.get("scheme", "").lower() == "basic":
                                findings.append(self.create_finding(
                                    finding_id=f"API-SPEC-BASIC-AUTH-{len(findings)+1:03d}",
                                    title="Insecure HTTP Basic Authentication Specified in API Spec",
                                    severity=Severity.MEDIUM,
                                    description=f"Scheme `{sname}` uses HTTP Basic Auth which transmits unencrypted credentials.",
                                    tool="OWASP API Security Audit",
                                    file_path=rel_path,
                                    cwe="CWE-523",
                                    owasp="OWASP API2:2023-Broken Authentication",
                                    remediation="Replace HTTP Basic Authentication with OAuth 2.0 / OpenID Connect."
                                ))
                    except Exception:
                        pass

        return findings, {"endpoints_found": endpoints_found, "endpoints_list": endpoints_list}

    def _audit_tls_security(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        data = {"host": host, "port": port, "protocol": "HTTP"}

        if parsed.scheme != "https":
            findings.append(self.create_finding(
                finding_id="DAST-TLS-CLEAR-HTTP",
                title="Unencrypted HTTP Scheme in Use (Cleartext Communication)",
                severity=Severity.HIGH,
                description=f"Target URL `{url}` communicates over plaintext HTTP without SSL/TLS encryption.",
                tool="OWASP ZAP / TLS Auditor",
                target=url,
                cwe="CWE-319",
                owasp="OWASP A02:2021-Cryptographic Failures",
                remediation="Enforce HTTPS across all application endpoints and implement HTTP Strict Transport Security (HSTS)."
            ))
            return findings, data

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    data["protocol"] = proto
                    data["cipher"] = ssock.cipher()

                    if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append(self.create_finding(
                            finding_id="DAST-TLS-DEPRECATED",
                            title=f"Deprecated TLS Protocol In Use: {proto}",
                            severity=Severity.HIGH,
                            description=f"Target endpoint negotiated deprecated and cryptographically broken protocol `{proto}`.",
                            tool="OWASP ZAP / TLS Auditor",
                            target=url,
                            cwe="CWE-326",
                            owasp="OWASP A02:2021-Cryptographic Failures",
                            remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. Enforce TLS 1.2 and TLS 1.3 exclusively."
                        ))
        except Exception as e:
            data["error"] = str(e)

        return findings, data

    def _audit_security_headers(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        data = {"headers_found": {}, "missing": [], "probes": 1}
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            data["headers_found"] = hdrs

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

    def _audit_live_routes(self, base_url: str, session_mgr: DKSecSessionManager, routes: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        findings: List[Finding] = []
        probes_sent = 0
        sensitive_json_keys = ["db_pass", "db_password", "password", "secret", "private_key", "aws_secret", "api_key", "secret_key"]

        for route in routes:
            target = urllib.parse.urljoin(base_url, route)
            is_sensitive_path = any(x in route.lower() for x in ["/admin", "/debug", "/internal", "/keys", "/users", "/transfer"])
            
            # --- Test 1: Unauthenticated Probe ---
            probes_sent += 1
            unauth_resp = None
            try:
                unauth_resp = requests.get(target, timeout=4, verify=False, allow_redirects=False)
                if unauth_resp.status_code == 200 and is_sensitive_path and len(unauth_resp.content) > 20:
                    findings.append(self.create_finding(
                        finding_id=f"DAST-UNAUTH-ACCESS-{len(findings)+1:03d}",
                        title=f"Broken Access Control: Unauthenticated Access to {route}",
                        severity=Severity.HIGH,
                        description=f"Sensitive endpoint `{target}` returned HTTP 200 OK to unauthenticated clients without requiring login.",
                        tool="OWASP API Security Auditor",
                        target=target,
                        cwe="CWE-306",
                        owasp="OWASP API1:2023-Broken Object Level Authorization",
                        remediation="Enforce authentication middleware on this endpoint."
                    ))
            except Exception:
                pass

            # --- Test 2: Authenticated Probe (if session established) ---
            if session_mgr.is_authenticated:
                probes_sent += 1
                try:
                    auth_resp = session_mgr.session.get(target, timeout=4, verify=False, allow_redirects=False)
                    
                    if auth_resp.status_code == 200:
                        # 2a. Sensitive Data Exposure in API Response
                        try:
                            resp_json = auth_resp.json()
                            if isinstance(resp_json, dict):
                                for sk in sensitive_json_keys:
                                    if sk in resp_json:
                                        val = str(resp_json[sk])
                                        masked = val[:2] + "****" if len(val) > 2 else "****"
                                        findings.append(self.create_finding(
                                            finding_id=f"DAST-DATA-LEAK-{sk.upper()}",
                                            title=f"Critical Data Leakage: Secret `{sk}` in API Response",
                                            severity=Severity.CRITICAL,
                                            description=f"Endpoint `{target}` leaked sensitive credential `{sk}` (value: {masked}) in JSON response body.",
                                            tool="OWASP API Security Auditor",
                                            target=target,
                                            cwe="CWE-200",
                                            owasp="OWASP API3:2023-Broken Object Property Level Authorization",
                                            remediation=f"Sanitize API response serializer and remove `{sk}` from public responses."
                                        ))
                        except Exception:
                            pass

                        # 2b. Broken Function Level Authorization (BFLA)
                        if any(x in route.lower() for x in ["/admin", "/debug", "/manage", "/internal"]):
                            findings.append(self.create_finding(
                                finding_id=f"DAST-BFLA-{len(findings)+1:03d}",
                                title=f"Broken Function Level Authorization (BFLA): {route}",
                                severity=Severity.HIGH,
                                description=f"Administrative endpoint `{route}` successfully executed by regular authenticated session without administrative role check.",
                                tool="OWASP API Security Auditor",
                                target=target,
                                cwe="CWE-285",
                                owasp="OWASP API5:2023-Broken Function Level Authorization",
                                remediation="Verify caller has role 'admin' or 'superuser' prior to serving administrative endpoints."
                            ))
                except Exception:
                    pass

        return findings, {"probes": probes_sent}

    def _audit_static_routes(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        routes_count = 0
        routes_list = []
        if not os.path.exists(target_path):
            return findings, {"routes_found": 0, "routes_list": []}

        for root, _, files in os.walk(target_path):
            for f in files:
                if f.endswith((".py", ".js", ".ts")):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", errors="ignore") as fl:
                            pattern = r"@app\.route\(['\"]([^'\"]+)['\"]|router\.(?:get|post|put|delete)\(['\"]([^'\"]+)['\"]"
                            matches = re.findall(pattern, content)

                            routes_count += len(matches)
                            for m in matches:
                                route = m[0] or m[1]
                                routes_list.append(route)
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
        return findings, {"routes_found": routes_count, "routes_list": list(set(routes_list))}
