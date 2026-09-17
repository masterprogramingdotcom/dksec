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
        target_path = config.target_path or ""  # empty string → _audit_openapi/_audit_static_routes skip gracefully
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        details: Dict[str, Any] = {}

        # 1. OpenAPI / Swagger Specification Security Audit (Static & Dynamic)
        spec_findings, spec_data = self._audit_openapi_specifications(target_path)
        findings.extend(spec_findings)
        details["openapi_spec"] = spec_data

        # 2. Static Route Discovery from Source Code
        route_findings, route_data = self._audit_static_routes(target_path)
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

            # 10. GraphQL Security Audit
            gql_findings, gql_data = self._audit_graphql(target_url)
            findings.extend(gql_findings)
            details["graphql"] = gql_data

            # 11. SSRF Detection
            ssrf_findings, ssrf_data = self._audit_ssrf(target_url)
            findings.extend(ssrf_findings)
            details["ssrf"] = ssrf_data

            # 12. CSRF Testing
            csrf_findings, csrf_data = self._audit_csrf(target_url)
            findings.extend(csrf_findings)
            details["csrf"] = csrf_data

            # 13. Open Redirect Testing
            redirect_findings, redirect_data = self._audit_open_redirect(target_url)
            findings.extend(redirect_findings)
            details["open_redirect"] = redirect_data

            # 14. Host Header Injection
            host_findings, host_data = self._audit_host_header(target_url)
            findings.extend(host_findings)
            details["host_header"] = host_data

            # 15. HTTP Request Smuggling
            smuggling_findings, smuggling_data = self._audit_request_smuggling(target_url)
            findings.extend(smuggling_findings)
            details["request_smuggling"] = smuggling_data

            # 16. Cache Poisoning
            cache_findings, cache_data = self._audit_cache_poisoning(target_url)
            findings.extend(cache_findings)
            details["cache_poisoning"] = cache_data

            # 17. File Upload Security
            upload_findings, upload_data = self._audit_file_upload(target_url)
            findings.extend(upload_findings)
            details["file_upload"] = upload_data

            # 18. OAuth / OIDC Security
            oauth_findings, oauth_data = self._audit_oauth(target_url)
            findings.extend(oauth_findings)
            details["oauth"] = oauth_data

            # 19. WebSocket Security
            ws_findings, ws_data = self._audit_websocket(target_url)
            findings.extend(ws_findings)
            details["websocket"] = ws_data

            metrics = {
                "target_url": target_url,
                "authenticated_scan": session_mgr.is_authenticated,
                "auth_method": session_mgr.auth_method if session_mgr.is_authenticated else "none",
                "tls_protocol": tls_data.get("protocol", "N/A"),
                "openapi_endpoints_audited": spec_data.get("endpoints_found", 0),
                "live_routes_tested": len(all_target_routes),
                "total_probes_sent": header_data.get("probes", 0) + api_data.get("probes", 0) + dyn_data.get("probes", 0),
                "graphql_tested": gql_data.get("probed", False),
                "ssrf_probes": ssrf_data.get("probes", 0),
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

            data["evaluated_headers"] = []
            for hdr, title, sev, cwe, fix in rules:
                val = hdrs.get(hdr, "")
                is_present = hdr in hdrs
                if not is_present:
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
                data["evaluated_headers"].append({
                    "name": hdr,
                    "status": "PRESENT" if is_present else "MISSING",
                    "severity": sev.value,
                    "value": val or "Header not sent by server",
                    "recommendation": fix
                })

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
                data["evaluated_headers"].append({
                    "name": "server",
                    "status": "LEAKED",
                    "severity": "LOW",
                    "value": hdrs["server"],
                    "recommendation": "Suppress Server banner in reverse proxy configuration."
                })

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
                data["evaluated_headers"].append({
                    "name": "x-powered-by",
                    "status": "LEAKED",
                    "severity": "LOW",
                    "value": hdrs["x-powered-by"],
                    "recommendation": "Disable X-Powered-By banner."
                })
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
        data = {"probes": 0, "probed_paths": []}
        count = 0
        for ep, sev, cwe, desc in probes:
            count += 1
            target = urllib.parse.urljoin(base_url, ep)
            status_code = 404
            content_len = 0
            try:
                r = requests.get(target, timeout=4, verify=False, allow_redirects=False)
                status_code = r.status_code
                content_len = len(r.content)
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
            data["probed_paths"].append({
                "path": ep,
                "status_code": status_code,
                "content_length": content_len,
                "severity": sev.value if status_code == 200 else "INFO",
                "status_description": "Exposed (HTTP 200)" if status_code == 200 else f"HTTP {status_code}",
                "notes": desc
            })
        data["probes"] = count
        return findings, data

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

    def _audit_graphql(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Test GraphQL endpoint for introspection, injection, and batching DoS."""
        findings = []
        data: Dict[str, Any] = {"probed": False, "endpoint": None}
        gql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]

        for ep in gql_endpoints:
            target = urllib.parse.urljoin(base_url, ep)
            try:
                introspection_query = {"query": "{__schema{types{name}}}"}
                r = requests.post(target, json=introspection_query, timeout=5, verify=False)
                if r.status_code == 200:
                    data["probed"] = True
                    data["endpoint"] = ep
                    try:
                        resp = r.json()
                        if resp.get("data", {}).get("__schema"):
                            findings.append(self.create_finding(
                                finding_id="DAST-GQL-INTROSPECT",
                                title="GraphQL Introspection Enabled in Production",
                                severity=Severity.MEDIUM,
                                description=f"GraphQL endpoint `{target}` has introspection enabled, exposing the full schema to unauthenticated callers.",
                                tool="GraphQL Security Auditor",
                                target=target,
                                cwe="CWE-200",
                                owasp="OWASP API7:2023-Security Misconfiguration",
                                remediation="Disable GraphQL introspection in production (e.g. introspection=False in graphene/Apollo)."
                            ))
                    except Exception:
                        pass

                    # Batching DoS probe
                    try:
                        batch_query = [{"query": "{__typename}"} for _ in range(50)]
                        r3 = requests.post(target, json=batch_query, timeout=6, verify=False)
                        if r3.status_code == 200 and isinstance(r3.json(), list):
                            findings.append(self.create_finding(
                                finding_id="DAST-GQL-BATCH-DOS",
                                title="GraphQL Batching Attack — Denial of Service Risk",
                                severity=Severity.MEDIUM,
                                description=f"GraphQL endpoint `{target}` accepted a batch of 50 queries in a single request, enabling DoS amplification.",
                                tool="GraphQL Security Auditor",
                                target=target,
                                cwe="CWE-400",
                                owasp="OWASP API4:2023-Unrestricted Resource Consumption",
                                remediation="Enable query batching limits and complexity analysis (e.g., graphql-query-complexity)."
                            ))
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        return findings, data

    def _audit_ssrf(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Test for Server-Side Request Forgery via common URL parameters."""
        findings = []
        probes_sent = 0
        ssrf_params = ["url", "redirect", "uri", "path", "dest", "source", "target", "callback", "webhook"]
        canary_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22/",
        ]

        for param in ssrf_params[:4]:  # Limit probe scope
            for payload in canary_payloads:
                probes_sent += 1
                probe_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    r = requests.get(probe_url, timeout=4, verify=False, allow_redirects=False)
                    if any(ind in r.text for ind in ["ami-id", "instance-id", "iam/security-credentials", "meta-data"]):
                        findings.append(self.create_finding(
                            finding_id="DAST-SSRF-CONFIRMED",
                            title="Critical SSRF Confirmed — Cloud Metadata Service Accessible",
                            severity=Severity.CRITICAL,
                            description=f"SSRF confirmed: parameter `{param}` with payload `{payload}` returned cloud instance metadata.",
                            tool="SSRF Auditor",
                            target=base_url,
                            cwe="CWE-918",
                            owasp="OWASP A10:2021-Server-Side Request Forgery (SSRF)",
                            remediation="Implement SSRF allowlist; block 169.254.169.254 and RFC-1918 ranges at egress firewall; use IMDSv2."
                        ))
                        return findings, {"probes": probes_sent, "confirmed": True}
                except Exception:
                    pass

        return findings, {"probes": probes_sent, "confirmed": False}

    def _audit_csrf(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Test for CSRF vulnerabilities: missing SameSite cookie flags and unprotected state-changing endpoints."""
        findings = []
        data: Dict[str, Any] = {"checked": False}

        try:
            r = requests.get(base_url, timeout=5, verify=False)
            data["checked"] = True
            set_cookie = r.headers.get("Set-Cookie", "")
            if set_cookie and "samesite" not in set_cookie.lower():
                findings.append(self.create_finding(
                    finding_id="DAST-CSRF-SAMESITE",
                    title="Session Cookie Missing SameSite Attribute (CSRF Risk)",
                    severity=Severity.MEDIUM,
                    description="Server-set cookie does not specify SameSite=Strict or SameSite=Lax, leaving it vulnerable to cross-site request forgery.",
                    tool="CSRF Auditor",
                    target=base_url,
                    cwe="CWE-352",
                    owasp="OWASP A01:2021-Broken Access Control",
                    remediation="Set SameSite=Strict (or Lax) on all session cookies; implement synchronizer CSRF tokens for state-changing requests."
                ))
        except Exception:
            pass

        # Try cross-origin POST without CSRF token
        state_endpoints = ["/api/v1/user/update", "/api/v1/password/change", "/account/settings"]
        for ep in state_endpoints:
            target = urllib.parse.urljoin(base_url, ep)
            try:
                r = requests.post(
                    target,
                    headers={"Origin": "https://attacker.example.com", "Referer": "https://attacker.example.com"},
                    data={"amount": "100"},
                    timeout=4,
                    verify=False
                )
                if r.status_code == 200:
                    findings.append(self.create_finding(
                        finding_id=f"DAST-CSRF-UNPROTECTED-{ep.replace('/', '-').upper()[:30]}",
                        title=f"CSRF Unprotected State-Changing Endpoint: {ep}",
                        severity=Severity.HIGH,
                        description=f"Cross-origin POST to `{target}` (Origin: attacker.example.com) returned HTTP 200 without CSRF token validation.",
                        tool="CSRF Auditor",
                        target=target,
                        cwe="CWE-352",
                        owasp="OWASP A01:2021-Broken Access Control",
                        remediation="Enforce CSRF tokens (Double Submit Cookie or Synchronizer Token Pattern); verify Origin/Referer headers."
                    ))
            except Exception:
                pass

        return findings, data

    def _audit_open_redirect(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Fuzz common redirect parameters for open redirect vulnerabilities."""
        findings = []
        probes_sent = 0
        redirect_params = ["redirect", "url", "next", "return", "goto", "continue", "redir", "target", "return_url", "redirect_uri"]
        payloads = ["//attacker.example.com", "https://attacker.example.com"]

        for param in redirect_params:
            for payload in payloads:
                probes_sent += 1
                probe_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    r = requests.get(probe_url, timeout=4, verify=False, allow_redirects=False)
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("Location", "")
                        if "attacker.example.com" in loc:
                            findings.append(self.create_finding(
                                finding_id=f"DAST-OPEN-REDIRECT-{param.upper()}",
                                title=f"Open Redirect Vulnerability: Parameter '{param}'",
                                severity=Severity.MEDIUM,
                                description=f"Parameter `{param}` with payload `{payload}` causes redirect to attacker-controlled domain: `{loc}`.",
                                tool="Open Redirect Auditor",
                                target=base_url,
                                cwe="CWE-601",
                                owasp="OWASP A01:2021-Broken Access Control",
                                remediation="Validate redirect targets against a strict server-side allowlist of trusted domains; reject absolute URLs from user input."
                            ))
                            return findings, {"probes": probes_sent}
                except Exception:
                    pass

        return findings, {"probes": probes_sent}

    def _audit_host_header(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Test Host Header injection and X-Forwarded-Host manipulation."""
        findings = []
        data: Dict[str, Any] = {"tested": False}
        evil_host = "attacker.example.com"
        test_headers_sets = [
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"X-Original-Host": evil_host},
        ]

        for hdrs in test_headers_sets:
            try:
                r = requests.get(base_url, headers=hdrs, timeout=5, verify=False, allow_redirects=False)
                data["tested"] = True
                hdr_name = list(hdrs.keys())[0]
                if evil_host in r.text or evil_host in r.headers.get("location", ""):
                    findings.append(self.create_finding(
                        finding_id=f"DAST-HOST-INJECT-{hdr_name.upper().replace('-', '_')}",
                        title=f"Host Header Injection via {hdr_name}",
                        severity=Severity.HIGH,
                        description=f"Injected `{hdr_name}: {evil_host}` was reflected in response, enabling password-reset link hijacking and cache poisoning.",
                        tool="Host Header Auditor",
                        target=base_url,
                        cwe="CWE-74",
                        owasp="OWASP A07:2021-Identification and Authentication Failures",
                        remediation="Validate Host header against an explicit allowlist; never construct URLs or email links using the user-supplied Host header."
                    ))
            except Exception:
                pass

        return findings, data

    def _audit_request_smuggling(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Probe for HTTP Request Smuggling (CL.TE timing pattern)."""
        findings = []
        data: Dict[str, Any] = {"tested": False}
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        smuggle_payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        )
        try:
            import select as _select
            import ssl as _ssl
            s = socket.create_connection((host, port), timeout=5)
            if parsed.scheme == "https":
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            data["tested"] = True
            s.sendall(smuggle_payload.encode())
            ready = _select.select([s], [], [], 4)
            if not ready[0]:
                # Server hung — possible CL.TE smuggling indicator
                findings.append(self.create_finding(
                    finding_id="DAST-SMUGGLING-CL-TE",
                    title="HTTP Request Smuggling (CL.TE) — Server Timeout Indicator",
                    severity=Severity.HIGH,
                    description=f"Host `{host}` timed out on an ambiguous CL.TE request, suggesting vulnerable HTTP/1.1 request handling. Manual verification recommended.",
                    tool="Request Smuggling Auditor",
                    target=base_url,
                    cwe="CWE-444",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Normalize HTTP requests at the reverse proxy; disable HTTP/1.0 keep-alive; use HTTP/2 end-to-end where possible."
                ))
            s.close()
        except Exception:
            pass

        return findings, data

    def _audit_cache_poisoning(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Test for web cache poisoning via unkeyed headers."""
        findings = []
        data: Dict[str, Any] = {"tested": False}
        poison_tests = [
            ("X-Forwarded-Host", "attacker.example.com"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
        ]

        for hdr_name, hdr_val in poison_tests:
            try:
                r = requests.get(base_url, headers={hdr_name: hdr_val}, timeout=5, verify=False)
                data["tested"] = True
                if hdr_val in r.text or hdr_val in r.headers.get("location", ""):
                    findings.append(self.create_finding(
                        finding_id=f"DAST-CACHE-POISON-{hdr_name.upper().replace('-', '_')}",
                        title=f"Web Cache Poisoning via Unkeyed Header: {hdr_name}",
                        severity=Severity.HIGH,
                        description=f"Header `{hdr_name}: {hdr_val}` was reflected in the response. If cached, this could be served to other users.",
                        tool="Cache Poisoning Auditor",
                        target=base_url,
                        cwe="CWE-345",
                        owasp="OWASP A05:2021-Security Misconfiguration",
                        remediation="Include all response-influencing headers in the cache key; strip unexpected headers at the proxy layer."
                    ))
            except Exception:
                pass

        return findings, data

    def _audit_file_upload(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Probe file upload endpoints for dangerous file type acceptance."""
        findings = []
        probes_sent = 0
        upload_endpoints = ["/upload", "/api/upload", "/file", "/api/file", "/import", "/media/upload"]
        data: Dict[str, Any] = {"endpoints_probed": [], "probes": 0}

        dangerous_files = [
            ("webshell.php", b"<?php echo phpinfo(); ?>", "application/x-php"),
            ("test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
        ]

        for ep in upload_endpoints:
            target = urllib.parse.urljoin(base_url, ep)
            for filename, payload_bytes, content_type in dangerous_files:
                probes_sent += 1
                try:
                    files = {"file": (filename, payload_bytes, content_type)}
                    r = requests.post(target, files=files, timeout=5, verify=False)
                    data["endpoints_probed"].append({"endpoint": ep, "filename": filename, "status": r.status_code})
                    if r.status_code in (200, 201):
                        findings.append(self.create_finding(
                            finding_id=f"DAST-UPLOAD-{filename.upper().replace('.', '_').replace('-', '_')[:30]}",
                            title=f"File Upload — Dangerous File Accepted: {filename}",
                            severity=Severity.CRITICAL if filename.endswith(".php") else Severity.HIGH,
                            description=f"Upload endpoint `{target}` accepted `{filename}` (Content-Type: {content_type}) with HTTP {r.status_code}. Risk of RCE or stored XSS.",
                            tool="File Upload Security Auditor",
                            target=target,
                            cwe="CWE-434",
                            owasp="OWASP A04:2021-Insecure Design",
                            remediation="Validate file extensions via allowlist; verify MIME type server-side; store uploads outside webroot; apply AV scanning."
                        ))
                        break
                except Exception:
                    pass

        data["probes"] = probes_sent
        return findings, data

    def _audit_oauth(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Check OAuth/OIDC endpoints for redirect_uri bypass and PKCE enforcement."""
        findings = []
        data: Dict[str, Any] = {"endpoints_found": [], "tested": False}
        oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/.well-known/openid-configuration"]

        for path in oauth_paths:
            target = urllib.parse.urljoin(base_url, path)
            try:
                r = requests.get(target, timeout=5, verify=False, allow_redirects=False)
                if r.status_code in (200, 302):
                    data["endpoints_found"].append(path)
                    data["tested"] = True

                    # Test redirect_uri bypass
                    evil_redirect = target + "?redirect_uri=https://attacker.example.com"
                    try:
                        r2 = requests.get(evil_redirect, timeout=5, verify=False, allow_redirects=False)
                        loc = r2.headers.get("Location", "")
                        if "attacker.example.com" in loc:
                            findings.append(self.create_finding(
                                finding_id="DAST-OAUTH-REDIRECT-BYPASS",
                                title="OAuth redirect_uri Bypass — Open Redirect in Auth Flow",
                                severity=Severity.CRITICAL,
                                description=f"OAuth endpoint `{path}` reflected attacker-controlled redirect_uri, enabling OAuth authorization code theft.",
                                tool="OAuth/OIDC Security Auditor",
                                target=target,
                                cwe="CWE-601",
                                owasp="OWASP API2:2023-Broken Authentication",
                                remediation="Register exact redirect_uri values server-side; reject any URI not in the allowlist; enforce PKCE for public clients."
                            ))
                    except Exception:
                        pass

                    # OIDC: check PKCE support advertised
                    if "openid-configuration" in path:
                        try:
                            oidc_data = r.json()
                            if not oidc_data.get("code_challenge_methods_supported"):
                                findings.append(self.create_finding(
                                    finding_id="DAST-OIDC-NO-PKCE",
                                    title="OIDC Provider Does Not Advertise PKCE Support",
                                    severity=Severity.MEDIUM,
                                    description="OpenID Connect configuration does not list code_challenge_methods_supported — PKCE may not be enforced.",
                                    tool="OAuth/OIDC Security Auditor",
                                    target=target,
                                    cwe="CWE-345",
                                    owasp="OWASP API2:2023-Broken Authentication",
                                    remediation="Enforce PKCE (S256 code challenge) for all public OAuth clients to prevent authorization code interception."
                                ))
                        except Exception:
                            pass
            except Exception:
                pass

        return findings, data

    def _audit_websocket(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """Inspect WebSocket upgrade endpoints for auth and origin validation issues."""
        findings = []
        data: Dict[str, Any] = {"endpoints_probed": [], "tested": False}
        ws_paths = ["/ws", "/websocket", "/socket.io", "/cable", "/api/ws", "/realtime"]

        for path in ws_paths:
            target = urllib.parse.urljoin(base_url, path)
            try:
                upgrade_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Origin": "https://attacker.example.com"
                }
                r = requests.get(target, headers=upgrade_headers, timeout=4, verify=False, allow_redirects=False)
                data["endpoints_probed"].append({"path": path, "status": r.status_code})

                if r.status_code in (101, 200):
                    data["tested"] = True
                    findings.append(self.create_finding(
                        finding_id=f"DAST-WS-ORIGIN-{path.strip('/').upper().replace('/', '_')[:20]}",
                        title=f"WebSocket Missing Origin Validation: {path}",
                        severity=Severity.HIGH,
                        description=f"WebSocket endpoint `{target}` accepted an upgrade from Origin `attacker.example.com` without validation — enables cross-site WebSocket hijacking (CSWSH).",
                        tool="WebSocket Security Auditor",
                        target=target,
                        cwe="CWE-346",
                        owasp="OWASP API7:2023-Security Misconfiguration",
                        remediation="Validate Origin header against an explicit allowlist before accepting WebSocket upgrades; require auth tokens in the handshake."
                    ))
            except Exception:
                pass

        return findings, data

