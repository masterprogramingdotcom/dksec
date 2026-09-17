"""
Enterprise Authentication & Live Session Management for DKSec.
Supports Automated JSON/Form Login, Bearer Tokens (JWT), Session Cookies,
Custom Headers, JWT Security Audits, and Multi-Role / BOLA Differential Testing.
"""

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List, Tuple
import requests

from dksec.models import Finding, Severity, FindingStatus


@dataclass
class AuthConfig:
    enabled: bool = False
    auth_type: str = "none"  # "none", "login", "bearer", "cookie", "header"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    payload_type: str = "json"  # "json" or "form"
    token_json_path: Optional[str] = None  # e.g., "token", "data.token", "access_token"
    token_header_name: str = "Authorization"
    token_header_prefix: str = "Bearer "
    bearer_token: Optional[str] = None
    cookies: Optional[str] = None  # e.g., "session=abc123; role=admin"
    custom_header: Optional[str] = None  # e.g., "X-API-Key: secret123"
    secondary_username: Optional[str] = None  # For BOLA / IDOR differential testing
    secondary_password: Optional[str] = None
    timeout: int = 6

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthConfig":
        if not data:
            return cls()
        return cls(
            enabled=data.get("enabled", False),
            auth_type=data.get("auth_type", data.get("type", "none")),
            login_url=data.get("login_url"),
            username=data.get("username"),
            password=data.get("password"),
            payload_type=data.get("payload_type", "json"),
            token_json_path=data.get("token_json_path"),
            token_header_name=data.get("token_header_name", "Authorization"),
            token_header_prefix=data.get("token_header_prefix", "Bearer "),
            bearer_token=data.get("bearer_token", data.get("token")),
            cookies=data.get("cookies", data.get("cookie")),
            custom_header=data.get("custom_header", data.get("header")),
            secondary_username=data.get("secondary_username"),
            secondary_password=data.get("secondary_password"),
            timeout=data.get("timeout", 6)
        )


class DKSecSessionManager:
    def __init__(self, auth_config: Optional[AuthConfig] = None, base_url: Optional[str] = None):
        self.config = auth_config or AuthConfig()
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "DKSec-Enterprise-Auditor/2.0 (Security Testing Platform; +https://github.com/dksec/dksec)"
        })
        self.is_authenticated = False
        self.auth_method = "none"
        self.captured_token: Optional[str] = None
        self.captured_cookies: Dict[str, str] = {}
        self.login_status_code: Optional[int] = None
        self.login_error: Optional[str] = None
        self.session_audit_findings: List[Finding] = []
        self.last_login_response: Optional[requests.Response] = None

        if self.config.enabled or self.config.auth_type != "none" or self.config.login_url or self.config.bearer_token:
            self._setup_session()

    def _setup_session(self):
        auth_type = self.config.auth_type.lower() if self.config.auth_type else "none"

        # 1. Bearer Token direct configuration
        if auth_type == "bearer" or self.config.bearer_token:
            token = (self.config.bearer_token or "").strip()
            if token.lower().startswith("bearer "):
                raw_token = token[7:].strip()
            else:
                raw_token = token
            self.captured_token = raw_token
            header_val = f"{self.config.token_header_prefix}{raw_token}"
            self.session.headers[self.config.token_header_name] = header_val
            self.is_authenticated = True
            self.auth_method = "bearer"

        # 2. Custom Authentication Header
        if auth_type == "header" or self.config.custom_header:
            hdr_str = (self.config.custom_header or "").strip()
            if ":" in hdr_str:
                k, v = hdr_str.split(":", 1)
                self.session.headers[k.strip()] = v.strip()
                self.is_authenticated = True
                self.auth_method = "header"

        # 3. Session Cookies direct configuration
        if auth_type == "cookie" or self.config.cookies:
            cookie_str = (self.config.cookies or "").strip()
            self._apply_cookie_string(cookie_str)
            self.is_authenticated = True
            self.auth_method = "cookie"

        # 4. Automated Login Request
        if auth_type == "login" or (self.config.login_url and self.config.username):
            self.perform_login(self.config.username or "", self.config.password or "")

    def _apply_cookie_string(self, cookie_str: str):
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k:
                    self.session.cookies.set(k, v)
                    self.captured_cookies[k] = v

    def perform_login(self, username: str, password: str, is_secondary: bool = False) -> Tuple[bool, str]:
        target_login = self.config.login_url
        if not target_login and self.base_url:
            target_login = urllib.parse.urljoin(self.base_url, "/api/v1/login")

        if not target_login:
            err = "Login URL not provided in auth configuration."
            self.login_error = err
            return False, err

        try:
            if self.config.payload_type == "form":
                payload = {"username": username, "password": password}
                r = self.session.post(target_login, data=payload, timeout=self.config.timeout, verify=False)
            else:
                payload = {"username": username, "password": password}
                r = self.session.post(target_login, json=payload, timeout=self.config.timeout, verify=False)

            self.login_status_code = r.status_code
            self.last_login_response = r

            # Check for Set-Cookie headers
            for cookie in self.session.cookies:
                self.captured_cookies[cookie.name] = cookie.value

            # Extract Token if JSON response
            token_found = None
            try:
                data = r.json()
                token_found = self._extract_token_from_dict(data, self.config.token_json_path)
            except Exception:
                pass

            if token_found:
                self.captured_token = token_found
                self.session.headers[self.config.token_header_name] = f"{self.config.token_header_prefix}{token_found}"

            if r.status_code in (200, 201, 204) or token_found or len(self.session.cookies) > 0:
                if not is_secondary:
                    self.is_authenticated = True
                    self.auth_method = "login"
                return True, f"Login successful (HTTP {r.status_code})"
            else:
                err = f"Login failed with status code {r.status_code}: {r.text[:120]}"
                self.login_error = err
                return False, err

        except Exception as e:
            err = f"Exception during authentication request: {str(e)}"
            self.login_error = err
            return False, err

    def _extract_token_from_dict(self, data: Any, custom_path: Optional[str] = None) -> Optional[str]:
        if not isinstance(data, dict):
            return None

        # If custom path specified (e.g. "data.access_token")
        if custom_path:
            parts = custom_path.split(".")
            curr = data
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    curr = None
                    break
            if curr and isinstance(curr, str):
                return curr

        # Automated standard token field scan
        candidates = ["token", "access_token", "jwt", "id_token", "auth_token", "authToken", "accessToken", "bearer"]
        for c in candidates:
            if c in data and isinstance(data[c], str) and len(data[c]) > 5:
                return data[c]

        # Scan 1-level nested dicts (e.g. {"data": {"token": "..."}})
        for val in data.values():
            if isinstance(val, dict):
                for c in candidates:
                    if c in val and isinstance(val[c], str) and len(val[c]) > 5:
                        return val[c]

        return None

    def test_connection(self, test_url: Optional[str] = None) -> Dict[str, Any]:
        url = test_url or self.base_url or self.config.login_url
        if not url:
            return {"success": False, "message": "No test URL or base URL provided."}

        try:
            r = self.session.get(url, timeout=self.config.timeout, verify=False)
            return {
                "success": True,
                "status_code": r.status_code,
                "authenticated": self.is_authenticated,
                "auth_method": self.auth_method,
                "has_token": bool(self.captured_token),
                "cookie_count": len(self.captured_cookies),
                "headers_sent": dict(self.session.headers),
                "message": f"Connected to {url} (HTTP {r.status_code})"
            }
        except Exception as e:
            return {
                "success": False,
                "status_code": None,
                "authenticated": False,
                "message": f"Connection failed: {str(e)}"
            }

    def audit_jwt(self, token: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []
        raw = token or self.captured_token
        if not raw:
            return findings

        # Check if JWT structure
        parts = raw.split(".")
        if len(parts) != 3:
            return findings

        def b64_decode(data: str) -> Optional[Dict[str, Any]]:
            try:
                rem = len(data) % 4
                if rem > 0:
                    data += "=" * (4 - rem)
                decoded = base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="ignore")
                return json.loads(decoded)
            except Exception:
                return None

        header = b64_decode(parts[0])
        payload = b64_decode(parts[1])

        if not header or not payload:
            return findings

        # 1. Check for Alg None
        alg = str(header.get("alg", "")).upper()
        if alg in ("NONE", "NONE_ALG", ""):
            findings.append(Finding(
                id="AUTH-JWT-ALG-NONE",
                title="Critical JWT Vulnerability: Unsigned 'none' Algorithm Allowed",
                severity=Severity.CRITICAL,
                description="The JWT token header specifies 'alg': 'none', which allows attackers to forge arbitrary tokens without a signature.",
                stage_id=4,
                stage_name="DAST + API Security Testing",
                tool="DKSec Authentication Engine",
                cwe="CWE-345",
                owasp="OWASP API2:2023-Broken Authentication",
                remediation="Reject any JWTs specifying alg: 'none'. Enforce asymmetric algorithms (RS256, Ed25519) or strong symmetric algorithms with strict verification."
            ))

        # 2. Check for Weak / Symmetric Alg
        if alg in ("HS256", "HS384", "HS512"):
            findings.append(Finding(
                id="AUTH-JWT-SYMMETRIC",
                title="Symmetric Key JWT in Use (HMAC-SHA256)",
                severity=Severity.LOW,
                description=f"Token uses symmetric signing algorithm `{alg}`. Ensure the shared secret possesses minimum 256 bits of high entropy.",
                stage_id=4,
                stage_name="DAST + API Security Testing",
                tool="DKSec Authentication Engine",
                cwe="CWE-327",
                owasp="OWASP API2:2023-Broken Authentication",
                remediation="Prefer asymmetric key pairs (e.g. RS256, ES256) so verifying services do not possess the signing private key."
            ))

        # 3. Check for Missing Expiration Claim ('exp')
        if "exp" not in payload:
            findings.append(Finding(
                id="AUTH-JWT-NO-EXP",
                title="Missing JWT Expiration Claim ('exp')",
                severity=Severity.MEDIUM,
                description="The JWT does not contain an 'exp' (expiration) claim, granting the token perpetual validity if intercepted.",
                stage_id=4,
                stage_name="DAST + API Security Testing",
                tool="DKSec Authentication Engine",
                cwe="CWE-613",
                owasp="OWASP API2:2023-Broken Authentication",
                remediation="Always enforce short-lived expiration timestamps (e.g. 15-60 minutes) with refresh token rotation."
            ))

        # 4. Check for Sensitive Information in Payload
        sensitive_keys = ["password", "pass", "pwd", "secret", "private_key", "db_pass", "ssn", "credit_card"]
        for sk in sensitive_keys:
            if sk in payload:
                findings.append(Finding(
                    id=f"AUTH-JWT-LEAK-{sk.upper()}",
                    title=f"Sensitive Credential Leaked in JWT Payload: {sk}",
                    severity=Severity.HIGH,
                    description=f"The unencrypted JWT payload contains sensitive field `{sk}`. JWT payloads are base64-encoded and fully readable by clients.",
                    stage_id=4,
                    stage_name="DAST + API Security Testing",
                    tool="DKSec Authentication Engine",
                    cwe="CWE-312",
                    owasp="OWASP API2:2023-Broken Authentication",
                    remediation=f"Never store confidential data or credentials (`{sk}`) in client-accessible JWT tokens."
                ))

        return findings

    def audit_cookies(self, response: requests.Response, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        set_cookie_headers = [v for k, v in response.raw.headers.items() if k.lower() == "set-cookie"] if hasattr(response, "raw") else []
        if not set_cookie_headers and "Set-Cookie" in response.headers:
            set_cookie_headers = [response.headers["Set-Cookie"]]

        is_https = target_url.lower().startswith("https://")

        for sc in set_cookie_headers:
            cookie_name = sc.split("=", 1)[0].strip() if "=" in sc else "session"
            lower_sc = sc.lower()

            # Check HttpOnly
            if "httponly" not in lower_sc:
                findings.append(Finding(
                    id=f"AUTH-COOKIE-NO-HTTPONLY-{cookie_name.upper()}",
                    title=f"Session Cookie Missing HttpOnly Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    description=f"Cookie `{cookie_name}` is set without the `HttpOnly` flag. It can be accessed and stolen via client-side JavaScript (XSS attacks).",
                    stage_id=4,
                    stage_name="DAST + API Security Testing",
                    tool="OWASP ZAP / Cookie Auditor",
                    target=target_url,
                    cwe="CWE-1004",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation=f"Set 'HttpOnly' attribute on cookie `{cookie_name}`."
                ))

            # Check Secure (only if HTTPS or production target)
            if is_https and "secure" not in lower_sc:
                findings.append(Finding(
                    id=f"AUTH-COOKIE-NO-SECURE-{cookie_name.upper()}",
                    title=f"Session Cookie Missing Secure Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    description=f"Cookie `{cookie_name}` on HTTPS target is missing the `Secure` flag. Browsers may transmit it over unencrypted HTTP.",
                    stage_id=4,
                    stage_name="DAST + API Security Testing",
                    tool="OWASP ZAP / Cookie Auditor",
                    target=target_url,
                    cwe="CWE-614",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation=f"Set 'Secure' attribute on cookie `{cookie_name}`."
                ))

            # Check SameSite
            if "samesite" not in lower_sc:
                findings.append(Finding(
                    id=f"AUTH-COOKIE-NO-SAMESITE-{cookie_name.upper()}",
                    title=f"Session Cookie Missing SameSite Flag: {cookie_name}",
                    severity=Severity.LOW,
                    description=f"Cookie `{cookie_name}` is missing the `SameSite` attribute, making requests vulnerable to Cross-Site Request Forgery (CSRF).",
                    stage_id=4,
                    stage_name="DAST + API Security Testing",
                    tool="OWASP ZAP / Cookie Auditor",
                    target=target_url,
                    cwe="CWE-1275",
                    owasp="OWASP A01:2021-Broken Access Control",
                    remediation=f"Configure 'SameSite=Lax' or 'SameSite=Strict' on `{cookie_name}`."
                ))

        return findings

    def audit_login_endpoint(self, login_url: str) -> List[Finding]:
        findings: List[Finding] = []
        if not login_url:
            return findings

        # 1. Audit Brute Force & Rate Limiting (Sends 5 invalid login attempts)
        responses = []
        for i in range(5):
            try:
                r = requests.post(
                    login_url,
                    json={"username": f"dksec_probe_{i}", "password": "WrongPassword123!"},
                    timeout=3,
                    verify=False
                )
                responses.append(r)
            except Exception:
                pass

        if len(responses) == 5:
            all_unlocked = all(r.status_code == 401 for r in responses)
            has_ratelimit_header = any(
                any("ratelimit" in k.lower() or "retry-after" in k.lower() for k in r.headers)
                for r in responses
            )
            if all_unlocked and not has_ratelimit_header:
                findings.append(Finding(
                    id="AUTH-NO-BRUTE-FORCE-PROTECTION",
                    title="Missing Login Rate Limiting & Account Lockout Mechanism",
                    severity=Severity.HIGH,
                    description=f"Target login endpoint {login_url} permitted consecutive rapid failed authentication attempts without HTTP 429 or rate-limit throttle headers.",
                    stage_id=4,
                    stage_name="DAST + API Security Testing",
                    tool="OWASP WSTG / Authentication Prober",
                    target=login_url,
                    cwe="CWE-307",
                    owasp="OWASP API4:2023-Unrestricted Resource Consumption",
                    remediation="Implement IP and username based rate limiting (HTTP 429 Too Many Requests) and temporary account lockout after repeated failures.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lockout_Mechanism"]
                ))

        # 2. Check for Credentials in GET request (CWE-598)
        try:
            probe_get = requests.get(
                login_url,
                params={"username": "admin", "password": "test"},
                timeout=3,
                verify=False
            )
            if probe_get.status_code in (200, 401):
                findings.append(Finding(
                    id="AUTH-GET-CREDENTIALS",
                    title="Login Endpoint Accepts Credentials via HTTP GET (CWE-598)",
                    severity=Severity.MEDIUM,
                    description=f"Endpoint {login_url} processed credentials in URL query parameters, causing sensitive passwords to be stored in browser history, proxy caches, and web server access logs.",
                    stage_id=4,
                    stage_name="DAST + API Security Testing",
                    tool="OWASP API Security Auditor",
                    target=login_url,
                    cwe="CWE-598",
                    owasp="OWASP A07:2021-Identification and Authentication Failures",
                    remediation="Only permit authentication requests via HTTP POST with secure request body payloads."
                ))
        except Exception:
            pass

        return findings
