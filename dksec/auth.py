"""
Enterprise Authentication & Live Session Management for DKSec.
Supports all web technologies and authentication mechanisms:
- Automated Form & JSON Login with Universal Framework CSRF Support
  (Django, Laravel, Ruby on Rails, ASP.NET MVC/Core, Spring Security, Express, WordPress)
- OAuth2 Client Credentials Grant Flow (REST APIs, Microservices, Auth0, Okta, Keycloak)
- API Key Authentication (Header & Query Parameter modes)
- Bearer Token / JWT with built-in JWT Security Auditing
- HTTP Basic Authentication (RFC 7617)
- HTTP Digest Authentication (RFC 7616)
- Session Cookies Direct Injection
- Custom Authorization Headers
- Mutual TLS (mTLS) Client Certificates
- Multi-Role / BOLA Differential Testing Support
"""

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List, Tuple
import requests
import requests.auth

from dksec.models import Finding, Severity, FindingStatus


# Common session cookies indicating an active authenticated session
KNOWN_AUTH_COOKIE_NAMES = [
    "sessionid", "session", "phpsessid", "jsessionid", "connect.sid",
    "laravel_session", "remember_web_", "auth_token", "jwt", "token",
    "_session_id", "asp.net_sessionid", ".aspnetcore.cookies",
    ".aspnetcore.identity.application", "sid", "user_session",
    "wordpress_logged_in_", "grafana_session", "gitlab_session",
    "auth0", "next-auth.session-token", "__secure-next-auth.session-token"
]

# Common error keywords in login responses indicating failed credentials
LOGIN_ERROR_KEYWORDS = [
    "invalid username", "invalid password", "incorrect password",
    "invalid credentials", "authentication failed", "login failed",
    "wrong password", "user not found", "please enter a correct",
    "access denied", "csrf verification failed", "unauthorized",
    "could not be verified", "bad credentials", "invalid email or password"
]


@dataclass
class AuthConfig:
    enabled: bool = False
    auth_type: str = "none"  # "none", "login", "oauth2", "bearer", "apikey", "basic", "digest", "cookie", "header", "mtls"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    payload_type: str = "auto"  # "auto", "form", "json"
    token_json_path: Optional[str] = None  # e.g., "token", "data.token", "access_token"
    token_header_name: str = "Authorization"
    token_header_prefix: str = "Bearer "
    bearer_token: Optional[str] = None
    cookies: Optional[str] = None  # e.g., "session=abc123; role=admin"
    custom_header: Optional[str] = None  # e.g., "X-API-Key: secret123"
    
    # OAuth2 Client Credentials Flow
    oauth_token_url: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_scope: Optional[str] = None
    
    # API Key Authentication
    api_key_name: str = "X-API-Key"
    api_key_value: Optional[str] = None
    api_key_in: str = "header"  # "header" or "query"
    
    # Custom form field names (optional override, otherwise auto-detected)
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    csrf_token_name: Optional[str] = None
    
    # Mutual TLS (mTLS)
    client_cert_file: Optional[str] = None
    client_key_file: Optional[str] = None

    # Multi-Role / BOLA Differential Testing
    secondary_username: Optional[str] = None
    secondary_password: Optional[str] = None
    timeout: int = 10

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
            payload_type=data.get("payload_type", "auto"),
            token_json_path=data.get("token_json_path"),
            token_header_name=data.get("token_header_name", "Authorization"),
            token_header_prefix=data.get("token_header_prefix", "Bearer "),
            bearer_token=data.get("bearer_token", data.get("token")),
            cookies=data.get("cookies", data.get("cookie")),
            custom_header=data.get("custom_header", data.get("header")),
            oauth_token_url=data.get("oauth_token_url", data.get("token_url")),
            oauth_client_id=data.get("oauth_client_id", data.get("client_id")),
            oauth_client_secret=data.get("oauth_client_secret", data.get("client_secret")),
            oauth_scope=data.get("oauth_scope", data.get("scope")),
            api_key_name=data.get("api_key_name", "X-API-Key"),
            api_key_value=data.get("api_key_value", data.get("api_key")),
            api_key_in=data.get("api_key_in", "header"),
            username_field=data.get("username_field"),
            password_field=data.get("password_field"),
            csrf_token_name=data.get("csrf_token_name"),
            client_cert_file=data.get("client_cert_file"),
            client_key_file=data.get("client_key_file"),
            secondary_username=data.get("secondary_username"),
            secondary_password=data.get("secondary_password"),
            timeout=data.get("timeout", 10)
        )


class DKSecSessionManager:
    def __init__(self, auth_config: Optional[AuthConfig] = None, base_url: Optional[str] = None):
        self.config = auth_config or AuthConfig()
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 DKSec-Enterprise-Auditor/2.0"
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
        auth_type = (self.config.auth_type or "none").lower()

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

        # 4. HTTP Basic Authentication
        if auth_type == "basic":
            self.session.auth = requests.auth.HTTPBasicAuth(self.config.username or "", self.config.password or "")
            self.is_authenticated = True
            self.auth_method = "basic"

        # 5. HTTP Digest Authentication
        if auth_type == "digest":
            self.session.auth = requests.auth.HTTPDigestAuth(self.config.username or "", self.config.password or "")
            self.is_authenticated = True
            self.auth_method = "digest"

        # 6. OAuth2 Client Credentials Flow
        if auth_type in ("oauth2", "client_credentials"):
            self.perform_oauth2()

        # 7. API Key Authentication (Header or Query Parameter)
        if auth_type in ("apikey", "api_key") or self.config.api_key_value:
            key_name = self.config.api_key_name or "X-API-Key"
            key_val = self.config.api_key_value or ""
            if self.config.api_key_in == "query":
                self.session.params = self.session.params or {}
                self.session.params[key_name] = key_val
            else:
                self.session.headers[key_name] = key_val
            self.is_authenticated = True
            self.auth_method = "apikey"

        # 8. Mutual TLS (mTLS)
        if auth_type == "mtls" or (self.config.client_cert_file and self.config.client_key_file):
            if self.config.client_cert_file and self.config.client_key_file:
                self.session.cert = (self.config.client_cert_file, self.config.client_key_file)
                self.is_authenticated = True
                self.auth_method = "mtls"

        # 9. Automated Login Request (Web Form / JSON / Multi-Framework CSRF)
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

    def perform_oauth2(self) -> Tuple[bool, str]:
        """Executes the OAuth2 Client Credentials Grant Flow."""
        token_url = self.config.oauth_token_url
        client_id = self.config.oauth_client_id
        client_secret = self.config.oauth_client_secret
        scope = self.config.oauth_scope

        if not token_url or not client_id or not client_secret:
            err = "OAuth2 requires Token URL, Client ID, and Client Secret."
            self.login_error = err
            return False, err

        try:
            payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret
            }
            if scope:
                payload["scope"] = scope

            # Try form post first (RFC 6749 standard)
            r = self.session.post(token_url, data=payload, timeout=self.config.timeout, verify=False)
            if r.status_code not in (200, 201):
                # Fallback to JSON payload
                r = self.session.post(token_url, json=payload, timeout=self.config.timeout, verify=False)

            self.login_status_code = r.status_code
            self.last_login_response = r

            if r.status_code in (200, 201):
                try:
                    data = r.json()
                except Exception:
                    data = {}
                token = self._extract_token_from_dict(data, self.config.token_json_path)
                if token:
                    self.captured_token = token
                    token_type = data.get("token_type", "Bearer").strip()
                    prefix = f"{token_type} " if not token_type.endswith(" ") else token_type
                    self.session.headers["Authorization"] = f"{prefix}{token}"
                    self.is_authenticated = True
                    self.auth_method = "oauth2"
                    return True, f"OAuth2 token issued successfully (HTTP {r.status_code})"
                else:
                    err = f"OAuth2 response HTTP {r.status_code} did not contain an access token."
                    self.login_error = err
                    return False, err
            else:
                err_msg = r.text[:120].strip().replace("\n", " ")
                err = f"OAuth2 token request rejected (HTTP {r.status_code}): {err_msg}"
                self.login_error = err
                return False, err
        except Exception as e:
            err = f"OAuth2 connection error: {str(e)}"
            self.login_error = err
            return False, err

    def perform_login(self, username: str, password: str, is_secondary: bool = False) -> Tuple[bool, str]:
        """
        Universal Login Handler supporting all major web frameworks & technologies:
        - Django, Laravel, Ruby on Rails, ASP.NET MVC/Core, Spring Security, Express, WordPress
        - Automatic CSRF extraction across forms, cookies, and meta headers
        - Dynamic form input discovery (username vs email vs login vs log)
        - Preflight redirect resolution
        - Strict false-positive filtering
        """
        target_login = self.config.login_url
        if not target_login and self.base_url:
            target_login = urllib.parse.urljoin(self.base_url, "/login")

        if not target_login:
            err = "Login URL not provided in auth configuration."
            self.login_error = err
            return False, err

        try:
            # 1. Preflight GET request to establish initial cookies and inspect HTML/API
            preflight = self.session.get(
                target_login,
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=True
            )
            actual_url = preflight.url or target_login
            html_content = preflight.text or ""

            # Check if JSON endpoint (e.g. REST API)
            is_json_endpoint = False
            if self.config.payload_type == "json":
                is_json_endpoint = True
            elif self.config.payload_type == "form":
                is_json_endpoint = False
            elif "application/json" in preflight.headers.get("Content-Type", "").lower():
                is_json_endpoint = True
            elif any(p in target_login.lower() for p in ("/api/", "/v1/", "/v2/", "/auth/login", "/token")):
                is_json_endpoint = True
            elif "<form" not in html_content.lower():
                is_json_endpoint = True

            # 2. Extract CSRF token across all web frameworks
            csrf_token = None
            csrf_field_name = None

            # 2a. Check Cookies: Django (csrftoken), Laravel (XSRF-TOKEN), Spring (XSRF-TOKEN), Express (_csrf)
            for c_name in ("csrftoken", "XSRF-TOKEN", "_csrf", "csrf_token", "xsrf_token"):
                if c_name in self.session.cookies:
                    csrf_token = self.session.cookies[c_name]
                    break

            # 2b. Check HTML Form Inputs: Django, Laravel, Rails, ASP.NET, Spring, WordPress
            csrf_field_candidates = [
                ("csrfmiddlewaretoken", "csrfmiddlewaretoken"),
                ("_token", "_token"),
                ("authenticity_token", "authenticity_token"),
                ("__RequestVerificationToken", "__RequestVerificationToken"),
                ("_csrf", "_csrf"),
                ("csrf-token", "csrf-token"),
                ("csrf_token", "csrf_token"),
            ]
            for fname, mapped_name in csrf_field_candidates:
                m = re.search(rf'<input[^>]*name=[\"\']{re.escape(fname)}[\"\'][^>]*value=[\"\']([^\"\']+)[\"\']', html_content, re.IGNORECASE)
                if not m:
                    m = re.search(rf'<input[^>]*value=[\"\']([^\"\']+)[\"\'][^>]*name=[\"\']{re.escape(fname)}[\"\']', html_content, re.IGNORECASE)
                if m:
                    csrf_token = m.group(1)
                    csrf_field_name = mapped_name
                    break

            # 2c. Check HTML Meta Tags (standard in Rails, Laravel, SPA apps)
            if not csrf_token:
                meta_match = re.search(r"<meta\s+name=[\"\']csrf-token[\"\']\s+content=[\"\']([^\"\']+)[\"\']", html_content, re.IGNORECASE)
                if meta_match:
                    csrf_token = meta_match.group(1)

            # 3. Dynamic Field Discovery (Username and Password inputs)
            post_action_url = actual_url
            uname_field = self.config.username_field or "username"
            pword_field = self.config.password_field or "password"
            extra_fields: Dict[str, str] = {}

            if not is_json_endpoint and "<form" in html_content.lower():
                # Extract form action if present
                form_action_match = re.search(r"<form[^>]*action=[\"\']([^\"\']*)[\"\']", html_content, re.IGNORECASE)
                if form_action_match and form_action_match.group(1):
                    post_action_url = urllib.parse.urljoin(actual_url, form_action_match.group(1))

                # Discover username input field name
                if not self.config.username_field:
                    uname_candidates = [
                        "username", "email", "login", "user", "account",
                        "user[email]", "user[login]", "user_login", "log",
                        "identifier", "auth_user", "identity"
                    ]
                    for cand in uname_candidates:
                        if re.search(rf"<input[^>]*name=[\"\']{re.escape(cand)}[\"\']", html_content, re.IGNORECASE):
                            uname_field = cand
                            break

                # Discover password input field name
                if not self.config.password_field:
                    pwd_candidates = ["password", "pass", "pwd", "user[password]", "user_pass", "auth_pass"]
                    for cand in pwd_candidates:
                        if re.search(rf"<input[^>]*name=[\"\']{re.escape(cand)}[\"\']", html_content, re.IGNORECASE):
                            pword_field = cand
                            break

                # Extract other hidden inputs (e.g. WordPress, OAuth redirects, nonces)
                hidden_inputs = re.findall(r"<input[^>]*type=[\"\']hidden[\"\'][^>]*name=[\"\']([^\"\']+)[\"\'][^>]*value=[\"\']([^\"\']*)[\"\']", html_content, re.IGNORECASE)
                for hname, hval in hidden_inputs:
                    if hname not in (csrf_field_name or "", uname_field, pword_field):
                        extra_fields[hname] = hval

            # 4. Prepare Headers (inject CSRF tokens into framework-standard header names)
            post_headers: Dict[str, str] = {
                "Referer": actual_url,
                "Origin": f"{urllib.parse.urlsplit(actual_url).scheme}://{urllib.parse.urlsplit(actual_url).netloc}"
            }
            if csrf_token:
                post_headers["X-CSRFToken"] = csrf_token       # Django
                post_headers["X-CSRF-TOKEN"] = csrf_token      # Laravel / Spring
                post_headers["X-XSRF-TOKEN"] = csrf_token      # Angular / Spring / Axios
                post_headers["RequestVerificationToken"] = csrf_token  # ASP.NET

            # 5. Execute Authentication Request
            if is_json_endpoint:
                json_payload = {uname_field: username, pword_field: password}
                if csrf_token:
                    json_payload["csrf_token"] = csrf_token
                r = self.session.post(
                    post_action_url,
                    json=json_payload,
                    headers=post_headers,
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=False
                )
                # Fallback to form post if server rejects JSON with 415 or 400
                if r.status_code in (415, 400) and self.config.payload_type == "auto":
                    form_data = {uname_field: username, pword_field: password}
                    if csrf_token and csrf_field_name:
                        form_data[csrf_field_name] = csrf_token
                    form_data.update(extra_fields)
                    r = self.session.post(
                        post_action_url,
                        data=form_data,
                        headers=post_headers,
                        timeout=self.config.timeout,
                        verify=False,
                        allow_redirects=False
                    )
            else:
                form_data = {uname_field: username, pword_field: password}
                if csrf_token and csrf_field_name:
                    form_data[csrf_field_name] = csrf_token
                elif csrf_token:
                    form_data["csrfmiddlewaretoken"] = csrf_token
                    form_data["_token"] = csrf_token
                form_data.update(extra_fields)
                r = self.session.post(
                    post_action_url,
                    data=form_data,
                    headers=post_headers,
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=False
                )

            self.login_status_code = r.status_code
            self.last_login_response = r

            # Update cookies cache
            for cookie in self.session.cookies:
                self.captured_cookies[cookie.name] = cookie.value

            # Extract Token if returned in response body
            token_found = None
            try:
                data = r.json()
                token_found = self._extract_token_from_dict(data, self.config.token_json_path)
            except Exception:
                pass

            if token_found:
                self.captured_token = token_found
                self.session.headers[self.config.token_header_name] = f"{self.config.token_header_prefix}{token_found}"

            # 6. Deep Verification: Success vs Failure Analysis
            resp_text = (r.text or "").strip()
            resp_lower = resp_text.lower()

            # Identify if an authenticated session cookie was set
            has_auth_cookie = any(
                any(c_pattern in c_name.lower() for c_pattern in KNOWN_AUTH_COOKIE_NAMES)
                for c_name in self.session.cookies.keys()
            )

            # Check for explicitly detected error phrases
            contains_error_msg = any(kw in resp_lower for kw in LOGIN_ERROR_KEYWORDS)

            # Check for successful redirection (HTTP 301, 302, 303, 307, 308)
            is_redirect_to_dashboard = False
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                # If redirected back to login or an error path, it is failed
                if not any(k in location.lower() for k in ("login", "signin", "error", "auth/failed")):
                    is_redirect_to_dashboard = True

            # Evaluate overall authentication success
            auth_success = False
            if token_found:
                auth_success = True
            elif is_redirect_to_dashboard:
                auth_success = True
            elif has_auth_cookie and not contains_error_msg:
                auth_success = True
            elif r.status_code in (200, 201) and "json" in r.headers.get("Content-Type", "").lower() and not contains_error_msg:
                auth_success = True

            if auth_success:
                if not is_secondary:
                    self.is_authenticated = True
                    self.auth_method = "login"
                cookie_summary = ", ".join([k for k in self.captured_cookies if k.lower() not in ("csrftoken", "xsrf-token")])
                detail = f"Login successful (HTTP {r.status_code})"
                if cookie_summary:
                    detail += f". Captured Session: {cookie_summary}"
                if token_found:
                    detail += f". Token captured."
                return True, detail
            else:
                # Provide clear diagnosis of why authentication was rejected
                if contains_error_msg:
                    err = f"Login rejected: Invalid credentials or account locked (HTTP {r.status_code} returned with error notification)."
                elif r.status_code in (401, 403):
                    err = f"Login rejected by server (HTTP {r.status_code} Unauthorized/Forbidden)."
                elif "<form" in resp_lower:
                    err = f"Login failed: Server returned HTTP {r.status_code} login form without issuing a valid session cookie or token."
                else:
                    err_clean = resp_text[:120].replace("\n", " ")
                    err = f"Login failed (HTTP {r.status_code}): {err_clean}"

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
        """Tests live connectivity to the target using the active session credentials."""
        url = test_url or self.base_url or self.config.login_url
        if not url:
            return {"success": False, "message": "No test URL or base URL provided."}

        try:
            r = self.session.get(url, timeout=self.config.timeout, verify=False)
            
            # Auth cookies (exclude pure CSRF tokens)
            auth_cookies = [
                k for k in self.captured_cookies.keys()
                if k.lower() not in ("csrftoken", "xsrf-token", "_csrf", "csrf_token")
            ]

            return {
                "success": True,
                "status_code": r.status_code,
                "authenticated": self.is_authenticated,
                "auth_method": self.auth_method,
                "has_token": bool(self.captured_token),
                "cookie_count": len(self.captured_cookies),
                "auth_cookies": auth_cookies,
                "headers_sent": {k: v for k, v in self.session.headers.items() if k.lower() in ("authorization", "x-api-key", "cookie")},
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

        # 3. Check for Missing Expiration Claim (exp)
        if "exp" not in payload:
            findings.append(Finding(
                id="AUTH-JWT-NO-EXP",
                title="Missing JWT Expiration Claim (exp)",
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

        # 1. Audit Brute Force & Rate Limiting (Sends 5 rapid invalid attempts)
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
