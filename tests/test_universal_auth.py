"""
Deep Verification Suite for DKSec Universal Authentication Engine.
Tests all web technologies, frameworks, and auth mechanisms:
- None (Public)
- Bearer / JWT (Extraction, Header Prefix, and Security Auditing)
- Session Cookies (Parsing and Cookie Security Flags)
- Custom Headers
- HTTP Basic Authentication (RFC 7617)
- HTTP Digest Authentication (RFC 7616)
- API Key (Header and Query Parameter)
- OAuth2 Client Credentials Flow (Simulation and Token extraction)
- Universal Framework CSRF Extraction (Django, Laravel, Rails, ASP.NET, Spring)
- Form Field Auto-Discovery (Username vs Email vs Login, Password vs Pwd)
- False-Positive Prevention on Invalid Credentials (HTTP 200 HTML)
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import base64
import requests

from dksec.auth import AuthConfig, DKSecSessionManager


class TestUniversalAuthEngine(unittest.TestCase):

    def test_01_none_auth(self):
        cfg = AuthConfig(enabled=False, auth_type="none")
        mgr = DKSecSessionManager(cfg, base_url="http://example.com")
        self.assertFalse(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "none")

    def test_02_bearer_token(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIn0.signature"
        cfg1 = AuthConfig(enabled=True, auth_type="bearer", bearer_token=token)
        mgr1 = DKSecSessionManager(cfg1)
        self.assertTrue(mgr1.is_authenticated)
        self.assertEqual(mgr1.session.headers.get("Authorization"), f"Bearer {token}")

        cfg2 = AuthConfig(enabled=True, auth_type="bearer", bearer_token=f"Bearer {token}")
        mgr2 = DKSecSessionManager(cfg2)
        self.assertTrue(mgr2.is_authenticated)
        self.assertEqual(mgr2.session.headers.get("Authorization"), f"Bearer {token}")

    def test_03_jwt_security_audit(self):
        cfg = AuthConfig(enabled=True, auth_type="bearer")
        mgr = DKSecSessionManager(cfg)

        b64_hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        b64_payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "password": "secret"}).encode()).decode().rstrip("=")
        bad_token = f"{b64_hdr}.{b64_payload}."
        findings = mgr.audit_jwt(bad_token)
        finding_ids = [f.id for f in findings]
        self.assertIn("AUTH-JWT-ALG-NONE", finding_ids)
        self.assertIn("AUTH-JWT-NO-EXP", finding_ids)
        self.assertIn("AUTH-JWT-LEAK-PASSWORD", finding_ids)

    def test_04_session_cookies(self):
        cookie_str = "sessionid=test_session_123; role=admin; user_id=42"
        cfg = AuthConfig(enabled=True, auth_type="cookie", cookies=cookie_str)
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.captured_cookies.get("sessionid"), "test_session_123")
        self.assertEqual(mgr.captured_cookies.get("role"), "admin")
        self.assertEqual(mgr.captured_cookies.get("user_id"), "42")
        self.assertEqual(mgr.session.cookies.get("sessionid"), "test_session_123")

    def test_05_custom_header(self):
        hdr = "X-Enterprise-Token: enterprise_secret_key_889"
        cfg = AuthConfig(enabled=True, auth_type="header", custom_header=hdr)
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.session.headers.get("X-Enterprise-Token"), "enterprise_secret_key_889")

    def test_06_http_basic_auth(self):
        cfg = AuthConfig(enabled=True, auth_type="basic", username="audit_user", password="secret_password")
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "basic")
        self.assertIsInstance(mgr.session.auth, requests.auth.HTTPBasicAuth)
        self.assertEqual(mgr.session.auth.username, "audit_user")
        self.assertEqual(mgr.session.auth.password, "secret_password")

    def test_07_http_digest_auth(self):
        cfg = AuthConfig(enabled=True, auth_type="digest", username="digest_user", password="digest_password")
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "digest")
        self.assertIsInstance(mgr.session.auth, requests.auth.HTTPDigestAuth)

    def test_08_api_key_header_and_query(self):
        cfg_hdr = AuthConfig(enabled=True, auth_type="apikey", api_key_name="X-API-Key", api_key_value="live_key_999", api_key_in="header")
        mgr_hdr = DKSecSessionManager(cfg_hdr)
        self.assertTrue(mgr_hdr.is_authenticated)
        self.assertEqual(mgr_hdr.session.headers.get("X-API-Key"), "live_key_999")

        cfg_qry = AuthConfig(enabled=True, auth_type="apikey", api_key_name="api_token", api_key_value="token_abc", api_key_in="query")
        mgr_qry = DKSecSessionManager(cfg_qry)
        self.assertTrue(mgr_qry.is_authenticated)
        self.assertEqual(mgr_qry.session.params.get("api_token"), "token_abc")

    @patch("requests.Session.post")
    def test_09_oauth2_client_credentials(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "oauth2_bearer_token_xyz",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        mock_post.return_value = mock_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="oauth2",
            oauth_token_url="https://auth.company.com/oauth/token",
            oauth_client_id="client_123",
            oauth_client_secret="secret_abc",
            oauth_scope="read:all"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "oauth2")
        self.assertEqual(mgr.session.headers.get("Authorization"), "Bearer oauth2_bearer_token_xyz")

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_10_django_csrf_and_form_login(self, mock_post, mock_get):
        preflight_resp = MagicMock()
        preflight_resp.url = "https://app.com/login/"
        preflight_resp.status_code = 200
        preflight_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        preflight_resp.text = '<form action="/login/" method="post"><input type="hidden" name="csrfmiddlewaretoken" value="django_csrf_secret_token_123"><input type="text" name="username"><input type="password" name="password"></form>'
        mock_get.return_value = preflight_resp

        login_resp = MagicMock()
        login_resp.status_code = 302
        login_resp.headers = {"Location": "/dashboard"}
        login_resp.text = ""
        mock_post.return_value = login_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="https://app.com/login/",
            username="admin",
            password="SecurePassword123!"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "login")

        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["csrfmiddlewaretoken"], "django_csrf_secret_token_123")
        self.assertEqual(kwargs["data"]["username"], "admin")
        self.assertEqual(kwargs["data"]["password"], "SecurePassword123!")
        self.assertEqual(kwargs["headers"]["X-CSRFToken"], "django_csrf_secret_token_123")

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_11_laravel_csrf_and_email_field(self, mock_post, mock_get):
        preflight_resp = MagicMock()
        preflight_resp.url = "https://app.com/login"
        preflight_resp.status_code = 200
        preflight_resp.headers = {"Content-Type": "text/html"}
        preflight_resp.text = '<form action="/login" method="POST"><input type="hidden" name="_token" value="laravel_token_xyz"><input type="email" name="email"><input type="password" name="password"></form>'
        mock_get.return_value = preflight_resp

        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.headers = {"Content-Type": "application/json"}
        login_resp.text = '{"status": "success"}'
        login_resp.json.return_value = {"status": "success", "token": "laravel_bearer_456"}
        mock_post.return_value = login_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="https://app.com/login",
            username="test@domain.com",
            password="Password123"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["email"], "test@domain.com")
        self.assertEqual(kwargs["data"]["_token"], "laravel_token_xyz")

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_12_invalid_password_rejection_no_false_positive(self, mock_post, mock_get):
        preflight_resp = MagicMock()
        preflight_resp.url = "https://app.com/login"
        preflight_resp.status_code = 200
        preflight_resp.headers = {"Content-Type": "text/html"}
        preflight_resp.text = '<form><input name="csrfmiddlewaretoken" value="token"></form>'
        mock_get.return_value = preflight_resp

        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.headers = {"Content-Type": "text/html"}
        login_resp.text = '<html><div class="alert alert-danger">Please enter a correct username and password.</div><form action="/login" method="post"><input name="username"></form></html>'
        mock_post.return_value = login_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="https://app.com/login",
            username="wrong_user",
            password="wrong_password"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertFalse(mgr.is_authenticated)
        self.assertIsNotNone(mgr.login_error)
        self.assertIn("rejected", mgr.login_error.lower())





    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_13_rails_csrf_meta_tag(self, mock_post, mock_get):
        # Rails CSRF via meta tag and user[email]
        preflight_resp = MagicMock()
        preflight_resp.url = "https://rails-app.com/users/sign_in"
        preflight_resp.status_code = 200
        preflight_resp.headers = {"Content-Type": "text/html"}
        preflight_resp.text = '''
        <html>
        <head><meta name="csrf-token" content="rails_meta_csrf_token_888"></head>
        <body>
          <form action="/users/sign_in" method="post">
             <input type="text" name="user[email]">
             <input type="password" name="user[password]">
          </form>
        </body>
        </html>
        '''
        mock_get.return_value = preflight_resp

        login_resp = MagicMock()
        login_resp.status_code = 302
        login_resp.headers = {"Location": "/projects"}
        login_resp.text = ""
        mock_post.return_value = login_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="https://rails-app.com/users/sign_in",
            username="ruby_dev@domain.com",
            password="RailsSecretPassword!"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["user[email]"], "ruby_dev@domain.com")
        self.assertEqual(kwargs["data"]["user[password]"], "RailsSecretPassword!")
        self.assertEqual(kwargs["headers"]["X-CSRFToken"], "rails_meta_csrf_token_888")

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_14_aspnet_antiforgery_token(self, mock_post, mock_get):
        preflight_resp = MagicMock()
        preflight_resp.url = "https://dotnet-app.com/Account/Login"
        preflight_resp.status_code = 200
        preflight_resp.headers = {"Content-Type": "text/html"}
        preflight_resp.text = '''
        <form action="/Account/Login" method="post">
            <input name="__RequestVerificationToken" type="hidden" value="CfDJ8_DotNet_Antiforgery_Secret">
            <input type="text" name="Username">
            <input type="password" name="Password">
        </form>
        '''
        mock_get.return_value = preflight_resp

        login_resp = MagicMock()
        login_resp.status_code = 302
        login_resp.headers = {"Location": "/Home/Index"}
        mock_post.return_value = login_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="https://dotnet-app.com/Account/Login",
            username="dotnet_admin",
            password="DotNetPassword123#"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["__RequestVerificationToken"], "CfDJ8_DotNet_Antiforgery_Secret")
        self.assertEqual(kwargs["headers"]["RequestVerificationToken"], "CfDJ8_DotNet_Antiforgery_Secret")

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_15_spring_security_csrf(self, mock_post, mock_get):
        preflight_resp = MagicMock()
        preflight_resp.url = "https://spring-app.com/login"
        preflight_resp.status_code = 200
        preflight_resp.headers = {"Content-Type": "text/html"}
        preflight_resp.text = '''
        <form action="/login" method="post">
            <input type="hidden" name="_csrf" value="spring_security_csrf_token_999">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        '''
        mock_get.return_value = preflight_resp

        login_resp = MagicMock()
        login_resp.status_code = 302
        login_resp.headers = {"Location": "/"}
        mock_post.return_value = login_resp

        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="https://spring-app.com/login",
            username="spring_user",
            password="SpringPassword123"
        )
        mgr = DKSecSessionManager(cfg)
        self.assertTrue(mgr.is_authenticated)
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["_csrf"], "spring_security_csrf_token_999")
        self.assertEqual(kwargs["headers"]["X-CSRF-TOKEN"], "spring_security_csrf_token_999")

if __name__ == "__main__":
    unittest.main()
