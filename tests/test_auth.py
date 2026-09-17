"""
Unit and integration tests for DKSec Authentication & Live Session Management.
"""

import unittest
import os
import json
import base64
import http.server
import threading
import time
from dksec.auth import AuthConfig, DKSecSessionManager
from dksec.config import DKSecConfig
from dksec.stages.stage4_dast_api import Stage4DastApi
from dksec.stages.stage6_vapt import Stage6Vapt


class MockAuthServer(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if self.path == "/api/v1/login":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
            if body.get("username") == "admin" and body.get("password") == "AdminSecretPassword99!":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                # Set session cookie missing HttpOnly and Secure for testing
                self.send_header("Set-Cookie", "session_id=mock_session_abc123; Path=/")
                self.end_headers()
                # Return mock JWT with alg none for testing
                jwt_h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("utf-8").rstrip("=")
                jwt_p = base64.urlsafe_b64encode(b'{"sub":"admin","role":"superuser","db_pass":"leaked_secret"}').decode("utf-8").rstrip("=")
                token = f"{jwt_h}.{jwt_p}."
                self.wfile.write(json.dumps({"status": "success", "token": token}).encode("utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid credentials"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        auth_hdr = self.headers.get("Authorization", "")
        cookie_hdr = self.headers.get("Cookie", "")

        if self.path == "/api/v1/admin/debug":
            if "Bearer " in auth_hdr or "session_id=" in cookie_hdr:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"env": "test", "db_pass": "ProductionDBPassword123!"}).encode("utf-8"))
            else:
                self.send_response(401)
                self.end_headers()
        elif self.path == "/api/v1/users/1":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id": 1, "username": "admin", "email": "admin@example.com"}).encode("utf-8"))
        elif self.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()


class TestDKSecAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockAuthServer)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_auth_config_serialization(self):
        cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url="http://127.0.0.1:5000/login",
            username="admin",
            password="secretpassword"
        )
        d = cfg.to_dict()
        self.assertEqual(d["auth_type"], "login")
        self.assertEqual(d["username"], "admin")

        reloaded = AuthConfig.from_dict(d)
        self.assertTrue(reloaded.enabled)
        self.assertEqual(reloaded.password, "secretpassword")

    def test_bearer_token_session(self):
        auth_cfg = AuthConfig(
            enabled=True,
            auth_type="bearer",
            bearer_token="mock_bearer_jwt_token_12345"
        )
        mgr = DKSecSessionManager(auth_cfg, base_url=self.base_url)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "bearer")
        self.assertIn("Authorization", mgr.session.headers)
        self.assertEqual(mgr.session.headers["Authorization"], "Bearer mock_bearer_jwt_token_12345")

    def test_cookie_session(self):
        auth_cfg = AuthConfig(
            enabled=True,
            auth_type="cookie",
            cookies="session=abc123xyz; role=admin"
        )
        mgr = DKSecSessionManager(auth_cfg, base_url=self.base_url)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.session.cookies.get("session"), "abc123xyz")
        self.assertEqual(mgr.session.cookies.get("role"), "admin")

    def test_custom_header_session(self):
        auth_cfg = AuthConfig(
            enabled=True,
            auth_type="header",
            custom_header="X-Custom-API-Key: SuperSecretKey"
        )
        mgr = DKSecSessionManager(auth_cfg, base_url=self.base_url)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.session.headers.get("X-Custom-API-Key"), "SuperSecretKey")

    def test_automated_login_flow(self):
        auth_cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url=f"{self.base_url}/api/v1/login",
            username="admin",
            password="AdminSecretPassword99!"
        )
        mgr = DKSecSessionManager(auth_cfg, base_url=self.base_url)
        self.assertTrue(mgr.is_authenticated)
        self.assertEqual(mgr.auth_method, "login")
        self.assertIsNotNone(mgr.captured_token)
        self.assertIn("session_id", mgr.captured_cookies)

        # Audit JWT token
        jwt_findings = mgr.audit_jwt()
        self.assertTrue(any(f.id == "AUTH-JWT-ALG-NONE" for f in jwt_findings))
        self.assertTrue(any("LEAK" in f.id for f in jwt_findings))

        # Test authenticated connection
        res = mgr.test_connection(f"{self.base_url}/api/v1/admin/debug")
        self.assertTrue(res["success"])
        self.assertEqual(res["status_code"], 200)

    def test_stage4_authenticated_scan(self):
        auth_cfg = AuthConfig(
            enabled=True,
            auth_type="login",
            login_url=f"{self.base_url}/api/v1/login",
            username="admin",
            password="AdminSecretPassword99!"
        )
        config = DKSecConfig(
            project_name="Live Auth Test",
            target_path="samples/app",
            target_url=self.base_url,
            auth=auth_cfg
        )
        stage4 = Stage4DastApi()
        context = {"stage_results": {}, "all_findings": []}
        findings, metrics, details = stage4.run(config, context)

        self.assertTrue(metrics.get("authenticated_scan"))
        self.assertTrue(len(findings) > 0)
        # Verify sensitive data leak detection (db_pass)
        self.assertTrue(any("DATA-LEAK" in f.id or "AUTH" in f.id for f in findings))

    def test_stage6_authenticated_vapt(self):
        auth_cfg = AuthConfig(
            enabled=True,
            auth_type="bearer",
            bearer_token="test_token"
        )
        config = DKSecConfig(
            project_name="Live VAPT Test",
            target_path="samples/app",
            target_url=self.base_url,
            auth=auth_cfg
        )
        stage6 = Stage6Vapt()
        context = {"stage_results": {}, "all_findings": []}
        findings, metrics, details = stage6.run(config, context)

        self.assertTrue(metrics.get("authenticated_pentest"))
        self.assertIn("endpoints_fuzzed", metrics)


if __name__ == "__main__":
    unittest.main()
