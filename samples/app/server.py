"""
Sample Fintech Microservice Application for DKSec demonstration.
Supports both Flask (if installed) and zero-dependency Python http.server fallback.
"""
import os
import json
import sqlite3
import yaml

# Hardcoded credentials (SAST & Secret Scanning Target)
DB_PASS = "AdminSecretPassword99!"

try:
    from flask import Flask, request, jsonify
    app = Flask(__name__)
    app.config['DEBUG'] = True
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

    class FlaskShim:
        def __init__(self, name):
            self.routes = {}

        def route(self, path, methods=["GET"]):
            def decorator(func):
                for m in methods:
                    self.routes[(path, m.upper())] = func
                return func
            return decorator

    app = FlaskShim(__name__)


@app.route("/api/v1/login", methods=["POST"])
def login(req_data=None):
    # SAST: SQL Injection vulnerability
    data = req_data or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Simulated SQL query
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
    except Exception:
        pass
    
    if username == "admin" and password == "AdminSecretPassword99!":
        return {
            "status": "success",
            "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImRiX3Bhc3MiOiJBZG1pblNlY3JldFBhc3N3b3JkOTkhIn0."
        }, 200
    return {"error": "invalid credentials"}, 401


@app.route("/api/v1/transfer", methods=["POST"])
def transfer(req_data=None):
    # Repudiation / Missing audit trail
    data = req_data or {}
    amount = data.get("amount")
    to_acc = data.get("to_account")
    return {"status": "transferred", "amount": amount, "to_account": to_acc}, 200


@app.route("/api/v1/import-config", methods=["POST"])
def import_config(raw_content=None):
    # SAST: Unsafe YAML deserialization
    content = raw_content or ""
    try:
        cfg = yaml.load(content)
    except Exception:
        pass
    return {"imported": True}, 200



@app.route("/api/v1/admin/debug", methods=["GET"])
def admin_debug():
    # BOLA / BFLA: Sensitive DB password leak in API response
    return {
        "env": os.environ.get("ENV", "production"),
        "service": "Fintech-Core-Banking",
        "db_pass": DB_PASS
    }, 200


if __name__ == "__main__":
    if HAS_FLASK:
        app.run(host="0.0.0.0", port=5000, debug=True)
    else:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse

        class FallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/api/v1/admin/debug":
                    res, code = admin_debug()
                    self._send_json(res, code)
                elif parsed.path == "/api/v1/users/1":
                    self._send_json({"id": 1, "username": "admin", "role": "admin"}, 200)
                elif parsed.path == "/api/v1/users":
                    self._send_json([{"id": 1, "username": "admin"}, {"id": 2, "username": "bob"}], 200)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                parsed = urllib.parse.urlparse(self.path)
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body.decode("utf-8"))
                except Exception:
                    data = {}

                if parsed.path == "/api/v1/login":
                    res, code = login(data)
                    self._send_json(res, code, set_cookie="session=fintech_session_token_xyz; Path=/")
                elif parsed.path == "/api/v1/transfer":
                    res, code = transfer(data)
                    self._send_json(res, code)
                elif parsed.path == "/api/v1/import-config":
                    res, code = import_config(body.decode("utf-8", errors="ignore"))
                    self._send_json(res, code)
                else:
                    self.send_response(404)
                    self.end_headers()

            def _send_json(self, data, code=200, set_cookie=None):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                if set_cookie:
                    self.send_header("Set-Cookie", set_cookie)
                self.end_headers()
                self.wfile.write(json.dumps(data).encode("utf-8"))

        server = HTTPServer(("0.0.0.0", 5000), FallbackHandler)
        print("Sample Fintech App active at http://127.0.0.1:5000")
        server.serve_forever()
