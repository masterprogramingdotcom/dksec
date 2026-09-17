"""
Sample Fintech Microservice Application for DKSec demonstration.
"""
import os
import sqlite3
import pickle
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)
# Insecure configuration
app.config['DEBUG'] = True

# Hardcoded credentials
DB_PASS = "AdminSecretPassword99!"

@app.route("/api/v1/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    
    # SAST: SQL Injection vulnerability
    conn = sqlite3.connect("database.sqlite")
    cursor = conn.cursor()
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({"status": "success", "token": "eyJh...dummy_jwt..."})
    return jsonify({"error": "invalid credentials"}), 401

@app.route("/api/v1/transfer", methods=["POST"])
def transfer():
    # Repudiation / Missing audit trail
    data = request.get_json() or {}
    amount = data.get("amount")
    to_acc = data.get("to_account")
    # No logging, no authorization check
    return jsonify({"status": "transferred", "amount": amount})

@app.route("/api/v1/import-config", methods=["POST"])
def import_config():
    # SAST: Unsafe YAML deserialization
    content = request.data.decode("utf-8")
    cfg = yaml.load(content)
    return jsonify({"imported": True})

@app.route("/api/v1/admin/debug", methods=["GET"])
def admin_debug():
    # BOLA / Missing RBAC on sensitive admin endpoint
    return jsonify({
        "env": os.environ.get("ENV", "production"),
        "db_pass": DB_PASS
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
