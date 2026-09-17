"""
DKSec Web Dashboard Server (Enterprise Edition).
Provides a modern, lightweight browser interface with workflow presets,
live authenticated session testing, execution telemetry, and instant report downloads.
"""

from typing import Any, Dict, List, Optional
import os
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from dksec.config import DKSecConfig, STAGE_METADATA
from dksec.auth import AuthConfig, DKSecSessionManager
from dksec.llm import LLMConfig, LLMAssistant
from dksec.runner import DKSecRunner
from dksec.reporters import (
    HtmlReporter, JsonReporter, MarkdownReporter,
    SarifReporter, CycloneDXReporter
)

CURRENT_RUN = {
    "running": False,
    "progress": 0,
    "current_stage": None,
    "logs": [],
    "last_report": None,
    "report_dir": "./reports",
    "report_html_path": None
}


class DKSecWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            self._serve_dashboard()
        elif path == "/api/status":
            self._serve_json(CURRENT_RUN)
        elif path == "/api/metadata":
            self._serve_json(STAGE_METADATA)
        elif path.startswith("/download/"):
            fname = os.path.basename(path.replace("/download/", ""))
            fpath = os.path.join(CURRENT_RUN["report_dir"], fname)
            if os.path.exists(fpath):
                self.send_response(200)
                mime = "application/json" if fname.endswith((".json", ".sarif")) else ("text/html" if fname.endswith(".html") else "text/plain")
                self.send_header("Content-Type", f"{mime}; charset=utf-8")
                self.send_header("Content-Disposition", f'inline; filename="{fname}"')
                self.end_headers()
                with open(fpath, "rb") as fl:
                    self.wfile.write(fl.read())
            else:
                self.send_error(404, f"File {fname} not found")
        elif path == "/report" and CURRENT_RUN.get("report_html_path"):
            if os.path.exists(CURRENT_RUN["report_html_path"]):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(CURRENT_RUN["report_html_path"], "rb") as fl:
                    self.wfile.write(fl.read())
            else:
                self.send_error(404, "Report not yet generated.")
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/auth/test":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = {}

            target_url = data.get("target_url")
            auth_dict = data.get("auth", {})
            auth_cfg = AuthConfig.from_dict(auth_dict)
            auth_cfg.enabled = True

            session_mgr = DKSecSessionManager(auth_cfg, base_url=target_url)
            status = session_mgr.test_connection(target_url)
            status["is_authenticated"] = session_mgr.is_authenticated
            status["auth_method"] = session_mgr.auth_method
            status["token_found"] = bool(session_mgr.captured_token)
            status["cookies_captured"] = list(session_mgr.captured_cookies.keys())
            if session_mgr.login_error:
                status["login_error"] = session_mgr.login_error

            self._serve_json(status)
            return

        elif path == "/api/llm/test":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = {}

            llm_cfg = LLMConfig.from_dict(data)
            llm_cfg.enabled = True
            assistant = LLMAssistant(llm_cfg)
            status = assistant.test_connection()
            self._serve_json(status)
            return

        elif path == "/api/run":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = {}

            if CURRENT_RUN["running"]:
                self._serve_json({"status": "error", "message": "An audit is already running."}, status=400)
                return

            thread = threading.Thread(target=self._execute_scan_thread, args=(data,))
            thread.daemon = True
            thread.start()

            self._serve_json({"status": "started", "message": "DKSec pipeline started."})
        else:
            self.send_error(404, "Not Found")

    def _serve_json(self, data: Any, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _serve_dashboard(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        stages_html = ""
        for s_id, meta in sorted(STAGE_METADATA.items()):
            stages_html += f"""
            <div class="stage-card selected" id="card-{s_id}" onclick="toggleStage({s_id})">
              <div class="stage-cb">
                <input type="checkbox" id="stage-{s_id}" value="{s_id}" checked onclick="event.stopPropagation(); syncCard({s_id})" />
              </div>
              <div class="stage-info">
                <div class="stage-hdr">
                  <span class="stage-badge">Stage {s_id}</span>
                  <strong>{meta['name']}</strong>
                </div>
                <div class="stage-tool">{meta['recommended_repo']}</div>
                <div class="stage-desc">{meta['what_it_covers']}</div>
              </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DKSec - Enterprise Product Security Platform</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card: #131b2e;
      --card-inner: #0d1424;
      --card-hover: #1c2742;
      --border: #233252;
      --accent: #3b82f6;
      --accent-hover: #1d4ed8;
      --text: #f1f5f9;
      --heading: #ffffff;
      --muted: #94a3b8;
      --green: #10b981;
      --input-bg: #090d16;
      --input-text: #ffffff;
      --card-selected: #14203a;
      --stage-badge-bg: #233252;
      --stage-badge-text: #93c5fd;
      --stage-tool-text: #60a5fa;
      --console-bg: #090d16;
      --console-text: #94a3b8;
      --btn-preset-bg: #1a253e;
      --btn-preset-text: #cbd5e1;
      --btn-secondary-bg: #1e293b;
      --btn-secondary-text: #cbd5e1;
      --progress-track: #090d16;
      --dl-btn-bg: #162238;
      --dl-btn-text: #e2e8f0;
      --shadow: 0 4px 12px rgba(0,0,0,0.4);
    }}
    [data-theme="light"] {{
      --bg: #f8fafc;
      --card: #ffffff;
      --card-inner: #ffffff;
      --card-hover: #f1f5f9;
      --border: #cbd5e1;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --text: #1e293b;
      --heading: #0f172a;
      --muted: #64748b;
      --green: #059669;
      --input-bg: #ffffff;
      --input-text: #0f172a;
      --card-selected: #eff6ff;
      --stage-badge-bg: #dbeafe;
      --stage-badge-text: #1d4ed8;
      --stage-tool-text: #2563eb;
      --console-bg: #f8fafc;
      --console-text: #334155;
      --btn-preset-bg: #f1f5f9;
      --btn-preset-text: #334155;
      --btn-secondary-bg: #f1f5f9;
      --btn-secondary-text: #334155;
      --progress-track: #e2e8f0;
      --dl-btn-bg: #f1f5f9;
      --dl-btn-text: #1e293b;
      --shadow: 0 4px 16px rgba(0,0,0,0.06);
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 28px 20px; line-height: 1.5; transition: background 0.2s, color 0.2s; }}
    .container {{ max-width: 1180px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 18px; flex-wrap: wrap; gap: 16px; }}
    .logo {{ display: flex; align-items: center; gap: 14px; }}
    .shield {{ background: linear-gradient(135deg, #2563eb, #1d4ed8); width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 24px; box-shadow: 0 4px 12px rgba(37,99,235,0.4); }}
    .panel {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 22px; margin-bottom: 22px; box-shadow: var(--shadow); transition: background 0.2s, border-color 0.2s; }}
    h2 {{ font-size: 17px; margin-bottom: 14px; color: var(--heading); display: flex; align-items: center; gap: 8px; }}

    .preset-bar {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 18px; }}
    .btn-preset {{ background: var(--btn-preset-bg); border: 1px solid var(--border); color: var(--btn-preset-text); padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
    .btn-preset:hover {{ background: var(--card-hover); color: var(--heading); }}
    .btn-preset.active {{ background: #2563eb; color: #fff; border-color: #3b82f6; }}

    .form-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 14px; }}
    .form-group {{ display: flex; flex-direction: column; gap: 6px; }}
    label {{ font-size: 13px; font-weight: 600; color: var(--muted); }}
    input[type="text"], input[type="password"], select {{ background: var(--input-bg); border: 1px solid var(--border); color: var(--input-text); padding: 9px 12px; border-radius: 8px; font-size: 13px; transition: border-color 0.2s; }}
    input[type="text"]:focus, input[type="password"]:focus, select:focus {{ outline: none; border-color: var(--accent); }}

    .stages-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
    .stage-card {{ background: var(--card-inner); border: 1px solid var(--border); border-radius: 10px; padding: 14px; display: flex; gap: 12px; cursor: pointer; transition: all 0.2s; }}
    .stage-card:hover {{ border-color: var(--accent); background: var(--card-hover); }}
    .stage-card.selected {{ border-color: #3b82f6; background: var(--card-selected); }}
    .stage-cb input {{ width: 18px; height: 18px; cursor: pointer; margin-top: 2px; }}
    .stage-hdr {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
    .stage-hdr strong {{ color: var(--heading); }}
    .stage-badge {{ background: var(--stage-badge-bg); color: var(--stage-badge-text); font-size: 11px; font-weight: 800; padding: 2px 6px; border-radius: 4px; }}
    .stage-tool {{ font-size: 12px; color: var(--stage-tool-text); font-family: monospace; margin-bottom: 4px; }}
    .stage-desc {{ font-size: 12px; color: var(--muted); }}

    .action-row {{ display: flex; justify-content: space-between; align-items: center; margin-top: 20px; }}
    .btn {{ padding: 10px 20px; font-size: 13px; font-weight: 700; border-radius: 8px; cursor: pointer; border: none; transition: all 0.2s; display: inline-flex; align-items: center; gap: 8px; text-decoration: none; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .btn-success {{ background: #10b981; color: #fff; }}
    .btn-success:hover {{ background: #059669; }}
    .btn-secondary {{ background: var(--btn-secondary-bg); color: var(--btn-secondary-text); border: 1px solid var(--border); }}
    .btn-secondary:hover {{ background: var(--card-hover); color: var(--heading); }}

    #progressArea {{ display: none; }}
    .progress-track {{ background: var(--progress-track); border: 1px solid var(--border); border-radius: 10px; height: 16px; overflow: hidden; margin: 14px 0; }}
    .progress-fill {{ background: linear-gradient(90deg, #3b82f6, #10b981); height: 100%; width: 0%; transition: width 0.3s ease; }}
    .console {{ background: var(--console-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-family: monospace; font-size: 12px; height: 220px; overflow-y: auto; color: var(--console-text); }}

    .download-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-top: 16px; }}
    .dl-btn {{ background: var(--dl-btn-bg); border: 1px solid var(--border); padding: 10px 14px; border-radius: 8px; color: var(--dl-btn-text); font-size: 12px; font-weight: 600; text-decoration: none; display: flex; align-items: center; gap: 8px; transition: all 0.2s; }}
    .dl-btn:hover {{ background: var(--card-hover); color: var(--heading); border-color: var(--accent); }}
    
    .auth-badge {{ font-size: 11px; padding: 3px 8px; border-radius: 6px; font-weight: 700; }}
    .auth-badge.ok {{ background: rgba(16, 185, 129, 0.2); color: #059669; border: 1px solid #10b981; }}
    .auth-badge.err {{ background: rgba(239, 68, 68, 0.2); color: #dc2626; border: 1px solid #ef4444; }}
    .theme-toggle-btn {{ background: var(--btn-secondary-bg); color: var(--btn-secondary-text); border: 1px solid var(--border); padding: 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }}
    .theme-toggle-btn:hover {{ background: var(--card-hover); color: var(--heading); }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <div class="shield">🛡️</div>
        <div>
          <div style="font-size: 20px; font-weight: 800; color: var(--heading);">DKSec Platform</div>
          <div style="font-size: 12px; color: var(--muted);">Unified 9-Stage Product Security Lifecycle & DevSecOps Platform</div>
        </div>
      </div>
      <div id="topActions" style="display: flex; align-items: center; gap: 10px;">
        <button id="themeToggleBtn" onclick="toggleTheme()" class="theme-toggle-btn">🌓 Theme: Auto</button>
        <a id="btnOpenReport" href="/report" target="_blank" class="btn btn-success" style="display: none;">📄 Open Interactive Report</a>
      </div>
    </header>

    <div class="panel">
      <h2><span>⚙️</span> 1. Target Environment Configuration</h2>
      <div class="form-row">
        <div class="form-group">
          <label>Project Name</label>
          <input type="text" id="projectName" value="Enterprise Security Audit" />
        </div>
        <div class="form-group">
          <label>Source Code Directory Path</label>
          <input type="text" id="targetPath" value="samples/app" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Live Target URL / API Endpoint (Optional for DAST & VAPT)</label>
          <input type="text" id="targetUrl" placeholder="http://127.0.0.1:5000 or https://api.example.com" value="http://127.0.0.1:5000" />
        </div>
        <div class="form-group">
          <label>Reports Destination Directory</label>
          <input type="text" id="outputDir" value="./reports/web_audit" />
        </div>
      </div>
    </div>

    <!-- Live Authentication Panel -->
    <div class="panel">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <h2><span>🔐</span> 1b. Live Target Authentication & Session Configuration</h2>
        <span id="authStatusBadge" class="auth-badge ok" style="display: none;"></span>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Authentication Mode</label>
          <select id="authType" onchange="onAuthTypeChange()">
            <option value="none">None (Public Unauthenticated Scan)</option>
            <option value="login" selected>Automated Login URL (JSON / Form POST)</option>
            <option value="bearer">Bearer Token / JWT</option>
            <option value="cookie">Session Cookies</option>
            <option value="header">Custom Authorization Header</option>
          </select>
        </div>
        <div class="form-group" style="display: flex; flex-direction: row; align-items: flex-end; gap: 10px;">
          <button type="button" class="btn btn-secondary" onclick="testAuthentication()" style="height: 38px;">⚡ Test Session Connection</button>
        </div>
      </div>

      <!-- Login fields -->
      <div id="groupLogin" class="form-row">
        <div class="form-group">
          <label>Login Endpoint URL</label>
          <input type="text" id="authLoginUrl" placeholder="http://127.0.0.1:5000/api/v1/login" value="http://127.0.0.1:5000/api/v1/login" />
        </div>
        <div class="form-group" style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
          <div>
            <label>Username / Email</label>
            <input type="text" id="authUsername" value="admin" />
          </div>
          <div>
            <label>Password</label>
            <input type="password" id="authPassword" value="AdminSecretPassword99!" />
          </div>
        </div>
      </div>

      <!-- Bearer token field -->
      <div id="groupBearer" class="form-group" style="display: none; margin-bottom: 12px;">
        <label>Bearer Token / JWT</label>
        <input type="text" id="authBearer" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." />
      </div>

      <!-- Cookie field -->
      <div id="groupCookie" class="form-group" style="display: none; margin-bottom: 12px;">
        <label>Session Cookies (Key=Value; Key2=Value2)</label>
        <input type="text" id="authCookie" placeholder="session=abc123xyz; role=admin" />
      </div>

      <!-- Custom Header field -->
      <div id="groupHeader" class="form-group" style="display: none; margin-bottom: 12px;">
        <label>Custom Header (Header-Name: Header-Value)</label>
        <input type="text" id="authHeader" placeholder="X-API-Key: secret_production_token_123" />
      </div>

      <div id="authTestResult" style="display: none; margin-top: 10px; padding: 10px 14px; border-radius: 8px; font-size: 12px; font-family: monospace;"></div>
    </div>

    <!-- Dynamic AI / LLM Intelligence Panel -->
    <div class="panel">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <h2><span>🤖</span> 1c. Dynamic AI / LLM Security Assistant (Optional)</h2>
        <span id="llmStatusBadge" class="auth-badge ok" style="display: none;"></span>
      </div>
      <p style="font-size: 13px; color: var(--muted); margin-bottom: 14px;">
        Empower audits with autonomous AI triaging, false-positive elimination, contextual remediation diffs, and board-ready CISO executive summaries.
      </p>

      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
        <input type="checkbox" id="llmEnabled" onchange="onLLMEnabledChange()" style="width: 18px; height: 18px; cursor: pointer;" />
        <label for="llmEnabled" style="font-weight: 700; color: #fff; cursor: pointer;">Enable Smart LLM Engine</label>
      </div>

      <div id="llmConfigFields" style="display: none;">
        <div class="form-row">
          <div class="form-group">
            <label>LLM Provider</label>
            <select id="llmProvider" onchange="onLLMProviderChange()">
              <option value="openai" selected>OpenAI (GPT-4o / GPT-4o-mini)</option>
              <option value="gemini">Google Gemini (Gemini 1.5 Pro / Flash)</option>
              <option value="anthropic">Anthropic Claude (Claude 3.5 Sonnet)</option>
              <option value="ollama">Ollama Local / Private (Zero Telemetry)</option>
              <option value="custom">Custom OpenAI-Compatible Endpoint</option>
            </select>
          </div>
          <div class="form-group">
            <label>Model Name</label>
            <input type="text" id="llmModel" value="gpt-4o" placeholder="gpt-4o, gemini-1.5-pro, claude-3-5-sonnet, llama3..." />
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>API Key <span style="font-size: 11px; color: var(--muted); font-weight: normal;">(Optional if ENV var set: OPENAI_API_KEY, GEMINI_API_KEY, etc.)</span></label>
            <input type="password" id="llmApiKey" placeholder="sk-... (Leave empty to use environment variable)" />
          </div>
          <div class="form-group">
            <label>Custom Base URL <span style="font-size: 11px; color: var(--muted); font-weight: normal;">(For Ollama or private LLM gateway)</span></label>
            <input type="text" id="llmBaseUrl" placeholder="http://localhost:11434/v1" />
          </div>
        </div>

        <div style="display: flex; gap: 10px; align-items: center; margin-top: 10px;">
          <button type="button" class="btn btn-secondary" onclick="testLLMConnection()" style="height: 38px;">⚡ Test AI Connection</button>
          <span style="font-size: 12px; color: var(--muted);">Tests live LLM model connectivity and verifies credentials</span>
        </div>

        <div id="llmTestResult" style="display: none; margin-top: 12px; padding: 10px 14px; border-radius: 8px; font-size: 12px; font-family: monospace;"></div>
      </div>
    </div>

    <div class="panel">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h2><span>🎯</span> 2. Select Workflow Preset or Custom Stages</h2>
      </div>

      <div class="preset-bar">
        <button class="btn-preset active" onclick="applyPreset('all', this)">⚡ Full 9-Stage Audit</button>
        <button class="btn-preset" onclick="applyPreset('pr', this)">🚀 Fast PR Gate (1, 3, 8)</button>
        <button class="btn-preset" onclick="applyPreset('api', this)">🌐 API & Web Pentest (4, 5, 6)</button>
        <button class="btn-preset" onclick="applyPreset('sbom', this)">📦 Supply Chain & SBOM (2, 3, 8)</button>
        <button class="btn-preset" onclick="applyPreset('vapt', this)">🎯 VAPT Only (Stage 6)</button>
        <button class="btn-preset" onclick="applyPreset('sast', this)">🔍 SAST Only (Stage 3)</button>
        <button class="btn-preset" onclick="applyPreset('threat', this)">📐 Threat Model (Stage 1)</button>
      </div>

      <div class="stages-grid">
        {stages_html}
      </div>

      <div class="action-row">
        <span id="selectedCounter" style="color: var(--muted); font-size: 13px;">9 of 9 stages selected</span>
        <button id="btnRun" class="btn btn-primary" onclick="launchAudit()">🚀 Run Selected Security Audit</button>
      </div>
    </div>

    <div id="progressArea" class="panel">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2><span>📡</span> Live Pipeline Execution</h2>
        <span id="statusBadge" style="background: #2563eb; color: #fff; font-size: 11px; padding: 4px 10px; border-radius: 12px; font-weight: 700;">RUNNING</span>
      </div>
      <div class="progress-track">
        <div id="progressFill" class="progress-fill"></div>
      </div>
      <div id="statusMessage" style="font-size: 13px; color: #93c5fd; margin-bottom: 10px;">Initializing DKSec engines...</div>
      <div id="consoleLog" class="console"></div>

      <div id="downloadSection" style="display: none; margin-top: 20px; border-top: 1px solid var(--border); padding-top: 18px;">
        <h3 style="font-size: 15px; margin-bottom: 8px;">📦 Download Generated Industry Artifacts:</h3>
        <div class="download-grid">
          <a class="dl-btn" href="/download/dksec-report.html" target="_blank">🌐 Interactive HTML</a>
          <a class="dl-btn" href="/download/cyclonedx-sbom.json" target="_blank">📦 CycloneDX 1.5 SBOM</a>
          <a class="dl-btn" href="/download/dksec-results.sarif" target="_blank">📥 OASIS SARIF 2.1.0</a>
          <a class="dl-btn" href="/download/defectdojo-findings.json" target="_blank">🎯 DefectDojo JSON</a>
          <a class="dl-btn" href="/download/threat-dragon-model.json" target="_blank">📐 Threat Dragon v2</a>
          <a class="dl-btn" href="/download/wazuh-local_rules.xml" target="_blank">🛡️ Wazuh SIEM XML</a>
          <a class="dl-btn" href="/download/sigma-rules.yml" target="_blank">⚡ Sigma YAML</a>
          <a class="dl-btn" href="/download/jira-issues.json" target="_blank">🎟️ Jira Issues JSON</a>
        </div>
      </div>
    </div>
  </div>

  <script>
    let poll = null;

    function setTheme(t) {{
      document.documentElement.setAttribute('data-theme', t);
      try {{ localStorage.setItem('dksec_theme', t); }} catch(e) {{}}
      const btn = document.getElementById('themeToggleBtn');
      if (btn) {{
        btn.innerHTML = (t === 'light') ? '☀️ Theme: Light' : '🌙 Theme: Dark';
      }}
    }}

    function toggleTheme() {{
      const cur = document.documentElement.getAttribute('data-theme') || 'dark';
      setTheme(cur === 'light' ? 'dark' : 'light');
    }}

    (function() {{
      let saved = 'dark';
      try {{
        saved = localStorage.getItem('dksec_theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      }} catch(e) {{}}
      setTheme(saved);
    }})();

    function onAuthTypeChange() {{
      const type = document.getElementById('authType').value;
      document.getElementById('groupLogin').style.display = (type === 'login') ? 'grid' : 'none';
      document.getElementById('groupBearer').style.display = (type === 'bearer') ? 'block' : 'none';
      document.getElementById('groupCookie').style.display = (type === 'cookie') ? 'block' : 'none';
      document.getElementById('groupHeader').style.display = (type === 'header') ? 'block' : 'none';
    }}

    function getAuthConfig() {{
      const type = document.getElementById('authType').value;
      if (type === 'none') return {{ enabled: false, auth_type: 'none' }};
      return {{
        enabled: true,
        auth_type: type,
        login_url: document.getElementById('authLoginUrl').value || null,
        username: document.getElementById('authUsername').value || null,
        password: document.getElementById('authPassword').value || null,
        bearer_token: document.getElementById('authBearer').value || null,
        cookies: document.getElementById('authCookie').value || null,
        custom_header: document.getElementById('authHeader').value || null
      }};
    }}

    function testAuthentication() {{
      const targetUrl = document.getElementById('targetUrl').value;
      const auth = getAuthConfig();
      const resBox = document.getElementById('authTestResult');
      resBox.style.display = 'block';
      resBox.style.background = '#090d16';
      resBox.style.border = '1px solid var(--border)';
      resBox.style.color = '#93c5fd';
      resBox.innerHTML = 'Connecting to target and validating session...';

      fetch('/api/auth/test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ target_url: targetUrl, auth: auth }})
      }}).then(r => r.json()).then(d => {{
        if (d.success || d.is_authenticated) {{
          resBox.style.border = '1px solid #10b981';
          resBox.style.color = '#34d399';
          let details = `✔ Success: Authenticated via ${{(d.auth_method||'session').toUpperCase()}} (HTTP ${{d.status_code||200}}).`;
          if (d.token_found) details += ` Token captured.`;
          if (d.cookies_captured && d.cookies_captured.length > 0) details += ` Cookies: ${{d.cookies_captured.join(', ')}}.`;
          resBox.innerText = details;
        }} else {{
          resBox.style.border = '1px solid #ef4444';
          resBox.style.color = '#f87171';
          resBox.innerText = `✖ Authentication test failed: ${{d.message || d.login_error || 'Could not verify session'}}`;
        }}
      }}).catch(err => {{
        resBox.style.border = '1px solid #ef4444';
        resBox.style.color = '#f87171';
        resBox.innerText = 'Connection error: ' + err;
      }});
    }}

    function onLLMEnabledChange() {{
      const en = document.getElementById('llmEnabled').checked;
      document.getElementById('llmConfigFields').style.display = en ? 'block' : 'none';
    }}

    function onLLMProviderChange() {{
      const prov = document.getElementById('llmProvider').value;
      const modelMap = {{
        'openai': 'gpt-4o',
        'gemini': 'gemini-1.5-pro',
        'anthropic': 'claude-3-5-sonnet-20240620',
        'ollama': 'llama3',
        'custom': 'default'
      }};
      document.getElementById('llmModel').value = modelMap[prov] || 'gpt-4o';
      if (prov === 'ollama') {{
        document.getElementById('llmBaseUrl').value = 'http://localhost:11434/v1';
      }}
    }}

    function getLLMConfig() {{
      const enabled = document.getElementById('llmEnabled').checked;
      return {{
        enabled: enabled,
        provider: document.getElementById('llmProvider').value,
        model: document.getElementById('llmModel').value,
        api_key: document.getElementById('llmApiKey').value || null,
        api_base_url: document.getElementById('llmBaseUrl').value || null
      }};
    }}

    function testLLMConnection() {{
      const cfg = getLLMConfig();
      const resBox = document.getElementById('llmTestResult');
      resBox.style.display = 'block';
      resBox.style.background = '#090d16';
      resBox.style.border = '1px solid var(--border)';
      resBox.style.color = '#93c5fd';
      resBox.innerHTML = 'Testing connection to ' + cfg.provider.toUpperCase() + ' (' + cfg.model + ')...';

      fetch('/api/llm/test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(cfg)
      }}).then(r => r.json()).then(d => {{
        if (d.success) {{
          resBox.style.border = '1px solid #10b981';
          resBox.style.color = '#34d399';
          resBox.innerText = `✔ Success: ${{d.message}}`;
        }} else {{
          resBox.style.border = '1px solid #ef4444';
          resBox.style.color = '#f87171';
          resBox.innerText = `✖ Connection failed: ${{d.message}}`;
        }}
      }}).catch(err => {{
        resBox.style.border = '1px solid #ef4444';
        resBox.style.color = '#f87171';
        resBox.innerText = 'Connection error: ' + err;
      }});
    }}

    function toggleStage(sId) {{
      const cb = document.getElementById('stage-' + sId);
      cb.checked = !cb.checked;
      syncCard(sId);
    }}

    function syncCard(sId) {{
      const cb = document.getElementById('stage-' + sId);
      const card = document.getElementById('card-' + sId);
      if (cb.checked) {{
        card.classList.add('selected');
      }} else {{
        card.classList.remove('selected');
      }}
      updateCounter();
    }}

    function applyPreset(preset, btn) {{
      document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');

      let targets = [];
      if (preset === 'all') targets = [1, 2, 3, 4, 5, 6, 7, 8, 9];
      else if (preset === 'pr') targets = [1, 3, 8];
      else if (preset === 'api') targets = [4, 5, 6];
      else if (preset === 'sbom') targets = [2, 3, 8];
      else if (preset === 'vapt') targets = [6];
      else if (preset === 'sast') targets = [3];
      else if (preset === 'threat') targets = [1];

      for (let i = 1; i <= 9; i++) {{
        const cb = document.getElementById('stage-' + i);
        if (cb) {{
          cb.checked = targets.includes(i);
          syncCard(i);
        }}
      }}
    }}

    function updateCounter() {{
      const count = document.querySelectorAll('input[type="checkbox"]:checked').length;
      document.getElementById('selectedCounter').innerText = `${{count}} of 9 stages selected`;
    }}

    function launchAudit() {{
      const selected = Array.from(document.querySelectorAll('input[type="checkbox"]:checked')).map(c => parseInt(c.value));
      if (selected.length === 0) {{
        alert('Please select at least one stage.');
        return;
      }}

      const payload = {{
        project_name: document.getElementById('projectName').value,
        target_path: document.getElementById('targetPath').value,
        target_url: document.getElementById('targetUrl').value || null,
        auth: getAuthConfig(),
        llm: getLLMConfig(),
        output_dir: document.getElementById('outputDir').value,
        stages: selected
      }};

      document.getElementById('btnRun').disabled = true;
      document.getElementById('btnRun').innerText = '⏳ Executing Security Audit...';
      document.getElementById('progressArea').style.display = 'block';
      document.getElementById('downloadSection').style.display = 'none';
      document.getElementById('consoleLog').innerHTML = '';

      fetch('/api/run', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }}).then(res => res.json()).then(data => {{
        poll = setInterval(checkProgress, 800);
      }}).catch(err => {{
        alert('Failed to start audit: ' + err);
        document.getElementById('btnRun').disabled = false;
      }});
    }}

    function checkProgress() {{
      fetch('/api/status').then(r => r.json()).then(d => {{
        document.getElementById('progressFill').style.width = d.progress + '%';
        if (d.current_stage) {{
          document.getElementById('statusMessage').innerText = d.current_stage + ` (${{d.progress}}%)`;
        }}

        const box = document.getElementById('consoleLog');
        box.innerHTML = d.logs.map(l => `<div>${{l}}</div>`).join('');
        box.scrollTop = box.scrollHeight;

        if (!d.running && d.progress === 100) {{
          clearInterval(poll);
          document.getElementById('statusBadge').innerText = 'COMPLETED';
          document.getElementById('statusBadge').style.background = '#10b981';
          document.getElementById('statusMessage').innerText = '🎉 Audit successfully completed! Artifacts ready below.';
          document.getElementById('btnOpenReport').style.display = 'inline-flex';
          document.getElementById('downloadSection').style.display = 'block';
          document.getElementById('btnRun').disabled = false;
          document.getElementById('btnRun').innerText = '🚀 Run Another Audit';
        }}
      }});
    }}
  </script>
</body>
</html>
        """
        self.wfile.write(html.encode("utf-8"))

    def _execute_scan_thread(self, data: Dict[str, Any]):
        global CURRENT_RUN
        CURRENT_RUN["running"] = True
        CURRENT_RUN["progress"] = 5
        CURRENT_RUN["logs"] = ["Initializing DKSec Platform..."]
        CURRENT_RUN["current_stage"] = "Configuring environment"
        output_dir = data.get("output_dir", "./reports/web_audit")
        CURRENT_RUN["report_dir"] = output_dir

        try:
            auth_data = data.get("auth", {})
            auth_cfg = AuthConfig.from_dict(auth_data)

            llm_data = data.get("llm", {})
            llm_cfg = LLMConfig.from_dict(llm_data)

            cfg = DKSecConfig(
                project_name=data.get("project_name", "Enterprise Security Audit"),
                target_path=data.get("target_path", "."),
                target_url=data.get("target_url"),
                auth=auth_cfg,
                llm=llm_cfg,
                output_dir=output_dir
            )

            stages = data.get("stages", list(range(1, 10)))
            total = len(stages)

            def event_callback(evt: str, payload: Dict[str, Any]):
                if evt == "stage_started":
                    s_id = payload.get("stage_id")
                    s_name = payload.get("stage_name")
                    CURRENT_RUN["current_stage"] = f"Stage {s_id}: {s_name}"
                    idx = stages.index(s_id) if s_id in stages else 0
                    CURRENT_RUN["progress"] = int(10 + (idx / total) * 80)
                    CURRENT_RUN["logs"].append(f"[RUNNING] Stage {s_id}: {s_name}")
                elif evt == "stage_completed":
                    s_id = payload.get("stage_id")
                    count = payload.get("findings_count", 0)
                    CURRENT_RUN["logs"].append(f"[SUCCESS] Stage {s_id} complete: {count} findings identified.")
                elif evt == "stage_error":
                    s_id = payload.get("stage_id")
                    err = payload.get("error")
                    CURRENT_RUN["logs"].append(f"[ERROR] Stage {s_id}: {err}")
                elif evt == "llm_started":
                    prov = payload.get("provider", "AI").upper()
                    mod = payload.get("model", "")
                    CURRENT_RUN["logs"].append(f"[AI ENGINE] Starting Smart Triage & CISO Executive Synthesis ({prov} {mod})...")
                elif evt == "llm_completed":
                    CURRENT_RUN["logs"].append("[AI ENGINE] LLM triaging and executive briefing generated.")
                elif evt == "llm_error":
                    CURRENT_RUN["logs"].append(f"[AI WARNING] LLM issue ({payload.get('error')}) - activated heuristic fallback.")

            runner = DKSecRunner(cfg, event_callback=event_callback)
            report = runner.run(selected_stages=stages)

            CURRENT_RUN["progress"] = 92
            CURRENT_RUN["current_stage"] = "Generating standard artifacts (HTML, SARIF, SBOM, DefectDojo)"

            os.makedirs(cfg.output_dir, exist_ok=True)
            html_path = os.path.join(cfg.output_dir, "dksec-report.html")
            json_path = os.path.join(cfg.output_dir, "dksec-report.json")
            md_path = os.path.join(cfg.output_dir, "dksec-report.md")
            sarif_path = os.path.join(cfg.output_dir, "dksec-results.sarif")
            sbom_path = os.path.join(cfg.output_dir, "cyclonedx-sbom.json")

            HtmlReporter.generate(report, html_path)
            JsonReporter.generate(report, json_path)
            MarkdownReporter.generate(report, md_path)
            SarifReporter.generate(report, sarif_path)
            CycloneDXReporter.generate(report, sbom_path)

            CURRENT_RUN["report_html_path"] = html_path
            CURRENT_RUN["last_report"] = report.to_dict()
            CURRENT_RUN["progress"] = 100
            CURRENT_RUN["current_stage"] = "Completed"
            CURRENT_RUN["logs"].append(f"[DONE] Security Score: {report.overall_score}/100 | Gate: {report.gate_verdict.status}")
            CURRENT_RUN["logs"].append(f"[DONE] Generated HTML, SARIF 2.1.0, CycloneDX 1.5 SBOM, DefectDojo, and Sigma rules.")

        except Exception as e:
            CURRENT_RUN["logs"].append(f"[FATAL] Pipeline error: {str(e)}")
        finally:
            CURRENT_RUN["running"] = False


def start_server(port: int = 8080, host: str = "127.0.0.1"):
    server = HTTPServer((host, port), DKSecWebHandler)
    print(f"\n=======================================================")
    print(f"🛡️  DKSec Web Dashboard active at: http://{host}:{port}")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DKSec Web Server.")
        server.server_close()
