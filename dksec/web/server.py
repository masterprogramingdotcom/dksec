"""
DKSec Web Dashboard Server (Enterprise Edition).
Provides a modern, lightweight browser interface with workflow presets,
live authenticated session testing, execution telemetry, and instant report downloads.
"""

from typing import Any, Dict, List, Optional
import os
import json
import threading
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
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
    "report_html_path": None,
    "report_summary": None,
}

# Auto-discover any existing report from previous runs at startup (picks newest)
def _auto_discover_report():
    candidates = [
        "./reports/dksec-report.html",
        "./reports/web_audit/dksec-report.html",
        "./reports/web_pentest/dksec-report.html",
        "./reports/code_audit/dksec-report.html",
        "./reports/url_only/dksec-report.html",
    ]
    newest = None
    newest_mtime = 0
    for c in candidates:
        if os.path.exists(c):
            try:
                mt = os.path.getmtime(c)
                if mt > newest_mtime:
                    newest_mtime = mt
                    newest = c
            except Exception:
                pass
    if newest:
        CURRENT_RUN["report_html_path"] = os.path.abspath(newest)
        CURRENT_RUN["report_dir"] = os.path.dirname(os.path.abspath(newest))

_auto_discover_report()


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
        elif path == "/api/scan/stream":
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            last_log_idx = 0
            import time
            while True:
                if len(CURRENT_RUN["logs"]) > last_log_idx:
                    for i in range(last_log_idx, len(CURRENT_RUN["logs"])):
                        log = CURRENT_RUN["logs"][i]
                        self.wfile.write(f"data: {json.dumps(log)}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    last_log_idx = len(CURRENT_RUN["logs"])
                
                if not CURRENT_RUN["running"] and last_log_idx == len(CURRENT_RUN["logs"]):
                    self.wfile.write(f"data: {json.dumps({'event': 'completed'})}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    break
                
                time.sleep(1)
            return

        elif path.startswith("/download/"):
            fname = os.path.basename(path.replace("/download/", ""))
            # Search in current report_dir first, then fallback dirs
            search_dirs = [
                CURRENT_RUN["report_dir"],
                "./reports",
                "./reports/web_audit",
                "./reports/web_pentest",
                "./reports/code_audit",
            ]
            fpath = None
            for d in search_dirs:
                candidate = os.path.join(d, fname)
                if os.path.exists(candidate):
                    fpath = candidate
                    break
            if fpath:
                self.send_response(200)
                mime = "application/json" if fname.endswith((".json", ".sarif")) else ("text/html" if fname.endswith(".html") else ("text/xml" if fname.endswith(".xml") else ("text/plain")))
                self.send_header("Content-Type", f"{mime}; charset=utf-8")
                self.send_header("Content-Disposition", f'inline; filename="{fname}"')
                self.end_headers()
                with open(fpath, "rb") as fl:
                    self.wfile.write(fl.read())
            else:
                self.send_error(404, f"File '{fname}' not found. Run a scan first to generate it.")
        elif path == "/report":
            # Try from last scan first, then fall back to known report paths
            # Always pick the most recently generated report
            candidates = [
                CURRENT_RUN.get("report_html_path"),
                os.path.join(CURRENT_RUN["report_dir"], "dksec-report.html"),
                "./reports/dksec-report.html",
                "./reports/web_pentest/dksec-report.html",
                "./reports/web_audit/dksec-report.html",
                "./reports/code_audit/dksec-report.html",
                "./reports/url_only/dksec-report.html",
            ]
            newest = None
            newest_mtime = 0
            for c in candidates:
                if c and os.path.exists(str(c)):
                    try:
                        mt = os.path.getmtime(c)
                        if mt > newest_mtime:
                            newest_mtime = mt
                            newest = c
                    except Exception:
                        pass
            html_path = newest
            if html_path:
                CURRENT_RUN["report_html_path"] = os.path.abspath(html_path)
            if html_path and os.path.exists(html_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(html_path, "rb") as fl:
                    self.wfile.write(fl.read())
            else:
                self.send_error(404, "No report found. Please run a scan first.")
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
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DKSec - Enterprise Security Platform</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --card: #ffffff;
      --card-inner: #f1f5f9;
      --card-hover: #f8fafc;
      --card-selected: #eff6ff;
      --border: #e2e8f0;
      --border-focus: #3b82f6;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --heading: #0f172a;
      --text: #334155;
      --muted: #64748b;
      --input-bg: #ffffff;
      --input-text: #0f172a;
      --console-bg: #0f172a;
      --console-text: #e2e8f0;
      --tab-bg: #e2e8f0;
      --tab-btn-bg: transparent;
      --tab-btn-text: #475569;
      --tab-btn-active-bg: #ffffff;
      --tab-btn-active-text: #2563eb;
      --tag-bg: #dbeafe;
      --tag-text: #1d4ed8;
      --shadow: 0 4px 14px rgba(0, 0, 0, 0.05), 0 1px 3px rgba(0, 0, 0, 0.04);
      --guide-bg: #eff6ff;
      --guide-border: #bfdbfe;
    }}
    [data-theme="dark"] {{
      --bg: #0b0f19;
      --card: #131b2e;
      --card-inner: #0d1424;
      --card-hover: #1c2742;
      --card-selected: #14203a;
      --border: #233252;
      --border-focus: #3b82f6;
      --accent: #3b82f6;
      --accent-hover: #1d4ed8;
      --heading: #ffffff;
      --text: #cbd5e1;
      --muted: #94a3b8;
      --input-bg: #090d16;
      --input-text: #ffffff;
      --console-bg: #090d16;
      --console-text: #94a3b8;
      --tab-bg: #090d16;
      --tab-btn-bg: transparent;
      --tab-btn-text: #94a3b8;
      --tab-btn-active-bg: #1e293b;
      --tab-btn-active-text: #60a5fa;
      --tag-bg: #1e293b;
      --tag-text: #93c5fd;
      --shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
      --guide-bg: #101c36;
      --guide-border: #1e3a8a;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 24px 16px; line-height: 1.5; transition: background 0.2s, color 0.2s; }}
    .container {{ max-width: 1140px; margin: 0 auto; }}
    
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 16px; flex-wrap: wrap; gap: 14px; }}
    .logo {{ display: flex; align-items: center; gap: 12px; }}
    .shield {{ background: linear-gradient(135deg, #2563eb, #1d4ed8); width: 42px; height: 42px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; box-shadow: 0 4px 12px rgba(37,99,235,0.3); color: #fff; }}
    
    /* Guide Banner */
    .guide-banner {{ display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; align-items: center; gap: 12px; background: var(--guide-bg); border: 1px solid var(--guide-border); border-radius: 12px; padding: 14px 18px; margin-bottom: 22px; }}
    .guide-step {{ display: flex; align-items: flex-start; gap: 10px; }}
    .step-num {{ background: #2563eb; color: #fff; width: 26px; height: 26px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 13px; flex-shrink: 0; }}
    .step-content strong {{ display: block; font-size: 13px; color: var(--heading); margin-bottom: 2px; }}
    .step-content span {{ font-size: 12px; color: var(--muted); }}
    .guide-arrow {{ color: var(--muted); font-size: 16px; font-weight: bold; text-align: center; }}
    @media (max-width: 768px) {{
      .guide-banner {{ grid-template-columns: 1fr; gap: 10px; }}
      .guide-arrow {{ display: none; }}
    }}

    /* Tab Navigation */
    .tabs-nav {{ display: flex; background: var(--tab-bg); padding: 4px; border-radius: 10px; gap: 4px; margin-bottom: 20px; overflow-x: auto; }}
    .tab-btn {{ flex: 1; padding: 10px 16px; border: none; background: var(--tab-btn-bg); color: var(--tab-btn-text); font-size: 13px; font-weight: 700; border-radius: 8px; cursor: pointer; transition: all 0.2s; white-space: nowrap; display: flex; align-items: center; justify-content: center; gap: 8px; }}
    .tab-btn:hover {{ color: var(--heading); }}
    .tab-btn.active {{ background: var(--tab-btn-active-bg); color: var(--tab-btn-active-text); box-shadow: 0 2px 6px rgba(0,0,0,0.08); }}

    /* Tab Panels */
    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}
    
    .panel {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 22px; margin-bottom: 22px; box-shadow: var(--shadow); }}
    .section-title {{ margin-bottom: 18px; }}
    .section-title h3 {{ font-size: 18px; color: var(--heading); display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
    .section-desc {{ font-size: 13px; color: var(--muted); }}

    /* Cards & Option Grids */
    .field-card {{ background: var(--card-inner); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    .field-label {{ display: block; font-size: 13px; font-weight: 700; color: var(--heading); margin-bottom: 6px; }}
    .field-hint {{ font-size: 12px; color: var(--muted); margin-top: 4px; display: block; }}
    .required {{ color: #ef4444; }}
    
    .text-input {{ width: 100%; background: var(--input-bg); border: 1px solid var(--border); color: var(--input-text); padding: 10px 14px; border-radius: 8px; font-size: 14px; transition: border-color 0.2s; }}
    .text-input:focus {{ outline: none; border-color: var(--border-focus); }}
    
    .option-cards-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; margin-top: 8px; }}
    .option-card {{ background: var(--card); border: 2px solid var(--border); border-radius: 10px; padding: 14px; cursor: pointer; transition: all 0.2s; display: flex; gap: 12px; align-items: flex-start; }}
    .option-card:hover {{ border-color: var(--accent); }}
    .option-card.selected {{ border-color: #2563eb; background: var(--card-selected); }}
    .opt-radio {{ margin-top: 2px; }}
    .opt-body strong {{ display: block; font-size: 13px; color: var(--heading); margin-bottom: 4px; }}
    .opt-body p {{ font-size: 12px; color: var(--muted); line-height: 1.4; margin-bottom: 6px; }}
    .opt-tag {{ display: inline-block; background: var(--tag-bg); color: var(--tag-text); font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px; }}

    /* Preset Grid */
    .preset-cards-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
    .preset-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; box-shadow: var(--shadow); display: flex; flex-direction: column; justify-content: space-between; transition: all 0.2s; }}
    .preset-card:hover {{ border-color: var(--accent); transform: translateY(-2px); }}
    .preset-badge {{ display: inline-block; align-self: flex-start; background: var(--tag-bg); color: var(--tag-text); font-size: 11px; font-weight: 800; padding: 3px 8px; border-radius: 6px; margin-bottom: 10px; text-transform: uppercase; }}
    .preset-card h4 {{ font-size: 15px; color: var(--heading); margin-bottom: 6px; }}
    .preset-card p {{ font-size: 12px; color: var(--muted); line-height: 1.4; margin-bottom: 12px; flex-grow: 1; }}
    .preset-meta {{ font-size: 11px; color: var(--muted); margin-bottom: 14px; font-family: monospace; }}

    /* Accordions */
    .accordion {{ background: var(--card-inner); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
    .accordion-summary {{ padding: 14px 16px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; font-size: 13px; font-weight: 700; color: var(--heading); list-style: none; user-select: none; }}
    .accordion-summary::-webkit-details-marker {{ display: none; }}
    .accordion-subtext {{ font-size: 12px; font-weight: normal; color: var(--muted); }}
    .accordion-content {{ padding: 16px; border-top: 1px solid var(--border); background: var(--card); }}

    /* Forms */
    .form-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 12px; }}
    .form-group {{ display: flex; flex-direction: column; gap: 6px; }}
    .form-group label {{ font-size: 12px; font-weight: 600; color: var(--muted); }}
    select {{ background: var(--input-bg); border: 1px solid var(--border); color: var(--input-text); padding: 9px 12px; border-radius: 8px; font-size: 13px; }}

    /* Buttons */
    .btn {{ padding: 10px 18px; font-size: 13px; font-weight: 700; border-radius: 8px; cursor: pointer; border: none; transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px; text-decoration: none; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .btn-secondary {{ background: var(--card-inner); color: var(--heading); border: 1px solid var(--border); }}
    .btn-secondary:hover {{ background: var(--card-hover); }}
    .btn-success {{ background: #10b981; color: #fff; }}
    .btn-success:hover {{ background: #059669; }}
    .btn-lg {{ padding: 12px 24px; font-size: 14px; }}
    .btn-block {{ width: 100%; }}
    
    .launch-card {{ display: flex; justify-content: space-between; align-items: center; background: var(--card-selected); border: 1px solid #bfdbfe; border-radius: 10px; padding: 16px 20px; margin-top: 14px; flex-wrap: wrap; gap: 12px; }}
    
    /* Stages 9 Grid for Advanced */
    .stages-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; margin-bottom: 16px; }}
    .stage-card {{ background: var(--card-inner); border: 1px solid var(--border); border-radius: 8px; padding: 12px; display: flex; gap: 10px; cursor: pointer; transition: all 0.2s; }}
    .stage-card:hover {{ border-color: var(--accent); }}
    .stage-card.selected {{ border-color: #3b82f6; background: var(--card-selected); }}
    .stage-cb input {{ width: 16px; height: 16px; cursor: pointer; margin-top: 2px; }}
    .stage-hdr {{ display: flex; align-items: center; gap: 6px; margin-bottom: 2px; }}
    .stage-hdr strong {{ font-size: 13px; color: var(--heading); }}
    .stage-badge {{ background: var(--tag-bg); color: var(--tag-text); font-size: 10px; font-weight: 800; padding: 2px 5px; border-radius: 4px; }}
    .stage-tool {{ font-size: 11px; color: #2563eb; font-family: monospace; }}
    .stage-desc {{ font-size: 11px; color: var(--muted); }}

    /* Execution & Verdict Section */
    #executionSection {{ display: none; }}
    .progress-track {{ background: var(--border); border-radius: 8px; height: 14px; overflow: hidden; margin: 12px 0; }}
    .progress-fill {{ background: linear-gradient(90deg, #3b82f6, #10b981); height: 100%; width: 0%; transition: width 0.3s ease; }}
    .console {{ background: var(--console-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-family: monospace; font-size: 12px; height: 200px; overflow-y: auto; color: var(--console-text); line-height: 1.4; }}
    
    /* Post Scan Summary Banner */
    .verdict-banner {{ border-radius: 12px; padding: 20px; margin-bottom: 18px; border: 2px solid; }}
    .verdict-banner.approved {{ background: #ecfdf5; border-color: #10b981; color: #065f46; }}
    .verdict-banner.blocked {{ background: #fef2f2; border-color: #ef4444; color: #991b1b; }}
    .verdict-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px; }}
    .verdict-title {{ font-size: 18px; font-weight: 800; display: flex; align-items: center; gap: 8px; }}
    .verdict-score {{ font-size: 18px; font-weight: 800; }}
    .pills-grid {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }}
    .pill {{ padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 700; display: inline-flex; align-items: center; gap: 6px; }}
    .pill-critical {{ background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }}
    .pill-high {{ background: #ffedd5; color: #c2410c; border: 1px solid #fb923c; }}
    .pill-medium {{ background: #fef9c3; color: #a16207; border: 1px solid #facc15; }}
    .pill-low {{ background: #e0f2fe; color: #0369a1; border: 1px solid #38bdf8; }}
    .pill-info {{ background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }}
    
    .download-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-top: 14px; }}
    .dl-btn {{ background: var(--card-inner); border: 1px solid var(--border); padding: 10px 12px; border-radius: 8px; color: var(--heading); font-size: 12px; font-weight: 600; text-decoration: none; display: flex; align-items: center; gap: 8px; transition: all 0.2s; }}
    .dl-btn:hover {{ background: var(--card-hover); border-color: var(--accent); }}
    
    .test-result-box {{ margin-top: 10px; padding: 8px 12px; border-radius: 6px; font-size: 12px; font-family: monospace; }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="logo">
        <div class="shield">🛡️</div>
        <div>
          <div style="font-size: 20px; font-weight: 800; color: var(--heading);">DKSec Security Platform</div>
          <div style="font-size: 12px; color: var(--muted);">Complete DevSecOps, SAST, DAST, Pentest & Compliance Suite</div>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 10px;">
        <button id="themeToggleBtn" onclick="toggleTheme()" class="btn btn-secondary">☀️ Theme: Light</button>
        <a id="btnOpenReportTop" href="/report" target="_blank" class="btn btn-success" style="display: none;">📄 Open Interactive Report</a>
        <button id="btnNewScanTop" onclick="location.reload()" class="btn btn-primary" style="display: none; background: #2563eb; color: white; border: none;">🔄 New Scan</button>
      </div>
    </header>

    <!-- Step 1: Audit Type -->
    
    <!-- STEP 1: Select Type -->
    <div class="panel" id="step1Container">
      <div class="section-title">
        <h3>Step 1: What would you like to scan?</h3>
        <p class="section-desc">Select an audit profile to begin. The form will dynamically update based on your selection.</p>
      </div>
      <div class="option-cards-grid" style="grid-template-columns: repeat(2, 1fr);">
        <div class="option-card" id="flowCardUrl" onclick="selectFlow('url')">
          <div style="font-size: 28px; margin-right: 12px;">🌐</div>
          <div class="opt-body">
            <strong>Live Website / API Pentest</strong>
            <p>Black-box security scans against a running application.</p>
          </div>
        </div>
        <div class="option-card" id="flowCardCode" onclick="selectFlow('code')">
          <div style="font-size: 28px; margin-right: 12px;">📂</div>
          <div class="opt-body">
            <strong>Source Code & Secret Scan</strong>
            <p>Static code analysis, hardcoded secrets, and SBOM generation.</p>
          </div>
        </div>
        <div class="option-card" id="flowCardPresets" onclick="selectFlow('presets')">
          <div style="font-size: 28px; margin-right: 12px;">⚡</div>
          <div class="opt-body">
            <strong>1-Click Quick Presets</strong>
            <p>Run pre-configured CI/CD workflows instantly.</p>
          </div>
        </div>
        <div class="option-card" id="flowCardCustom" onclick="selectFlow('custom')">
          <div style="font-size: 28px; margin-right: 12px;">⚙️</div>
          <div class="opt-body">
            <strong>Custom Pipeline & AI</strong>
            <p>Select specific stages and attach AI triage models.</p>
          </div>
        </div>
      </div>
    </div>


    <!-- TAB 1: Live Website / API Pentest -->
    <div class="tab-pane active" id="tabContentUrl">
      <div class="panel">
        <div class="section-title">
          <h3>Step 2: Test a Live Web Application or REST API</h3>
          <p class="section-desc">Run black-box/gray-box security scans against a running web application, microservice, or REST API without needing source code.</p>
        </div>

        <!-- Target URL Field -->
        <div class="field-card">
          <label class="field-label" for="urlTargetUrl">Target URL or API Base URL <span class="required">*</span></label>
          <input type="text" id="urlTargetUrl" class="text-input" placeholder="https://campaignmitra.com or http://127.0.0.1:5000" value="https://campaignmitra.com" />
          <span class="field-hint">Supports live production/staging URLs (e.g. https://campaignmitra.com) and localhost dev servers without needing source code.</span>
        </div>

        <!-- Scope Selection -->
        <div class="field-card">
          <label class="field-label">Select Live Testing Scope</label>
          <div class="option-cards-grid">
            <div class="option-card selected" id="optUrlFull" onclick="selectUrlMode('full')">
              <div class="opt-radio"><input type="radio" name="urlScanMode" value="full" checked /></div>
              <div class="opt-body">
                <strong>🎯 Full Pentest & VAPT (Recommended)</strong>
                <p>Runs Stages 4, 5 & 6: REST API Fuzzing, OWASP Top 10 DAST Crawler, and Deep Exploit Simulation.</p>
                <span class="opt-tag">Stages 4, 5, 6</span>
              </div>
            </div>

            <div class="option-card" id="optUrlDast" onclick="selectUrlMode('dast')">
              <div class="opt-radio"><input type="radio" name="urlScanMode" value="dast" /></div>
              <div class="opt-body">
                <strong>⚡ Quick Web DAST Scan</strong>
                <p>Active web crawler searching for XSS, SQL injection, SSRF, header flaws, and cookie issues.</p>
                <span class="opt-tag">Stage 5 Only</span>
              </div>
            </div>

            <div class="option-card" id="optUrlVapt" onclick="selectUrlMode('vapt')">
              <div class="opt-radio"><input type="radio" name="urlScanMode" value="vapt" /></div>
              <div class="opt-body">
                <strong>🛡️ Deep VAPT Exploit Probing</strong>
                <p>OWASP ASVS 4.0.3 & WSTG verification, access control tests, and simulated payload exploitation.</p>
                <span class="opt-tag">Stage 6 Only</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Authentication Accordion (Optional) -->
        <details class="accordion">
          <summary class="accordion-summary">
            <span>🔐 Target Authentication (Optional — unauthenticated public scan by default)</span>
            <span class="accordion-subtext">Configure login form, JWT token, or session cookie ▾</span>
          </summary>
          <div class="accordion-content">
            <div class="form-row">
              <div class="form-group">
                <label>Authentication Mode</label>
                <select id="authType" onchange="onAuthTypeChange()">
                  <option value="none" selected>None (Public Unauthenticated Scan)</option>
                  <option value="login">Automated Login URL (JSON / Form POST)</option>
                  <option value="bearer">Bearer Token / JWT</option>
                  <option value="cookie">Session Cookies</option>
                  <option value="header">Custom Authorization Header</option>
                </select>
              </div>
              <div class="form-group" style="display: flex; flex-direction: row; align-items: flex-end;">
                <button type="button" class="btn btn-secondary" onclick="testAuthentication()">⚡ Test Login Connection</button>
              </div>
            </div>

            <div id="groupLogin" class="form-row" style="display: none;">
              <div class="form-group">
                <label>Login Endpoint URL</label>
                <input type="text" id="authLoginUrl" class="text-input" placeholder="https://target.com/api/v1/login" value="" />
              </div>
              <div class="form-group" style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                <div>
                  <label>Username / Email</label>
                  <input type="text" id="authUsername" class="text-input" placeholder="admin" value="" />
                </div>
                <div>
                  <label>Password</label>
                  <input type="password" id="authPassword" class="text-input" placeholder="••••••••" value="" />
                </div>
              </div>
            </div>

            <div id="groupBearer" class="form-group" style="display: none; margin-bottom: 12px;">
              <label>Bearer Token / JWT</label>
              <input type="text" id="authBearer" class="text-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." />
            </div>

            <div id="groupCookie" class="form-group" style="display: none; margin-bottom: 12px;">
              <label>Session Cookies (Key=Value; Key2=Value2)</label>
              <input type="text" id="authCookie" class="text-input" placeholder="session=abc123xyz; role=admin" />
            </div>

            <div id="groupHeader" class="form-group" style="display: none; margin-bottom: 12px;">
              <label>Custom Header (Header-Name: Header-Value)</label>
              <input type="text" id="authHeader" class="text-input" placeholder="X-API-Key: secret_production_token_123" />
            </div>

            <div id="authTestResult" style="display: none;" class="test-result-box"></div>
          </div>
        </details>

        <!-- Dynamic AI Accordion (Optional) -->
        <details class="accordion">
          <summary class="accordion-summary">
            <span>🤖 Dynamic AI Smart Triage (Optional)</span>
            <span class="accordion-subtext">Enable LLM false-positive filtering & CISO summary ▾</span>
          </summary>
          <div class="accordion-content">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
              <input type="checkbox" id="llmEnabledUrl" onchange="syncLLM('url')" style="width: 18px; height: 18px; cursor: pointer;" />
              <label for="llmEnabledUrl" style="font-weight: 700; cursor: pointer; color: var(--heading);">Enable AI Smart Triage & CISO Executive Summary</label>
            </div>
            <div id="llmFieldsUrl" style="display: none;">
              <div class="form-row">
                <div class="form-group">
                  <label>Provider</label>
                  <select id="llmProviderUrl" onchange="onLLMProviderChange('url')">
                    <option value="openai" selected>OpenAI (GPT-4o / GPT-4o-mini)</option>
                    <option value="gemini">Google Gemini (Gemini 1.5 Pro / Flash)</option>
                    <option value="anthropic">Anthropic Claude (Claude 3.5 Sonnet)</option>
                    <option value="ollama">Ollama Local (Zero Telemetry)</option>
                    <option value="custom">Custom OpenAI-Compatible</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>Model Name</label>
                  <input type="text" id="llmModelUrl" class="text-input" value="gpt-4o" />
                </div>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>API Key <span class="field-hint">(Optional if set in environment)</span></label>
                  <input type="password" id="llmApiKeyUrl" class="text-input" placeholder="sk-..." />
                </div>
                <div class="form-group">
                  <label>Custom Base URL <span class="field-hint">(For Ollama or local gateway)</span></label>
                  <input type="text" id="llmBaseUrlUrl" class="text-input" placeholder="http://localhost:11434/v1" />
                </div>
              </div>
              <button type="button" class="btn btn-secondary" onclick="testLLMConnection('url')">⚡ Test AI Connection</button>
              <div id="llmTestResultUrl" style="display: none;" class="test-result-box"></div>
            </div>
          </div>
        </details>

        <!-- Launch Card -->
        <div class="launch-card">
          <div>
            <div style="font-size: 15px; font-weight: 700; color: var(--heading);">Ready to launch live pentest?</div>
            <div style="font-size: 12px; color: var(--muted);">Clicking start will actively crawl, fuzz, and simulate exploit payloads against your live target.</div>
          </div>
          <button id="btnRunUrl" class="btn btn-primary btn-lg" onclick="runUrlScan()">🚀 Launch Live Pentest</button>
        </div>
      </div>
    </div>

    <!-- TAB 2: Source Code & Secret Scan -->
    <div class="tab-pane" id="tabContentCode">
      <div class="panel">
        <div class="section-title">
          <h3>📂 Scan Local Source Code & Open Source Dependencies</h3>
          <p class="section-desc">Audit source code for hardcoded passwords, tokens, code injection vulnerabilities, and vulnerable third-party dependencies.</p>
        </div>

        <!-- Target Code Path -->
        <div class="field-card">
          <label class="field-label" for="codeTargetPath">1. Source Code Repository Directory <span class="required">*</span></label>
          <input type="text" id="codeTargetPath" class="text-input" placeholder=". or samples/app or /path/to/project" value="." />
          <span class="field-hint">Specify relative (e.g. `.` or `samples/app`) or absolute path to your repository.</span>
        </div>

        <!-- Code Scope Selection -->
        <div class="field-card">
          <label class="field-label">2. Select Code Audit Scope</label>
          <div class="option-cards-grid">
            <div class="option-card selected" id="optCodeSast" onclick="selectCodeMode('sast')">
              <div class="opt-radio"><input type="radio" name="codeScanMode" value="sast" checked /></div>
              <div class="opt-body">
                <strong>🔍 SAST & Hardcoded Secrets (Recommended)</strong>
                <p>Stages 2 & 3: High-speed secret detection, Bandit/Semgrep rule patterns, and SQLi/RCE detection.</p>
                <span class="opt-tag">Stages 2, 3</span>
              </div>
            </div>

            <div class="option-card" id="optCodePr" onclick="selectCodeMode('pr')">
              <div class="opt-radio"><input type="radio" name="codeScanMode" value="pr" /></div>
              <div class="opt-body">
                <strong>🚀 Fast CI/CD PR Gate</strong>
                <p>Stages 1, 3 & 8: Fast gate for commits. STRIDE threat model, SAST security checks, and gate policy.</p>
                <span class="opt-tag">Stages 1, 3, 8</span>
              </div>
            </div>

            <div class="option-card" id="optCodeSbom" onclick="selectCodeMode('sbom')">
              <div class="opt-radio"><input type="radio" name="codeScanMode" value="sbom" /></div>
              <div class="opt-body">
                <strong>📦 Supply Chain & CycloneDX SBOM</strong>
                <p>Stages 2, 3 & 8: Dependency vulnerability analysis, license risks, and CycloneDX 1.5 SBOM generation.</p>
                <span class="opt-tag">Stages 2, 3, 8</span>
              </div>
            </div>

            <div class="option-card" id="optCodeThreat" onclick="selectCodeMode('threat')">
              <div class="opt-radio"><input type="radio" name="codeScanMode" value="threat" /></div>
              <div class="opt-body">
                <strong>📐 STRIDE Threat Modeling Only</strong>
                <p>Stage 1: Automated architectural threat modeling and MITRE ATT&CK enterprise mapping.</p>
                <span class="opt-tag">Stage 1 Only</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Launch Card -->
        <div class="launch-card">
          <div>
            <div style="font-size: 15px; font-weight: 700; color: var(--heading);">Ready to audit source code?</div>
            <div style="font-size: 12px; color: var(--muted);">Scans your files locally and privately without uploading your code anywhere.</div>
          </div>
          <button id="btnRunCode" class="btn btn-primary btn-lg" onclick="runCodeScan()">🔍 Scan Source Code Now</button>
        </div>
      </div>
    </div>

    <!-- TAB 3: 1-Click Quick Presets -->
    <div class="tab-pane" id="tabContentPresets">
      <div class="panel">
        <div class="section-title">
          <h3>⚡ 1-Click Ready Presets</h3>
          <p class="section-desc">Click any card below to immediately run a targeted security workflow with optimal defaults.</p>
        </div>

        <div class="preset-cards-grid">
          <!-- Preset 1 -->
          <div class="preset-card">
            <div class="preset-badge">All 9 Stages</div>
            <h4>🛡️ Full 9-Stage Enterprise Audit</h4>
            <p>End-to-end security lifecycle: Threat model, Secrets, SAST, API security, DAST crawler, VAPT exploits, SIEM alerts, Compliance, and DefectDojo export.</p>
            <div class="preset-meta">Covers: STRIDE, OWASP Top 10, ASVS 4.0.3, WSTG, CycloneDX, Sigma, Wazuh</div>
            <button class="btn btn-primary btn-block" onclick="runPreset('all')">🚀 Run Full Audit</button>
          </div>

          <!-- Preset 2 -->
          <div class="preset-card">
            <div class="preset-badge">Fast Gate</div>
            <h4>🚀 Fast CI/CD Pull Request Gate</h4>
            <p>Lightweight check built for Git pull requests. Runs threat model check, SAST code review, and ASVS gate policy in seconds.</p>
            <div class="preset-meta">Stages 1, 3, 8 | Evaluates Pass/Fail Gate</div>
            <button class="btn btn-primary btn-block" onclick="runPreset('pr')">⚡ Run PR Gate</button>
          </div>

          <!-- Preset 3 -->
          <div class="preset-card">
            <div class="preset-badge">Live Pentest</div>
            <h4>🌐 Web & API Security Pentest</h4>
            <p>Probes live web servers and REST endpoints with active fuzzing, OWASP Top 10 web crawler, and automated exploit tests.</p>
            <div class="preset-meta">Stages 4, 5, 6 | Target: Live Web / API</div>
            <button class="btn btn-primary btn-block" onclick="runPreset('api')">🌐 Run Web Pentest</button>
          </div>

          <!-- Preset 4 -->
          <div class="preset-card">
            <div class="preset-badge">Software Supply Chain</div>
            <h4>📦 Supply Chain & SBOM Security</h4>
            <p>Identifies vulnerable 3rd-party dependencies, license compliance risks, and produces full CycloneDX 1.5 SBOM.</p>
            <div class="preset-meta">Stages 2, 3, 8 | CycloneDX & OSV/NVD</div>
            <button class="btn btn-primary btn-block" onclick="runPreset('sbom')">📦 Run SBOM Scan</button>
          </div>

          <!-- Preset 5 -->
          <div class="preset-card">
            <div class="preset-badge">ASVS & WSTG</div>
            <h4>🎯 Deep VAPT Exploit Probing</h4>
            <p>Simulates real-world cyberattacks against running applications with payload injections, authorization bypass, and WSTG tests.</p>
            <div class="preset-meta">Stage 6 Only | Active Attack Simulation</div>
            <button class="btn btn-primary btn-block" onclick="runPreset('vapt')">🎯 Run VAPT Scan</button>
          </div>

          <!-- Preset 6 -->
          <div class="preset-card">
            <div class="preset-badge">Architecture</div>
            <h4>📐 STRIDE Threat Modeling</h4>
            <p>Generates OWASP Threat Dragon v2 architecture diagram and identifies spoofing, tampering, and information disclosure threats.</p>
            <div class="preset-meta">Stage 1 Only | MITRE ATT&CK Mapping</div>
            <button class="btn btn-primary btn-block" onclick="runPreset('threat')">📐 Run Threat Model</button>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 4: Custom Pipeline & AI (Advanced) -->
    <div class="tab-pane" id="tabContentCustom">
      <div class="panel">
        <div class="section-title">
          <h3>⚙️ Custom Pipeline & Advanced Configuration</h3>
          <p class="section-desc">Granular control over target parameters, individual stages 1-9, LLM intelligence provider, and artifact output.</p>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Project Name</label>
            <input type="text" id="projectName" class="text-input" value="Enterprise Security Audit" />
          </div>
          <div class="form-group">
            <label>Source Code Directory Path <span class="field-hint">(Leave empty for live URL scans)</span></label>
            <input type="text" id="targetPath" class="text-input" placeholder="e.g. . or samples/app (optional)" value="" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Live Target URL / API Endpoint <span class="field-hint">(Leave empty for code-only scans)</span></label>
            <input type="text" id="targetUrl" class="text-input" placeholder="e.g. https://campaignmitra.com" value="https://campaignmitra.com" />
          </div>
          <div class="form-group">
            <label>Reports Destination Directory</label>
            <input type="text" id="outputDir" class="text-input" value="./reports/web_audit" />
          </div>
        </div>

        <!-- Stage Selectors -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 14px;">
          <label style="font-weight: 700; color: var(--heading);">Select Individual Stages to Execute:</label>
          <div style="display: flex; gap: 8px;">
            <button type="button" class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="selectAllStages(true)">Select All</button>
            <button type="button" class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="selectAllStages(false)">Deselect All</button>
          </div>
        </div>

        <div class="stages-grid">
          {stages_html}
        </div>

        <!-- Advanced AI Options -->
        <div class="field-card" style="margin-top: 14px;">
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
            <input type="checkbox" id="llmEnabledAdv" onchange="syncLLM('adv')" style="width: 18px; height: 18px; cursor: pointer;" />
            <label for="llmEnabledAdv" style="font-weight: 700; cursor: pointer; color: var(--heading);">Enable Smart LLM Engine</label>
          </div>

          <div id="llmFieldsAdv" style="display: none;">
            <div class="form-row">
              <div class="form-group">
                <label>Provider</label>
                <select id="llmProviderAdv" onchange="onLLMProviderChange('adv')">
                  <option value="openai" selected>OpenAI (GPT-4o / GPT-4o-mini)</option>
                  <option value="gemini">Google Gemini (Gemini 1.5 Pro / Flash)</option>
                  <option value="anthropic">Anthropic Claude (Claude 3.5 Sonnet)</option>
                  <option value="ollama">Ollama Local (Zero Telemetry)</option>
                  <option value="custom">Custom OpenAI-Compatible</option>
                </select>
              </div>
              <div class="form-group">
                <label>Model Name</label>
                <input type="text" id="llmModelAdv" class="text-input" value="gpt-4o" />
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label>API Key <span class="field-hint">(Optional if ENV variable set)</span></label>
                <input type="password" id="llmApiKeyAdv" class="text-input" placeholder="sk-..." />
              </div>
              <div class="form-group">
                <label>Custom Base URL <span class="field-hint">(For Ollama or local gateway)</span></label>
                <input type="text" id="llmBaseUrlAdv" class="text-input" placeholder="http://localhost:11434/v1" />
              </div>
            </div>
            <button type="button" class="btn btn-secondary" onclick="testLLMConnection('adv')">⚡ Test AI Connection</button>
            <div id="llmTestResultAdv" style="display: none;" class="test-result-box"></div>
          </div>
        </div>

        <div class="launch-card">
          <span id="selectedCounter" style="color: var(--muted); font-size: 13px;">9 of 9 stages selected</span>
          <button id="btnRunAdv" class="btn btn-primary btn-lg" onclick="runCustomPipeline()">🚀 Run Custom Pipeline</button>
        </div>
      </div>
    </div>

    <!-- LIVE PIPELINE EXECUTION & VERDICT SECTION -->
    <div id="executionSection" class="panel">
      <!-- Post-Scan Verdict Card -->
      <div id="verdictBanner" class="verdict-banner approved" style="display: none;">
        <div class="verdict-header">
          <div class="verdict-title" id="verdictTitle">✅ SECURITY GATE: APPROVED</div>
          <div class="verdict-score" id="verdictScore">Score: 100/100 (Grade A)</div>
        </div>
        <div id="verdictSubtitle" style="font-size: 13px; margin-bottom: 12px;">All security thresholds satisfied. Safe to release to production.</div>
        
        <div class="pills-grid">
          <span class="pill pill-critical" id="pillCrit">Critical: 0</span>
          <span class="pill pill-high" id="pillHigh">High: 0</span>
          <span class="pill pill-medium" id="pillMed">Medium: 0</span>
          <span class="pill pill-low" id="pillLow">Low: 0</span>
          <span class="pill pill-info" id="pillInfo">Info: 0</span>
        </div>

        <div style="margin-top: 14px;">
          <a id="btnOpenReportCard" href="/report" target="_blank" class="btn btn-success" style="font-size: 14px; padding: 10px 20px;">📄 Open Full Interactive HTML Report ➔</a>
        </div>
      </div>

      <!-- Live Execution Progress -->
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h3 style="font-size: 16px; color: var(--heading); display: flex; align-items: center; gap: 8px;">
          <span>📡</span> Pipeline Execution Telemetry
        </h3>
        <span id="statusBadge" style="background: #2563eb; color: #fff; font-size: 11px; padding: 4px 10px; border-radius: 12px; font-weight: 700;">RUNNING</span>
      </div>

      <div class="progress-track">
        <div id="progressFill" class="progress-fill"></div>
      </div>
      <div id="statusMessage" style="font-size: 13px; color: #2563eb; font-weight: 600; margin-bottom: 10px;">Initializing DKSec engines...</div>
      <div id="consoleLog" class="console"></div>

      <!-- Industry Artifacts Downloads -->
      <div id="downloadSection" style="display: none; margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px;">
        <h4 style="font-size: 14px; color: var(--heading); margin-bottom: 10px;">📦 Download Industry-Standard Artifacts:</h4>
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
      const cur = document.documentElement.getAttribute('data-theme') || 'light';
      setTheme(cur === 'light' ? 'dark' : 'light');
    }}

    (function() {{
      let saved = 'light';
      try {{
        saved = localStorage.getItem('dksec_theme') || 'light';
      }} catch(e) {{}}
      setTheme(saved);
    }})();

    /* Tab Switcher */
    
    function selectFlow(flowType) {
      // Highlight the selected card
      document.querySelectorAll('#step1Container .option-card').forEach(c => c.classList.remove('selected', 'flow-active'));
      let card = document.getElementById('flowCard' + flowType.charAt(0).toUpperCase() + flowType.slice(1));
      if (card) {
        card.classList.add('selected', 'flow-active');
        card.style.borderColor = 'var(--accent)';
      }
      
      // Hide all panels, then show the corresponding one as Step 2
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      const targetPane = document.getElementById('tabContent' + flowType.charAt(0).toUpperCase() + flowType.slice(1));
      if (targetPane) {
        targetPane.classList.add('active');
        // Scroll to it smoothly
        setTimeout(() => targetPane.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
      }
    }
    
    // Hide all tab panes on initial load so the user *must* pick Step 1
    window.addEventListener('DOMContentLoaded', () => {
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    });

    function switchTab(tabId) {{
      const tabs = ['url', 'code', 'presets', 'custom'];
      tabs.forEach(t => {{
        const btn = document.getElementById('tabNav' + t.charAt(0).toUpperCase() + t.slice(1));
        const pane = document.getElementById('tabContent' + t.charAt(0).toUpperCase() + t.slice(1));
        if (btn) btn.classList.remove('active');
        if (pane) pane.classList.remove('active');
      }});

      const curBtn = document.getElementById('tabNav' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      const curPane = document.getElementById('tabContent' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      if (curBtn) curBtn.classList.add('active');
      if (curPane) curPane.classList.add('active');
    }}

    /* Radio Mode Selectors */
    function selectUrlMode(mode) {{
      ['full', 'dast', 'vapt'].forEach(m => {{
        const card = document.getElementById('optUrl' + m.charAt(0).toUpperCase() + m.slice(1));
        if (card) card.classList.remove('selected');
      }});
      const cur = document.getElementById('optUrl' + mode.charAt(0).toUpperCase() + mode.slice(1));
      if (cur) {{
        cur.classList.add('selected');
        const r = cur.querySelector('input[type="radio"]');
        if (r) r.checked = true;
      }}
    }}

    function selectCodeMode(mode) {{
      ['sast', 'pr', 'sbom', 'threat'].forEach(m => {{
        const card = document.getElementById('optCode' + m.charAt(0).toUpperCase() + m.slice(1));
        if (card) card.classList.remove('selected');
      }});
      const cur = document.getElementById('optCode' + mode.charAt(0).toUpperCase() + mode.slice(1));
      if (cur) {{
        cur.classList.add('selected');
        const r = cur.querySelector('input[type="radio"]');
        if (r) r.checked = true;
      }}
    }}

    /* Auth Handlers */
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
      const targetUrl = document.getElementById('urlTargetUrl').value;
      const auth = getAuthConfig();
      const resBox = document.getElementById('authTestResult');
      resBox.style.display = 'block';
      resBox.style.background = 'var(--card-inner)';
      resBox.style.border = '1px solid var(--border)';
      resBox.style.color = '#2563eb';
      resBox.innerHTML = 'Connecting to target and validating session credentials...';

      fetch('/api/auth/test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ target_url: targetUrl, auth: auth }})
      }}).then(r => r.json()).then(d => {{
        if (d.success || d.is_authenticated) {{
          resBox.style.border = '1px solid #10b981';
          resBox.style.color = '#059669';
          let details = `✔ Success: Authenticated via ${{(d.auth_method||'session').toUpperCase()}} (HTTP ${{d.status_code||200}}).`;
          if (d.token_found) details += ` Token captured.`;
          if (d.cookies_captured && d.cookies_captured.length > 0) details += ` Cookies: ${{d.cookies_captured.join(', ')}}.`;
          resBox.innerText = details;
        }} else {{
          resBox.style.border = '1px solid #ef4444';
          resBox.style.color = '#dc2626';
          resBox.innerText = `✖ Authentication failed: ${{d.message || d.login_error || 'Could not verify session'}}`;
        }}
      }}).catch(err => {{
        resBox.style.border = '1px solid #ef4444';
        resBox.style.color = '#dc2626';
        resBox.innerText = 'Connection error: ' + err;
      }});
    }}

    /* AI / LLM Handlers */
    function syncLLM(source) {{
      const en = (source === 'url') ? document.getElementById('llmEnabledUrl').checked : document.getElementById('llmEnabledAdv').checked;
      document.getElementById('llmFieldsUrl').style.display = en ? 'block' : 'none';
      document.getElementById('llmFieldsAdv').style.display = en ? 'block' : 'none';
      document.getElementById('llmEnabledUrl').checked = en;
      document.getElementById('llmEnabledAdv').checked = en;
    }}

    function onLLMProviderChange(source) {{
      const prov = (source === 'url') ? document.getElementById('llmProviderUrl').value : document.getElementById('llmProviderAdv').value;
      const modelMap = {{
        'openai': 'gpt-4o',
        'gemini': 'gemini-1.5-pro',
        'anthropic': 'claude-3-5-sonnet-20240620',
        'ollama': 'llama3',
        'custom': 'default'
      }};
      const model = modelMap[prov] || 'gpt-4o';
      document.getElementById('llmModelUrl').value = model;
      document.getElementById('llmModelAdv').value = model;
      document.getElementById('llmProviderUrl').value = prov;
      document.getElementById('llmProviderAdv').value = prov;
      if (prov === 'ollama') {{
        document.getElementById('llmBaseUrlUrl').value = 'http://localhost:11434/v1';
        document.getElementById('llmBaseUrlAdv').value = 'http://localhost:11434/v1';
      }}
    }}

    function getLLMConfig() {{
      const enabled = document.getElementById('llmEnabledUrl').checked || document.getElementById('llmEnabledAdv').checked;
      const prov = document.getElementById('llmProviderUrl').value;
      const model = document.getElementById('llmModelUrl').value;
      const key = document.getElementById('llmApiKeyUrl').value || document.getElementById('llmApiKeyAdv').value || null;
      const base = document.getElementById('llmBaseUrlUrl').value || document.getElementById('llmBaseUrlAdv').value || null;
      return {{
        enabled: enabled,
        provider: prov,
        model: model,
        api_key: key,
        api_base_url: base
      }};
    }}

    function testLLMConnection(source) {{
      const cfg = getLLMConfig();
      const resBox = (source === 'url') ? document.getElementById('llmTestResultUrl') : document.getElementById('llmTestResultAdv');
      resBox.style.display = 'block';
      resBox.style.background = 'var(--card-inner)';
      resBox.style.border = '1px solid var(--border)';
      resBox.style.color = '#2563eb';
      resBox.innerHTML = `Testing connection to ${{cfg.provider.toUpperCase()}} (${{cfg.model}})...`;

      fetch('/api/llm/test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(cfg)
      }}).then(r => r.json()).then(d => {{
        if (d.success) {{
          resBox.style.border = '1px solid #10b981';
          resBox.style.color = '#059669';
          resBox.innerText = `✔ Success: ${{d.message}}`;
        }} else {{
          resBox.style.border = '1px solid #ef4444';
          resBox.style.color = '#dc2626';
          resBox.innerText = `✖ Connection failed: ${{d.message}}`;
        }}
      }}).catch(err => {{
        resBox.style.border = '1px solid #ef4444';
        resBox.style.color = '#dc2626';
        resBox.innerText = 'Connection error: ' + err;
      }});
    }}

    /* Stage Selection Helpers (Tab 4) */
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

    function selectAllStages(val) {{
      for (let i = 1; i <= 9; i++) {{
        const cb = document.getElementById('stage-' + i);
        if (cb) {{
          cb.checked = val;
          syncCard(i);
        }}
      }}
    }}

    function updateCounter() {{
      const count = document.querySelectorAll('.stage-cb input[type="checkbox"]:checked').length;
      const el = document.getElementById('selectedCounter');
      if (el) el.innerText = `${{count}} of 9 stages selected`;
    }}

    /* Execution Triggers */
    function runUrlScan() {{
      const url = document.getElementById('urlTargetUrl').value.trim();
      if (!url) {{
        alert('Please specify a target URL (e.g. http://127.0.0.1:5000)');
        return;
      }}
      const checkedRadio = document.querySelector('input[name="urlScanMode"]:checked');
      const mode = checkedRadio ? checkedRadio.value : 'full';
      let stages = [4, 5, 6];
      if (mode === 'dast') stages = [5];
      else if (mode === 'vapt') stages = [6];

      executePipeline({{
        project_name: 'Live Web Pentest: ' + url,
        target_path: null,
        target_url: url,
        auth: getAuthConfig(),
        llm: getLLMConfig(),
        output_dir: './reports/web_pentest',
        stages: stages
      }});
    }}

    function runCodeScan() {{
      const path = document.getElementById('codeTargetPath').value.trim() || '.';
      const checkedRadio = document.querySelector('input[name="codeScanMode"]:checked');
      const mode = checkedRadio ? checkedRadio.value : 'sast';
      let stages = [2, 3];
      if (mode === 'pr') stages = [1, 3, 8];
      else if (mode === 'sbom') stages = [2, 3, 8];
      else if (mode === 'threat') stages = [1];

      executePipeline({{
        project_name: 'Code Repository Security Audit',
        target_path: path,
        target_url: null,
        auth: {{ enabled: false, auth_type: 'none' }},
        llm: getLLMConfig(),
        output_dir: './reports/code_audit',
        stages: stages
      }});
    }}

    function runPreset(presetKey) {{
      let stages = [1, 2, 3, 4, 5, 6, 7, 8, 9];
      let name = 'Enterprise 9-Stage Audit';
      let url = document.getElementById('urlTargetUrl').value.trim() || null;
      let path = document.getElementById('codeTargetPath').value.trim() || null;

      if (presetKey === 'pr') {{
        stages = [1, 3, 8];
        name = 'Fast CI/CD Pull Request Gate';
        url = null;
        path = path || '.';
      }} else if (presetKey === 'api') {{
        stages = [4, 5, 6];
        name = 'Web & API Security Pentest';
        path = null;
        url = url || 'https://campaignmitra.com';
      }} else if (presetKey === 'sbom') {{
        stages = [2, 3, 8];
        name = 'Supply Chain & SBOM Security';
        url = null;
        path = path || '.';
      }} else if (presetKey === 'vapt') {{
        stages = [6];
        name = 'Deep VAPT Exploit Probing';
        path = null;
        url = url || 'https://campaignmitra.com';
      }} else if (presetKey === 'threat') {{
        stages = [1];
        name = 'STRIDE Threat Model';
        url = null;
        path = path || '.';
      }}

      executePipeline({{
        project_name: name,
        target_path: path,
        target_url: url,
        auth: getAuthConfig(),
        llm: getLLMConfig(),
        output_dir: './reports/' + presetKey + '_audit',
        stages: stages
      }});
    }}

    function runCustomPipeline() {{
      const selected = Array.from(document.querySelectorAll('.stage-cb input[type="checkbox"]:checked')).map(c => parseInt(c.value));
      if (selected.length === 0) {{
        alert('Please select at least one stage in the grid.');
        return;
      }}

      let cPath = document.getElementById('targetPath').value.trim();
      let cUrl = document.getElementById('targetUrl').value.trim() || null;
      if (!cPath && cUrl) {{
        cPath = null;
      }} else if (!cPath && !cUrl) {{
        cPath = '.';
      }}

      executePipeline({{
        project_name: document.getElementById('projectName').value,
        target_path: cPath,
        target_url: cUrl,
        auth: getAuthConfig(),
        llm: getLLMConfig(),
        output_dir: document.getElementById('outputDir').value,
        stages: selected
      }});
    }}

    function executePipeline(payload) {{
      const execSec = document.getElementById('executionSection');
      execSec.style.display = 'block';
      execSec.scrollIntoView({{ behavior: 'smooth' }});

      document.getElementById('statusBadge').innerText = 'RUNNING';
      document.getElementById('statusBadge').style.background = '#2563eb';
      document.getElementById('verdictBanner').style.display = 'none';
      document.getElementById('downloadSection').style.display = 'none';
      document.getElementById('progressFill').style.width = '5%';
      document.getElementById('statusMessage').innerText = 'Initializing scan engines...';
      document.getElementById('consoleLog').innerHTML = '';

      fetch('/api/run', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }}).then(res => res.json()).then(data => {{
        if (poll) clearInterval(poll);
        poll = setInterval(checkProgress, 800);
      }}).catch(err => {{
        alert('Failed to start security pipeline: ' + err);
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
          document.getElementById('statusMessage').innerText = '🎉 Pipeline completed! Full artifacts available below.';
          document.getElementById('btnOpenReportTop').style.display = 'inline-flex';
          document.getElementById('btnNewScanTop').style.display = 'inline-flex';
          document.getElementById('downloadSection').style.display = 'block';

          if (d.report_summary) {{
            const rep = d.report_summary;
            const vBanner = document.getElementById('verdictBanner');
            vBanner.style.display = 'block';
            
            const isApproved = (rep.verdict === 'APPROVED');
            vBanner.className = 'verdict-banner ' + (isApproved ? 'approved' : 'blocked');
            
            document.getElementById('verdictTitle').innerText = isApproved ? '✅ SECURITY GATE: APPROVED' : '❌ SECURITY GATE: BLOCKED';
            document.getElementById('verdictScore').innerText = `Score: ${{rep.score}}/100 (Grade ${{rep.grade}})`;
            
            if (isApproved) {{
              document.getElementById('verdictSubtitle').innerText = 'All security gate thresholds satisfied. Build is safe to deploy.';
            }} else {{
              const reasons = (rep.reasons && rep.reasons.length > 0) ? rep.reasons.join(', ') : 'Critical vulnerabilities must be remediated.';
              document.getElementById('verdictSubtitle').innerText = 'Deployment Blocked: ' + reasons;
            }}

            document.getElementById('pillCrit').innerText = `Critical: ${{rep.critical || 0}}`;
            document.getElementById('pillHigh').innerText = `High: ${{rep.high || 0}}`;
            document.getElementById('pillMed').innerText = `Medium: ${{rep.medium || 0}}`;
            document.getElementById('pillLow').innerText = `Low: ${{rep.low || 0}}`;
            document.getElementById('pillInfo').innerText = `Info: ${{rep.info || 0}}`;
          }}
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
        CURRENT_RUN["report_summary"] = None
        output_dir = data.get("output_dir", "./reports/web_audit")
        CURRENT_RUN["report_dir"] = output_dir

        try:
            auth_data = data.get("auth", {})
            auth_cfg = AuthConfig.from_dict(auth_data)

            llm_data = data.get("llm", {})
            llm_cfg = LLMConfig.from_dict(llm_data)

            target_path = data.get("target_path")
            target_url = data.get("target_url")
            if not target_path and target_url:
                target_path = None
            elif not target_path and not target_url:
                target_path = "."

            cfg = DKSecConfig(
                project_name=data.get("project_name", "Enterprise Security Audit"),
                target_path=target_path,
                target_url=target_url,
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

            sev = report.severity_counts or {}
            crit = sev.get("CRITICAL", 0) + sev.get("critical", 0)
            high = sev.get("HIGH", 0) + sev.get("high", 0)
            med = sev.get("MEDIUM", 0) + sev.get("medium", 0)
            low = sev.get("LOW", 0) + sev.get("low", 0)
            info = sev.get("INFO", 0) + sev.get("info", 0)

            score = round(report.overall_score, 1)
            grade = "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 50 else "F"))
            verdict_str = report.gate_verdict.status if report.gate_verdict else "APPROVED"

            CURRENT_RUN["report_summary"] = {
                "verdict": verdict_str,
                "score": score,
                "grade": grade,
                "total_findings": len(report.all_findings),
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "info": info,
                "reasons": report.gate_verdict.reasons if report.gate_verdict else [],
            }

            CURRENT_RUN["logs"].append(f"[DONE] Security Score: {score}/100 | Gate: {verdict_str}")
            CURRENT_RUN["logs"].append(f"[DONE] Generated HTML, SARIF 2.1.0, CycloneDX 1.5 SBOM, DefectDojo, and Sigma rules.")

        except Exception as e:
            CURRENT_RUN["logs"].append(f"[FATAL] Pipeline error: {str(e)}")
        finally:
            CURRENT_RUN["running"] = False


def start_server(port: int = 8080, host: str = "127.0.0.1"):
    server = ThreadingHTTPServer((host, port), DKSecWebHandler)
    print(f"\n=======================================================")
    print(f"🛡️  DKSec Web Dashboard active at: http://{host}:{port}")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DKSec Web Server.")
        server.server_close()
