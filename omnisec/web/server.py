from typing import Any, Dict, List, Optional
"""
Built-in Web Dashboard Server for OmniSec.
Allows non-CLI users to select stages, configure targets, trigger scans, and view reports in a browser.
"""

import os
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from omnisec.config import OmniSecConfig, STAGE_METADATA
from omnisec.runner import OmniSecRunner
from omnisec.reporters import HtmlReporter, JsonReporter, MarkdownReporter

CURRENT_RUN = {
    "running": False,
    "progress": 0,
    "current_stage": None,
    "logs": [],
    "last_report": None,
    "report_html_path": None
}


class OmniSecWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence standard HTTP access logging to keep terminal clean
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
        elif path == "/report" and CURRENT_RUN.get("report_html_path"):
            if os.path.exists(CURRENT_RUN["report_html_path"]):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(CURRENT_RUN["report_html_path"], "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Report file not found")
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/run":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = {}

            if CURRENT_RUN["running"]:
                self._serve_json({"status": "error", "message": "An audit is already running."}, status=400)
                return

            # Launch runner in background thread
            thread = threading.Thread(target=self._execute_scan_thread, args=(data,))
            thread.daemon = True
            thread.start()

            self._serve_json({"status": "started", "message": "Audit pipeline initiated."})
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
            <div class="stage-option" onclick="toggleStage({s_id}, this)">
              <div class="stage-check">
                <input type="checkbox" id="stage-{s_id}" value="{s_id}" checked onclick="event.stopPropagation(); syncCard({s_id})" />
              </div>
              <div class="stage-details">
                <div class="stage-header">
                  <span class="stage-num">#{s_id}</span>
                  <strong>{meta['name']}</strong>
                </div>
                <div class="stage-repo">{meta['recommended_repo']}</div>
                <div class="stage-desc">{meta['what_it_covers']}</div>
              </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>OmniSec - Product Security Workflow Orchestrator</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card: #131b2e;
      --border: #233252;
      --accent: #3b82f6;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 32px 20px; }}
    .container {{ max-width: 1080px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }}
    .logo {{ display: flex; align-items: center; gap: 12px; font-size: 22px; font-weight: 800; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
    h2 {{ font-size: 18px; margin-bottom: 16px; color: #fff; }}
    .form-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 18px; }}
    .form-group {{ display: flex; flex-direction: column; gap: 6px; }}
    label {{ font-size: 13px; font-weight: 600; color: var(--text-muted); }}
    input[type="text"] {{ background: #0b0f19; border: 1px solid var(--border); color: #fff; padding: 10px 14px; border-radius: 8px; font-size: 14px; }}
    
    .stages-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
    .stage-option {{
      background: #0d1424;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
      display: flex;
      gap: 12px;
      align-items: flex-start;
      cursor: pointer;
      transition: all 0.2s;
    }}
    .stage-option:hover {{ border-color: var(--accent); }}
    .stage-option.selected {{ border-color: #3b82f6; background: #14203a; }}
    .stage-check input {{ width: 18px; height: 18px; cursor: pointer; }}
    .stage-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
    .stage-num {{ background: #233252; color: #93c5fd; font-size: 11px; font-weight: 800; padding: 2px 6px; border-radius: 4px; }}
    .stage-repo {{ font-size: 12px; color: #60a5fa; font-family: monospace; margin-bottom: 4px; }}
    .stage-desc {{ font-size: 12px; color: var(--text-muted); }}

    .actions-bar {{ display: flex; justify-content: space-between; align-items: center; margin-top: 20px; }}
    .btn {{
      padding: 12px 28px;
      font-size: 15px;
      font-weight: 700;
      border-radius: 8px;
      cursor: pointer;
      border: none;
      transition: all 0.2s;
    }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .btn-secondary {{ background: #1e293b; color: #cbd5e1; border: 1px solid var(--border); }}
    .btn-secondary:hover {{ background: #334155; }}

    #progressCard {{ display: none; }}
    .progress-bar {{ background: #0b0f19; border-radius: 10px; height: 16px; overflow: hidden; margin: 16px 0; border: 1px solid var(--border); }}
    .progress-fill {{ background: linear-gradient(90deg, #3b82f6, #10b981); height: 100%; width: 0%; transition: width 0.3s ease; }}
    .console {{ background: #090d16; border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: monospace; font-size: 12px; height: 220px; overflow-y: auto; color: #94a3b8; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <span style="font-size: 28px;">🛡️</span>
        <div>
          <div>OmniSec Unified Security Engine</div>
          <div style="font-size: 12px; color: var(--text-muted); font-weight: normal;">All-in-One 9-Stage Product Security Workflow Orchestrator</div>
        </div>
      </div>
      <div id="topActions">
        <a id="viewReportLink" href="/report" target="_blank" class="btn btn-secondary" style="text-decoration: none; display: none;">📄 View Generated Report</a>
      </div>
    </header>

    <div class="card">
      <h2>1. Scan Targets & Configuration</h2>
      <div class="form-grid">
        <div class="form-group">
          <label>Project Name</label>
          <input type="text" id="projectName" value="Product Security Audit" />
        </div>
        <div class="form-group">
          <label>Target Source Code Directory</label>
          <input type="text" id="targetPath" value="." />
        </div>
      </div>
      <div class="form-grid">
        <div class="form-group">
          <label>Target URL / API Endpoint (Optional for DAST/VAPT)</label>
          <input type="text" id="targetUrl" placeholder="http://localhost:8000 or https://api.my-app.com" />
        </div>
        <div class="form-group">
          <label>Reports Directory</label>
          <input type="text" id="outputDir" value="./reports" />
        </div>
      </div>
    </div>

    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <h2>2. Select Workflow Stages to Execute</h2>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="selectAll(true)">Select All</button>
          <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="selectAll(false)">Deselect All</button>
        </div>
      </div>
      <div class="stages-grid">
        {stages_html}
      </div>

      <div class="actions-bar">
        <span id="selectedCount" style="color: var(--text-muted); font-size: 14px;">9 of 9 stages selected</span>
        <button id="runBtn" class="btn btn-primary" onclick="startAudit()">🚀 Run Selected Security Stages</button>
      </div>
    </div>

    <div id="progressCard" class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2>Pipeline Execution Status</h2>
        <span id="statusBadge" style="background: #2563eb; color: #fff; font-size: 12px; padding: 4px 10px; border-radius: 12px; font-weight: 700;">Running</span>
      </div>
      <div class="progress-bar">
        <div id="progressFill" class="progress-fill"></div>
      </div>
      <div id="currentStageText" style="font-size: 14px; margin-bottom: 10px; color: #93c5fd;">Initializing engine...</div>
      <div id="consoleOutput" class="console"></div>
    </div>
  </div>

  <script>
    let pollInterval = null;

    function toggleStage(sId, el) {{
      const cb = document.getElementById('stage-' + sId);
      cb.checked = !cb.checked;
      syncCard(sId);
    }}

    function syncCard(sId) {{
      const cb = document.getElementById('stage-' + sId);
      const card = cb.closest('.stage-option');
      if (cb.checked) {{
        card.classList.add('selected');
      }} else {{
        card.classList.remove('selected');
      }}
      updateCount();
    }}

    function selectAll(val) {{
      for (let i = 1; i <= 9; i++) {{
        const cb = document.getElementById('stage-' + i);
        if (cb) {{
          cb.checked = val;
          syncCard(i);
        }}
      }}
    }}

    function updateCount() {{
      const selected = Array.from(document.querySelectorAll('input[type="checkbox"]:checked')).map(c => c.value);
      document.getElementById('selectedCount').innerText = `${{selected.length}} of 9 stages selected`;
    }}

    // Init card states
    document.querySelectorAll('.stage-option').forEach(c => c.classList.add('selected'));

    function startAudit() {{
      const selected = Array.from(document.querySelectorAll('input[type="checkbox"]:checked')).map(c => parseInt(c.value));
      if (selected.length === 0) {{
        alert('Please select at least one stage to execute.');
        return;
      }}

      const payload = {{
        project_name: document.getElementById('projectName').value,
        target_path: document.getElementById('targetPath').value,
        target_url: document.getElementById('targetUrl').value || null,
        output_dir: document.getElementById('outputDir').value,
        stages: selected
      }};

      document.getElementById('runBtn').disabled = true;
      document.getElementById('runBtn').innerText = '⏳ Auditing in Progress...';
      document.getElementById('progressCard').style.display = 'block';
      document.getElementById('consoleOutput').innerHTML = '';

      fetch('/api/run', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }}).then(res => res.json()).then(data => {{
        pollInterval = setInterval(checkStatus, 800);
      }}).catch(err => {{
        alert('Error starting audit: ' + err);
        document.getElementById('runBtn').disabled = false;
      }});
    }}

    function checkStatus() {{
      fetch('/api/status').then(r => r.json()).then(data => {{
        const pFill = document.getElementById('progressFill');
        pFill.style.width = data.progress + '%';

        if (data.current_stage) {{
          document.getElementById('currentStageText').innerText = `Executing: ${{data.current_stage}} (${{data.progress}}%)`;
        }}

        const consoleBox = document.getElementById('consoleOutput');
        consoleBox.innerHTML = data.logs.map(l => `<div>${{l}}</div>`).join('');
        consoleBox.scrollTop = consoleBox.scrollHeight;

        if (!data.running && data.progress === 100) {{
          clearInterval(pollInterval);
          document.getElementById('statusBadge').innerText = 'COMPLETED';
          document.getElementById('statusBadge').style.background = '#10b981';
          document.getElementById('currentStageText').innerText = '🎉 Audit complete! Reports successfully generated.';
          document.getElementById('viewReportLink').style.display = 'inline-block';
          document.getElementById('runBtn').disabled = false;
          document.getElementById('runBtn').innerText = '🚀 Run Another Audit';
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
        CURRENT_RUN["logs"] = ["Initializing OmniSec engine..."]
        CURRENT_RUN["current_stage"] = "Configuring environment"

        try:
            cfg = OmniSecConfig(
                project_name=data.get("project_name", "Product Security Audit"),
                target_path=data.get("target_path", "."),
                target_url=data.get("target_url"),
                output_dir=data.get("output_dir", "./reports")
            )

            stages = data.get("stages", list(range(1, 10)))
            total_stages = len(stages)

            def event_callback(event_type: str, payload: Dict[str, Any]):
                if event_type == "stage_started":
                    s_id = payload.get("stage_id")
                    s_name = payload.get("stage_name")
                    CURRENT_RUN["current_stage"] = f"Stage {s_id}: {s_name}"
                    idx = stages.index(s_id) if s_id in stages else 0
                    CURRENT_RUN["progress"] = int(10 + (idx / total_stages) * 80)
                    CURRENT_RUN["logs"].append(f"[RUNNING] Stage {s_id}: {s_name}")
                elif event_type == "stage_completed":
                    s_id = payload.get("stage_id")
                    count = payload.get("findings_count", 0)
                    CURRENT_RUN["logs"].append(f"[SUCCESS] Stage {s_id} completed: {count} findings identified.")
                elif event_type == "stage_error":
                    s_id = payload.get("stage_id")
                    err = payload.get("error")
                    CURRENT_RUN["logs"].append(f"[ERROR] Stage {s_id} error: {err}")

            runner = OmniSecRunner(cfg, event_callback=event_callback)
            report = runner.run(selected_stages=stages)

            CURRENT_RUN["progress"] = 92
            CURRENT_RUN["current_stage"] = "Generating HTML, JSON, and Markdown reports"

            # Write Reports
            html_path = os.path.join(cfg.output_dir, "omnisec-report.html")
            json_path = os.path.join(cfg.output_dir, "omnisec-report.json")
            md_path = os.path.join(cfg.output_dir, "omnisec-report.md")

            HtmlReporter.generate(report, html_path)
            JsonReporter.generate(report, json_path)
            MarkdownReporter.generate(report, md_path)

            CURRENT_RUN["report_html_path"] = html_path
            CURRENT_RUN["last_report"] = report.to_dict()
            CURRENT_RUN["progress"] = 100
            CURRENT_RUN["current_stage"] = "Done"
            CURRENT_RUN["logs"].append(f"[FINISHED] HTML Report: {html_path}")
            CURRENT_RUN["logs"].append(f"[FINISHED] Overall Score: {report.overall_score}/100 | Gate: {report.gate_verdict.status}")

        except Exception as e:
            CURRENT_RUN["logs"].append(f"[FATAL] Engine exception: {str(e)}")
        finally:
            CURRENT_RUN["running"] = False


def start_server(port: int = 8080, host: str = "127.0.0.1"):
    server = HTTPServer((host, port), OmniSecWebHandler)
    print(f"\n=======================================================")
    print(f"🛡️  OmniSec Web Dashboard active at: http://{host}:{port}")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OmniSec Web Server.")
        server.server_close()
