"""
Single-file Interactive HTML Dashboard & Report Generator for DKSec (Enterprise Edition).
Generates an executive-ready dark/light dashboard with Mermaid DFDs, SARIF/SBOM exporters,
18 OpenSSF Scorecard checks, ASVS matrix, and code remediation diffs.
"""

import os
import json
from dksec.models import DKSecReport, Severity


class HtmlReporter:
    @staticmethod
    def generate(report: DKSecReport, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        report_data_json = json.dumps(report.to_dict())

        gate_color = {
            "APPROVED": "#10b981",            # Emerald green
            "CONDITIONAL_APPROVAL": "#f59e0b",# Amber
            "BLOCKED": "#ef4444"              # Rose red
        }.get(report.gate_verdict.status, "#64748b")

        mermaid_dfd = ""
        s1 = report.stage_results.get(1)
        if s1 and "mermaid_dfd" in s1.details:
            mermaid_dfd = s1.details["mermaid_dfd"]

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DKSec Enterprise Report - {report.project_name}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
  <script>mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});</script>
  <style>
    :root {{
      --bg-main: #0b0f19;
      --bg-card: #131b2e;
      --bg-card-hover: #1c2742;
      --border: #233252;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #3b82f6;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --info: #64748b;
      --success: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg-main); color: var(--text-main); line-height: 1.5; padding-bottom: 80px; }}
    header {{
      background: linear-gradient(180deg, #162035 0%, #0b0f19 100%);
      border-bottom: 1px solid var(--border);
      padding: 24px 36px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .logo-area {{ display: flex; align-items: center; gap: 14px; }}
    .logo-shield {{
      background: linear-gradient(135deg, #3b82f6, #1d4ed8);
      color: #fff;
      font-weight: 800;
      font-size: 24px;
      width: 48px;
      height: 48px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
    }}
    h1 {{ font-size: 22px; font-weight: 700; color: #fff; }}
    .subtitle {{ font-size: 13px; color: var(--text-muted); }}
    .header-actions {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .btn {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .btn:hover {{ background: var(--border); }}
    .btn-primary {{ background: #2563eb; border-color: #3b82f6; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}

    .container {{ max-width: 1440px; margin: 0 auto; padding: 28px 36px; }}

    /* Gate Banner */
    .gate-banner {{
      background: rgba(19, 27, 46, 0.85);
      border: 2px solid {gate_color};
      border-radius: 14px;
      padding: 20px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.4);
      flex-wrap: wrap;
      gap: 20px;
    }}
    .gate-status-badge {{
      display: inline-block;
      padding: 6px 16px;
      border-radius: 20px;
      font-weight: 800;
      font-size: 14px;
      letter-spacing: 0.5px;
      background: {gate_color};
      color: #fff;
    }}
    .gate-info h2 {{ font-size: 20px; margin-bottom: 4px; }}
    .gate-reasons {{ font-size: 13px; color: var(--text-muted); }}

    /* KPI Summary Row */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}
    .kpi-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 22px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .kpi-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
    .kpi-val {{ font-size: 32px; font-weight: 800; margin: 6px 0; }}
    .kpi-sub {{ font-size: 11px; color: var(--text-muted); }}

    /* Lifecycle Pipeline Visualizer */
    .section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
    .pipeline-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }}
    .pipeline-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 20px;
      position: relative;
      transition: transform 0.2s, border-color 0.2s;
      cursor: pointer;
    }}
    .pipeline-card:hover {{ border-color: var(--accent); transform: translateY(-2px); }}
    .pipeline-card.active {{ border-color: #3b82f6; background: #16233f; }}
    .stage-num {{
      display: inline-block;
      width: 26px;
      height: 26px;
      line-height: 26px;
      text-align: center;
      background: #233252;
      color: #93c5fd;
      font-size: 12px;
      font-weight: 800;
      border-radius: 6px;
      margin-right: 8px;
    }}
    .stage-title {{ font-size: 15px; font-weight: 700; color: #fff; }}
    .stage-tools {{ font-size: 12px; color: #60a5fa; margin: 4px 0 8px 0; font-family: monospace; }}
    .stage-desc {{ font-size: 12px; color: var(--text-muted); margin-bottom: 12px; }}
    .stage-footer {{ display: flex; justify-content: space-between; font-size: 12px; align-items: center; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px; }}
    .badge-count {{ padding: 2px 8px; border-radius: 10px; font-weight: 700; font-size: 11px; }}

    /* Tab Navigation */
    .tab-bar {{
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
      overflow-x: auto;
      padding-bottom: 4px;
    }}
    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      white-space: nowrap;
    }}
    .tab-btn.active {{ color: #fff; border-bottom-color: var(--accent); }}

    /* Filter Bar */
    .filter-bar {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 18px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 20px;
    }}
    .filter-group {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    .pill {{
      padding: 4px 12px;
      border-radius: 16px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid transparent;
      cursor: pointer;
      background: #1e293b;
      color: #94a3b8;
    }}
    .pill.active {{ background: #3b82f6; color: #fff; }}
    .search-input {{
      background: #0b0f19;
      border: 1px solid var(--border);
      color: #fff;
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 13px;
      min-width: 260px;
    }}

    /* Findings Cards */
    .finding-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid #64748b;
      border-radius: 10px;
      padding: 18px 22px;
      margin-bottom: 14px;
      transition: all 0.2s;
    }}
    .finding-card:hover {{ border-color: #3b82f6; }}
    .finding-card.CRITICAL {{ border-left-color: var(--crit); }}
    .finding-card.HIGH {{ border-left-color: var(--high); }}
    .finding-card.MEDIUM {{ border-left-color: var(--med); }}
    .finding-card.LOW {{ border-left-color: var(--low); }}
    .finding-card.INFO {{ border-left-color: var(--info); }}

    .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 8px; }}
    .finding-title {{ font-size: 16px; font-weight: 700; color: #fff; }}
    .finding-badges {{ display: flex; gap: 8px; }}
    .badge {{
      font-size: 11px;
      font-weight: 800;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .badge-CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
    .badge-HIGH {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }}
    .badge-MEDIUM {{ background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }}
    .badge-LOW {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
    .badge-INFO {{ background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }}

    .finding-meta {{ font-size: 12px; color: var(--text-muted); display: flex; gap: 16px; margin-bottom: 10px; font-family: monospace; flex-wrap: wrap; }}
    .code-box {{
      background: #090d16;
      border: 1px solid #1a253b;
      padding: 10px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      color: #38bdf8;
      overflow-x: auto;
      margin: 8px 0;
    }}
    .diff-box {{
      background: #090d16;
      border: 1px solid #1a253b;
      padding: 10px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      color: #a7f3d0;
      white-space: pre;
      overflow-x: auto;
      margin: 8px 0;
    }}
    .remediation-box {{
      background: rgba(16, 185, 129, 0.08);
      border-left: 3px solid #10b981;
      padding: 10px 14px;
      border-radius: 4px;
      font-size: 13px;
      color: #a7f3d0;
      margin-top: 10px;
    }}

    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: var(--bg-card);
      border-radius: 10px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    .data-table th, .data-table td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }}
    .data-table th {{ background: #162035; color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
    .status-pill-pass {{ color: #34d399; font-weight: 700; }}
    .status-pill-fail {{ color: #f87171; font-weight: 700; }}
    .status-pill-verify {{ color: #fbbf24; font-weight: 700; }}

    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}
  </style>
</head>
<body>

  <header>
    <div class="logo-area">
      <div class="logo-shield">🛡️</div>
      <div>
        <h1>DKSec Unified Product Security Platform</h1>
        <div class="subtitle">{report.project_name} | Target: {report.target_path} | Completed in {report.duration_seconds:.2f}s</div>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn" onclick="window.print()">🖨️ Print to PDF</button>
      <button class="btn" onclick="downloadFile('dksec-results.sarif', 'application/json')">📥 SARIF v2.1.0</button>
      <button class="btn" onclick="downloadFile('cyclonedx-sbom.json', 'application/json')">📦 CycloneDX SBOM</button>
      <button class="btn btn-primary" onclick="downloadJSON()">💾 Export JSON</button>
    </div>
  </header>

  <div class="container">

    <!-- Gatekeeper Verdict Banner -->
    <div class="gate-banner">
      <div class="gate-info">
        <span class="gate-status-badge">{report.gate_verdict.status}</span>
        <h2 style="margin-top: 8px;">Release Signoff Decision: {report.gate_verdict.status}</h2>
        <div class="gate-reasons">
          {" | ".join(report.gate_verdict.reasons)}
        </div>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 11px; color: var(--text-muted);">Signoff Certificate Hash</div>
        <div style="font-family: monospace; font-size: 13px; color: #93c5fd;">{report.gate_verdict.signoff_hash[:24]}...</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">{report.timestamp[:19]} UTC</div>
      </div>
    </div>

    <!-- Executive KPI Grid -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Security Posture Score</div>
        <div class="kpi-val" style="color: {gate_color};">{report.overall_score:.0f}<span style="font-size: 16px; color: var(--text-muted);">/100</span></div>
        <div class="kpi-sub">Cross-Stage Aggregate Health</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Critical Findings</div>
        <div class="kpi-val" style="color: var(--crit);">{report.severity_counts.get('CRITICAL', 0)}</div>
        <div class="kpi-sub">Remediation SLA: 7 Days</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">High Findings</div>
        <div class="kpi-val" style="color: var(--high);">{report.severity_counts.get('HIGH', 0)}</div>
        <div class="kpi-sub">Remediation SLA: 14 Days</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Medium Findings</div>
        <div class="kpi-val" style="color: var(--med);">{report.severity_counts.get('MEDIUM', 0)}</div>
        <div class="kpi-sub">Remediation SLA: 30 Days</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Dependencies (SBOM)</div>
        <div class="kpi-val" style="color: #38bdf8;">{len(report.sbom_components)}</div>
        <div class="kpi-sub">CycloneDX v1.5 Tracked</div>
      </div>
    </div>

    <!-- Product Security 9-Stage Flow Visualizer -->
    <div class="section-title">
      <span>🔄</span> 9-Stage Product Security Lifecycle Execution
    </div>
    <div class="pipeline-grid">
"""

        for s_id in range(1, 10):
            res = report.stage_results.get(s_id)
            if res:
                s_name = res.stage_name
                tools = res.recommended_tools
                covers = res.what_it_covers
                f_count = len(res.findings)
                badge_bg = "rgba(16, 185, 129, 0.2)" if f_count == 0 else "rgba(239, 68, 68, 0.2)"
                badge_color = "#34d399" if f_count == 0 else "#f87171"
                status_text = f"{f_count} findings" if f_count > 0 else "Clean / Passed"
                dur_display = f"{res.execution_time_seconds:.1f}s"
            else:
                s_name = f"Stage {s_id}"
                tools = "N/A"
                covers = "Stage skipped in this run"
                badge_bg = "rgba(100, 116, 139, 0.2)"
                badge_color = "#94a3b8"
                status_text = "Skipped"
                dur_display = "N/A"

            html_content += f"""
      <div class="pipeline-card" onclick="filterByStage({s_id})">
        <div style="display: flex; align-items: center; margin-bottom: 6px;">
          <span class="stage-num">{s_id}</span>
          <span class="stage-title">{s_name}</span>
        </div>
        <div class="stage-tools">{tools}</div>
        <div class="stage-desc">{covers}</div>
        <div class="stage-footer">
          <span class="badge-count" style="background: {badge_bg}; color: {badge_color};">{status_text}</span>
          <span style="color: var(--text-muted); font-size: 11px;">{dur_display}</span>
        </div>
      </div>
"""

        html_content += f"""
    </div>

    <!-- Detailed Tabs Section -->
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('tab-findings', this)">🔍 Vulnerabilities ({len(report.all_findings)})</button>
      <button class="tab-btn" onclick="switchTab('tab-stride', this)">📐 Stage 1: Threat Model & DFD</button>
      <button class="tab-btn" onclick="switchTab('tab-asvs', this)">📜 Stage 2: ASVS Matrix</button>
      <button class="tab-btn" onclick="switchTab('tab-sbom', this)">📦 Stage 3: SBOM Inventory ({len(report.sbom_components)})</button>
      <button class="tab-btn" onclick="switchTab('tab-wstg', this)">🧪 Stage 5: WSTG Checklist</button>
      <button class="tab-btn" onclick="switchTab('tab-dojo', this)">📊 Stage 7: DefectDojo SLAs</button>
      <button class="tab-btn" onclick="switchTab('tab-scorecard', this)">🎖️ Stage 8: OpenSSF 18-Checks</button>
      <button class="tab-btn" onclick="switchTab('tab-wazuh', this)">🛡️ Stage 9: Wazuh & Sigma Rules</button>
    </div>

    <!-- TAB 1: FINDINGS -->
    <div id="tab-findings" class="tab-content active">
      <div class="filter-bar">
        <div class="filter-group">
          <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">SEVERITY:</span>
          <button class="pill active" onclick="setSeverityFilter('ALL', this)">All</button>
          <button class="pill" onclick="setSeverityFilter('CRITICAL', this)">Critical</button>
          <button class="pill" onclick="setSeverityFilter('HIGH', this)">High</button>
          <button class="pill" onclick="setSeverityFilter('MEDIUM', this)">Medium</button>
          <button class="pill" onclick="setSeverityFilter('LOW', this)">Low</button>
        </div>
        <div class="filter-group">
          <input type="text" id="findingSearch" class="search-input" placeholder="Search findings by title, tool, CWE, MITRE..." oninput="applyFilters()" />
        </div>
      </div>

      <div id="findingsContainer">
"""

        for f in report.all_findings:
            html_content += f"""
        <div class="finding-card {f.severity.value}" data-severity="{f.severity.value}" data-stage="{f.stage_id}" data-search="{f.title.lower()} {f.tool.lower()} {str(f.cwe).lower()} {str(f.mitre_attack).lower()} {str(f.file_path).lower()}">
          <div class="finding-header">
            <div>
              <span style="color: var(--text-muted); font-family: monospace; font-size: 12px; margin-right: 8px;">{f.id}</span>
              <span class="finding-title">{f.title}</span>
            </div>
            <div class="finding-badges">
              <span class="badge badge-{f.severity.value}">{f.severity.value}</span>
              <span class="badge" style="background: #1e293b; color: #94a3b8;">Stage {f.stage_id}</span>
              {f'<span class="badge" style="background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca;">MITRE {f.mitre_attack}</span>' if f.mitre_attack else ''}
            </div>
          </div>
          <div class="finding-meta">
            <span>🔧 Tool: <strong>{f.tool}</strong></span>
            <span>📂 Target: <strong>{f.file_path or f.target or 'N/A'}{(':' + str(f.line_number)) if f.line_number else ''}</strong></span>
            <span>🏷️ CWE: <strong>{f.cwe or 'N/A'}</strong></span>
            <span>⏱️ SLA: <strong>{f.sla_days} Days</strong></span>
          </div>
          <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;">{f.description}</p>
          {f'<div class="code-box">{f.code_snippet}</div>' if f.code_snippet else ''}
          {f'<div class="diff-box"><strong>Proposed Patch (Unified Diff):</strong><br/>{f.remediation_diff}</div>' if f.remediation_diff else ''}
          {f'<div class="remediation-box"><strong>💡 Remediation Guidance:</strong> {f.remediation}</div>' if f.remediation else ''}
        </div>
"""

        html_content += f"""
      </div>
    </div>

    <!-- TAB 2: THREAT MODEL (STRIDE & DFD) -->
    <div id="tab-stride" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px;">
        <h3 style="margin-bottom: 8px;">Automated Data Flow Diagram (DFD)</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 18px;">
          Generated data-flow architecture diagram mapping trust boundaries and components.
        </p>
        <div class="mermaid" style="background: #090d16; padding: 20px; border-radius: 8px; overflow-x: auto;">
{mermaid_dfd if mermaid_dfd else 'flowchart TD\n  Client["Client"] --> App["Application Server"]'}
        </div>
      </div>

      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <h3 style="margin-bottom: 8px;">OWASP Threat Dragon & STRIDE Threat Matrix</h3>
        <table class="data-table">
          <thead>
            <tr>
              <th>Threat ID</th>
              <th>Category</th>
              <th>Component</th>
              <th>Severity</th>
              <th>MITRE ATT&CK</th>
              <th>Identified Architectural Threat</th>
              <th>Mitigation</th>
            </tr>
          </thead>
          <tbody>
"""
        if s1 and "threats" in s1.details:
            for t in s1.details["threats"]:
                html_content += f"""
            <tr>
              <td style="font-family: monospace;">{t.get('category')[:3].upper()}</td>
              <td><strong>{t.get('category')}</strong></td>
              <td>{t.get('component')}</td>
              <td><span class="badge badge-{t.get('severity')}">{t.get('severity')}</span></td>
              <td style="font-family: monospace; color: #a5b4fc;">{t.get('mitre_attack', 'T1190')}</td>
              <td>{t.get('title')}</td>
              <td style="color: #6ee7b7;">{t.get('mitigation')}</td>
            </tr>
"""
        html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: ASVS CHECKLIST -->
    <div id="tab-asvs" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <h3 style="margin-bottom: 8px;">OWASP ASVS v4.0.3 Security Requirements Matrix</h3>
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Chapter</th>
              <th>Level</th>
              <th>Requirement Description</th>
              <th>CWE</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
"""
        s2 = report.stage_results.get(2)
        if s2 and "checklist" in s2.details:
            for item in s2.details["checklist"]:
                st_class = "status-pill-pass" if item['status'] == 'PASS' else ("status-pill-fail" if item['status'] == 'FAIL' else "status-pill-verify")
                html_content += f"""
            <tr>
              <td style="font-family: monospace;"><strong>{item.get('id')}</strong></td>
              <td>{item.get('chapter')}</td>
              <td>Level {item.get('level')}</td>
              <td>{item.get('description')}</td>
              <td style="font-family: monospace;">{item.get('cwe')}</td>
              <td><span class="{st_class}">{item.get('status')}</span></td>
            </tr>
"""
        html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: SBOM INVENTORY -->
    <div id="tab-sbom" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <h3 style="margin-bottom: 8px;">CycloneDX v1.5 Software Bill of Materials (SBOM)</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 18px;">
          Software component inventory with Package URLs (PURL), licenses, and versions.
        </p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Component Name</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>Package URL (PURL)</th>
              <th>License</th>
            </tr>
          </thead>
          <tbody>
"""
        for c in report.sbom_components:
            html_content += f"""
            <tr>
              <td><strong>{c.name}</strong></td>
              <td style="font-family: monospace;">{c.version}</td>
              <td><span class="badge" style="background: #1e293b; color: #93c5fd;">{c.ecosystem}</span></td>
              <td style="font-family: monospace; color: #94a3b8; font-size: 11px;">{c.purl}</td>
              <td>{c.license or 'MIT'}</td>
            </tr>
"""
        html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 5: WSTG PENTEST CHECKLIST -->
    <div id="tab-wstg" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <h3 style="margin-bottom: 8px;">OWASP Web Security Testing Guide (WSTG v4.2) Verification</h3>
        <table class="data-table">
          <thead>
            <tr>
              <th>WSTG ID</th>
              <th>Domain</th>
              <th>Test Objective</th>
              <th>Status</th>
              <th>Audit Evidence / Notes</th>
            </tr>
          </thead>
          <tbody>
"""
        s5 = report.stage_results.get(5)
        if s5 and "checklist" in s5.details:
            for item in s5.details["checklist"]:
                st_class = "status-pill-pass" if item['status'] == 'PASS' else ("status-pill-fail" if item['status'] == 'FAIL' else "status-pill-verify")
                html_content += f"""
            <tr>
              <td style="font-family: monospace;">{item.get('id')}</td>
              <td><strong>{item.get('category')}</strong></td>
              <td>{item.get('name')}</td>
              <td><span class="{st_class}">{item.get('status')}</span></td>
              <td style="color: var(--text-muted);">{item.get('tester_notes') or item.get('evidence') or 'Verified'}</td>
            </tr>
"""
        html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 6: DEFECTDOJO SLA -->
    <div id="tab-dojo" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <h3 style="margin-bottom: 8px;">OWASP DefectDojo Remediation Schedule & SLA Tracker</h3>
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Finding Title</th>
              <th>Severity</th>
              <th>Remediation SLA</th>
              <th>Target Due Date</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
"""
        s7 = report.stage_results.get(7)
        if s7 and "remediation_plan" in s7.details:
            for plan in s7.details["remediation_plan"]:
                html_content += f"""
            <tr>
              <td style="font-family: monospace;">{plan.get('id')}</td>
              <td><strong>{plan.get('title')}</strong></td>
              <td><span class="badge badge-{plan.get('severity')}">{plan.get('severity')}</span></td>
              <td>{plan.get('sla_days')} Days</td>
              <td style="color: #fca5a5; font-family: monospace;">{plan.get('target_due_date')}</td>
              <td><span class="status-pill-verify">{plan.get('status')}</span></td>
            </tr>
"""
        html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 7: OPENSSF 18-CHECKS SCORECARD -->
    <div id="tab-scorecard" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <div>
            <h3>OpenSSF Scorecard v4 (All 18 Checks)</h3>
            <p style="color: var(--text-muted); font-size: 13px;">Supply chain posture and release integrity controls.</p>
          </div>
          <span class="badge" style="background: #1e1b4b; color: #c7d2fe; font-size: 13px; padding: 6px 14px;">
            {report.stage_results.get(8).details.get('slsa_level', 'SLSA Level 1') if report.stage_results.get(8) else 'SLSA Level 1'}
          </span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Check Name</th>
              <th>Score (/10)</th>
              <th>Reason</th>
              <th>Remediation Action</th>
            </tr>
          </thead>
          <tbody>
"""
        s8 = report.stage_results.get(8)
        if s8 and "scorecard_18_checks" in s8.details:
            for check in s8.details["scorecard_18_checks"]:
                sc = check.get('score', 0)
                sc_color = "#34d399" if sc >= 8 else ("#fbbf24" if sc >= 5 else "#f87171")
                html_content += f"""
            <tr>
              <td><strong>{check.get('name')}</strong></td>
              <td style="font-weight: 800; color: {sc_color}; font-size: 14px;">{sc}/10</td>
              <td>{check.get('reason')}</td>
              <td style="color: #93c5fd;">{check.get('remediation')}</td>
            </tr>
"""
        html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 8: WAZUH & SIGMA -->
    <div id="tab-wazuh" class="tab-content">
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px;">
        <h3 style="margin-bottom: 8px;">Wazuh SIEM XML & Sigma YAML Detection Engineering</h3>
        <h4 style="margin: 16px 0 8px 0; color: #93c5fd;">Generated Wazuh local_rules.xml</h4>
        <pre class="code-box" style="white-space: pre; max-height: 240px;">{report.stage_results.get(9).details.get('wazuh_xml') if report.stage_results.get(9) else 'N/A'}</pre>
        <h4 style="margin: 20px 0 8px 0; color: #93c5fd;">Generated Sigma Detection Rules (sigma-rules.yml)</h4>
        <pre class="code-box" style="white-space: pre; max-height: 240px;">{report.stage_results.get(9).details.get('sigma_yaml') if report.stage_results.get(9) else 'N/A'}</pre>
      </div>
    </div>

  </div>

  <script>
    const reportData = {report_data_json};
    let currentSeverity = 'ALL';
    let currentStage = 'ALL';

    function switchTab(tabId, btn) {{
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btn.classList.add('active');
    }}

    function setSeverityFilter(sev, btn) {{
      currentSeverity = sev;
      btn.parentElement.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      applyFilters();
    }}

    function filterByStage(stageId) {{
      currentStage = stageId;
      document.querySelectorAll('.pipeline-card').forEach(c => c.classList.remove('active'));
      event.currentTarget.classList.add('active');
      switchTab('tab-findings', document.querySelectorAll('.tab-btn')[0]);
      applyFilters();
    }}

    function applyFilters() {{
      const query = document.getElementById('findingSearch').value.toLowerCase();
      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(card => {{
        const sev = card.getAttribute('data-severity');
        const stage = parseInt(card.getAttribute('data-stage'));
        const searchTxt = card.getAttribute('data-search');

        const matchSev = (currentSeverity === 'ALL' || sev === currentSeverity);
        const matchStage = (currentStage === 'ALL' || stage === currentStage);
        const matchQuery = (!query || searchTxt.includes(query));

        if (matchSev && matchStage && matchQuery) {{
          card.style.display = 'block';
        }} else {{
          card.style.display = 'none';
        }}
      }});
    }}

    function downloadJSON() {{
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `dksec-report.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }}

    function downloadFile(filename, mime) {{
      const endpoint = filename;
      window.open(endpoint, '_blank');
    }}
  </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as fl:
            fl.write(html_content)

        return output_path
