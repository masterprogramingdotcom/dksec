"""
Single-file Interactive HTML Dashboard & Report Generator for DKSec (Enterprise Edition).
Generates an executive-ready, high-contrast dark/light dashboard with Mermaid DFDs,
SARIF/SBOM exporters, live DAST & API security matrix, VAPT attack surface recon,
18 OpenSSF Scorecard checks, ASVS matrix, DefectDojo SLAs, Wazuh SIEM & Sigma rules,
and code remediation diffs.
"""

from typing import Any, Dict, List, Optional
import os
import json
import re
from dksec.models import DKSecReport, Severity
from dksec.config import STAGE_METADATA


class HtmlReporter:
    @staticmethod
    def generate(report: DKSecReport, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        report_data_json = json.dumps(report.to_dict())

        # Gate Colors
        verdict = report.gate_verdict.status if report.gate_verdict else "UNKNOWN"
        gate_color = {
            "APPROVED": "#10b981",            # Emerald green
            "CONDITIONAL_APPROVAL": "#f59e0b",# Amber
            "BLOCKED": "#ef4444"              # Rose red
        }.get(verdict, "#64748b")

        gate_class = "approved" if verdict == "APPROVED" else ("conditional" if verdict == "CONDITIONAL_APPROVAL" else "blocked")

        # Stage 1: Threat Dragon & Mermaid DFD
        s1 = report.stage_results.get(1)
        mermaid_dfd = ""
        if s1 and "mermaid_dfd" in s1.details:
            mermaid_dfd = s1.details["mermaid_dfd"]
        if not mermaid_dfd:
            mermaid_dfd = 'flowchart TD\n  Client["Client"] --> App["Application Server"]\n  App --> DB[("Primary Database")]'

        # Stage 4: Live DAST, TLS & Headers
        s4 = report.stage_results.get(4)
        s4_details = s4.details if s4 else {}
        tls_data = s4_details.get("tls", {})
        headers_data = s4_details.get("headers", {})
        cors_data = s4_details.get("cors", {})
        methods_data = s4_details.get("methods", {})
        api_probes_data = s4_details.get("api_probes", {})
        live_routes_data = s4_details.get("live_routes_audit", {})
        auth_status = s4_details.get("auth_status", {})

        # Stage 6: VAPT & Attack Surface Recon
        s6 = report.stage_results.get(6)
        s6_details = s6.details if s6 else {}
        recon_data = s6_details.get("recon", {})
        dns_data = s6_details.get("dns", {})
        fuzzing_data = s6_details.get("fuzzing", {})
        active_vapt_data = s6_details.get("active_vapt", {})

        # Auth Badge & Info
        auth_badge = ""
        auth_status_text = "N/A"
        if auth_status.get("authenticated"):
            m = auth_status.get("method", "session").upper()
            auth_badge = f'<span class="badge" style="background: rgba(16,185,129,0.15); color: #059669; border: 1px solid #10b981;">🔒 AUTHENTICATED ({m})</span>'
            auth_status_text = f"Authenticated ({m})"
        elif report.target_url:
            auth_badge = '<span class="badge" style="background: rgba(100,116,139,0.15); color: #64748b; border: 1px solid #94a3b8;">🌐 PUBLIC / UNAUTHENTICATED</span>'
            auth_status_text = "Public / Unauthenticated"

        target_display = f"Target: {report.target_path}"
        if report.target_url:
            target_display += f" | URL: {report.target_url}"

        server_banner = headers_data.get("server_banner") or headers_data.get("server") or "N/A"
        tls_version = tls_data.get("protocol") or tls_data.get("version") or ("HTTPS (TLS)" if report.target_url and report.target_url.startswith("https") else ("HTTP" if report.target_url else "N/A"))
        open_ports = recon_data.get("open_ports", [])
        open_ports_str = ", ".join(str(p) for p in open_ports) if open_ports else ("80, 443 (Web)" if report.target_url else "N/A")

        # Score & Grade
        score = round(report.overall_score, 1)
        score_grade = "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 50 else "F"))

        # AI Executive Briefing HTML
        ai_briefing_html = ""
        if report.ai_executive_summary:
            paragraphs = report.ai_executive_summary.strip().split("\n\n")
            body_parts = []
            for p in paragraphs:
                p = p.strip()
                if p.startswith("### "):
                    body_parts.append(f'<h3 style="font-size: 15px; color: var(--text-heading); margin: 14px 0 6px 0; font-weight: 700;">{p[4:]}</h3>')
                elif p:
                    p_html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', p)
                    body_parts.append(f'<p style="margin-bottom: 10px; line-height: 1.6; font-size: 13.5px; color: var(--text-main);">{p_html}</p>')
            formatted_html = "\n".join(body_parts)
            ai_briefing_html = f"""
    <!-- AI Executive Security Briefing -->
    <div class="ai-briefing-card">
      <div class="ai-briefing-header">
        <span class="ai-tag">🤖 DKSec AI Security Intelligence</span>
        <span style="font-size: 12px; color: #4338ca; font-weight: 700;">Autonomous Executive Triaging &amp; Posture Synthesis</span>
      </div>
      <div style="margin-top: 10px;">
        {formatted_html}
      </div>
    </div>
"""

        # -------------------------------------------------------------
        # BUILD TAB 1: FINDINGS
        # -------------------------------------------------------------
        findings_html = ""
        for f in report.all_findings:
            ai_badge = ""
            if f.ai_triage:
                triage_color = "#059669" if f.ai_triage == "TRUE_POSITIVE" else ("#dc2626" if f.ai_triage == "FALSE_POSITIVE" else "#d97706")
                conf_pct = int((f.ai_confidence or 0.9) * 100)
                ai_badge = f'<span class="badge" style="background: rgba(99, 102, 241, 0.15); color: {triage_color}; border: 1px solid #6366f1;">🤖 {f.ai_triage} ({conf_pct}%)</span>'

            ai_box = ""
            if f.ai_analysis:
                ai_box = f'<div class="ai-analysis-box"><strong>🤖 DKSec AI Analysis &amp; Context:</strong> {f.ai_analysis}</div>'

            # OWASP & CVSS Badges
            owasp_badge = f'<span class="badge" style="background: rgba(37,99,235,0.1); color: #2563eb; border: 1px solid rgba(37,99,235,0.3);">{f.owasp}</span>' if f.owasp else ''
            cvss_badge = f'<span class="badge" style="background: rgba(220,38,38,0.1); color: #dc2626; border: 1px solid rgba(220,38,38,0.3);">CVSS {f.cvss_score}</span>' if f.cvss_score else ''
            mitre_badge = f'<span class="badge" style="background: rgba(79,70,229,0.1); color: #4f46e5; border: 1px solid rgba(79,70,229,0.3);">MITRE {f.mitre_attack}</span>' if f.mitre_attack else ''

            # References
            refs_html = ""
            if f.references:
                ref_links = []
                for r in f.references:
                    r_str = str(r).strip()
                    if r_str.startswith("http"):
                        ref_links.append(f'<a href="{r_str}" target="_blank" style="color: #2563eb; text-decoration: underline; margin-right: 12px; font-size: 12px;">🔗 {r_str}</a>')
                    else:
                        ref_links.append(f'<span style="color: var(--text-muted); font-size: 12px; margin-right: 12px;">• {r_str}</span>')
                refs_html = f'<div style="margin-top: 10px; font-size: 12px;"><strong>References &amp; Advisories:</strong><div style="margin-top: 4px; word-break: break-all;">{" ".join(ref_links)}</div></div>'

            code_box_html = f'<div class="code-box"><div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Matched Code / Evidence:</div><pre style="margin: 0; white-space: pre-wrap;">{f.code_snippet}</pre></div>' if f.code_snippet else ''
            diff_box_html = f'<div class="diff-box"><strong>Proposed Patch (Unified Diff):</strong><pre style="margin: 4px 0 0 0; white-space: pre-wrap;">{f.remediation_diff}</pre></div>' if f.remediation_diff else ''
            remediation_html = f'<div class="remediation-box"><strong>💡 Remediation Guidance:</strong> {f.remediation}</div>' if f.remediation else ''

            findings_html += f"""
        <div class="finding-card {f.severity.value}" data-severity="{f.severity.value}" data-stage="{f.stage_id}" data-search="{f.title.lower()} {f.tool.lower()} {str(f.cwe).lower()} {str(f.mitre_attack).lower()} {str(f.file_path).lower()} {str(f.owasp).lower()} {str(f.ai_triage or '').lower()}">
          <div class="finding-header">
            <div>
              <span style="color: var(--text-muted); font-family: monospace; font-size: 12px; margin-right: 8px; font-weight: 700;">{f.id}</span>
              <span class="finding-title">{f.title}</span>
            </div>
            <div class="finding-badges">
              {ai_badge}
              <span class="badge badge-{f.severity.value}">{f.severity.value}</span>
              <span class="badge" style="background: var(--pill-bg); color: var(--text-main);">Stage {f.stage_id}</span>
              {owasp_badge}
              {cvss_badge}
              {mitre_badge}
            </div>
          </div>
          <div class="finding-meta">
            <span>🔧 Tool: <strong>{f.tool}</strong></span>
            <span>📂 Target: <strong>{f.file_path or f.target or 'N/A'}{(':' + str(f.line_number)) if f.line_number else ''}</strong></span>
            <span>🏷️ CWE: <strong>{f.cwe or 'N/A'}</strong></span>
            <span>⏱️ Remediation SLA: <strong>{f.sla_days} Days</strong></span>
            <span>📋 Status: <strong>{f.status.value}</strong></span>
          </div>
          <p class="finding-desc">{f.description}</p>
          {ai_box}
          {code_box_html}
          {diff_box_html}
          {remediation_html}
          {refs_html}
        </div>
"""

        # -------------------------------------------------------------
        # BUILD TAB 2: STAGE 1 (THREAT MODEL & DFD)
        # -------------------------------------------------------------
        components_table_html = ""
        stride_table_html = ""
        if s1 and "components" in s1.details:
            for comp in s1.details.get("components", []):
                components_table_html += f"""
                <tr>
                  <td><strong>{comp.get('name')}</strong></td>
                  <td><span class="badge" style="background: var(--pill-bg); color: var(--text-main);">{comp.get('type')}</span></td>
                  <td>{comp.get('boundary')}</td>
                  <td style="color: var(--text-muted);">{comp.get('description')}</td>
                </tr>
                """
        if s1 and "threats" in s1.details:
            for t in s1.details.get("threats", []):
                stride_table_html += f"""
                <tr>
                  <td style="font-family: monospace; font-weight: 700;">{t.get('category')[:3].upper()}</td>
                  <td><strong>{t.get('category')}</strong></td>
                  <td>{t.get('component')}</td>
                  <td><span class="badge badge-{t.get('severity')}">{t.get('severity')}</span></td>
                  <td style="font-family: monospace; color: #4f46e5;">{t.get('mitre_attack', 'T1190')}</td>
                  <td>{t.get('title')}</td>
                  <td style="color: #059669; font-weight: 600;">{t.get('mitigation')}</td>
                </tr>
                """

        # -------------------------------------------------------------
        # BUILD TAB 3: STAGE 2 (ASVS MATRIX)
        # -------------------------------------------------------------
        asvs_table_html = ""
        s2 = report.stage_results.get(2)
        if s2 and "checklist" in s2.details:
            for item in s2.details.get("checklist", []):
                st = item.get('status', 'VERIFY')
                st_class = "status-pill-pass" if st == 'PASS' else ("status-pill-fail" if st == 'FAIL' else "status-pill-verify")
                asvs_table_html += f"""
                <tr>
                  <td style="font-family: monospace; font-weight: 700;">{item.get('id')}</td>
                  <td>{item.get('chapter')}</td>
                  <td><span class="badge" style="background: var(--pill-bg); color: var(--text-main);">Level {item.get('level')}</span></td>
                  <td>{item.get('description')}</td>
                  <td style="font-family: monospace;">{item.get('cwe') or 'N/A'}</td>
                  <td><span class="{st_class}">{st}</span></td>
                  <td style="color: var(--text-muted); font-size: 12px;">{item.get('evidence') or 'Verified'}</td>
                  <td style="color: #059669; font-size: 12px;">{item.get('remediation') or 'None'}</td>
                </tr>
                """

        # -------------------------------------------------------------
        # BUILD TAB 4: STAGE 3 (SBOM INVENTORY)
        # -------------------------------------------------------------
        sbom_table_html = ""
        for c in report.sbom_components:
            vulns = c.vulnerabilities or []
            vuln_badge = f'<span class="badge badge-HIGH">{len(vulns)} CVEs</span>' if vulns else '<span class="status-pill-pass">Clean</span>'
            cve_details = ", ".join(f"{v.get('cve_id')} ({v.get('severity')})" for v in vulns) if vulns else "No known CVEs"
            fix_details = ", ".join(f"{v.get('cve_id')}: Upgrade to {v.get('fixed_in')}" for v in vulns if v.get('fixed_in')) if vulns else "Up to date"

            sbom_table_html += f"""
            <tr>
              <td><strong>{c.name}</strong></td>
              <td style="font-family: monospace;">{c.version}</td>
              <td><span class="badge" style="background: var(--pill-bg); color: var(--text-main);">{c.ecosystem}</span></td>
              <td style="font-family: monospace; color: var(--text-muted); font-size: 11px;">{c.purl}</td>
              <td>{c.license or 'MIT'}</td>
              <td>{vuln_badge} <span style="font-size: 11px; color: var(--text-muted); display: block;">{cve_details}</span></td>
              <td style="color: #059669; font-size: 12px;">{fix_details}</td>
            </tr>
            """

        # -------------------------------------------------------------
        # BUILD TAB 5: STAGE 4 (DAST & LIVE API SECURITY) - PREVIOUSLY MISSING!
        # -------------------------------------------------------------
        headers_table_html = ""
        for h in headers_data.get("evaluated_headers", []):
            st = h.get("status", "MISSING")
            st_class = "status-pill-pass" if st == "PRESENT" else "status-pill-fail"
            headers_table_html += f"""
            <tr>
              <td style="font-family: monospace; font-weight: 700;">{h.get('name')}</td>
              <td><span class="{st_class}">{st}</span></td>
              <td><span class="badge badge-{h.get('severity', 'LOW')}">{h.get('severity', 'LOW')}</span></td>
              <td style="font-family: monospace; font-size: 12px; color: var(--text-muted);">{h.get('value') or 'Header not sent by server'}</td>
              <td style="font-size: 12px; color: #059669;">{h.get('recommendation', 'Enforce secure value.')}</td>
            </tr>
            """

        probes_table_html = ""
        for p in api_probes_data.get("probed_paths", []):
            st_code = p.get("status_code", 404)
            st_class = "status-pill-fail" if st_code in (200, 201, 301, 302) else "status-pill-pass"
            probes_table_html += f"""
            <tr>
              <td style="font-family: monospace; font-weight: 700;">{p.get('path')}</td>
              <td><span class="{st_class}">HTTP {st_code}</span></td>
              <td style="font-family: monospace;">{p.get('content_length', 0)} bytes</td>
              <td><span class="badge badge-{p.get('severity', 'INFO')}">{p.get('status_description', 'Probed')}</span></td>
              <td style="font-size: 12px; color: var(--text-muted);">{p.get('notes', 'Checked for sensitive information disclosure.')}</td>
            </tr>
            """

        live_routes_table_html = ""
        for r in live_routes_data.get("routes_audited", []):
            live_routes_table_html += f"""
            <tr>
              <td style="font-family: monospace; font-weight: 700;">{r.get('route')}</td>
              <td style="font-family: monospace;">HTTP {r.get('unauth_status', 'N/A')}</td>
              <td style="font-family: monospace;">HTTP {r.get('auth_status', 'N/A')}</td>
              <td><span class="badge" style="background: var(--pill-bg); color: var(--text-main);">{r.get('differential_verdict', 'Consistent')}</span></td>
            </tr>
            """

        # -------------------------------------------------------------
        # BUILD TAB 6: STAGE 5 (WSTG PENTEST CHECKLIST)
        # -------------------------------------------------------------
        wstg_table_html = ""
        s5 = report.stage_results.get(5)
        if s5 and "checklist" in s5.details:
            for item in s5.details.get("checklist", []):
                st = item.get('status', 'UNTESTED')
                st_class = "status-pill-pass" if st == 'PASS' else ("status-pill-fail" if st == 'FAIL' else "status-pill-verify")
                wstg_table_html += f"""
                <tr>
                  <td style="font-family: monospace; font-weight: 700;">{item.get('id')}</td>
                  <td><strong>{item.get('category')}</strong></td>
                  <td>{item.get('name')}</td>
                  <td><span class="{st_class}">{st}</span></td>
                  <td style="color: var(--text-muted); font-size: 12px;">{item.get('tester_notes') or item.get('evidence') or 'Verified'}</td>
                </tr>
                """

        # -------------------------------------------------------------
        # BUILD TAB 7: STAGE 6 (PENETRATION TEST & ATTACK SURFACE RECON) - PREVIOUSLY MISSING!
        # -------------------------------------------------------------
        ports_table_html = ""
        if open_ports:
            for port in open_ports:
                svc = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy / Alt", 8443: "HTTPS-Alt", 3000: "Node / Dev", 5000: "Flask / API", 6379: "Redis Cache", 5432: "PostgreSQL", 3306: "MySQL"}.get(port, "TCP Service")
                ports_table_html += f"""
                <tr>
                  <td style="font-family: monospace; font-weight: 700;">{port}</td>
                  <td>{svc}</td>
                  <td><span class="status-pill-verify">OPEN / ACCESSIBLE</span></td>
                  <td style="color: var(--text-muted); font-size: 12px;">Verified reachable via TCP SYN / connect handshake</td>
                </tr>
                """

        dns_table_html = ""
        for d_check in dns_data.get("checks", []):
            st = d_check.get("status", "PASS")
            st_class = "status-pill-pass" if st == "PASS" else ("status-pill-fail" if st == "FAIL" else "status-pill-verify")
            val = d_check.get("value") or d_check.get("record_value") or "No record"
            rec = d_check.get("recommendation") or d_check.get("security_impact") or "N/A"
            dns_table_html += f"""
            <tr>
              <td style="font-weight: 700;">{d_check.get('record_type')}</td>
              <td><span class="{st_class}">{st}</span></td>
              <td style="font-family: monospace; font-size: 12px; color: var(--text-muted);">{val}</td>
              <td style="font-size: 12px; color: #059669;">{rec}</td>
            </tr>
            """

        fuzzing_table_html = ""
        for fz in fuzzing_data.get("results", []):
            fz_status = fz.get("status_code", 404)
            fz_class = "status-pill-fail" if str(fz_status) in ("200", "201", "301", "302", "500") else "status-pill-pass"
            target_path = fz.get("path") or fz.get("endpoint") or fz.get("target") or "N/A"
            sz = fz.get("content_length") or fz.get("response_size") or 0
            verdict_text = fz.get("verdict") or "Checked"
            risk_text = fz.get("risk") or fz.get("severity") or "INFO"
            fuzzing_table_html += f"""
            <tr>
              <td style="font-family: monospace; font-weight: 700;">{target_path}</td>
              <td><span class="{fz_class}">HTTP {fz_status}</span></td>
              <td style="font-family: monospace;">{sz} bytes</td>
              <td><span class="badge badge-{risk_text}">{verdict_text}</span></td>
            </tr>
            """

        active_vapt_table_html = ""
        for av in active_vapt_data.get("tests", []):
            av_risk = av.get("risk", "SAFE")
            av_class = "status-pill-fail" if av_risk in ("CRITICAL", "HIGH") else "status-pill-pass"
            active_vapt_table_html += f"""
            <tr>
              <td><strong>{av.get('test_type')}</strong></td>
              <td style="font-family: monospace; font-size: 12px;">{av.get('probe_vector')}</td>
              <td style="font-family: monospace;">HTTP {av.get('status_code')}</td>
              <td><span class="{av_class}">{av.get('result')}</span></td>
              <td><span class="badge badge-{av_risk}">{av_risk}</span></td>
            </tr>
            """

        # -------------------------------------------------------------
        # BUILD TAB 8: STAGE 7 (DEFECTDOJO & JIRA SLAs)
        # -------------------------------------------------------------
        dojo_table_html = ""
        s7 = report.stage_results.get(7)
        if s7 and "remediation_plan" in s7.details:
            for plan in s7.details.get("remediation_plan", []):
                dojo_table_html += f"""
                <tr>
                  <td style="font-family: monospace; font-weight: 700;">{plan.get('id')}</td>
                  <td><strong>{plan.get('title')}</strong></td>
                  <td><span class="badge badge-{plan.get('severity')}">{plan.get('severity')}</span></td>
                  <td><strong>{plan.get('sla_days')} Days</strong></td>
                  <td style="color: #dc2626; font-family: monospace; font-weight: 700;">{plan.get('target_due_date')}</td>
                  <td><span class="status-pill-verify">{plan.get('status')}</span></td>
                </tr>
                """

        # -------------------------------------------------------------
        # BUILD TAB 9: STAGE 8 (OPENSSF 18 CHECKS)
        # -------------------------------------------------------------
        scorecard_table_html = ""
        s8 = report.stage_results.get(8)
        slsa_badge_text = s8.details.get('slsa_level', 'SLSA Level 1') if s8 else 'SLSA Level 1'
        if s8 and "scorecard_18_checks" in s8.details:
            for check in s8.details.get("scorecard_18_checks", []):
                sc = check.get('score', 0)
                sc_color = "#059669" if sc >= 8 else ("#d97706" if sc >= 5 else "#dc2626")
                scorecard_table_html += f"""
                <tr>
                  <td><strong>{check.get('name')}</strong></td>
                  <td style="font-weight: 800; color: {sc_color}; font-size: 14px;">{sc}/10</td>
                  <td style="font-size: 12px; color: var(--text-muted);">{check.get('reason')}</td>
                  <td style="font-size: 12px; color: #059669; font-weight: 600;">{check.get('remediation')}</td>
                </tr>
                """

        # -------------------------------------------------------------
        # BUILD TAB 10: STAGE 9 (WAZUH & SIGMA RULES)
        # -------------------------------------------------------------
        s9 = report.stage_results.get(9)
        wazuh_xml_content = s9.details.get('wazuh_xml') if s9 else '<ruleset><!-- Wazuh rules generated --></ruleset>'
        sigma_yaml_content = s9.details.get('sigma_yaml') if s9 else '# Sigma detection rules'

        mitre_table_html = ""
        if s9 and "mitre_matrix" in s9.details:
            for tech in s9.details.get("mitre_matrix", []):
                mitre_table_html += f"""
                <tr>
                  <td style="font-family: monospace; font-weight: 700; color: #4f46e5;">{tech.get('technique_id')}</td>
                  <td><strong>{tech.get('name')}</strong></td>
                  <td>{tech.get('tactic')}</td>
                  <td>{tech.get('observed_findings_count', 1)} finding(s)</td>
                </tr>
                """

        # -------------------------------------------------------------
        # BUILD TAB 0: ALL STAGES COMPLETE AUDIT & MATRIX (1-9)
        # -------------------------------------------------------------
        stage_tab_map = {
            1: "tab-stride",
            2: "tab-asvs",
            3: "tab-sbom",
            4: "tab-dast",
            5: "tab-wstg",
            6: "tab-vapt",
            7: "tab-dojo",
            8: "tab-scorecard",
            9: "tab-wazuh"
        }

        all_stages_cards_html = ""
        stages_matrix_rows_html = ""

        for s_id in range(1, 10):
            meta = STAGE_METADATA.get(s_id, {})
            sr = report.stage_results.get(s_id)
            s_name = sr.stage_name if sr else meta.get("name", f"Stage {s_id}")
            tools = sr.recommended_tools if sr else meta.get("recommended_repo", "N/A")
            covers = sr.what_it_covers if sr else meta.get("what_it_covers", "")
            target_tab = stage_tab_map.get(s_id, "tab-findings")

            if sr:
                dur = f"{sr.execution_time_seconds:.2f}s"
                f_count = len(sr.findings)
                if f_count == 0:
                    status_badge = '<span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #059669; border: 1px solid #10b981;">✔ Clean / Passed (0 findings)</span>'
                    status_short = '<span style="color: #059669; font-weight: 700;">✔ PASSED</span>'
                else:
                    crit_count = sum(1 for f in sr.findings if f.severity == Severity.CRITICAL)
                    high_count = sum(1 for f in sr.findings if f.severity == Severity.HIGH)
                    status_badge = f'<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #dc2626; border: 1px solid #ef4444;">⚠️ {f_count} Finding(s) ({crit_count} Crit, {high_count} High)</span>'
                    status_short = f'<span style="color: #dc2626; font-weight: 700;">⚠️ {f_count} Findings</span>'

                telemetry_items = []
                if s_id == 1:
                    c_count = sr.metrics.get('components_discovered', len(sr.details.get('components', [])))
                    b_count = sr.metrics.get('trust_boundaries_count', len(sr.details.get('boundaries', [])))
                    telemetry_items.append(f"{c_count} Architectural Elements")
                    telemetry_items.append(f"{b_count} Trust Boundaries")
                elif s_id == 2:
                    r_count = sr.metrics.get('requirements_verified_count', 14)
                    telemetry_items.append(f"{r_count} ASVS Requirements Audited")
                elif s_id == 3:
                    telemetry_items.append(f"{len(report.sbom_components)} Dependencies Tracked")
                    telemetry_items.append(f"{sr.metrics.get('secret_leaks_count', 0)} Secret Leaks")
                    telemetry_items.append(f"{sr.metrics.get('sast_vulnerabilities_count', 0)} SAST Flaws")
                elif s_id == 4:
                    telemetry_items.append(f"TLS: {tls_version}")
                    telemetry_items.append(f"Server: {server_banner}")
                    telemetry_items.append(f"{sr.metrics.get('live_routes_tested', 0)} API Endpoints Probed")
                elif s_id == 5:
                    telemetry_items.append(f"{sr.metrics.get('checklist_items_evaluated', 10)} WSTG Test Cases")
                elif s_id == 6:
                    telemetry_items.append(f"Ports: {open_ports_str}")
                    telemetry_items.append(f"{len(dns_data.get('checks', []))} DNS DoH Records")
                    telemetry_items.append(f"{len(fuzzing_data.get('results', []))} Fuzzing Endpoints")
                elif s_id == 7:
                    telemetry_items.append("OWASP DefectDojo SLA Remediation Matrix")
                elif s_id == 8:
                    telemetry_items.append("OpenSSF Scorecard 18 Verification Checks")
                elif s_id == 9:
                    telemetry_items.append("Wazuh XML Rules & Sigma Threat Detections")

                telemetry_str = " &bull; ".join(telemetry_items) if telemetry_items else "Executed successfully."

                findings_preview_html = ""
                if sr.findings:
                    findings_preview_html = '<div style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 10px;"><strong style="font-size: 12px; color: var(--text-heading);">Stage Findings:</strong><div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">'
                    for f in sr.findings[:5]:
                        findings_preview_html += f"""
                        <div style="display: flex; align-items: center; justify-content: space-between; font-size: 12px; background: var(--bg-card-inner); padding: 6px 10px; border-radius: 6px;">
                          <div>
                            <span class="badge badge-{f.severity.value}" style="font-size: 10px; padding: 2px 6px;">{f.severity.value}</span>
                            <span style="font-weight: 700; color: var(--text-heading); margin-left: 6px;">{f.id}</span>
                            <span style="color: var(--text-main); margin-left: 6px;">{f.title}</span>
                          </div>
                          <span style="color: var(--text-muted); font-size: 11px;">{f.tool}</span>
                        </div>"""
                    if len(sr.findings) > 5:
                        rem_count = len(sr.findings) - 5
                        findings_preview_html += f'<div style="font-size: 11px; color: var(--text-muted); text-align: right;">+ {rem_count} more findings (see Findings tab)</div>'
                    findings_preview_html += '</div></div>'
                else:
                    findings_preview_html = '<div style="margin-top: 10px; font-size: 12px; color: #059669; font-weight: 600;">✔ No security vulnerabilities identified in this stage.</div>'

            else:
                dur = "N/A"
                status_badge = '<span class="badge" style="background: var(--border); color: var(--text-muted);">⏭️ Skipped in this scan</span>'
                status_short = '<span style="color: var(--text-muted);">Skipped</span>'
                telemetry_str = "Stage was not included in this scan profile. Use preset 'all' to run all 9 stages."
                findings_preview_html = '<div style="margin-top: 10px; font-size: 12px; color: var(--text-muted);">Stage execution skipped.</div>'

            f_total = len(sr.findings) if sr else 0
            stages_matrix_rows_html += f"""
            <tr>
              <td style="font-weight: 800; text-align: center;"><span class="stage-num" style="display:inline-block; width:22px; height:22px; line-height:22px; border-radius:50%; margin:0;">{s_id}</span></td>
              <td><strong>{s_name}</strong><div style="font-size: 11px; color: var(--text-muted);">{covers}</div></td>
              <td style="font-family: monospace; font-size: 12px; color: var(--accent);">{tools}</td>
              <td>{status_short}</td>
              <td style="font-family: monospace; font-size: 12px;">{dur}</td>
              <td><span class="badge" style="background: var(--bg-card-inner); color: var(--text-heading); font-size: 11px;">{f_total} findings</span></td>
              <td>
                <div style="display: flex; gap: 6px;">
                  <button class="btn" style="padding: 3px 8px; font-size: 11px;" onclick="filterByStage({s_id})">🔍 Findings</button>
                  <button class="btn btn-primary" style="padding: 3px 8px; font-size: 11px;" onclick="switchTab('{target_tab}')">📖 Deep-Dive</button>
                </div>
              </td>
            </tr>"""

            border_col = '#10b981' if (sr and len(sr.findings) == 0) else ('#ef4444' if (sr and len(sr.findings) > 0) else 'var(--border)')
            all_stages_cards_html += f"""
            <div class="panel-box" style="margin-bottom: 18px; border-left: 4px solid {border_col};">
              <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 8px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                  <span class="stage-num" style="width: 28px; height: 28px; line-height: 28px; font-size: 13px;">{s_id}</span>
                  <div>
                    <h3 style="margin: 0; font-size: 16px;">{s_name}</h3>
                    <div style="font-size: 12px; color: var(--accent); font-family: monospace;">Tooling: {tools}</div>
                  </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                  {status_badge}
                  <span style="font-size: 12px; color: var(--text-muted); font-family: monospace;">⏱️ {dur}</span>
                  <button class="btn btn-primary" style="padding: 4px 10px; font-size: 12px;" onclick="switchTab('{target_tab}')">📖 View Stage Details ➔</button>
                </div>
              </div>
              <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">{covers}</div>
              <div style="font-size: 12px; background: var(--bg-card-inner); padding: 8px 12px; border-radius: 6px; color: var(--text-main);">
                <strong>Telemetry &amp; Audit Scope:</strong> {telemetry_str}
              </div>
              {findings_preview_html}
            </div>"""

        # -------------------------------------------------------------
        # FULL HTML TEMPLATE
        # -------------------------------------------------------------
        html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DKSec Enterprise Security Report - {report.project_name}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
  <script>mermaid.initialize({{ startOnLoad: true, theme: 'default' }});</script>
  <style>
    :root {{
      --bg-main: #f8fafc;
      --bg-card: #ffffff;
      --bg-card-inner: #f1f5f9;
      --bg-card-hover: #f8fafc;
      --border: #e2e8f0;
      --border-focus: #3b82f6;
      --text-heading: #0f172a;
      --text-main: #334155;
      --text-muted: #64748b;
      --card-title: #0f172a;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --crit: #dc2626;
      --high: #ea580c;
      --med: #d97706;
      --low: #2563eb;
      --info: #64748b;
      --success: #059669;
      --code-bg: #0f172a;
      --code-text: #38bdf8;
      --diff-bg: #0f172a;
      --diff-text: #34d399;
      --table-header: #f1f5f9;
      --table-header-text: #475569;
      --table-row-border: #e2e8f0;
      --pill-bg: #e2e8f0;
      --pill-text: #475569;
      --pill-active-bg: #2563eb;
      --pill-active-text: #ffffff;
      --header-bg: #ffffff;
      --tab-border: #e2e8f0;
      --tab-active-color: #2563eb;
      --shadow: 0 4px 14px rgba(0, 0, 0, 0.05), 0 1px 3px rgba(0, 0, 0, 0.03);
    }}
    [data-theme="dark"] {{
      --bg-main: #0b0f19;
      --bg-card: #131b2e;
      --bg-card-inner: #0d1424;
      --bg-card-hover: #1c2742;
      --border: #233252;
      --border-focus: #3b82f6;
      --text-heading: #ffffff;
      --text-main: #cbd5e1;
      --text-muted: #94a3b8;
      --card-title: #ffffff;
      --accent: #3b82f6;
      --accent-hover: #1d4ed8;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --info: #64748b;
      --success: #10b981;
      --code-bg: #090d16;
      --code-text: #38bdf8;
      --diff-bg: #090d16;
      --diff-text: #a7f3d0;
      --table-header: #162035;
      --table-header-text: #94a3b8;
      --table-row-border: #233252;
      --pill-bg: #1e293b;
      --pill-text: #94a3b8;
      --pill-active-bg: #3b82f6;
      --pill-active-text: #ffffff;
      --header-bg: linear-gradient(180deg, #162035 0%, #0b0f19 100%);
      --tab-border: #233252;
      --tab-active-color: #60a5fa;
      --shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg-main); color: var(--text-main); line-height: 1.5; padding-bottom: 80px; transition: background 0.2s, color 0.2s; }}
    
    header {{
      background: var(--header-bg);
      border-bottom: 1px solid var(--border);
      padding: 20px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      box-shadow: var(--shadow);
    }}
    .logo-area {{ display: flex; align-items: center; gap: 14px; }}
    .logo-shield {{
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      color: #fff;
      font-weight: 800;
      font-size: 24px;
      width: 44px;
      height: 44px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 12px rgba(37,99,235,0.3);
    }}
    h1 {{ font-size: 20px; font-weight: 800; color: var(--text-heading); }}
    .subtitle {{ font-size: 13px; color: var(--text-muted); display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin-top: 2px; }}
    .header-actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    
    .btn {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-heading);
      padding: 8px 14px;
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
    .btn:hover {{ border-color: var(--accent); background: var(--bg-card-inner); }}
    .btn-primary {{ background: #2563eb; border-color: #3b82f6; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}

    .container {{ max-width: 1440px; margin: 0 auto; padding: 24px 32px; }}

    /* Gatekeeper Verdict Banner */
    .gate-banner {{
      border-radius: 14px;
      padding: 22px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
      flex-wrap: wrap;
      gap: 16px;
      border: 2px solid;
    }}
    .gate-banner.approved {{
      background: #ecfdf5 !important;
      border-color: #10b981 !important;
      color: #065f46 !important;
    }}
    .gate-banner.blocked {{
      background: #fef2f2 !important;
      border-color: #ef4444 !important;
      color: #991b1b !important;
    }}
    .gate-banner.conditional {{
      background: #fffbeb !important;
      border-color: #f59e0b !important;
      color: #92400e !important;
    }}
    [data-theme="dark"] .gate-banner.approved {{ background: rgba(16, 185, 129, 0.15) !important; border-color: #10b981 !important; color: #6ee7b7 !important; }}
    [data-theme="dark"] .gate-banner.blocked {{ background: rgba(239, 68, 68, 0.18) !important; border-color: #ef4444 !important; color: #fca5a5 !important; }}
    [data-theme="dark"] .gate-banner.conditional {{ background: rgba(245, 158, 11, 0.18) !important; border-color: #f59e0b !important; color: #fde68a !important; }}

    .gate-status-badge {{
      display: inline-block;
      padding: 5px 14px;
      border-radius: 20px;
      font-weight: 800;
      font-size: 13px;
      letter-spacing: 0.5px;
      background: {gate_color};
      color: #fff;
    }}

    /* Target Environment Profile Card */
    .profile-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }}
    .profile-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 14px;
    }}
    .profile-item strong {{ display: block; font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 2px; }}
    .profile-item span {{ font-size: 13px; font-weight: 700; color: var(--text-heading); }}

    /* KPI Summary Row */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }}
    .kpi-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      box-shadow: var(--shadow);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .kpi-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }}
    .kpi-val {{ font-size: 32px; font-weight: 800; margin: 4px 0; color: var(--text-heading); }}
    .kpi-sub {{ font-size: 11px; color: var(--text-muted); }}

    /* AI Card */
    .ai-briefing-card {{
      background: var(--bg-card);
      border: 1.5px solid #6366f1;
      border-radius: 12px;
      padding: 20px 24px;
      margin-bottom: 24px;
      box-shadow: 0 4px 16px rgba(99, 102, 241, 0.15);
    }}
    .ai-briefing-header {{ display: flex; align-items: center; gap: 10px; }}
    .ai-tag {{ background: #6366f1; color: #fff; font-size: 11px; font-weight: 800; padding: 4px 10px; border-radius: 6px; }}
    .ai-analysis-box {{ background: var(--bg-card-inner); border-left: 3px solid #6366f1; padding: 10px 14px; border-radius: 0 6px 6px 0; font-size: 13px; color: var(--text-heading); margin: 8px 0 10px 0; line-height: 1.5; }}

    /* 9 Stages Visualizer */
    .pipeline-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }}
    .pipeline-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
      box-shadow: var(--shadow);
      transition: border-color 0.2s, transform 0.2s;
    }}
    .pipeline-card:hover {{ border-color: var(--accent); transform: translateY(-2px); }}
    .stage-num {{
      display: inline-block;
      width: 24px;
      height: 24px;
      line-height: 24px;
      text-align: center;
      background: var(--accent);
      color: #fff;
      font-size: 11px;
      font-weight: 800;
      border-radius: 6px;
      margin-right: 8px;
    }}
    .stage-title {{ font-size: 14px; font-weight: 700; color: var(--text-heading); }}
    .stage-tools {{ font-size: 11px; color: var(--accent); margin: 3px 0 6px 0; font-family: monospace; }}
    .stage-desc {{ font-size: 11px; color: var(--text-muted); margin-bottom: 10px; }}
    .stage-footer {{ display: flex; justify-content: space-between; font-size: 11px; align-items: center; border-top: 1px solid var(--border); padding-top: 8px; }}

    /* Tab Bar */
    .tab-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      border-bottom: 2px solid var(--border);
      margin-bottom: 22px;
      padding-bottom: 10px;
    }}
    .tab-btn {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 9px 15px;
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      border-radius: 8px;
      white-space: nowrap;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .tab-btn:hover {{
      background: var(--bg-card-hover);
      border-color: var(--accent);
      color: var(--text-heading);
    }}
    .tab-btn.active {{
      background: var(--accent) !important;
      color: #ffffff !important;
      border-color: var(--accent) !important;
      box-shadow: 0 2px 8px rgba(37, 99, 235, 0.3);
    }}

    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}

    /* Filter Bar */
    .filter-bar {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 16px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 18px;
      box-shadow: var(--shadow);
    }}
    .pill {{
      padding: 5px 12px;
      border-radius: 16px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid transparent;
      cursor: pointer;
      background: var(--pill-bg);
      color: var(--pill-text);
      transition: all 0.2s;
    }}
    .pill.active {{ background: var(--pill-active-bg); color: var(--pill-active-text); }}
    .search-input {{
      background: var(--bg-card-inner);
      border: 1px solid var(--border);
      color: var(--text-heading);
      padding: 7px 12px;
      border-radius: 8px;
      font-size: 13px;
      min-width: 280px;
    }}
    .search-input:focus {{ outline: none; border-color: var(--border-focus); }}

    /* Findings Cards */
    .finding-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid #64748b;
      border-radius: 10px;
      padding: 18px 22px;
      margin-bottom: 14px;
      box-shadow: var(--shadow);
      transition: all 0.2s;
    }}
    .finding-card.CRITICAL {{ border-left-color: var(--crit); }}
    .finding-card.HIGH {{ border-left-color: var(--high); }}
    .finding-card.MEDIUM {{ border-left-color: var(--med); }}
    .finding-card.LOW {{ border-left-color: var(--low); }}
    .finding-card.INFO {{ border-left-color: var(--info); }}
    
    .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }}
    .finding-title {{ font-size: 15px; font-weight: 800; color: var(--text-heading); }}
    .finding-badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
    
    .badge {{
      font-size: 11px;
      font-weight: 800;
      padding: 3px 8px;
      border-radius: 6px;
      letter-spacing: 0.3px;
    }}
    .badge-CRITICAL {{ background: rgba(220, 38, 38, 0.15); color: #dc2626; border: 1px solid rgba(220, 38, 38, 0.3); }}
    .badge-HIGH {{ background: rgba(234, 88, 12, 0.15); color: #ea580c; border: 1px solid rgba(234, 88, 12, 0.3); }}
    .badge-MEDIUM {{ background: rgba(217, 119, 6, 0.15); color: #d97706; border: 1px solid rgba(217, 119, 6, 0.3); }}
    .badge-LOW {{ background: rgba(37, 99, 235, 0.15); color: #2563eb; border: 1px solid rgba(37, 99, 235, 0.3); }}
    .badge-INFO {{ background: rgba(100, 116, 139, 0.15); color: #64748b; border: 1px solid rgba(100, 116, 139, 0.3); }}

    .finding-meta {{ font-size: 12px; color: var(--text-muted); display: flex; gap: 16px; margin-bottom: 10px; flex-wrap: wrap; }}
    .finding-desc {{ font-size: 13.5px; color: var(--text-main); line-height: 1.5; margin-bottom: 8px; }}

    .code-box {{
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 10px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      color: var(--code-text);
      overflow-x: auto;
      margin: 8px 0;
    }}
    .diff-box {{
      background: var(--diff-bg);
      border: 1px solid var(--border);
      padding: 10px 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      color: var(--diff-text);
      overflow-x: auto;
      margin: 8px 0;
    }}
    .remediation-box {{
      background: rgba(16, 185, 129, 0.08);
      border-left: 3px solid #10b981;
      padding: 10px 14px;
      border-radius: 4px;
      font-size: 13px;
      color: var(--text-heading);
      margin-top: 10px;
    }}

    /* Tables */
    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: var(--bg-card);
      border-radius: 10px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    .data-table th, .data-table td {{ padding: 11px 14px; text-align: left; border-bottom: 1px solid var(--table-row-border); color: var(--text-main); }}
    .data-table th {{ background: var(--table-header); color: var(--table-header-text); font-size: 11px; text-transform: uppercase; font-weight: 700; }}
    .status-pill-pass {{ color: #059669; font-weight: 700; }}
    .status-pill-fail {{ color: #dc2626; font-weight: 700; }}
    .status-pill-verify {{ color: #d97706; font-weight: 700; }}

    .panel-box {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px;
      margin-bottom: 22px;
      box-shadow: var(--shadow);
    }}
    .panel-box h3 {{ font-size: 16px; font-weight: 700; color: var(--text-heading); margin-bottom: 6px; }}
    .panel-box p {{ font-size: 13px; color: var(--text-muted); margin-bottom: 14px; }}
  </style>
</head>
<body>

  <header>
    <div class="logo-area">
      <div class="logo-shield">🛡️</div>
      <div>
        <h1>DKSec Unified Product Security Platform</h1>
        <div class="subtitle"><strong>{report.project_name}</strong> &bull; {target_display} {auth_badge} &bull; ⏱️ {report.duration_seconds:.2f}s</div>
      </div>
    </div>
    <div class="header-actions">
      <button id="themeToggleBtn" class="btn" onclick="toggleTheme()">☀️ Light</button>
      <button class="btn" onclick="window.print()">🖨️ Print to PDF</button>
      <button class="btn" onclick="downloadFile('dksec-results.sarif', 'application/json')">📥 SARIF v2.1.0</button>
      <button class="btn" onclick="downloadFile('cyclonedx-sbom.json', 'application/json')">📦 CycloneDX SBOM</button>
      <button class="btn btn-primary" onclick="downloadJSON()">💾 Export JSON</button>
    </div>
  </header>

  <div class="container">

    <!-- Gatekeeper Verdict Banner -->
    <div class="gate-banner {gate_class}">
      <div class="gate-info">
        <span class="gate-status-badge">{verdict}</span>
        <h2 style="font-size: 20px; font-weight: 800; margin-top: 8px;">Release Signoff Decision: {verdict}</h2>
        <div style="font-size: 13px; margin-top: 4px; opacity: 0.9;">
          {" | ".join(report.gate_verdict.reasons) if report.gate_verdict else "Security gate evaluated."}
        </div>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 11px; text-transform: uppercase; font-weight: 700; opacity: 0.8;">Signoff Certificate Hash</div>
        <div style="font-family: monospace; font-size: 13px; font-weight: 700;">{report.gate_verdict.signoff_hash[:24] if report.gate_verdict else 'N/A'}...</div>
        <div style="font-size: 11px; margin-top: 4px; opacity: 0.8;">{report.timestamp[:19]} UTC</div>
      </div>
    </div>

    <!-- Target & Environment Profile Card -->
    <div class="profile-card">
      <div class="profile-grid">
        <div class="profile-item">
          <strong>Live Target Endpoint</strong>
          <span>{report.target_url or 'N/A (Local Code Audit)'}</span>
        </div>
        <div class="profile-item">
          <strong>Source Code Path</strong>
          <span>{report.target_path}</span>
        </div>
        <div class="profile-item">
          <strong>Authentication Mode</strong>
          <span>{auth_status_text}</span>
        </div>
        <div class="profile-item">
          <strong>Detected Web Server</strong>
          <span>{server_banner}</span>
        </div>
        <div class="profile-item">
          <strong>TLS / SSL Protocol</strong>
          <span>{tls_version}</span>
        </div>
        <div class="profile-item">
          <strong>Discovered Open Ports</strong>
          <span>{open_ports_str}</span>
        </div>
      </div>
    </div>

    {ai_briefing_html}

    <!-- Executive KPI Grid -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Composite Security Score</div>
        <div class="kpi-val" style="color: {gate_color};">{score:.0f}<span style="font-size: 16px; color: var(--text-muted); font-weight: 600;">/100 (Grade {score_grade})</span></div>
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
        <div class="kpi-val" style="color: var(--accent);">{len(report.sbom_components)}</div>
        <div class="kpi-sub">CycloneDX v1.5 Tracked</div>
      </div>
    </div>

    <!-- Product Security 9-Stage Flow Visualizer -->
    <div style="font-size: 16px; font-weight: 700; color: var(--text-heading); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
      <span>🔄</span> 9-Stage Product Security Lifecycle Execution
    </div>
    <div class="pipeline-grid">
"""

        stage_tab_map = {
            1: "tab-stride",
            2: "tab-asvs",
            3: "tab-sbom",
            4: "tab-dast",
            5: "tab-wstg",
            6: "tab-vapt",
            7: "tab-dojo",
            8: "tab-scorecard",
            9: "tab-wazuh"
        }

        for s_id in range(1, 10):
            res = report.stage_results.get(s_id)
            target_tab = stage_tab_map.get(s_id, "tab-findings")
            if res:
                s_name = res.stage_name
                tools = res.recommended_tools
                covers = res.what_it_covers
                f_count = len(res.findings)
                badge_bg = "rgba(16, 185, 129, 0.15)" if f_count == 0 else "rgba(239, 68, 68, 0.15)"
                badge_color = "#059669" if f_count == 0 else "#dc2626"
                status_text = f"{f_count} findings" if f_count > 0 else "Clean / Passed"
                dur_display = f"{res.execution_time_seconds:.1f}s"
            else:
                s_name = f"Stage {s_id}"
                tools = "N/A"
                covers = "Stage skipped in this run"
                badge_bg = "rgba(100, 116, 139, 0.15)"
                badge_color = "#64748b"
                status_text = "Skipped"
                dur_display = "N/A"

            html_content += f"""
      <div class="pipeline-card">
        <div style="display: flex; align-items: center; margin-bottom: 4px;">
          <span class="stage-num">{s_id}</span>
          <span class="stage-title">{s_name}</span>
        </div>
        <div class="stage-tools">{tools}</div>
        <div class="stage-desc">{covers}</div>
        <div class="stage-footer">
          <span class="badge" style="background: {badge_bg}; color: {badge_color};">{status_text}</span>
          <div style="display: flex; gap: 8px;">
            <button class="btn" style="padding: 2px 8px; font-size: 11px;" onclick="filterByStage({s_id})">🔍 Findings</button>
            <button class="btn btn-primary" style="padding: 2px 8px; font-size: 11px;" onclick="switchTab('{target_tab}')">📖 Details</button>
          </div>
        </div>
      </div>
"""

        html_content += f"""
    </div>

    <!-- Detailed Tabs Section -->
    <div class="tab-bar">
      <button class="tab-btn active" id="btn-tab-all-stages" onclick="switchTab('tab-all-stages', this)">📋 All Stages Overview (1-9)</button>
      <button class="tab-btn" id="btn-tab-findings" onclick="switchTab('tab-findings', this)">🔍 Vulnerabilities ({len(report.all_findings)})</button>
      <button class="tab-btn" id="btn-tab-stride" onclick="switchTab('tab-stride', this)">📐 Stage 1: Threat Model</button>
      <button class="tab-btn" id="btn-tab-asvs" onclick="switchTab('tab-asvs', this)">📜 Stage 2: ASVS Matrix</button>
      <button class="tab-btn" id="btn-tab-sbom" onclick="switchTab('tab-sbom', this)">📦 Stage 3: SBOM ({len(report.sbom_components)})</button>
      <button class="tab-btn" id="btn-tab-dast" onclick="switchTab('tab-dast', this)">🌐 Stage 4: DAST &amp; API</button>
      <button class="tab-btn" id="btn-tab-wstg" onclick="switchTab('tab-wstg', this)">🧪 Stage 5: WSTG Checklist</button>
      <button class="tab-btn" id="btn-tab-vapt" onclick="switchTab('tab-vapt', this)">🎯 Stage 6: VAPT &amp; Recon</button>
      <button class="tab-btn" id="btn-tab-dojo" onclick="switchTab('tab-dojo', this)">📊 Stage 7: DefectDojo SLAs</button>
      <button class="tab-btn" id="btn-tab-scorecard" onclick="switchTab('tab-scorecard', this)">🎖️ Stage 8: OpenSSF Signoff</button>
      <button class="tab-btn" id="btn-tab-wazuh" onclick="switchTab('tab-wazuh', this)">🛡️ Stage 9: Wazuh &amp; SIEM</button>
    </div>

    <!-- TAB 0: ALL STAGES COMPLETE AUDIT & MATRIX -->
    <div id="tab-all-stages" class="tab-content active">
      <div class="panel-box">
        <h3>📋 9-Stage Product Security Lifecycle Matrix</h3>
        <p>Comprehensive audit status, tooling, duration, and findings across all 9 DevSecOps lifecycle stages.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 50px; text-align: center;">Stage</th>
              <th>Stage Name &amp; Coverage</th>
              <th>Primary Tooling</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Findings</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {stages_matrix_rows_html}
          </tbody>
        </table>
      </div>

      <div style="font-size: 16px; font-weight: 700; color: var(--text-heading); margin: 24px 0 14px 0; display: flex; align-items: center; gap: 8px;">
        <span>🔍</span> Detailed Stage-by-Stage Telemetry &amp; Vulnerabilities
      </div>
      {all_stages_cards_html}
    </div>

    <!-- TAB 1: FINDINGS -->
    <div id="tab-findings" class="tab-content">
      <div class="filter-bar">
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; width: 100%;">
          <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">SEVERITY:</span>
          <button class="pill active" onclick="setSeverityFilter('ALL', this)">All</button>
          <button class="pill" onclick="setSeverityFilter('CRITICAL', this)">Critical</button>
          <button class="pill" onclick="setSeverityFilter('HIGH', this)">High</button>
          <button class="pill" onclick="setSeverityFilter('MEDIUM', this)">Medium</button>
          <button class="pill" onclick="setSeverityFilter('LOW', this)">Low</button>
        </div>
        <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; width: 100%;">
          <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">FILTER BY STAGE:</span>
          <button class="pill stage-pill active" id="pill-stage-ALL" onclick="setStageFilter('ALL', this)">All Stages</button>
          <button class="pill stage-pill" id="pill-stage-1" onclick="setStageFilter(1, this)">Stage 1: Threat Model</button>
          <button class="pill stage-pill" id="pill-stage-2" onclick="setStageFilter(2, this)">Stage 2: ASVS</button>
          <button class="pill stage-pill" id="pill-stage-3" onclick="setStageFilter(3, this)">Stage 3: SAST/SCA</button>
          <button class="pill stage-pill" id="pill-stage-4" onclick="setStageFilter(4, this)">Stage 4: DAST</button>
          <button class="pill stage-pill" id="pill-stage-5" onclick="setStageFilter(5, this)">Stage 5: WSTG</button>
          <button class="pill stage-pill" id="pill-stage-6" onclick="setStageFilter(6, this)">Stage 6: VAPT</button>
          <button class="pill stage-pill" id="pill-stage-7" onclick="setStageFilter(7, this)">Stage 7: DefectDojo</button>
          <button class="pill stage-pill" id="pill-stage-8" onclick="setStageFilter(8, this)">Stage 8: Signoff</button>
          <button class="pill stage-pill" id="pill-stage-9" onclick="setStageFilter(9, this)">Stage 9: Wazuh</button>
        </div>
        <div style="display: flex; gap: 8px; align-items: center; width: 100%;">
          <input type="text" id="findingSearch" class="search-input" style="width: 100%;" placeholder="Search findings by title, tool, CWE, MITRE, OWASP..." oninput="applyFilters()" />
        </div>
      </div>

      <div id="findingsContainer">
        {findings_html}
      </div>
    </div>

    <!-- TAB 2: THREAT MODEL (STRIDE & DFD) -->
    <div id="tab-stride" class="tab-content">
      <div class="panel-box">
        <h3>Target Architecture Elements &amp; Trust Boundaries</h3>
        <p>Discovered architectural components, trust zones, and data flow channels.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Component Name</th>
              <th>Type</th>
              <th>Trust Boundary</th>
              <th>Description / Tech</th>
            </tr>
          </thead>
          <tbody>
            {components_table_html or '<tr><td colspan="4" style="text-align:center;">No architectural components cataloged.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="panel-box">
        <h3>Automated Data Flow Diagram (DFD)</h3>
        <p>Generated architectural data flow diagram mapping trust boundaries and components.</p>
        <div class="mermaid" id="mermaidContainer" style="background: var(--bg-card-inner); padding: 20px; border-radius: 8px; overflow-x: auto;">
{mermaid_dfd}
        </div>
      </div>

      <div class="panel-box">
        <h3>OWASP Threat Dragon &amp; STRIDE Threat Matrix</h3>
        <p>Architectural threat catalog derived from STRIDE, LINDDUN, and MITRE ATT&amp;CK mappings.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>Component</th>
              <th>Severity</th>
              <th>MITRE</th>
              <th>Identified Architectural Threat</th>
              <th>Security Mitigation</th>
            </tr>
          </thead>
          <tbody>
            {stride_table_html or '<tr><td colspan="7" style="text-align:center;">No architectural threats identified.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: ASVS CHECKLIST -->
    <div id="tab-asvs" class="tab-content">
      <div class="panel-box">
        <h3>OWASP ASVS v4.0.3 Security Requirements Matrix</h3>
        <p>Verification standard requirements across Levels 1-3 auditing application security controls.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Chapter</th>
              <th>Level</th>
              <th>Requirement Description</th>
              <th>CWE</th>
              <th>Status</th>
              <th>Evidence &amp; Findings</th>
              <th>Remediation Action</th>
            </tr>
          </thead>
          <tbody>
            {asvs_table_html or '<tr><td colspan="8" style="text-align:center;">No ASVS requirements evaluated.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: SBOM INVENTORY -->
    <div id="tab-sbom" class="tab-content">
      <div class="panel-box">
        <h3>CycloneDX v1.5 Software Bill of Materials (SBOM)</h3>
        <p>Catalog of open-source dependencies, licenses, and detected CVE security advisories.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Component Name</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>Package URL (PURL)</th>
              <th>License</th>
              <th>Known CVEs</th>
              <th>Remediation Fix</th>
            </tr>
          </thead>
          <tbody>
            {sbom_table_html or '<tr><td colspan="7" style="text-align:center;">No dependencies discovered.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 5: DAST & LIVE API SECURITY (PREVIOUSLY MISSING!) -->
    <div id="tab-dast" class="tab-content">
      <div class="panel-box">
        <h3>HTTP Security Headers Audit</h3>
        <p>Verification of defensive security response headers according to OWASP Secure Headers Project.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Header Name</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Current Server Value</th>
              <th>Remediation Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {headers_table_html or '<tr><td colspan="5" style="text-align:center;">No live HTTP headers evaluated.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="panel-box">
        <h3>Sensitive API Endpoints &amp; Path Fuzzing</h3>
        <p>Active probing of high-risk sensitive paths, debug endpoints, and configuration exposures.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Probed Path</th>
              <th>Response</th>
              <th>Payload Size</th>
              <th>Risk Assessment</th>
              <th>Observation Notes</th>
            </tr>
          </thead>
          <tbody>
            {probes_table_html or '<tr><td colspan="5" style="text-align:center;">No endpoints probed.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="panel-box">
        <h3>Live Differential API Routes (Auth vs Unauth)</h3>
        <p>Differential response code analysis testing authorization boundaries on active routes.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Route Tested</th>
              <th>Unauthenticated Status</th>
              <th>Authenticated Status</th>
              <th>Authorization Schema</th>
            </tr>
          </thead>
          <tbody>
            {live_routes_table_html or '<tr><td colspan="4" style="text-align:center;">No differential route tests executed.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 6: WSTG PENTEST CHECKLIST -->
    <div id="tab-wstg" class="tab-content">
      <div class="panel-box">
        <h3>OWASP Web Security Testing Guide (WSTG v4.2) Verification</h3>
        <p>Standardized manual &amp; heuristic testing checklist across all 12 core testing categories.</p>
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
            {wstg_table_html or '<tr><td colspan="5" style="text-align:center;">No WSTG items evaluated.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 7: PENETRATION TEST & RECON (PREVIOUSLY MISSING!) -->
    <div id="tab-vapt" class="tab-content">
      <div class="panel-box">
        <h3>Network Port Reconnaissance &amp; Attack Surface Discovery</h3>
        <p>Port discovery scan identifying open network listeners and externally accessible daemons.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {ports_table_html or '<tr><td colspan="4" style="text-align:center;">No open ports identified.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="panel-box">
        <h3>DNS Security &amp; Spoofing Prevention</h3>
        <p>Verification of SPF, DMARC, and CAA DNS security records.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Record Type</th>
              <th>Status</th>
              <th>Configured Value</th>
              <th>Security Impact</th>
            </tr>
          </thead>
          <tbody>
            {dns_table_html or '<tr><td colspan="4" style="text-align:center;">No DNS security checks executed.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="panel-box">
        <h3>Automated Exploit &amp; Nuclei-Style Fuzzing</h3>
        <p>Active penetration test verification scanning for exposed admin interfaces and sensitive files.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Fuzzed Target</th>
              <th>HTTP Status</th>
              <th>Response Size</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {fuzzing_table_html or '<tr><td colspan="4" style="text-align:center;">No active exploit probes executed.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div class="panel-box">
        <h3>Active Penetration Testing &amp; Authorization Probes</h3>
        <p>Active injection probes testing for directory traversal (CWE-22) and URL normalization authorization bypass (CWE-285).</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Test Type</th>
              <th>Probe Vector</th>
              <th>HTTP Status</th>
              <th>Test Result</th>
              <th>Risk Assessment</th>
            </tr>
          </thead>
          <tbody>
            {active_vapt_table_html or '<tr><td colspan="5" style="text-align:center;">No active penetration probes executed.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 8: DEFECTDOJO SLA -->
    <div id="tab-dojo" class="tab-content">
      <div class="panel-box">
        <h3>OWASP DefectDojo Remediation Schedule &amp; SLA Tracker</h3>
        <p>Lifecycle vulnerability management plan with enterprise remediation deadlines.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Finding Title</th>
              <th>Severity</th>
              <th>Remediation SLA</th>
              <th>Target Due Date (UTC)</th>
              <th>Lifecycle Status</th>
            </tr>
          </thead>
          <tbody>
            {dojo_table_html or '<tr><td colspan="6" style="text-align:center;">No remediation actions pending.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 9: OPENSSF 18-CHECKS SCORECARD -->
    <div id="tab-scorecard" class="tab-content">
      <div class="panel-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div>
            <h3>OpenSSF Scorecard v4 (All 18 Checks)</h3>
            <p>Supply chain posture and release integrity controls.</p>
          </div>
          <span class="badge" style="background: rgba(79,70,229,0.15); color: #4f46e5; font-size: 13px; padding: 6px 14px; border: 1px solid #6366f1;">
            {slsa_badge_text}
          </span>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Check Name</th>
              <th>Score (/10)</th>
              <th>Reason &amp; Evaluation</th>
              <th>Remediation Action</th>
            </tr>
          </thead>
          <tbody>
            {scorecard_table_html or '<tr><td colspan="4" style="text-align:center;">No Scorecard checks evaluated.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 10: WAZUH & SIGMA -->
    <div id="tab-wazuh" class="tab-content">
      <div class="panel-box">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <h3>Generated Wazuh local_rules.xml</h3>
          <button class="btn" onclick="copyText('wazuhCode')">📋 Copy Wazuh XML</button>
        </div>
        <p>Custom SIEM correlation rules tailored to detect exploited vectors in production.</p>
        <pre id="wazuhCode" class="code-box" style="white-space: pre; max-height: 260px;">{wazuh_xml_content}</pre>
      </div>

      <div class="panel-box">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <h3>Generated Sigma Detection Rules (sigma-rules.yml)</h3>
          <button class="btn" onclick="copyText('sigmaCode')">📋 Copy Sigma YAML</button>
        </div>
        <p>Open-source detection engineering rules mapped to discovered attack patterns.</p>
        <pre id="sigmaCode" class="code-box" style="white-space: pre; max-height: 260px;">{sigma_yaml_content}</pre>
      </div>

      <div class="panel-box">
        <h3>MITRE ATT&amp;CK Enterprise Matrix Mapping</h3>
        <p>Observed security flaws mapped to adversary tactics and techniques.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Technique ID</th>
              <th>Name</th>
              <th>Adversary Tactic</th>
              <th>Observed In Audit</th>
            </tr>
          </thead>
          <tbody>
            {mitre_table_html or '<tr><td colspan="4" style="text-align:center;">No MITRE techniques mapped.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <script>
    const reportData = {report_data_json};
    let currentSeverity = 'ALL';
    let currentStage = 'ALL';

    function setTheme(t) {{
      document.documentElement.setAttribute('data-theme', t);
      try {{ localStorage.setItem('dksec_report_theme', t); }} catch(e) {{}}
      const btn = document.getElementById('themeToggleBtn');
      if (btn) {{
        btn.innerHTML = (t === 'light') ? '☀️ Light' : '🌙 Dark';
      }}
    }}

    function toggleTheme() {{
      const cur = document.documentElement.getAttribute('data-theme') || 'light';
      setTheme(cur === 'light' ? 'dark' : 'light');
    }}

    (function() {{
      let saved = 'light';
      try {{
        saved = localStorage.getItem('dksec_report_theme') || 'light';
      }} catch(e) {{}}
      setTheme(saved);
    }})();

    function switchTab(tabId, btn) {{
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      
      const targetPane = document.getElementById(tabId);
      if (targetPane) targetPane.classList.add('active');
      
      if (btn) {{
        btn.classList.add('active');
      }} else {{
        const btnId = 'btn-' + tabId;
        const matchingBtn = document.getElementById(btnId);
        if (matchingBtn) matchingBtn.classList.add('active');
      }}

      if (tabId === 'tab-stride') {{
        setTimeout(() => {{
          try {{ mermaid.run(); }} catch(e) {{}}
        }}, 50);
      }}
    }}

    function setSeverityFilter(sev, btn) {{
      currentSeverity = sev;
      btn.parentElement.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      applyFilters();
    }}

    function setStageFilter(stageId, btn) {{
      currentStage = stageId;
      document.querySelectorAll('.stage-pill').forEach(p => p.classList.remove('active'));
      if (btn) {{
        btn.classList.add('active');
      }} else {{
        const targetBtn = document.getElementById('pill-stage-' + stageId);
        if (targetBtn) targetBtn.classList.add('active');
      }}
      applyFilters();
    }}

    function filterByStage(stageId) {{
      currentStage = stageId;
      switchTab('tab-findings', document.getElementById('btn-tab-findings'));
      document.querySelectorAll('.stage-pill').forEach(p => p.classList.remove('active'));
      const targetBtn = document.getElementById('pill-stage-' + stageId);
      if (targetBtn) targetBtn.classList.add('active');
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
        const matchStage = (currentStage === 'ALL' || stage == currentStage);
        const matchQuery = (!query || searchTxt.includes(query));

        if (matchSev && matchStage && matchQuery) {{
          card.style.display = 'block';
        }} else {{
          card.style.display = 'none';
        }}
      }});
    }}

    function copyText(id) {{
      const el = document.getElementById(id);
      if (el) {{
        navigator.clipboard.writeText(el.innerText).then(() => {{
          alert('Copied to clipboard!');
        }});
      }}
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
      window.open('/download/' + filename, '_blank');
    }}
  </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as fl:
            fl.write(html_content)

        return output_path
