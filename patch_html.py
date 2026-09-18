import sys

with open("dksec/reporters/html_reporter.py", "r") as f:
    content = f.read()

poc_logic = """
            code_box_html = f'<div class="code-box"><div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Matched Code / Evidence:</div><pre style="margin: 0; white-space: pre-wrap;">{f.code_snippet}</pre></div>' if f.code_snippet else ''
            
            poc_html = ""
            if f.curl_command or f.raw_request or f.raw_response:
                poc_html = f'<div class="poc-box" style="margin-top: 12px; background: var(--bg-card-inner); border: 1px dashed var(--border-focus); border-radius: 8px; padding: 12px;">'
                poc_html += f'<div style="font-weight: 700; font-size: 13px; color: var(--text-heading); margin-bottom: 8px;">Interactive Proof-of-Concept (PoC)</div>'
                if f.curl_command:
                    poc_html += f'<div style="margin-bottom: 10px;"><div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">cURL Command:</div><pre style="margin: 0; white-space: pre-wrap; font-family: monospace; background: var(--code-bg); color: #facc15; padding: 8px; border-radius: 6px; font-size: 11px;">{f.curl_command}</pre></div>'
                if f.raw_request:
                    poc_html += f'<div style="margin-bottom: 10px;"><div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Raw HTTP Request:</div><pre style="margin: 0; white-space: pre-wrap; font-family: monospace; background: var(--code-bg); color: var(--code-text); padding: 8px; border-radius: 6px; font-size: 11px;">{f.raw_request}</pre></div>'
                if f.raw_response:
                    poc_html += f'<div><div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Raw HTTP Response:</div><pre style="margin: 0; white-space: pre-wrap; font-family: monospace; background: var(--code-bg); color: #34d399; padding: 8px; border-radius: 6px; max-height: 200px; overflow-y: auto; font-size: 11px;">{f.raw_response}</pre></div>'
                poc_html += '</div>'
            
            diff_box_html = f'<div class="diff-box"><strong>Proposed Patch (Unified Diff):</strong><pre style="margin: 4px 0 0 0; white-space: pre-wrap;">{f.remediation_diff}</pre></div>' if f.remediation_diff else ''
            remediation_html = f'<div class="remediation-box"><strong>💡 Remediation Guidance:</strong> {f.remediation}</div>' if f.remediation else ''
"""

content = content.replace(
    """            code_box_html = f'<div class="code-box"><div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Matched Code / Evidence:</div><pre style="margin: 0; white-space: pre-wrap;">{f.code_snippet}</pre></div>' if f.code_snippet else ''
            diff_box_html = f'<div class="diff-box"><strong>Proposed Patch (Unified Diff):</strong><pre style="margin: 4px 0 0 0; white-space: pre-wrap;">{f.remediation_diff}</pre></div>' if f.remediation_diff else ''
            remediation_html = f'<div class="remediation-box"><strong>💡 Remediation Guidance:</strong> {f.remediation}</div>' if f.remediation else ''""",
    poc_logic
)

content = content.replace(
    """          {diff_box_html}
          {remediation_html}
          {refs_html}""",
    """          {diff_box_html}
          {remediation_html}
          {poc_html}
          {refs_html}"""
)

with open("dksec/reporters/html_reporter.py", "w") as f:
    f.write(content)
