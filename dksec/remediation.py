"""
Automated Remediation & Git Diff Patch Generator for DKSec.
Generates unified git diff patches and actionable configuration fixes
for SAST, DAST, SCA, and infrastructure security findings.
"""

import os
import re
from typing import Optional, List
from dksec.models import Finding, Severity


def generate_remediation_patch(finding: Finding, target_path: Optional[str] = None) -> Optional[str]:
    """
    Generates a unified diff patch for a given finding based on vulnerability pattern,
    CWE category, and context.
    """
    if finding.remediation_diff:
        return finding.remediation_diff

    title_lower = finding.title.lower()
    cwe = finding.cwe or ""
    tool_lower = (finding.tool or "").lower()

    # 1. SAST Code-level Patches (if file_path exists)
    if finding.file_path and finding.code_snippet:
        snippet = finding.code_snippet.strip()
        fpath = finding.file_path

        # SQL Injection
        if "sql" in title_lower or cwe == "CWE-89":
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    # [DKSec Auto-Remediation: Parameterized query enforcement]
+    cursor.execute("SELECT * FROM items WHERE id = %s", [item_id])"""

        # Pickle / Deserialization
        if "pickle" in title_lower or "deserial" in title_lower or cwe == "CWE-502":
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    # [DKSec Auto-Remediation: Secure JSON serialization]
+    import json
+    data = json.loads(untrusted_payload)"""

        # subprocess shell=True
        if "shell=true" in title_lower or "subprocess" in title_lower or cwe == "CWE-78":
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    # [DKSec Auto-Remediation: Disable shell=True and pass argument list]
+    subprocess.run(["safe_command", arg1, arg2], shell=False, check=True)"""

        # Prototype Pollution
        if "prototype" in title_lower or cwe == "CWE-1321":
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    // [DKSec Auto-Remediation: Prototype pollution guard]
+    const safeDict = Object.create(null);
+    Object.freeze(Object.prototype);"""

        # DOM XSS (innerHTML)
        if "innerhtml" in title_lower or "xss" in title_lower or cwe == "CWE-79":
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    // [DKSec Auto-Remediation: Safe DOM text assignment]
+    element.textContent = userSuppliedInput;"""

        # YAML load
        if "yaml" in title_lower or "safe_load" in title_lower:
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    # [DKSec Auto-Remediation: Safe YAML parser]
+    data = yaml.safe_load(yaml_content)"""

        # Debug Mode
        if "debug mode" in title_lower or cwe == "CWE-489":
            return f"""--- a/{fpath}
+++ b/{fpath}
@@ -{finding.line_number or 10},3 +{finding.line_number or 10},3 @@
-    {snippet}
+    # [DKSec Auto-Remediation: Disable production debug mode]
+    app.run(debug=False, host="0.0.0.0")"""

    # 2. DAST & Infrastructure Configuration Patches
    # OpenAPI / Swagger Exposure
    if "openapi" in title_lower or "swagger" in title_lower or "api-spec" in (finding.id or "").lower():
        return """--- a/urls.py
+++ b/urls.py
@@ -14,4 +14,6 @@
+from django.contrib.admin.views.decorators import staff_member_required
+
-# Publicly exposed Swagger documentation
-path('api/docs/', schema_view.with_ui('swagger', cache_timeout=0)),
+# [DKSec Auto-Remediation: Enforce authentication on API schema]
+path('api/docs/', staff_member_required(schema_view.with_ui('swagger', cache_timeout=0))),"""

    # Missing Security Headers (HSTS, CSP, X-Frame-Options)
    if "header" in title_lower or "hsts" in title_lower or "csp" in title_lower or "frame-options" in title_lower:
        return """--- a/nginx.conf
+++ b/nginx.conf
@@ -25,4 +25,9 @@
     server_name example.com;
 
+    # [DKSec Auto-Remediation: Hardened HTTP Security Headers]
+    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
+    add_header X-Frame-Options "DENY" always;
+    add_header X-Content-Type-Options "nosniff" always;
+    add_header Content-Security-Policy "default-src 'self';" always;
+    add_header Referrer-Policy "strict-origin-when-cross-origin" always;"""

    # OIDC PKCE Enforcement
    if "pkce" in title_lower or "oidc" in title_lower:
        return """--- a/settings.py
+++ b/settings.py
@@ -40,3 +40,5 @@
 # [DKSec Auto-Remediation: Mandatory PKCE enforcement]
 OAUTH2_PROVIDER = {
+    'PKCE_REQUIRED': True,
+    'CODE_CHALLENGE_METHODS': ['S256'],
 }"""

    # DNS CAA Records
    if "caa" in title_lower:
        return """--- a/domain_zonefile.dns
+++ b/domain_zonefile.dns
@@ -10,1 +10,3 @@
+; [DKSec Auto-Remediation: Restrict Certificate Authorities via CAA]
+@    IN    CAA    0 issue "pki.goog"
+@    IN    CAA    0 issue "letsencrypt.org""""

    # Server Banner Exposure
    if "banner" in title_lower or "server" in title_lower:
        return """--- a/nginx.conf
+++ b/nginx.conf
@@ -12,2 +12,3 @@
 http {
+    # [DKSec Auto-Remediation: Suppress web server banner version]
+    server_tokens off;"""

    # Cookie SameSite / Secure Flags
    if "cookie" in title_lower or "samesite" in title_lower:
        return """--- a/settings.py
+++ b/settings.py
@@ -50,3 +50,5 @@
+# [DKSec Auto-Remediation: Hardened cookie flags]
+SESSION_COOKIE_SECURE = True
+SESSION_COOKIE_HTTPONLY = True
+SESSION_COOKIE_SAMESITE = 'Lax'
+CSRF_COOKIE_SECURE = True"""

    return None


def enrich_findings_with_patches(findings: List[Finding], target_path: Optional[str] = None) -> None:
    """Enriches each finding with a concrete remediation diff patch if not already present."""
    for f in findings:
        if not f.remediation_diff:
            patch = generate_remediation_patch(f, target_path)
            if patch:
                f.remediation_diff = patch
