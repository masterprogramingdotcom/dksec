"""
Stage 3: SAST + SCA + Secret Scanning (Advanced Enterprise Edition)
Recommended Repos: Semgrep + Trivy + Gitleaks
What it covers: Source-code analysis (AST-powered), dependency/container scanning (CycloneDX SBOM), secrets
"""

import os
import re
import json
import ast
import math
from typing import List, Dict, Any, Tuple, Optional
from dksec.stages.base import BaseStage
from dksec.models import Finding, Severity, FindingStatus, SBOMComponent
from dksec.config import DKSecConfig
from dksec.multi_tech_scanner import _is_version_vulnerable



class Stage3SastScaSecrets(BaseStage):
    def __init__(self):
        super().__init__(3)

    def run(self, config: DKSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        target = config.target_path
        if target:
            from dksec.config import resolve_target_path
            resolved = resolve_target_path(target)
            if resolved and os.path.exists(resolved):
                target = resolved
                config.target_path = resolved

        exists = bool(target and os.path.exists(str(target)))

        if not exists:
            if config.target_url and not target:
                self.log(f"URL-only mode — no source code path provided. Skipping SAST/SCA/Secrets; use -t <dir> to enable code scanning.")
                return [], {
                    "tools_used": ["Skipped (no source code target)"],
                    "secret_leaks_count": 0,
                    "sast_vulnerabilities_count": 0,
                    "sca_vulnerabilities_count": 0,
                    "total_dependencies_inventoried": 0,
                    "total_stage_findings": 0,
                    "note": "Pass -t <path> or set target_path in dksec.yml to enable SAST/SCA/Secret scanning."
                }, {
                    "secrets": 0,
                    "sast": 0,
                    "sca": 0,
                    "sbom_summary": "No source code provided — SAST/SCA skipped (URL-only mode)",
                    "components": [],
                    "note": "To enable: dksec scan -u <url> -t <source_dir>"
                }
            else:
                self.log(f"[ERROR] Source code target not found at '{target}'. Cannot perform SAST/SCA/Secrets scan.")
                err_finding = self.create_finding(
                    finding_id="DKSEC-PATH-404",
                    title=f"Source Code Target Directory Not Found: '{target}'",
                    severity=Severity.HIGH,
                    description=f"The specified target repository directory '{target}' does not exist on the filesystem. No code was analyzed.",
                    tool="DKSec Validator",
                    remediation=f"Verify that the directory '{target}' exists and provide an absolute path or relative path from the current workspace.",
                    status=FindingStatus.OPEN,
                    file_path=str(target) if target else "target_path",
                    line_number=0
                )
                return [err_finding], {
                    "tools_used": ["Target Not Found"],
                    "secret_leaks_count": 0,
                    "sast_vulnerabilities_count": 0,
                    "sca_vulnerabilities_count": 0,
                    "total_dependencies_inventoried": 0,
                    "total_stage_findings": 1,
                    "error": f"Target path '{target}' not found on filesystem."
                }, {
                    "secrets": 0,
                    "sast": 0,
                    "sca": 0,
                    "sbom_summary": f"Directory '{target}' not found on filesystem",
                    "components": [],
                    "note": f"Directory '{target}' not found. Please provide an existing directory path."
                }

        self.log(f"Starting Multi-Layer Code Security Audit on: {target}")

        findings: List[Finding] = []
        tools_executed = []

        # 1. Secret Scanning (Gitleaks native or high-entropy built-in)
        secret_findings = self._run_secret_scanner(target)
        findings.extend(secret_findings)
        tools_executed.append("Gitleaks" if self.is_tool_installed("gitleaks") else "Gitleaks (Engine)")

        # 2. SAST Scanning (Semgrep native or Python AST + Multi-Lang Engine)
        sast_findings = self._run_sast_scanner(target)
        findings.extend(sast_findings)
        tools_executed.append("Semgrep" if self.is_tool_installed("semgrep") else "Semgrep AST Engine")

        # 3. SCA Dependency Scanning & SBOM Component Inventory (Trivy native or OSV/CycloneDX Engine)
        sca_findings, sbom_components = self._run_sca_scanner(target)
        findings.extend(sca_findings)
        tools_executed.append("Trivy" if self.is_tool_installed("trivy") else "Trivy / CycloneDX Engine")

        # 4. Supply Chain Risk Analysis (typosquatting, dependency confusion)
        supply_chain_findings = self._scan_for_supply_chain_risks(target)
        findings.extend(supply_chain_findings)

        # 5. Universal Multi-Technology Security Scanning (All Tech Stacks)
        from dksec.multi_tech_scanner import UniversalMultiTechScanner
        tech_scanner = UniversalMultiTechScanner(self)
        tech_findings, tech_components, tech_summary = tech_scanner.scan_all(target)

        # Merge findings with improved deduplication (CVE-aware)
        def _make_dedup_key(f_obj):
            t = f_obj.title.strip().lower()
            if "cve-" in t:
                cve_m = re.search(r'cve-\d{4}-\d+', t)
                pkg_m = re.search(r'dependency:\s*([^@]+)@', t)
                cve_id = cve_m.group(0) if cve_m else t
                pkg_id = pkg_m.group(1).strip() if pkg_m else (f_obj.file_path or "")
                return f"CVE:{cve_id}|pkg:{pkg_id}"
            return f"{t}|{f_obj.cwe}|{f_obj.file_path or ''}|{f_obj.line_number}"

        seen_keys = {_make_dedup_key(f) for f in findings}
        for tf in tech_findings:
            key = _make_dedup_key(tf)
            if key not in seen_keys:
                findings.append(tf)
                seen_keys.add(key)

        # Merge SBOM components
        seen_purls = {c.purl for c in sbom_components}
        for tc in tech_components:
            if tc.purl not in seen_purls:
                sbom_components.append(tc)
                seen_purls.add(tc.purl)

        tools_executed.append("DKSec Universal Multi-Tech Engine")

        # Pass SBOM and Tech Profile to context for reporter
        context["sbom_components"] = sbom_components
        context["tech_profile"] = tech_summary.get("tech_profile", {})

        # Calculate rich metrics
        sec_cnt = sum(1 for f in findings if f.tool in ("Gitleaks", "Gitleaks (Engine)", "DKSec Deep Secret Scanner") or "Secret" in f.title)
        sast_cnt = sum(1 for f in findings if "SAST" in f.id or "DKSec Universal SAST Engine" in f.tool or "Semgrep" in f.tool)
        sca_cnt = sum(1 for f in findings if "SCA" in f.id or "Dependency" in f.title)

        metrics = {
            "tools_used": tools_executed,
            "secret_leaks_count": max(sec_cnt, len(secret_findings)),
            "sast_vulnerabilities_count": max(sast_cnt, len(sast_findings)),
            "sca_vulnerabilities_count": max(sca_cnt, len(sca_findings)),
            "supply_chain_risks": len(supply_chain_findings),
            "total_dependencies_inventoried": len(sbom_components),
            "total_stage_findings": len(findings),
            "tech_profile": tech_summary.get("tech_profile", {})
        }

        details = {
            "secrets": metrics["secret_leaks_count"],
            "sast": metrics["sast_vulnerabilities_count"],
            "sca": metrics["sca_vulnerabilities_count"],
            "supply_chain": len(supply_chain_findings),
            "sbom_summary": f"Cataloged {len(sbom_components)} packages for CycloneDX SBOM across all ecosystems",
            "components": [c.to_cyclonedx() for c in sbom_components],
            "tech_profile": tech_summary.get("tech_profile", {})
        }

        return findings, metrics, details


    # =========================================================================
    # 1. SECRET SCANNING (Gitleaks + Shannon Entropy)
    # =========================================================================
    def _run_secret_scanner(self, target: str) -> List[Finding]:
        if self.is_tool_installed("gitleaks"):
            self.log("Invoking native Gitleaks binary...")
            cmd = ["gitleaks", "detect", "--source", target, "--no-git", "--report-format", "json"]
            code, stdout, stderr = self.execute_command(cmd)
            if stdout:
                try:
                    data = json.loads(stdout)
                    native_findings = []
                    for item in data:
                        f = self.create_finding(
                            finding_id=f"SEC-{len(native_findings)+1:03d}",
                            title=f"Hardcoded Secret: {item.get('RuleID', 'Secret Leak')}",
                            severity=Severity.CRITICAL,
                            description=f"Secret exposed in file {item.get('File')}: {item.get('Description')}",
                            tool="Gitleaks",
                            file_path=item.get("File"),
                            line_number=item.get("StartLine"),
                            code_snippet=item.get("Match"),
                            cwe="CWE-798",
                            owasp="OWASP A07:2021-Identification and Authentication Failures",
                            remediation="Revoke secret immediately, rotate credentials, and scrub file history.",
                            status=FindingStatus.OPEN,
                            references=["https://github.com/gitleaks/gitleaks"]
                        )
                        f.mitre_attack = "T1552"
                        native_findings.append(f)
                    return native_findings
                except Exception:
                    pass

        self.log("Executing High-Entropy Pattern Secret Scanner...")
        patterns = [
            ("AWS Access Key ID", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", Severity.CRITICAL, "CWE-798", "T1552"),
            ("AWS Secret Access Key", r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*=\s*['"]?[a-zA-Z0-9\/+=]{40}['"]?""", Severity.CRITICAL, "CWE-798", "T1552"),
            ("GitHub Personal Access Token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[a-zA-Z0-9_]{82}", Severity.CRITICAL, "CWE-798", "T1552"),
            ("Private Cryptographic Key", r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----", Severity.CRITICAL, "CWE-321", "T1552"),
            ("Slack API Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", Severity.HIGH, "CWE-798", "T1552"),
            ("Stripe Secret API Key", r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34}", Severity.CRITICAL, "CWE-798", "T1552"),

            ("Database URI with Plaintext Password", r"(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9_\-\.]+", Severity.CRITICAL, "CWE-256", "T1552"),
            ("Generic API Secret Assignment", r"""(?:api_secret|client_secret|db_pass|auth_secret)\s*[:=]\s*['"][a-zA-Z0-9!@#$%^&*()_+=-]{12,64}['"]""", Severity.HIGH, "CWE-798", "T1552"),
        ]

        findings = []
        if not os.path.exists(target):
            return findings

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv", "__pycache__"]]
            for fname in files:
                fpath = os.path.join(root, fname)
                if os.path.getsize(fpath) > 1024 * 1024:
                    continue
                rel_path = os.path.relpath(fpath, target)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fl:
                        lines = fl.readlines()
                    for line_no, line in enumerate(lines, 1):
                        for title, pat, sev, cwe, mitre in patterns:
                            match = re.search(pat, line)
                            if match:
                                val = match.group(0)
                                masked = val[:4] + "*" * max(0, len(val) - 8) + val[-4:] if len(val) > 8 else "***"
                                snippet = line.strip().replace(val, masked)
                                f_obj = self.create_finding(
                                    finding_id=f"SEC-{len(findings)+1:03d}",
                                    title=f"Hardcoded Secret: {title}",
                                    severity=sev,
                                    description=f"Potential high-entropy secret ({title}) discovered in {rel_path}:{line_no}.",
                                    tool="Gitleaks (Engine)",
                                    file_path=rel_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    cwe=cwe,
                                    owasp="OWASP A07:2021-Identification and Authentication Failures",
                                    remediation="Extract credential into an environment variable or secrets vault (e.g. AWS Secrets Manager, HashiCorp Vault). Revoke currently exposed secret.",
                                    status=FindingStatus.OPEN,
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]
                                )
                                f_obj.mitre_attack = mitre
                                findings.append(f_obj)
                except Exception:
                    pass
        return findings

    # =========================================================================
    # 2. SAST SCANNING (Semgrep + Python AST Analysis)
    # =========================================================================
    def _run_sast_scanner(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(target):
            return findings

        # Run Semgrep CLI if installed
        if self.is_tool_installed("semgrep"):
            self.log("Invoking native Semgrep static analyzer...")
            cmd = ["semgrep", "scan", "--json", "--quiet", target]
            code, stdout, stderr = self.execute_command(cmd, timeout=120)
            if stdout:
                try:
                    data = json.loads(stdout)
                    for item in data.get("results", []):
                        f = self.create_finding(
                            finding_id=f"SAST-NATIVE-{len(findings)+1:03d}",
                            title=f"Semgrep: {item.get('check_id')}",
                            severity=Severity.HIGH if item.get("extra", {}).get("severity") == "ERROR" else Severity.MEDIUM,
                            description=item.get("extra", {}).get("message", "Semgrep rule match"),
                            tool="Semgrep",
                            file_path=item.get("path"),
                            line_number=item.get("start", {}).get("line"),
                            code_snippet=item.get("extra", {}).get("lines", ""),
                            cwe=item.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-20"])[0] if item.get("extra", {}).get("metadata", {}).get("cwe") else "CWE-20",
                            owasp="OWASP Top 10 SAST",
                            remediation="Refactor code according to the secure coding guidance provided."
                        )
                        f.mitre_attack = "T1190"
                        findings.append(f)
                    if findings:
                        return findings
                except Exception:
                    pass

        self.log("Running Python Abstract Syntax Tree (AST) Taint/Sink Analysis...")
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv", "__pycache__"]]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, target)

                if fname.endswith(".py"):
                    ast_findings = self._analyze_python_ast(fpath, rel_path)
                    findings.extend(ast_findings)

                # Multi-language regex checks for JS/TS/Go
                if fname.endswith((".js", ".ts", ".jsx", ".tsx", ".go", ".php", ".java")):
                    multi_findings = self._analyze_other_languages(fpath, rel_path)
                    findings.extend(multi_findings)

        return findings

    def _analyze_python_ast(self, fpath: str, rel_path: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fl:
                source = fl.read()
            tree = ast.parse(source, filename=fpath)
            lines = source.splitlines()

            class SecurityVisitor(ast.NodeVisitor):
                def __init__(self, parent):
                    self.parent = parent
                    self.vars_assigned = {}

                def visit_Assign(self, node):
                    # Track variable assignments
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.vars_assigned[target.id] = node.value
                    self.generic_visit(node)

                def visit_Call(self, node):
                    # 1. SQL Injection check in cursor.execute / db.query
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    if func_name in ("execute", "raw", "select", "query") and node.args:
                        first_arg = node.args[0]
                        is_sqli = False
                        # Check f-string
                        if isinstance(first_arg, ast.JoinedStr):
                            is_sqli = True
                        # Check string concatenation or % formatting
                        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                            is_sqli = True
                        # Check variable that was assigned a joined string
                        elif isinstance(first_arg, ast.Name) and first_arg.id in self.vars_assigned:
                            assigned = self.vars_assigned[first_arg.id]
                            if isinstance(assigned, (ast.JoinedStr, ast.BinOp)):
                                is_sqli = True

                        if is_sqli:
                            line_no = node.lineno
                            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                            diff = (
                                f"--- {rel_path}:{line_no}\n"
                                f"+++ {rel_path}:{line_no}\n"
                                f"- {snippet}\n"
                                f"+ # Fix: Use parameterized statement:\n"
                                f"+ cursor.execute('SELECT ... WHERE field = ?', (user_input,))"
                            )
                            f_obj = self.parent.create_finding(
                                finding_id=f"SAST-SQLI-{len(findings)+1:03d}",
                                title="SQL Injection via Formatted Query String (AST Verified)",
                                severity=Severity.CRITICAL,
                                description=f"AST analyzer detected dynamic query construction passed to `{func_name}()` in {rel_path}:{line_no}.",
                                tool="Semgrep AST Engine",
                                file_path=rel_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                cwe="CWE-89",
                                owasp="OWASP A03:2021-Injection",
                                remediation="Replace string formatting with parameterized placeholders ('?' or '%s') and pass query parameters as a tuple.",
                                status=FindingStatus.OPEN,
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
                            )
                            f_obj.remediation_diff = diff
                            f_obj.mitre_attack = "T1190"
                            findings.append(f_obj)

                    # 2. Insecure Deserialization (pickle.loads / pickle.load)
                    if (isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load") and
                            isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle"):
                        line_no = node.lineno
                        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                        diff = (
                            f"--- {rel_path}:{line_no}\n"
                            f"+++ {rel_path}:{line_no}\n"
                            f"- {snippet}\n"
                            f"+ import json\n"
                            f"+ data = json.loads(payload) # Safe serializer"
                        )
                        f_obj = self.parent.create_finding(
                            finding_id=f"SAST-DESER-{len(findings)+1:03d}",
                            title="Arbitrary Code Execution via pickle Insecure Deserialization",
                            severity=Severity.CRITICAL,
                            description=f"Found `pickle.{node.func.attr}()` parsing untrusted payload in {rel_path}:{line_no}.",
                            tool="Semgrep AST Engine",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            cwe="CWE-502",
                            owasp="OWASP A08:2021-Software and Data Integrity Failures",
                            remediation="Avoid pickle for untrusted input. Migrate to JSON, Protocol Buffers, or HMAC-signed data.",
                            references=["https://docs.python.org/3/library/pickle.html"]
                        )
                        f_obj.remediation_diff = diff
                        f_obj.mitre_attack = "T1059"
                        findings.append(f_obj)

                    # 3. Unsafe YAML full_load
                    if (isinstance(node.func, ast.Attribute) and node.func.attr == "load" and
                            isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml"):
                        # check if Loader argument is present
                        has_safe_loader = any(kw.arg == "Loader" for kw in node.keywords)
                        if not has_safe_loader:
                            line_no = node.lineno
                            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                            diff = (
                                f"--- {rel_path}:{line_no}\n"
                                f"+++ {rel_path}:{line_no}\n"
                                f"- {snippet}\n"
                                f"+ cfg = yaml.safe_load(content)"
                            )
                            f_obj = self.parent.create_finding(
                                finding_id=f"SAST-YAML-{len(findings)+1:03d}",
                                title="Unsafe YAML Deserialization (RCE Risk)",
                                severity=Severity.HIGH,
                                description=f"Called `yaml.load()` without SafeLoader in {rel_path}:{line_no}.",
                                tool="Semgrep AST Engine",
                                file_path=rel_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                cwe="CWE-502",
                                owasp="OWASP A08:2021-Software and Data Integrity Failures",
                                remediation="Replace `yaml.load()` with `yaml.safe_load()`.",
                                references=["https://pyyaml.org/wiki/PyYAMLDocumentation"]
                            )
                            f_obj.remediation_diff = diff
                            f_obj.mitre_attack = "T1059"
                            findings.append(f_obj)

                    # 4. Command Injection (subprocess shell=True or os.system)
                    if (isinstance(node.func, ast.Attribute) and
                            node.func.attr in ("call", "Popen", "run", "check_output")):
                        has_shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                        if has_shell_true:
                            line_no = node.lineno
                            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                            f_obj = self.parent.create_finding(
                                finding_id=f"SAST-CMDI-{len(findings)+1:03d}",
                                title="Command Injection: subprocess invoked with shell=True",
                                severity=Severity.HIGH,
                                description=f"subprocess call executed with `shell=True` in {rel_path}:{line_no}.",
                                tool="Semgrep AST Engine",
                                file_path=rel_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                cwe="CWE-78",
                                owasp="OWASP A03:2021-Injection",
                                remediation="Set shell=False and pass command and arguments as a list of strings.",
                                references=["https://docs.python.org/3/library/subprocess.html"]
                            )
                            f_obj.mitre_attack = "T1059"
                            findings.append(f_obj)

                    self.generic_visit(node)

            visitor = SecurityVisitor(self)
            visitor.visit(tree)
        except Exception:
            pass
        return findings

    def _analyze_other_languages(self, fpath: str, rel_path: str) -> List[Finding]:
        findings = []
        rules = [
            # === JavaScript / Node.js ===
            ("js-dom-xss", r"\.(?:innerHTML|outerHTML)\s*=\s*(?!['\"][^'\"]*['\"])", "DOM-based Cross-Site Scripting (XSS)", Severity.HIGH, "CWE-79", "Use textContent or DOMPurify.sanitize()."),
            ("js-child-process-exec", r"child_process\.exec\s*\(", "Command Execution via child_process.exec", Severity.HIGH, "CWE-78", "Use child_process.execFile with argument array."),
            ("js-eval", r"\beval\s*\(", "Dangerous eval() Call (Code Injection)", Severity.HIGH, "CWE-95", "Avoid eval(); use JSON.parse() or safe alternatives."),
            ("js-prototype-pollution", r"__proto__\s*[\[.]|constructor\.prototype\s*[\[.]|Object\.assign\s*\(\s*(?:req|user|data)", "JavaScript Prototype Pollution", Severity.HIGH, "CWE-1321", "Validate input objects; use Object.create(null); freeze prototypes."),
            ("js-document-write", r"document\.write\s*\(", "Dangerous document.write() (XSS Risk)", Severity.MEDIUM, "CWE-79", "Replace document.write() with safe DOM manipulation APIs."),
            ("js-nosql-injection", r"\$where\s*:|\$regex\s*:|find\(\{.*req\.(body|query|params)", "NoSQL/MongoDB Injection Risk", Severity.HIGH, "CWE-943", "Sanitize query operators; use mongoose schema validation; reject $where."),
            ("js-hardcoded-secret", r"(?:password|secret|api_key|apikey|token)\s*=\s*['\"][A-Za-z0-9+/]{12,}['\"]", "Hardcoded Secret / Credential in JavaScript", Severity.HIGH, "CWE-798", "Remove hardcoded secrets; use environment variables or a secrets manager."),
            # === Python additional ===
            ("py-marshal", r"\bimport\s+marshal\b|marshal\.loads\s*\(", "Unsafe Python marshal Deserialization", Severity.HIGH, "CWE-502", "Avoid marshal.loads on untrusted data; use JSON instead."),
            ("py-exec", r"\bexec\s*\(", "Python exec() — Arbitrary Code Execution Risk", Severity.HIGH, "CWE-94", "Replace exec() with explicit function calls; validate all inputs."),
            ("py-xml-etree", r"xml\.etree\.ElementTree\.parse\s*\(|ET\.parse\s*\(|minidom\.parse\s*\(", "Python XML Parser XXE Risk", Severity.MEDIUM, "CWE-611", "Use defusedxml.ElementTree to prevent XXE and entity expansion attacks."),
            ("py-ssti-render", r"render_template_string\s*\(|Environment\(.*loader\).*\.from_string\s*\(", "Server-Side Template Injection (SSTI) — Jinja2", Severity.CRITICAL, "CWE-1336", "Never pass user-controlled strings to render_template_string(); use static template files."),
            ("py-popen-shell", r"os\.popen\s*\(", "Dangerous os.popen() — Command Injection Risk", Severity.HIGH, "CWE-78", "Use subprocess.run() with shell=False and argument list."),
            ("py-assert-auth", r"\bassert\s+.*(?:is_admin|is_authenticated|has_permission)", "Authentication via Python assert (Bypassed in -O mode)", Severity.HIGH, "CWE-617", "Never use assert for security checks; use explicit if/raise AuthenticationError."),
            # === Java ===
            ("java-deserial", r"ObjectInputStream\s*\(|readObject\s*\(\s*\)", "Unsafe Java Deserialization (ObjectInputStream)", Severity.CRITICAL, "CWE-502", "Use serialization filters (JEP 290); prefer JSON/Protobuf for data exchange."),
            ("java-xml-xxe", r"DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)", "Java XML Parser XXE Risk", Severity.HIGH, "CWE-611", "Disable DOCTYPE: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)."),
            ("java-sql-concat", r"\"\\s*\\+\\s*(?:request\\.getParameter|req\\.getParam|params\\.get)", "SQL Injection via String Concatenation (Java)", Severity.CRITICAL, "CWE-89", "Use PreparedStatement with parameterized queries."),
            ("java-ssrf", r"new\s+URL\s*\(.*(?:request\.getParameter|req\.getParam|params\.get)", "SSRF Risk — Java URL from User Input", Severity.HIGH, "CWE-918", "Validate and allowlist URL schemes/hosts before server-side HTTP requests."),
            ("java-xpath-inject", r"\.evaluate\s*\(.*(?:request\.getParameter|req\.getParam)", "XPath Injection Risk (Java)", Severity.HIGH, "CWE-643", "Use parameterized XPath queries; never concatenate user input into XPath expressions."),
            # === PHP ===
            ("php-deserial", r"\bunserialize\s*\(", "PHP Unsafe Deserialization (unserialize)", Severity.CRITICAL, "CWE-502", "Replace unserialize() with json_decode(); sign data with HMAC if deserialization required."),
            ("php-rce", r"\b(?:system|passthru|shell_exec|proc_open|popen)\s*\(", "PHP Remote Code Execution — Dangerous Function", Severity.CRITICAL, "CWE-78", "Remove shell execution functions; use native PHP APIs instead."),
            ("php-include-rfi", r"\b(?:include|require)(?:_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP Remote/Local File Inclusion (RFI/LFI)", Severity.CRITICAL, "CWE-98", "Never pass user input to include/require; use a static file allowlist."),
            ("php-eval", r"\beval\s*\(\s*\$", "PHP eval() with Variable — Code Injection", Severity.CRITICAL, "CWE-94", "Remove eval(); refactor to use safe equivalents."),
            ("php-ssti", r"->render\s*\(.*\$_(GET|POST|REQUEST)|Twig.*createTemplate\s*\(.*\$_(GET|POST)", "SSTI Risk — Twig/PHP Template from User Input", Severity.CRITICAL, "CWE-1336", "Never pass user-controlled data as template strings; use static template files with safe variable rendering."),
            # === .NET / C# ===
            ("dotnet-deserial", r"BinaryFormatter\s*\(\s*\)|NetDataContractSerializer\s*\(\s*\)|SoapFormatter\s*\(\s*\)", "Unsafe .NET Deserialization (BinaryFormatter)", Severity.CRITICAL, "CWE-502", "Microsoft deprecated BinaryFormatter; migrate to System.Text.Json or Protobuf."),
            ("dotnet-sql-concat", r"SqlCommand\s*\(\s*\"[^\"]*\"\s*\+", "SQL Injection via String Concatenation (.NET SqlCommand)", Severity.CRITICAL, "CWE-89", "Use SqlCommand.Parameters for parameterized queries."),
            ("dotnet-ssti", r"RazorEngine|Engine\.Razor\.Run\s*\(.*(?:Request|ViewBag|ViewData)", "SSTI Risk — Razor Engine from User Input (.NET)", Severity.CRITICAL, "CWE-1336", "Sanitize all user input before passing to Razor templates; use static templates."),
            # === Go ===
            ("go-sql-injection", r"db\.Query\s*\(\s*fmt\.Sprintf\(", "SQL Injection via fmt.Sprintf in Go", Severity.CRITICAL, "CWE-89", "Use parameterized placeholders ($1, $2) in db.Query."),
            ("go-ssrf", r"http\.Get\s*\(\s*(?:r\.FormValue|r\.URL\.Query|vars\[)", "SSRF Risk — Go http.Get from User Input", Severity.HIGH, "CWE-918", "Validate URL scheme and host against an allowlist before outbound requests."),
            ("go-ssti", r"template\.HTML\s*\(.*(?:r\.FormValue|r\.URL\.Query)|html/template.*Execute\s*\(.*r\.Form", "SSTI/XSS Risk — Go Template from User Input", Severity.HIGH, "CWE-1336", "Use html/template (not text/template); never pass raw user input as template content."),
            # === Infrastructure as Code (IaC) ===
            ("iac-tf-hardcoded-secret", r"(?:password|secret|private_key|access_key)\s*=\s*\"[A-Za-z0-9+/]{8,}\"", "Hardcoded Secret in Terraform/IaC Configuration", Severity.CRITICAL, "CWE-798", "Use Terraform variable references with sensitive=true; store secrets in Vault or AWS Secrets Manager."),
            ("iac-k8s-privileged", r"privileged\s*:\s*true", "Kubernetes Pod Running as Privileged", Severity.CRITICAL, "CWE-250", "Set privileged: false; apply Pod Security Admission restricted profile."),
            ("iac-k8s-host-network", r"hostNetwork\s*:\s*true|hostPID\s*:\s*true", "Kubernetes Host Namespace Sharing Enabled", Severity.HIGH, "CWE-269", "Disable hostNetwork and hostPID in pod spec to isolate workloads."),
            ("iac-unencrypted-storage", r"StorageEncrypted\s*:\s*false|encrypted\s*=\s*false", "IaC Database/Storage Encryption Disabled", Severity.HIGH, "CWE-312", "Enable StorageEncrypted: true for all RDS/storage resources."),
            ("iac-public-s3", r"BlockPublicAcls\s*:\s*false|acl\s*=\s*\"public-read\"", "S3 Bucket / Cloud Storage Public Access Enabled", Severity.HIGH, "CWE-732", "Set all S3 Block Public Access settings to true; audit bucket ACLs."),
            # === XXE Markers (generic) ===
            ("xxe-doctype", r"<!DOCTYPE[^>]*\[|<!ENTITY\s+\w+\s+SYSTEM", "XXE / External Entity Injection Marker in Source", Severity.CRITICAL, "CWE-611", "Disable DOCTYPE declarations and external entities in all XML parsers."),
            # === Supply Chain ===
            ("supply-chain-install-script", r"\"(?:preinstall|postinstall|install)\"\s*:\s*\"[^\"]+sh[^\"]*\"", "NPM Supply-Chain Risk: Shell Script in Install Hook", Severity.HIGH, "CWE-829", "Audit install scripts; use --ignore-scripts for untrusted packages."),
            # === Framework Debug Mode ===
            ("framework-debug-mode", r"app\.run\s*\(.*debug\s*=\s*True|DEBUG\s*=\s*True", "Production Debug Mode Enabled", Severity.MEDIUM, "CWE-489", "Disable debug mode in production."),
        ]
        try:
            with open(fpath, "r", errors="ignore") as fl:
                lines = fl.readlines()
            for line_no, line in enumerate(lines, 1):
                for r_id, pat, title, sev, cwe, fix in rules:
                    if re.search(pat, line):
                        f = self.create_finding(
                            finding_id=f"SAST-{r_id.upper()}-{len(findings)+1:03d}",
                            title=title,
                            severity=sev,
                            description=f"Pattern `{r_id}` detected dangerous code in {rel_path}:{line_no}.",
                            tool="Semgrep Multi-Lang Engine",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=line.strip(),
                            cwe=cwe,
                            owasp="OWASP A03:2021-Injection",
                            remediation=fix
                        )
                        findings.append(f)
        except Exception:
            pass
        return findings

    def _scan_for_supply_chain_risks(self, target_path: str) -> List[Finding]:
        """Detect dependency confusion, typosquatting, and malicious package indicators."""
        findings = []
        if not os.path.exists(target_path):
            return findings

        # Known typosquatting targets for common packages
        typosquat_pairs = [
            ("request", "requests"), ("urllib", "urllib3"), ("flask", "Flask"),
            ("djangoo", "django"), ("numpyy", "numpy"), ("expres", "express"),
            ("lodas", "lodash"), ("recat", "react"), ("axio", "axios"),
            ("boto", "boto3"), ("pil", "Pillow"), ("cv2", "opencv-python"),
        ]

        req_file = os.path.join(target_path, "requirements.txt")
        if os.path.exists(req_file):
            try:
                with open(req_file, "r", errors="ignore") as f:
                    content = f.read().lower()
                for suspect, legit in typosquat_pairs:
                    if re.search(r"^" + suspect + r"\b", content, re.MULTILINE) and legit.lower() not in content:
                        findings.append(self.create_finding(
                            finding_id=f"SC-TYPOSQUAT-{suspect.upper()}",
                            title=f"Potential Typosquatting Package: '{suspect}' (Intended: '{legit}')",
                            severity=Severity.HIGH,
                            description=f"Package name '{suspect}' resembles legitimate package '{legit}' — possible supply-chain typosquatting attack.",
                            tool="Supply Chain Risk Analyzer",
                            file_path="requirements.txt",
                            cwe="CWE-829",
                            owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                            remediation=f"Verify package name; install '{legit}' from official PyPI registry."
                        ))
            except Exception:
                pass

        # Check for dependency confusion: unpinned wildcard versions in package.json
        pkg_file = os.path.join(target_path, "package.json")
        if os.path.exists(pkg_file):
            try:
                with open(pkg_file, "r", errors="ignore") as f:
                    data = json.load(f)
                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))
                for pkg_name, ver in all_deps.items():
                    if ver in ("*", "latest", ""):
                        findings.append(self.create_finding(
                            finding_id=f"SC-DEPCONF-{pkg_name.upper()[:20]}",
                            title=f"Dependency Confusion Risk: Unpinned Package '{pkg_name}' (version: {ver})",
                            severity=Severity.MEDIUM,
                            description=f"Package '{pkg_name}' uses version specifier '{ver}' which may resolve to a malicious public package if an internal registry is used without scope enforcement.",
                            tool="Supply Chain Risk Analyzer",
                            file_path="package.json",
                            cwe="CWE-829",
                            owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                            remediation="Pin exact versions (e.g. '1.2.3') and use npm --registry with private registry scope enforcement."
                        ))
            except Exception:
                pass

        return findings

    # =========================================================================
    # 3. SCA SCANNING & CYCLONEDX 1.5 SBOM INVENTORY
    # =========================================================================
    def _run_sca_scanner(self, target: str) -> Tuple[List[Finding], List[SBOMComponent]]:
        findings: List[Finding] = []
        components: List[SBOMComponent] = []

        if not os.path.exists(target):
            return findings, components

        # Embedded Advisory Database (CVSS 7.5 - 9.8)
        cve_advisories = {
            "pypi": {
                "requests": [{"max_vuln": "2.31.0", "cve": "CVE-2023-32681", "sev": Severity.MEDIUM, "fix": ">=2.31.0", "desc": "Unintended leak of Proxy-Authorization header."}],
                "urllib3": [{"max_vuln": "2.0.7", "cve": "CVE-2023-45803", "sev": Severity.HIGH, "fix": ">=2.0.7", "desc": "HTTP redirect credential and body leakage."}],
                "pyyaml": [{"max_vuln": "5.4.0", "cve": "CVE-2020-14343", "sev": Severity.CRITICAL, "fix": ">=5.4.1", "desc": "FullLoad arbitrary code execution."}],
                "flask": [{"max_vuln": "2.2.5", "cve": "CVE-2023-30861", "sev": Severity.HIGH, "fix": ">=2.2.5", "desc": "Session cookie disclosure with caching proxies."}],
                "django": [{"max_vuln": "4.2.4", "cve": "CVE-2023-36053", "sev": Severity.HIGH, "fix": ">=4.2.4", "desc": "Regular Expression Denial of Service (ReDoS)."}],
            },
            "npm": {
                "lodash": [{"max_vuln": "4.17.21", "cve": "CVE-2021-23337", "sev": Severity.HIGH, "fix": "^4.17.21", "desc": "Command injection via template function."}],
                "axios": [{"max_vuln": "0.21.2", "cve": "CVE-2021-3749", "sev": Severity.HIGH, "fix": ">=0.21.2", "desc": "SSRF vulnerability via follow-redirects."}],
                "jsonwebtoken": [{"max_vuln": "9.0.0", "cve": "CVE-2022-23529", "sev": Severity.CRITICAL, "fix": ">=9.0.0", "desc": "Arbitrary code execution via crafted secret key."}],
                "minimist": [{"max_vuln": "1.2.6", "cve": "CVE-2021-44906", "sev": Severity.CRITICAL, "fix": ">=1.2.6", "desc": "Prototype pollution via argument parsing."}],
            }
        }

        # 1. Inspect Python requirements.txt
        req_file = os.path.join(target, "requirements.txt")
        if os.path.exists(req_file):
            try:
                with open(req_file, "r", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = re.split(r"==|>=|<=|~=", line)
                            pkg = parts[0].strip().lower()
                            ver = parts[1].strip() if len(parts) > 1 else "1.0.0"
                            purl = f"pkg:pypi/{pkg}@{ver}"
                            comp = SBOMComponent(name=pkg, version=ver, purl=purl, ecosystem="pypi", license="MIT")
                            components.append(comp)

                            if pkg in cve_advisories["pypi"]:
                                for adv in cve_advisories["pypi"][pkg]:
                                    # Version gating: skip if installed version is newer than max vulnerable
                                    if ver and ver != "1.0.0" and not _is_version_vulnerable(ver, adv["max_vuln"]):
                                        continue
                                    f_obj = self.create_finding(
                                        finding_id=f"SCA-{adv['cve']}",
                                        title=f"Vulnerable Dependency: {pkg}@{ver} ({adv['cve']})",
                                        severity=adv["sev"],
                                        description=f"Python package {pkg} version {ver} is vulnerable to {adv['desc']}",
                                        tool="Trivy / CycloneDX Engine",
                                        file_path="requirements.txt",
                                        line_number=line_no,
                                        code_snippet=line,
                                        cwe="CWE-1395",
                                        owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                                        remediation=f"Upgrade {pkg} to version {adv['fix']}.",
                                        status=FindingStatus.OPEN,
                                        references=[f"https://nvd.nist.gov/vuln/detail/{adv['cve']}"]
                                    )
                                    f_obj.mitre_attack = "T1190"
                                    findings.append(f_obj)
            except Exception:
                pass

        # 2. Inspect Node package.json
        pkg_file = os.path.join(target, "package.json")
        if os.path.exists(pkg_file):
            try:
                with open(pkg_file, "r", errors="ignore") as f:
                    data = json.load(f)
                    all_deps = {}
                    all_deps.update(data.get("dependencies", {}))
                    all_deps.update(data.get("devDependencies", {}))
                    for pkg, ver_raw in all_deps.items():
                        clean_ver = re.sub(r"[\^~>=<]", "", ver_raw)
                        purl = f"pkg:npm/{pkg}@{clean_ver}"
                        comp = SBOMComponent(name=pkg, version=clean_ver, purl=purl, ecosystem="npm", license="Apache-2.0")
                        components.append(comp)

                        if pkg in cve_advisories["npm"]:
                            for adv in cve_advisories["npm"][pkg]:
                                # Version gating: skip if installed version is newer than max vulnerable
                                if clean_ver and not _is_version_vulnerable(clean_ver, adv["max_vuln"]):
                                    continue
                                f_obj = self.create_finding(
                                    finding_id=f"SCA-{adv['cve']}",
                                    title=f"Vulnerable NPM Dependency: {pkg}@{clean_ver} ({adv['cve']})",
                                    severity=adv["sev"],
                                    description=f"NPM package {pkg} version {clean_ver} is vulnerable: {adv['desc']}",
                                    tool="Trivy / CycloneDX Engine",
                                    file_path="package.json",
                                    code_snippet=f'"{pkg}": "{ver_raw}"',
                                    cwe="CWE-1395",
                                    owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                                    remediation=f"Upgrade {pkg} to version {adv['fix']}.",
                                    status=FindingStatus.OPEN,
                                    references=[f"https://nvd.nist.gov/vuln/detail/{adv['cve']}"]
                                )
                                f_obj.mitre_attack = "T1190"
                                findings.append(f_obj)

            except Exception:
                pass

        return findings, components
