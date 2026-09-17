"""
Stage 3: SAST + SCA + Secret Scanning
Recommended Repos: Semgrep + Trivy + Gitleaks
What it covers: Source-code analysis, dependency/container scanning, secrets
"""

import os
import re
import json
from typing import List, Dict, Any, Tuple
from omnisec.stages.base import BaseStage
from omnisec.models import Finding, Severity, FindingStatus
from omnisec.config import OmniSecConfig


class Stage3SastScaSecrets(BaseStage):
    def __init__(self):
        super().__init__(3)

    def run(self, config: OmniSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        target = config.target_path
        self.log(f"Scanning target path: {target}")

        findings: List[Finding] = []
        tools_executed = []

        # 1. Gitleaks Secret Scanning
        secret_findings = self._run_secrets_scanner(target)
        findings.extend(secret_findings)
        tools_executed.append("Gitleaks" if self.is_tool_installed("gitleaks") else "Gitleaks (Built-in Engine)")

        # 2. Semgrep SAST Scanning
        sast_findings = self._run_sast_scanner(target)
        findings.extend(sast_findings)
        tools_executed.append("Semgrep" if self.is_tool_installed("semgrep") else "Semgrep (Built-in Engine)")

        # 3. Trivy SCA Dependency Scanning
        sca_findings = self._run_sca_scanner(target)
        findings.extend(sca_findings)
        tools_executed.append("Trivy" if self.is_tool_installed("trivy") else "Trivy (Built-in Engine)")

        metrics = {
            "tools_used": tools_executed,
            "secret_leaks_found": len(secret_findings),
            "sast_vulnerabilities_found": len(sast_findings),
            "sca_vulnerabilities_found": len(sca_findings),
            "total_stage_findings": len(findings)
        }

        details = {
            "secret_findings_count": len(secret_findings),
            "sast_findings_count": len(sast_findings),
            "sca_findings_count": len(sca_findings),
            "scanned_directory": os.path.abspath(target)
        }

        return findings, metrics, details

    # =========================================================================
    # 1. SECRET SCANNER (Gitleaks Engine & Fallback)
    # =========================================================================
    def _run_secrets_scanner(self, target: str) -> List[Finding]:
        if self.is_tool_installed("gitleaks"):
            self.log("Running native Gitleaks CLI...")
            # Run native gitleaks
            cmd = ["gitleaks", "detect", "--source", target, "--no-git", "--report-format", "json"]
            code, stdout, stderr = self.execute_command(cmd)
            if stdout:
                try:
                    data = json.loads(stdout)
                    native_findings = []
                    for item in data:
                        f = self.create_finding(
                            finding_id=f"SEC-{len(native_findings)+1:03d}",
                            title=f"Hardcoded Secret: {item.get('RuleID', 'Generic Secret')}",
                            severity=Severity.CRITICAL,
                            description=f"Exposed secret in file {item.get('File')}: {item.get('Description')}",
                            tool="Gitleaks",
                            file_path=item.get("File"),
                            line_number=item.get("StartLine"),
                            code_snippet=item.get("Match"),
                            cwe="CWE-798",
                            owasp="OWASP A07:2021-Identification and Authentication Failures",
                            remediation="Revoke the credential immediately, rotate secret, and remove from source history.",
                            status=FindingStatus.OPEN,
                            references=["https://github.com/gitleaks/gitleaks"]
                        )
                        native_findings.append(f)
                    return native_findings
                except Exception:
                    pass

        self.log("Running High-Entropy Built-in Secret Scanner (Gitleaks ruleset)...")
        patterns = [
            ("AWS Access Key ID", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", Severity.CRITICAL, "CWE-798"),
            ("GitHub Personal Access Token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}", Severity.CRITICAL, "CWE-798"),
            ("Private Cryptographic Key", r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----", Severity.CRITICAL, "CWE-321"),
            ("Slack API Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", Severity.HIGH, "CWE-798"),
            ("Stripe Secret Key", r"(?:sk|rk)_live_[0-9a-zA-Z]{24,34}", Severity.CRITICAL, "CWE-798"),
            ("JWT Hardcoded Token", r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_+/=]+\b", Severity.HIGH, "CWE-798"),
            ("Generic Hardcoded Secret/Password", r"""(?:password|passwd|api_key|secret_key|auth_token)\s*[:=]\s*['"][a-zA-Z0-9!@#$%^&*()_+=-]{8,64}['"]""", Severity.HIGH, "CWE-798"),
            ("Database Connection String", r"(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9_\-\.]+", Severity.CRITICAL, "CWE-256")
        ]

        findings = []
        if not os.path.exists(target):
            return findings

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"]]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, target)
                if os.path.getsize(fpath) > 1024 * 1024:  # skip files > 1MB
                    continue
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for line_no, line in enumerate(lines, 1):
                        for title, pattern, severity, cwe in patterns:
                            match = re.search(pattern, line)
                            if match:
                                val = match.group(0)
                                # Mask sensitive content
                                masked = val[:4] + "*" * max(0, len(val) - 8) + val[-4:] if len(val) > 8 else "***"
                                snippet = line.strip().replace(val, masked)
                                f_obj = self.create_finding(
                                    finding_id=f"SEC-{len(findings)+1:03d}",
                                    title=f"Hardcoded Secret: {title}",
                                    severity=severity,
                                    description=f"Found potential secret ({title}) exposed in plaintext in {rel_path}.",
                                    tool="Gitleaks (Engine)",
                                    file_path=rel_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    cwe=cwe,
                                    owasp="OWASP A07:2021-Identification and Authentication Failures",
                                    remediation="Extract secret into environment variables or secrets manager (AWS Secrets Manager / HashiCorp Vault). Invalidate current secret.",
                                    status=FindingStatus.OPEN,
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]
                                )
                                findings.append(f_obj)
                except Exception:
                    pass
        return findings

    # =========================================================================
    # 2. SAST SCANNER (Semgrep Engine & Fallback)
    # =========================================================================
    def _run_sast_scanner(self, target: str) -> List[Finding]:
        if self.is_tool_installed("semgrep"):
            self.log("Running native Semgrep CLI...")
            cmd = ["semgrep", "scan", "--json", "--quiet", target]
            code, stdout, stderr = self.execute_command(cmd, timeout=180)
            if stdout:
                try:
                    data = json.loads(stdout)
                    native_findings = []
                    for result in data.get("results", []):
                        f = self.create_finding(
                            finding_id=f"SAST-{len(native_findings)+1:03d}",
                            title=result.get("check_id", "Semgrep Rule Match"),
                            severity=Severity.HIGH if result.get("extra", {}).get("severity") == "ERROR" else Severity.MEDIUM,
                            description=result.get("extra", {}).get("message", ""),
                            tool="Semgrep",
                            file_path=result.get("path"),
                            line_number=result.get("start", {}).get("line"),
                            code_snippet=result.get("extra", {}).get("lines", ""),
                            cwe=result.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-20"])[0] if result.get("extra", {}).get("metadata", {}).get("cwe") else "CWE-20",
                            owasp="OWASP Top 10 SAST",
                            remediation="Refactor code according to the secure coding guidance provided.",
                            status=FindingStatus.OPEN,
                            references=["https://semgrep.dev/docs/"]
                        )
                        native_findings.append(f)
                    return native_findings
                except Exception:
                    pass

        self.log("Running Multi-Language Built-in SAST Engine (Semgrep ruleset)...")
        rules = [
            {
                "id": "py-sql-injection-format",
                "lang": [".py"],
                "pattern": r"(?:execute|cursor\.execute)\s*\(\s*f?[\"'].*(?:SELECT|INSERT|UPDATE|DELETE).*%s|\+\s*[a-zA-Z_]",
                "title": "SQL Injection via String Formatting/Concatenation",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-89",
                "owasp": "OWASP A03:2021-Injection",
                "remediation": "Use parameterized queries or ORM queries instead of string concatenation."
            },
            {
                "id": "py-command-injection-shell-true",
                "lang": [".py"],
                "pattern": r"subprocess\.(?:Popen|call|run|check_output)\s*\(.*shell\s*=\s*True",
                "title": "Command Injection Risk: subprocess with shell=True",
                "severity": Severity.HIGH,
                "cwe": "CWE-78",
                "owasp": "OWASP A03:2021-Injection",
                "remediation": "Set shell=False and pass command arguments as an array of strings."
            },
            {
                "id": "py-insecure-deserialization-pickle",
                "lang": [".py"],
                "pattern": r"pickle\.(?:loads|load)\s*\(",
                "title": "Insecure Deserialization via pickle",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-502",
                "owasp": "OWASP A08:2021-Software and Data Integrity Failures",
                "remediation": "Avoid deserializing untrusted data with pickle; use JSON, Protocol Buffers, or safe serializers."
            },
            {
                "id": "py-insecure-yaml-load",
                "lang": [".py"],
                "pattern": r"yaml\.load\s*\([^,)]*\)",
                "title": "Unsafe YAML Deserialization",
                "severity": Severity.HIGH,
                "cwe": "CWE-502",
                "owasp": "OWASP A08:2021-Software and Data Integrity Failures",
                "remediation": "Use yaml.safe_load() instead of yaml.load() without SafeLoader."
            },
            {
                "id": "py-code-eval",
                "lang": [".py", ".js", ".ts", ".php"],
                "pattern": r"\b(?:eval|exec)\s*\(",
                "title": "Arbitrary Code Execution via eval/exec",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-95",
                "owasp": "OWASP A03:2021-Injection",
                "remediation": "Eliminate dynamic code execution with eval/exec. Use safe parsing alternatives."
            },
            {
                "id": "js-dom-xss-innerhtml",
                "lang": [".js", ".ts", ".jsx", ".tsx"],
                "pattern": r"\.(?:innerHTML|outerHTML)\s*=\s*(?!['\"][^'\"]*['\"])",
                "title": "DOM-based Cross-Site Scripting (DOM XSS)",
                "severity": Severity.HIGH,
                "cwe": "CWE-79",
                "owasp": "OWASP A03:2021-Injection",
                "remediation": "Use textContent or DOMPurify.sanitize() before rendering user data."
            },
            {
                "id": "py-debug-mode-enabled",
                "lang": [".py"],
                "pattern": r"app\.run\s*\(.*debug\s*=\s*True|DEBUG\s*=\s*True",
                "title": "Framework Debug Mode Enabled in Code",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-489",
                "owasp": "OWASP A05:2021-Security Misconfiguration",
                "remediation": "Disable debug mode in production environments via environment variables."
            }
        ]

        findings = []
        if not os.path.exists(target):
            return findings

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv", "__pycache__"]]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                rel_path = os.path.relpath(fpath, target)

                matching_rules = [r for r in rules if ext in r["lang"]]
                if not matching_rules:
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for line_no, line in enumerate(lines, 1):
                        for rule in matching_rules:
                            if re.search(rule["pattern"], line):
                                f_obj = self.create_finding(
                                    finding_id=f"SAST-{len(findings)+1:03d}",
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    description=f"Detected pattern `{rule['id']}` matching dangerous construct in {rel_path}:{line_no}.",
                                    tool="Semgrep (Engine)",
                                    file_path=rel_path,
                                    line_number=line_no,
                                    code_snippet=line.strip(),
                                    cwe=rule["cwe"],
                                    owasp=rule["owasp"],
                                    remediation=rule["remediation"],
                                    status=FindingStatus.OPEN,
                                    references=["https://owasp.org/www-project-top-ten/"]
                                )
                                findings.append(f_obj)
                except Exception:
                    pass
        return findings

    # =========================================================================
    # 3. SCA SCANNER (Trivy Engine & Fallback)
    # =========================================================================
    def _run_sca_scanner(self, target: str) -> List[Finding]:
        if self.is_tool_installed("trivy"):
            self.log("Running native Trivy CLI...")
            cmd = ["trivy", "fs", "--format", "json", "--severity", "HIGH,CRITICAL", target]
            code, stdout, stderr = self.execute_command(cmd, timeout=180)
            if stdout:
                try:
                    data = json.loads(stdout)
                    native_findings = []
                    for result in data.get("Results", []):
                        for vuln in result.get("Vulnerabilities", []):
                            f = self.create_finding(
                                finding_id=f"SCA-{vuln.get('VulnerabilityID', len(native_findings)+1)}",
                                title=f"Vulnerable Dependency: {vuln.get('PkgName')} ({vuln.get('VulnerabilityID')})",
                                severity=Severity.CRITICAL if vuln.get("Severity") == "CRITICAL" else Severity.HIGH,
                                description=f"Package {vuln.get('PkgName')} version {vuln.get('InstalledVersion')} is vulnerable to {vuln.get('Title')}: {vuln.get('Description')}",
                                tool="Trivy",
                                file_path=result.get("Target"),
                                cwe=vuln.get("CweIDs", ["CWE-1395"])[0] if vuln.get("CweIDs") else "CWE-1395",
                                owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                                remediation=f"Upgrade {vuln.get('PkgName')} to version {vuln.get('FixedVersion', 'latest')}.",
                                status=FindingStatus.OPEN,
                                references=vuln.get("References", [])[:3]
                            )
                            native_findings.append(f)
                    return native_findings
                except Exception:
                    pass

        self.log("Running Embedded SCA Database Scanner (Trivy ruleset)...")
        # Known CVE database for common ecosystem dependencies
        known_vulns = {
            "python": {
                "requests": [
                    {"vulnerable_below": "2.31.0", "cve": "CVE-2023-32681", "severity": Severity.MEDIUM, "fix": ">=2.31.0", "desc": "Unintended leak of Proxy-Authorization header to destination server."},
                ],
                "urllib3": [
                    {"vulnerable_below": "2.0.7", "cve": "CVE-2023-45803", "severity": Severity.HIGH, "fix": ">=2.0.7", "desc": "Request body not stripped on HTTP redirect causing credential/payload leak."},
                ],
                "pyyaml": [
                    {"vulnerable_below": "5.4", "cve": "CVE-2020-14343", "severity": Severity.CRITICAL, "fix": ">=5.4.1", "desc": "Arbitrary code execution through full_load deserialization."},
                ],
                "flask": [
                    {"vulnerable_below": "2.2.5", "cve": "CVE-2023-30861", "severity": Severity.HIGH, "fix": ">=2.2.5", "desc": "Cookie session disclosure with caching proxies."},
                ]
            },
            "node": {
                "lodash": [
                    {"vulnerable_below": "4.17.21", "cve": "CVE-2021-23337", "severity": Severity.HIGH, "fix": "^4.17.21", "desc": "Command injection via template function."},
                ],
                "axios": [
                    {"vulnerable_below": "0.21.2", "cve": "CVE-2021-3749", "severity": Severity.HIGH, "fix": ">=0.21.2", "desc": "Server-Side Request Forgery via follow-redirects."},
                ],
                "jsonwebtoken": [
                    {"vulnerable_below": "9.0.0", "cve": "CVE-2022-23529", "severity": Severity.CRITICAL, "fix": ">=9.0.0", "desc": "Insecure key verification leading to arbitrary code execution."},
                ]
            }
        }

        findings = []
        if not os.path.exists(target):
            return findings

        # Check Python requirements.txt
        req_path = os.path.join(target, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = re.split(r"==|>=|<=|~=", line)
                            pkg = parts[0].strip().lower()
                            ver = parts[1].strip() if len(parts) > 1 else "0.0.0"
                            if pkg in known_vulns["python"]:
                                for vuln in known_vulns["python"][pkg]:
                                    findings.append(self.create_finding(
                                        finding_id=f"SCA-{vuln['cve']}",
                                        title=f"Vulnerable Dependency: {pkg} ({vuln['cve']})",
                                        severity=vuln["severity"],
                                        description=f"Package {pkg} version {ver} is vulnerable: {vuln['desc']}",
                                        tool="Trivy (Engine)",
                                        file_path="requirements.txt",
                                        line_number=line_no,
                                        code_snippet=line,
                                        cwe="CWE-1395",
                                        owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                                        remediation=f"Upgrade {pkg} to version {vuln['fix']}.",
                                        status=FindingStatus.OPEN,
                                        references=[f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"]
                                    ))
            except Exception:
                pass

        # Check Node package.json
        pkg_path = os.path.join(target, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg_data = json.load(f)
                    deps = {}
                    deps.update(pkg_data.get("dependencies", {}))
                    deps.update(pkg_data.get("devDependencies", {}))
                    for pkg, ver_spec in deps.items():
                        clean_ver = re.sub(r"[\^~>=<]", "", ver_spec)
                        if pkg in known_vulns["node"]:
                            for vuln in known_vulns["node"][pkg]:
                                findings.append(self.create_finding(
                                    finding_id=f"SCA-{vuln['cve']}",
                                    title=f"Vulnerable Dependency: {pkg} ({vuln['cve']})",
                                    severity=vuln["severity"],
                                    description=f"NPM package {pkg} version {clean_ver} is vulnerable: {vuln['desc']}",
                                    tool="Trivy (Engine)",
                                    file_path="package.json",
                                    code_snippet=f'"{pkg}": "{ver_spec}"',
                                    cwe="CWE-1395",
                                    owasp="OWASP A06:2021-Vulnerable and Outdated Components",
                                    remediation=f"Upgrade {pkg} to version {vuln['fix']}.",
                                    status=FindingStatus.OPEN,
                                    references=[f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"]
                                ))
            except Exception:
                pass

        return findings
