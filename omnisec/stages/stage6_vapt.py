"""
Stage 6: Penetration Test / VAPT
Recommended Repos: OWASP WSTG + Nuclei + OWASP Amass
What it covers: Pentest methodology, vulnerability scanning and attack-surface discovery
"""

import os
import json
import socket
import urllib.parse
from typing import List, Dict, Any, Tuple
import requests
from omnisec.stages.base import BaseStage
from omnisec.models import Finding, Severity, FindingStatus
from omnisec.config import OmniSecConfig


class Stage6Vapt(BaseStage):
    def __init__(self):
        super().__init__(6)

    def run(self, config: OmniSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        details: Dict[str, Any] = {}

        target_url = config.target_url
        if target_url:
            self.log(f"Executing VAPT & Attack-Surface Reconnaissance against {target_url}")

            # 1. Nuclei runner if installed
            nuclei_findings = self._run_nuclei_if_installed(target_url)
            findings.extend(nuclei_findings)

            # 2. Attack Surface Reconnaissance (Amass equivalent)
            recon_data = self._run_reconnaissance(target_url)
            details["recon"] = recon_data

            # 3. Built-in Nuclei-style Vulnerability & Sensitive Asset Fuzzing
            fuzz_findings, fuzz_data = self._fuzz_sensitive_endpoints(target_url)
            findings.extend(fuzz_findings)

            # 4. RFC 9116 Security.txt discovery
            sec_txt_findings = self._check_security_txt(target_url)
            findings.extend(sec_txt_findings)

            metrics = {
                "vapt_target": target_url,
                "endpoints_fuzzed": fuzz_data.get("probed_count", 0),
                "open_ports_detected": recon_data.get("open_ports", []),
                "vapt_vulnerabilities": len(findings)
            }
            details["fuzzing"] = fuzz_data
        else:
            self.log("No live target_url provided; conducting Static Attack-Surface Mapping & Penetration Vectors Audit...")
            surface_findings, surface_data = self._analyze_static_attack_surface(config.target_path)
            findings.extend(surface_findings)
            metrics = {
                "scan_mode": "Static Attack-Surface Discovery",
                "attack_vectors_identified": surface_data.get("vectors_count", 0),
                "vapt_vulnerabilities": len(findings)
            }
            details["attack_surface"] = surface_data

        return findings, metrics, details

    def _run_nuclei_if_installed(self, url: str) -> List[Finding]:
        findings = []
        if self.is_tool_installed("nuclei"):
            self.log("Running native Nuclei automated vulnerability scanner...")
            cmd = ["nuclei", "-u", url, "-json", "-severity", "low,medium,high,critical", "-silent"]
            code, stdout, stderr = self.execute_command(cmd, timeout=180)
            if stdout:
                for line in stdout.splitlines():
                    try:
                        data = json.loads(line)
                        sev_str = data.get("info", {}).get("severity", "LOW").upper()
                        sev = getattr(Severity, sev_str, Severity.LOW)
                        f = self.create_finding(
                            finding_id=f"NUC-{len(findings)+1:03d}",
                            title=f"Nuclei: {data.get('info', {}).get('name', 'Vulnerability')}",
                            severity=sev,
                            description=data.get("info", {}).get("description", "Nuclei template matched"),
                            tool="Nuclei",
                            target=data.get("matched-at", url),
                            cwe="CWE-20",
                            owasp="OWASP Top 10 VAPT",
                            remediation="Patch according to CVE / template advisory.",
                            references=data.get("info", {}).get("reference", [])
                        )
                        findings.append(f)
                    except Exception:
                        pass
        return findings

    def _run_reconnaissance(self, url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "localhost"
        open_ports = []
        
        # Check standard common web / DB ports
        test_ports = [80, 443, 8080, 8443, 3000, 5000, 27017, 6379]
        for port in test_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.6)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass

        return {
            "target_host": host,
            "open_ports": open_ports,
            "amass_equivalent_surface": f"Discovered {len(open_ports)} exposed network ports on {host}"
        }

    def _fuzz_sensitive_endpoints(self, base_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        # Nuclei & Pentest sensitive paths
        paths = [
            ("/.git/config", Severity.CRITICAL, "CWE-538", "Exposed Git Repository Configuration (Full Source Code Theft Risk)"),
            ("/.git/HEAD", Severity.CRITICAL, "CWE-538", "Exposed Git Version Control Metadata"),
            ("/.env", Severity.CRITICAL, "CWE-552", "Exposed Production Environment Credentials File"),
            ("/actuator/metrics", Severity.MEDIUM, "CWE-200", "Exposed Spring Boot Actuator Telemetry"),
            ("/wp-config.php.bak", Severity.HIGH, "CWE-530", "Exposed Backup Configuration File"),
            ("/database.sqlite", Severity.CRITICAL, "CWE-538", "Exposed SQLite Database Binary"),
            ("/backup.sql", Severity.CRITICAL, "CWE-538", "Exposed Raw SQL Database Backup"),
            ("/phpinfo.php", Severity.MEDIUM, "CWE-200", "Exposed PHP Information Page"),
            ("/server-status", Severity.MEDIUM, "CWE-200", "Exposed Apache/Nginx Server Status Page")
        ]

        probed = 0
        for path, sev, cwe, desc in paths:
            probed += 1
            target = urllib.parse.urljoin(base_url, path)
            try:
                r = requests.get(target, timeout=4, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 10:
                    # Validate content signature
                    is_valid = True
                    if ".git" in path and "repositoryformatversion" not in r.text and "ref:" not in r.text:
                        is_valid = False

                    if is_valid:
                        findings.append(self.create_finding(
                            finding_id=f"VAPT-EXPOSE-{probed:03d}",
                            title=f"Pentest Vulnerability: {desc}",
                            severity=sev,
                            description=f"Endpoint {target} is publicly accessible and returned status 200 OK. Risk of data/source theft.",
                            tool="Nuclei / Amass (Built-in VAPT Engine)",
                            target=target,
                            cwe=cwe,
                            owasp="OWASP A05:2021-Security Misconfiguration",
                            remediation="Block access to sensitive dotfiles and administrative paths on the reverse proxy/firewall.",
                            references=["https://github.com/projectdiscovery/nuclei"]
                        ))
            except Exception:
                pass

        return findings, {"probed_count": probed}

    def _check_security_txt(self, base_url: str) -> List[Finding]:
        findings = []
        target = urllib.parse.urljoin(base_url, "/.well-known/security.txt")
        try:
            r = requests.get(target, timeout=4, verify=False)
            if r.status_code != 200:
                findings.append(self.create_finding(
                    finding_id="VAPT-SECTXT-001",
                    title="Missing RFC 9116 security.txt Vulnerability Disclosure Policy",
                    severity=Severity.LOW,
                    description="The web service does not publish a standardized /.well-known/security.txt file for responsible vulnerability reporting.",
                    tool="OWASP WSTG / RFC 9116",
                    target=target,
                    cwe="CWE-1059",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Deploy /.well-known/security.txt containing Contact, Policy, and Canonical URLs according to RFC 9116.",
                    references=["https://securitytxt.org/"]
                ))
        except Exception:
            pass
        return findings

    def _analyze_static_attack_surface(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        vectors = []
        if not os.path.exists(target_path):
            return findings, {"vectors_count": 0}

        # Scan for sensitive exposed files locally (like .env, backup.sql, etc.)
        risky_files = [".env", ".env.local", "backup.sql", "dump.sql", "credentials.json", "id_rsa", "server.key"]
        for root, _, files in os.walk(target_path):
            for f in files:
                if f.lower() in risky_files or f.endswith((".bak", ".orig", ".swp")):
                    rel_path = os.path.relpath(os.path.join(root, f), target_path)
                    findings.append(self.create_finding(
                        finding_id=f"VAPT-SURFACE-{len(findings)+1:03d}",
                        title=f"Exposed High-Value Asset in Attack Surface: {f}",
                        severity=Severity.HIGH,
                        description=f"Sensitive file {rel_path} was found in repository root. If packaged into container or web root, it presents immediate exposure.",
                        tool="Nuclei / Amass (Attack Surface Engine)",
                        file_path=rel_path,
                        cwe="CWE-538",
                        owasp="OWASP A05:2021-Security Misconfiguration",
                        remediation="Add file to .gitignore, delete from repository history, and inject via environment variables."
                    ))
                    vectors.append(rel_path)

        return findings, {"vectors_count": len(vectors), "vectors": vectors}
