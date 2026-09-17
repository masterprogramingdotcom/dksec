"""
Stage 6: Penetration Test / VAPT (Advanced Enterprise Edition)
Recommended Repos: OWASP WSTG + Nuclei + OWASP Amass
What it covers: Pentest methodology, automated vulnerability templates, attack-surface discovery,
authenticated fuzzing, and DNS security posture.
"""

import os
import json
import socket
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
import requests

from dksec.stages.base import BaseStage
from dksec.models import Finding, Severity, FindingStatus
from dksec.config import DKSecConfig
from dksec.auth import DKSecSessionManager


class Stage6Vapt(BaseStage):
    def __init__(self):
        super().__init__(6)

    def run(self, config: DKSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        details: Dict[str, Any] = {}

        target_url = config.target_url
        if target_url:
            self.log(f"Executing Advanced VAPT & Attack-Surface Reconnaissance against: {target_url}")

            # Get or initialize authenticated session
            session_mgr: Optional[DKSecSessionManager] = context.get("session_manager")
            if not session_mgr and (config.auth.enabled or config.auth.login_url or config.auth.bearer_token):
                session_mgr = DKSecSessionManager(config.auth, base_url=target_url)
                context["session_manager"] = session_mgr

            # 1. Nuclei Native Execution if installed (with Auth headers)
            nuclei_findings = self._run_nuclei_if_installed(target_url, session_mgr)
            findings.extend(nuclei_findings)

            # 2. Attack Surface Reconnaissance (Amass equivalent)
            recon_data = self._run_reconnaissance(target_url)
            details["recon"] = recon_data

            # 3. DNS Security Posture (SPF, DMARC, CAA)
            dns_findings, dns_data = self._audit_dns_security(target_url)
            findings.extend(dns_findings)
            details["dns"] = dns_data

            # 4. Nuclei-Style High-Value Sensitive Asset Fuzzing
            fuzz_findings, fuzz_data = self._fuzz_sensitive_endpoints(target_url, session_mgr)
            findings.extend(fuzz_findings)
            details["fuzzing"] = fuzz_data

            # 5. Active Pentest Injection & Authorization Probes
            active_findings, active_data = self._probe_active_vulnerabilities(target_url, session_mgr)
            findings.extend(active_findings)
            details["active_vapt"] = active_data

            # 6. RFC 9116 security.txt check
            sec_txt_findings = self._check_security_txt(target_url)
            findings.extend(sec_txt_findings)

            metrics = {
                "vapt_target": target_url,
                "authenticated_pentest": bool(session_mgr and session_mgr.is_authenticated),
                "endpoints_fuzzed": fuzz_data.get("probed_count", 0),
                "open_ports_detected": recon_data.get("open_ports", []),
                "vapt_vulnerabilities": len(findings)
            }
        else:
            self.log("No live target_url provided; conducting Static Attack-Surface Vector Mapping...")
            surface_findings, surface_data = self._analyze_static_attack_surface(config.target_path)
            findings.extend(surface_findings)
            metrics = {
                "scan_mode": "Static Attack-Surface Discovery",
                "attack_vectors_identified": surface_data.get("vectors_count", 0),
                "vapt_vulnerabilities": len(findings)
            }
            details["attack_surface"] = surface_data

        return findings, metrics, details

    def _run_nuclei_if_installed(self, url: str, session_mgr: Optional[DKSecSessionManager] = None) -> List[Finding]:
        findings = []
        if self.is_tool_installed("nuclei"):
            self.log("Running native ProjectDiscovery Nuclei automated scanner...")
            cmd = ["nuclei", "-u", url, "-json", "-severity", "low,medium,high,critical", "-silent"]
            
            # If session is authenticated, inject Authorization or Cookie headers
            if session_mgr and session_mgr.is_authenticated:
                for h_key, h_val in session_mgr.session.headers.items():
                    if h_key.lower() in ("authorization", "x-api-key"):
                        cmd.extend(["-H", f"{h_key}: {h_val}"])
                for c_key, c_val in session_mgr.session.cookies.items():
                    cmd.extend(["-H", f"Cookie: {c_key}={c_val}"])

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
                        f.mitre_attack = "T1190"
                        findings.append(f)
                    except Exception:
                        pass
        return findings

    def _run_reconnaissance(self, url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "localhost"
        open_ports = []
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 6379, 27017, 5432, 3306]

        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass

        return {
            "target_host": host,
            "open_ports": open_ports,
            "probed_ports": common_ports,
            "surface_summary": f"Discovered {len(open_ports)} accessible service ports on {host}"
        }

    def _audit_dns_security(self, url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        data = {"host": host, "checks": []}

        if not host or host in ("localhost", "127.0.0.1"):
            return findings, data

        doh_url = "https://cloudflare-dns.com/dns-query"
        doh_headers = {"accept": "application/dns-json"}

        # 1. SPF Check
        spf_val = None
        spf_status = "FAIL"
        try:
            r = requests.get(f"{doh_url}?name={host}&type=TXT", headers=doh_headers, timeout=3)
            if r.status_code == 200:
                for ans in r.json().get("Answer", []):
                    txt = ans.get("data", "").strip('"')
                    if "v=spf1" in txt:
                        spf_val = txt
                        if "+all" in txt:
                            spf_status = "FAIL"
                        elif "?all" in txt:
                            spf_status = "WARN"
                        else:
                            spf_status = "PASS"
                        break
        except Exception:
            pass

        if not spf_val:
            findings.append(self.create_finding(
                finding_id="VAPT-DNS-SPF-MISSING",
                title="Missing DNS SPF (Sender Policy Framework) Record",
                severity=Severity.MEDIUM,
                description=f"Domain `{host}` does not publish a DNS SPF record, enabling domain impersonation and email spoofing.",
                tool="OWASP WSTG / DNS Posture",
                target=host,
                cwe="CWE-290",
                owasp="OWASP A05:2021-Security Misconfiguration",
                remediation="Publish a TXT record on the apex domain: 'v=spf1 include:_spf.yourprovider.com ~all'",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"]
            ))
        elif spf_status == "FAIL":
            findings.append(self.create_finding(
                finding_id="VAPT-DNS-SPF-PERMISSIVE",
                title="Permissive SPF Record (+all)",
                severity=Severity.HIGH,
                description=f"SPF record for `{host}` permits any host to send emails on its behalf (+all).",
                tool="OWASP WSTG / DNS Posture",
                target=host,
                cwe="CWE-290",
                owasp="OWASP A05:2021-Security Misconfiguration",
                remediation="Change '+all' to '-all' (hard fail) or '~all' (soft fail)."
            ))

        data["checks"].append({
            "record_type": "SPF",
            "target": host,
            "status": spf_status,
            "value": spf_val or "Missing / Not Found",
            "recommendation": "Enforce strict SPF policy (-all or ~all)." if spf_status == "PASS" else "Deploy valid SPF TXT record to prevent phishing spoofing."
        })

        # 2. DMARC Check
        dmarc_target = f"_dmarc.{host}"
        dmarc_val = None
        dmarc_status = "FAIL"
        try:
            r = requests.get(f"{doh_url}?name={dmarc_target}&type=TXT", headers=doh_headers, timeout=3)
            if r.status_code == 200:
                for ans in r.json().get("Answer", []):
                    txt = ans.get("data", "").strip('"')
                    if "v=DMARC1" in txt:
                        dmarc_val = txt
                        if "p=none" in txt:
                            dmarc_status = "WARN"
                        else:
                            dmarc_status = "PASS"
                        break
        except Exception:
            pass

        if not dmarc_val:
            findings.append(self.create_finding(
                finding_id="VAPT-DNS-DMARC-MISSING",
                title="Missing DNS DMARC Record (High Phishing Risk)",
                severity=Severity.HIGH,
                description=f"Domain `{host}` lacks a DMARC policy record (`{dmarc_target}`), preventing receiver verification of spoofed mail.",
                tool="OWASP WSTG / DNS Posture",
                target=dmarc_target,
                cwe="CWE-290",
                owasp="OWASP A05:2021-Security Misconfiguration",
                remediation="Add TXT record at '_dmarc.domain' with 'v=DMARC1; p=reject; rua=mailto:security@domain.com'.",
                references=["https://dmarc.org/"]
            ))
        elif dmarc_status == "WARN":
            findings.append(self.create_finding(
                finding_id="VAPT-DNS-DMARC-MONITORONLY",
                title="DMARC Policy in Monitoring-Only Mode (p=none)",
                severity=Severity.LOW,
                description=f"DMARC record for `{host}` has 'p=none', meaning unauthenticated spoofed emails are not blocked or quarantined.",
                tool="OWASP WSTG / DNS Posture",
                target=dmarc_target,
                cwe="CWE-290",
                owasp="OWASP A05:2021-Security Misconfiguration",
                remediation="Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'."
            ))

        data["checks"].append({
            "record_type": "DMARC",
            "target": dmarc_target,
            "status": dmarc_status,
            "value": dmarc_val or "Missing / Not Found",
            "recommendation": "Enforce p=reject or p=quarantine policy." if dmarc_status == "PASS" else "Add DMARC policy with quarantine/reject enforcement."
        })

        # 3. CAA Check
        caa_val = None
        caa_status = "WARN"
        try:
            r = requests.get(f"{doh_url}?name={host}&type=CAA", headers=doh_headers, timeout=3)
            if r.status_code == 200:
                answers = r.json().get("Answer", [])
                if answers:
                    caa_val = "; ".join(a.get("data", "") for a in answers)
                    caa_status = "PASS"
        except Exception:
            pass

        if not caa_val:
            findings.append(self.create_finding(
                finding_id="VAPT-DNS-CAA-MISSING",
                title="Missing DNS CAA (Certificate Authority Authorization) Record",
                severity=Severity.LOW,
                description=f"Domain `{host}` has no CAA records configured to restrict which CAs can issue SSL certificates.",
                tool="OWASP WSTG / DNS Posture",
                target=host,
                cwe="CWE-295",
                owasp="OWASP A05:2021-Security Misconfiguration",
                remediation="Publish CAA records designating trusted Certificate Authorities (e.g. '0 issue \"letsencrypt.org\"').",
                references=["https://datatracker.ietf.org/doc/html/rfc8659"]
            ))

        data["checks"].append({
            "record_type": "CAA",
            "target": host,
            "status": caa_status,
            "value": caa_val or "No CAA records defined",
            "recommendation": "Specify authorized Certificate Authorities via CAA records." if caa_status == "PASS" else "Add CAA records to restrict unauthorized certificate issuance."
        })

        return findings, data

    def _fuzz_sensitive_endpoints(self, base_url: str, session_mgr: Optional[DKSecSessionManager] = None) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        paths = [
            ("/.git/config", Severity.CRITICAL, "CWE-538", "Exposed Git Configuration (Full Source Code Theft Risk)"),
            ("/.git/HEAD", Severity.CRITICAL, "CWE-538", "Exposed Git Version Control Metadata"),
            ("/.env", Severity.CRITICAL, "CWE-552", "Exposed Production Environment Credentials File"),
            ("/.env.local", Severity.CRITICAL, "CWE-552", "Exposed Local Environment Secrets File"),
            ("/actuator/metrics", Severity.MEDIUM, "CWE-200", "Exposed Spring Boot Actuator Telemetry"),
            ("/actuator/env", Severity.CRITICAL, "CWE-552", "Exposed Spring Boot Actuator Environment Dump"),
            ("/wp-config.php.bak", Severity.HIGH, "CWE-530", "Exposed Backup Configuration File"),
            ("/database.sqlite", Severity.CRITICAL, "CWE-538", "Exposed SQLite Database Binary"),
            ("/backup.sql", Severity.CRITICAL, "CWE-538", "Exposed Raw SQL Database Backup"),
            ("/phpinfo.php", Severity.MEDIUM, "CWE-200", "Exposed PHP Information Diagnostic Page"),
            ("/server-status", Severity.MEDIUM, "CWE-200", "Exposed Web Server Status Page"),
            ("/.aws/credentials", Severity.CRITICAL, "CWE-552", "Exposed AWS Credentials File"),
            ("/swagger.json", Severity.LOW, "CWE-200", "Publicly Accessible Swagger Specification"),
            ("/openapi.json", Severity.LOW, "CWE-200", "Publicly Accessible OpenAPI Specification"),
            ("/graphql", Severity.LOW, "CWE-200", "GraphQL Endpoint Exposed to Anonymous Callers")
        ]

        probed = 0
        fuzz_results = []
        for path, sev, cwe, desc in paths:
            probed += 1
            target = urllib.parse.urljoin(base_url, path)
            status_code = None
            content_len = 0
            verdict = "SKIPPED / TIMEOUT"
            risk = "SAFE"
            try:
                r = requests.get(target, timeout=3, verify=False, allow_redirects=False)
                status_code = r.status_code
                content_len = len(r.content)
                if r.status_code == 200 and len(r.content) > 10:
                    valid = True
                    if ".git" in path and "ref:" not in r.text and "repositoryformatversion" not in r.text:
                        valid = False

                    if valid:
                        verdict = "EXPOSED"
                        risk = sev.value
                        f = self.create_finding(
                            finding_id=f"VAPT-EXPOSE-{probed:03d}",
                            title=f"Pentest Vulnerability: {desc}",
                            severity=sev,
                            description=f"Path {target} returned HTTP 200 OK without authentication. High risk of data or system compromise.",
                            tool="Nuclei / Amass (VAPT Engine)",
                            target=target,
                            cwe=cwe,
                            owasp="OWASP A05:2021-Security Misconfiguration",
                            remediation="Block access to sensitive paths and hidden dotfiles on the ingress gateway / reverse proxy.",
                            references=["https://github.com/projectdiscovery/nuclei"]
                        )
                        f.mitre_attack = "T1595"
                        findings.append(f)
                    else:
                        verdict = "FALSE_POSITIVE"
                        risk = "LOW"
                elif r.status_code in (401, 403):
                    verdict = f"PROTECTED ({r.status_code})"
                    risk = "SAFE"
                elif r.status_code == 404:
                    verdict = "NOT_FOUND (404)"
                    risk = "SAFE"
                else:
                    verdict = f"HTTP {r.status_code}"
                    risk = "LOW" if r.status_code < 400 else "SAFE"
            except Exception:
                pass

            fuzz_results.append({
                "path": path,
                "target": target,
                "status_code": status_code or "-",
                "content_length": content_len,
                "verdict": verdict,
                "risk": risk
            })

        return findings, {"probed_count": probed, "results": fuzz_results}

    def _probe_active_vulnerabilities(self, base_url: str, session_mgr: Optional[DKSecSessionManager] = None) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        probes_executed = 0
        active_tests = []

        client = session_mgr.session if (session_mgr and session_mgr.is_authenticated) else requests

        # 1. Path Traversal probe on common download/file parameters
        traversal_targets = [
            "/api/v1/download?file=../../../../etc/passwd",
            "/download?path=../../../../etc/passwd",
            "/api/file?name=../../../../etc/passwd"
        ]
        for t in traversal_targets:
            probes_executed += 1
            url = urllib.parse.urljoin(base_url, t)
            test_status = "SAFE"
            test_result = "SECURE"
            status_code = None
            try:
                r = client.get(url, timeout=3, verify=False)
                status_code = r.status_code
                if "root:x:0:0:" in r.text or "[extensions]" in r.text:
                    test_status = "CRITICAL"
                    test_result = "VULNERABLE (Arbitrary File Read)"
                    findings.append(self.create_finding(
                        finding_id="VAPT-TRAVERSAL-EXPLOIT",
                        title="Critical Directory Traversal / Arbitrary File Read (CWE-22)",
                        severity=Severity.CRITICAL,
                        description=f"Endpoint `{url}` returned contents of `/etc/passwd`. Arbitrary filesystem reading confirmed.",
                        tool="Nuclei / VAPT Active Engine",
                        target=url,
                        cwe="CWE-22",
                        owasp="OWASP A01:2021-Broken Access Control",
                        remediation="Validate user-supplied paths strictly against an allowlist and use secure path resolution."
                    ))
                else:
                    test_result = f"SECURE (HTTP {r.status_code})"
            except Exception:
                test_result = "TIMEOUT / UNREACHABLE"

            active_tests.append({
                "test_type": "Directory Traversal / LFI",
                "probe_vector": t,
                "target": url,
                "status_code": status_code or "-",
                "result": test_result,
                "risk": test_status
            })

        # 2. Authorization Bypass via URL Normalization
        bypass_paths = [
            "/api/v1/admin/../admin/debug",
            "/api/v1//admin/debug",
            "/api/v1/admin/debug%20"
        ]
        for bp in bypass_paths:
            probes_executed += 1
            url = urllib.parse.urljoin(base_url, bp)
            test_status = "SAFE"
            test_result = "SECURE"
            status_code = None
            try:
                r = requests.get(url, timeout=3, verify=False)
                status_code = r.status_code
                if r.status_code == 200 and ("env" in r.text or "db_pass" in r.text):
                    test_status = "HIGH"
                    test_result = "VULNERABLE (Bypass Confirmed)"
                    findings.append(self.create_finding(
                        finding_id="VAPT-AUTH-BYPASS-NORMALIZATION",
                        title="Authentication Bypass via URL Path Normalization",
                        severity=Severity.HIGH,
                        description=f"Endpoint `{url}` bypassed access controls using unnormalized path syntax.",
                        tool="Nuclei / VAPT Active Engine",
                        target=url,
                        cwe="CWE-285",
                        owasp="OWASP A01:2021-Broken Access Control",
                        remediation="Normalize URLs on reverse proxies before forwarding to backend microservices."
                    ))
                else:
                    test_result = f"SECURE (HTTP {r.status_code})"
            except Exception:
                test_result = "TIMEOUT / UNREACHABLE"

            active_tests.append({
                "test_type": "URL Normalization Auth Bypass",
                "probe_vector": bp,
                "target": url,
                "status_code": status_code or "-",
                "result": test_result,
                "risk": test_status
            })

        return findings, {"probes_executed": probes_executed, "tests": active_tests}

    def _check_security_txt(self, base_url: str) -> List[Finding]:
        findings = []
        target = urllib.parse.urljoin(base_url, "/.well-known/security.txt")
        try:
            r = requests.get(target, timeout=3, verify=False)
            if r.status_code != 200 or "Contact:" not in r.text:
                findings.append(self.create_finding(
                    finding_id="VAPT-SECTXT-MISSING",
                    title="Missing RFC 9116 security.txt Vulnerability Disclosure Policy",
                    severity=Severity.LOW,
                    description="The web service does not publish a standardized /.well-known/security.txt policy file.",
                    tool="OWASP WSTG / RFC 9116",
                    target=target,
                    cwe="CWE-1059",
                    owasp="OWASP A05:2021-Security Misconfiguration",
                    remediation="Deploy /.well-known/security.txt containing Contact and Policy fields per RFC 9116.",
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

        risky_files = [".env", ".env.local", "backup.sql", "dump.sql", "database.sqlite", "id_rsa", "server.key"]
        for root, _, files in os.walk(target_path):
            for f in files:
                if f.lower() in risky_files or f.endswith((".bak", ".orig", ".swp")):
                    rel_path = os.path.relpath(os.path.join(root, f), target_path)
                    f_obj = self.create_finding(
                        finding_id=f"VAPT-SURFACE-{len(findings)+1:03d}",
                        title=f"Exposed High-Value Asset in Attack Surface: {f}",
                        severity=Severity.HIGH,
                        description=f"Sensitive asset `{rel_path}` was committed into repository root.",
                        tool="Nuclei / Amass (Attack Surface Engine)",
                        file_path=rel_path,
                        cwe="CWE-538",
                        owasp="OWASP A05:2021-Security Misconfiguration",
                        remediation="Add to .gitignore, delete file from repository history, and inject via environment variables."
                    )
                    f_obj.mitre_attack = "T1552"
                    findings.append(f_obj)
                    vectors.append(rel_path)

        return findings, {"vectors_count": len(vectors), "vectors": vectors}
