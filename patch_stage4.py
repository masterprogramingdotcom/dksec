import re

with open("dksec/stages/stage4_dast_api.py", "r") as f:
    content = f.read()

run_hook = """
            # 19. WebSocket Security
            ws_findings, ws_data = self._audit_websocket(target_url)
            findings.extend(ws_findings)
            details["websocket"] = ws_data

            # 20. OpenAPI-Driven Active Parameter Fuzzing
            if spec_data.get("endpoints_list"):
                fuzz_findings, fuzz_data = self._fuzz_openapi_parameters(target_url, session_mgr, spec_data)
                findings.extend(fuzz_findings)
                details["openapi_fuzzing"] = fuzz_data

            # 21. Multi-Role RBAC / BOLA Matrix Auditor (Dual-Session Testing)
            user_b_token = context.get("user_b_token") or config.auth.user_b_token if hasattr(config.auth, 'user_b_token') else None
            if user_b_token:
                rbac_findings, rbac_data = self._audit_rbac_matrix(target_url, session_mgr, user_b_token, spec_data)
                findings.extend(rbac_findings)
                details["rbac_matrix"] = rbac_data
"""
content = content.replace(
    '            # 19. WebSocket Security\n            ws_findings, ws_data = self._audit_websocket(target_url)\n            findings.extend(ws_findings)\n            details["websocket"] = ws_data',
    run_hook.strip()
)

methods = """
    def _fuzz_openapi_parameters(self, base_url: str, session_mgr: DKSecSessionManager, spec_data: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        probes_sent = 0
        payloads = {
            "sqli": "' OR 1=1--",
            "xss": "<script>alert(1)</script>",
            "bola": "../../../etc/passwd"
        }
        
        endpoints = spec_data.get("endpoints_list", [])[:10]  # Limit to 10 for performance
        
        for ep in endpoints:
            for p_name, payload in payloads.items():
                target = urllib.parse.urljoin(base_url, ep)
                if "?" in target:
                    target += f"&fuzz={urllib.parse.quote(payload)}"
                else:
                    target += f"?fuzz={urllib.parse.quote(payload)}"
                
                probes_sent += 1
                try:
                    req_headers = {"User-Agent": "DKSec-Fuzzer"}
                    if session_mgr.is_authenticated:
                        resp = session_mgr.session.get(target, headers=req_headers, timeout=4, verify=False, allow_redirects=False)
                    else:
                        resp = requests.get(target, headers=req_headers, timeout=4, verify=False, allow_redirects=False)
                    
                    if resp.status_code == 500 or (p_name == "xss" and payload in resp.text):
                        finding = self.create_finding(
                            finding_id=f"DAST-FUZZ-{p_name.upper()}-{probes_sent:03d}",
                            title=f"Active Fuzzing: Potential {p_name.upper()} in {ep}",
                            severity=Severity.HIGH,
                            description=f"Injected payload `{payload}` into endpoint `{ep}` resulting in anomaly (HTTP {resp.status_code}).",
                            tool="OpenAPI Fuzzer",
                            target=target,
                            cwe="CWE-89" if p_name == "sqli" else "CWE-79",
                            owasp="OWASP API8:2023-Security Misconfiguration",
                            remediation="Implement strict input validation and parameterized queries."
                        )
                        finding.curl_command = f"curl -X GET '{target}' -H 'User-Agent: DKSec-Fuzzer'"
                        if session_mgr.captured_token:
                            finding.curl_command += f" -H 'Authorization: Bearer {session_mgr.captured_token}'"
                        finding.raw_request = f"GET {target} HTTP/1.1\\nUser-Agent: DKSec-Fuzzer"
                        finding.raw_response = f"HTTP/1.1 {resp.status_code} {resp.reason}\\n\\n{resp.text[:500]}"
                        findings.append(finding)
                except Exception:
                    pass

        return findings, {"probes": probes_sent, "endpoints_fuzzed": len(endpoints)}

    def _audit_rbac_matrix(self, base_url: str, session_mgr: DKSecSessionManager, user_b_token: str, spec_data: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        probes = 0
        endpoints = spec_data.get("endpoints_list", [])[:5]
        
        user_b_headers = {"Authorization": f"Bearer {user_b_token}"}
        
        for ep in endpoints:
            target = urllib.parse.urljoin(base_url, ep)
            probes += 1
            try:
                # User A (Admin) creates/accesses resource
                resp_a = session_mgr.session.get(target, timeout=4, verify=False)
                if resp_a.status_code == 200:
                    # User B (Low privilege) attempts access
                    resp_b = requests.get(target, headers=user_b_headers, timeout=4, verify=False)
                    if resp_b.status_code == 200 and len(resp_b.content) == len(resp_a.content):
                        finding = self.create_finding(
                            finding_id=f"DAST-RBAC-BOLA-{probes:03d}",
                            title=f"Broken Object Level Authorization (BOLA) in {ep}",
                            severity=Severity.HIGH,
                            description=f"Endpoint `{ep}` returned identical data for User A and User B, indicating lack of authorization checks.",
                            tool="RBAC Matrix Auditor",
                            target=target,
                            cwe="CWE-285",
                            owasp="OWASP API1:2023-Broken Object Level Authorization",
                            remediation="Implement resource-level authorization checks ensuring the caller owns the requested object."
                        )
                        finding.curl_command = f"curl -X GET '{target}' -H 'Authorization: Bearer {user_b_token}'"
                        finding.raw_request = f"GET {target} HTTP/1.1\\nAuthorization: Bearer {user_b_token}"
                        finding.raw_response = f"HTTP/1.1 {resp_b.status_code} {resp_b.reason}\\n\\n{resp_b.text[:500]}"
                        findings.append(finding)
            except Exception:
                pass
                
        return findings, {"probes": probes}
"""
content += "\n" + methods

with open("dksec/stages/stage4_dast_api.py", "w") as f:
    f.write(content)
