"""
Stage 8: Security Signoff
Recommended Repo: OpenSSF Scorecard (https://github.com/ossf/scorecard)
What it covers: Automated security-posture checks, repository/security-policy/release controls
"""

import os
import json
import hashlib
import datetime
from typing import List, Dict, Any, Tuple
from omnisec.stages.base import BaseStage
from omnisec.models import Finding, Severity, FindingStatus, GateVerdict
from omnisec.config import OmniSecConfig


class Stage8Signoff(BaseStage):
    def __init__(self):
        super().__init__(8)

    def run(self, config: OmniSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        self.log("Evaluating OpenSSF Scorecard Security Posture & Release Gate Criteria")

        target = config.target_path
        scorecard_checks = self._evaluate_openssf_scorecard(target)
        self.log(f"Completed {len(scorecard_checks)} OpenSSF Scorecard checks.")

        findings: List[Finding] = []
        for check in scorecard_checks:
            if check["score"] < 5.0:
                sev = Severity.HIGH if check["score"] == 0.0 else Severity.MEDIUM
                findings.append(self.create_finding(
                    finding_id=f"OSSF-{check['name'].upper().replace(' ', '-')}",
                    title=f"[OpenSSF Scorecard] {check['name']} Score: {check['score']}/10",
                    severity=sev,
                    description=f"OpenSSF Scorecard check '{check['name']}' scored {check['score']}/10.\nReason: {check['reason']}",
                    tool="OpenSSF Scorecard",
                    cwe="CWE-16",
                    owasp="OpenSSF Scorecard Security Best Practices",
                    remediation=check["remediation"],
                    status=FindingStatus.OPEN,
                    references=["https://github.com/ossf/scorecard"]
                ))

        # Calculate OpenSSF Scorecard overall score (average out of 10 converted to 0-100)
        avg_scorecard = sum(c["score"] for c in scorecard_checks) / len(scorecard_checks) * 10

        # Run Release Gatekeeper Decision Engine
        all_prior_findings: List[Finding] = context.get("deduped_findings", [])
        if not all_prior_findings:
            # fallback: aggregate from stage_results
            for s in context.get("stage_results", {}).values():
                all_prior_findings.extend(s.findings)

        crit_count = sum(1 for f in all_prior_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_prior_findings if f.severity == Severity.HIGH)

        # Composite overall health score
        # Deduct 15 pts per Critical, 5 pts per High, 2 pts per Medium
        med_count = sum(1 for f in all_prior_findings if f.severity == Severity.MEDIUM)
        penalty = (crit_count * 15) + (high_count * 5) + (med_count * 2)
        overall_score = max(0.0, min(100.0, 100.0 - penalty))

        # Gate decision logic
        reasons = []
        approved = True
        status = "APPROVED"

        if crit_count > config.signoff_max_critical:
            approved = False
            reasons.append(f"Found {crit_count} CRITICAL vulnerabilities (threshold is {config.signoff_max_critical})")

        if high_count > config.signoff_max_high:
            approved = False
            reasons.append(f"Found {high_count} HIGH vulnerabilities (threshold is {config.signoff_max_high})")

        if overall_score < config.signoff_min_score:
            approved = False
            reasons.append(f"Overall security score {overall_score:.1f} is below required threshold {config.signoff_min_score:.1f}")

        if not approved:
            status = "BLOCKED"
        elif high_count > 0 or med_count > 3:
            status = "CONDITIONAL_APPROVAL"
            reasons.append("Approved with conditional remediation required before next release cycle.")
        else:
            reasons.append("All release gating criteria satisfied successfully.")

        # Generate Cryptographic Signoff Stamp
        signoff_payload = f"{config.project_name}|{status}|{overall_score}|{crit_count}|{high_count}|{datetime.datetime.now(datetime.timezone.utc).isoformat()}"
        signoff_hash = hashlib.sha256(signoff_payload.encode()).hexdigest()

        verdict = GateVerdict(
            approved=approved,
            status=status,
            score=round(overall_score, 1),
            critical_count=crit_count,
            high_count=high_count,
            reasons=reasons,
            signoff_hash=signoff_hash,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )

        context["gate_verdict"] = verdict
        context["overall_score"] = overall_score

        metrics = {
            "openssf_average_score": round(avg_scorecard, 1),
            "gate_status": status,
            "overall_security_score": round(overall_score, 1),
            "signoff_hash": signoff_hash,
            "release_approved": approved
        }

        details = {
            "scorecard_checks": scorecard_checks,
            "gate_verdict": verdict.to_dict()
        }

        return findings, metrics, details

    def _evaluate_openssf_scorecard(self, target: str) -> List[Dict[str, Any]]:
        checks = []

        # 1. Security Policy check
        sec_policy_found = False
        candidates = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]
        for c in candidates:
            if os.path.exists(os.path.join(target, c)):
                sec_policy_found = True
                break
        checks.append({
            "name": "Security-Policy",
            "score": 10.0 if sec_policy_found else 0.0,
            "reason": "SECURITY.md policy file found." if sec_policy_found else "Missing SECURITY.md vulnerability disclosure policy.",
            "remediation": "Create a SECURITY.md file detailing security reporting channels and response SLAs."
        })

        # 2. Dependency Update Tool
        dep_tool_found = False
        dep_candidates = [".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc.json"]
        for c in dep_candidates:
            if os.path.exists(os.path.join(target, c)):
                dep_tool_found = True
                break
        checks.append({
            "name": "Dependency-Update-Tool",
            "score": 10.0 if dep_tool_found else 2.0,
            "reason": "Automated dependency manager configured." if dep_tool_found else "No Dependabot or Renovate configuration found.",
            "remediation": "Enable Dependabot or Renovate to automatically update dependencies with security patches."
        })

        # 3. Binary Artifacts check
        binary_exts = {".exe", ".so", ".dll", ".bin", ".jar", ".class", ".pyc", ".iso"}
        binaries_found = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "venv", ".venv", "__pycache__"]]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in binary_exts:
                    binaries_found.append(f)

        checks.append({
            "name": "Binary-Artifacts",
            "score": 0.0 if binaries_found else 10.0,
            "reason": f"Found {len(binaries_found)} binary artifacts in repository." if binaries_found else "No compiled binary artifacts checked into source code.",
            "remediation": "Remove compiled binary artifacts from source control; build them from verified source in CI."
        })

        # 4. Dangerous Workflows (GitHub Actions)
        workflow_dir = os.path.join(target, ".github", "workflows")
        dangerous_patterns = []
        if os.path.exists(workflow_dir):
            for wf in os.listdir(workflow_dir):
                if wf.endswith((".yml", ".yaml")):
                    try:
                        with open(os.path.join(workflow_dir, wf), "r") as f: content = f.read()
                        if "pull_request_target" in content:
                            dangerous_patterns.append(f"{wf}: pull_request_target trigger")
                        if "${{ github.event." in content and "run:" in content:
                            dangerous_patterns.append(f"{wf}: untrusted script injection context")
                    except Exception:
                        pass

        checks.append({
            "name": "Dangerous-Workflow",
            "score": 4.0 if dangerous_patterns else 10.0,
            "reason": f"Dangerous CI workflow constructs: {', '.join(dangerous_patterns)}" if dangerous_patterns else "CI workflows follow safe execution practices.",
            "remediation": "Avoid pull_request_target with checkout of untrusted PR branches and sanitize github.event parameters."
        })

        # 5. Branch Protection & Code Review
        git_dir = os.path.join(target, ".git")
        checks.append({
            "name": "Branch-Protection",
            "score": 8.0 if os.path.exists(git_dir) else 5.0,
            "reason": "Git version control active; verify branch protection rules in GitHub/GitLab repository settings.",
            "remediation": "Enable branch protection on main/master requiring PR review approvals and status checks before merge."
        })

        # 6. License
        license_found = any(os.path.exists(os.path.join(target, f)) for f in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"])
        checks.append({
            "name": "License",
            "score": 10.0 if license_found else 3.0,
            "reason": "Software license file identified." if license_found else "Missing LICENSE file in repository.",
            "remediation": "Include a standardized LICENSE file defining terms and intellectual property rights."
        })

        return checks
