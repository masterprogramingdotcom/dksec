"""
Configuration manager for DKSec.
Supports YAML file configuration, environment variables, and CLI arguments.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from dksec import yaml_compat as yaml
from dksec.auth import AuthConfig
from dksec.llm import LLMConfig




STAGE_METADATA = {
    1: {
        "name": "Architecture & Threat Model",
        "recommended_repo": "OWASP Threat Dragon",
        "github": "https://github.com/OWASP/threat-dragon",
        "what_it_covers": "Data-flow diagrams, threat identification, STRIDE/LINDDUN/CIA-style modeling and mitigations",
        "default_enabled": True,
    },
    2: {
        "name": "Security Requirements",
        "recommended_repo": "OWASP ASVS",
        "github": "https://github.com/OWASP/ASVS",
        "what_it_covers": "Application-security requirements for design, development and verification",
        "default_enabled": True,
    },
    3: {
        "name": "SAST + SCA + Secret Scanning",
        "recommended_repo": "Semgrep + Trivy + Gitleaks",
        "github": "https://github.com/semgrep/semgrep | https://github.com/aquasecurity/trivy | https://github.com/gitleaks/gitleaks",
        "what_it_covers": "Source-code analysis, dependency/container scanning, secrets",
        "default_enabled": True,
    },
    4: {
        "name": "DAST + API Security Testing",
        "recommended_repo": "OWASP ZAP + OWASP API Security",
        "github": "https://github.com/zaproxy/zaproxy | https://github.com/OWASP/API-Security",
        "what_it_covers": "Web/API dynamic testing, automated scanning and API-specific security guidance",
        "default_enabled": True,
    },
    5: {
        "name": "Manual Security Testing",
        "recommended_repo": "OWASP WSTG",
        "github": "https://github.com/OWASP/wstg",
        "what_it_covers": "Comprehensive manual web/API security-testing methodology and checklist",
        "default_enabled": True,
    },
    6: {
        "name": "Penetration Test / VAPT",
        "recommended_repo": "OWASP WSTG + Nuclei + OWASP Amass",
        "github": "https://github.com/projectdiscovery/nuclei | https://github.com/owasp-amass/amass",
        "what_it_covers": "Pentest methodology, vulnerability scanning and attack-surface discovery",
        "default_enabled": True,
    },
    7: {
        "name": "Fix & Retest",
        "recommended_repo": "OWASP DefectDojo",
        "github": "https://github.com/DefectDojo/django-DefectDojo",
        "what_it_covers": "Vulnerability/finding management, remediation tracking, verification and retesting",
        "default_enabled": True,
    },
    8: {
        "name": "Security Signoff",
        "recommended_repo": "OpenSSF Scorecard",
        "github": "https://github.com/ossf/scorecard",
        "what_it_covers": "Automated security-posture checks, repository/security-policy/release controls",
        "default_enabled": True,
    },
    9: {
        "name": "Monitoring & Incident Response",
        "recommended_repo": "Wazuh",
        "github": "https://github.com/wazuh/wazuh",
        "what_it_covers": "SIEM/XDR, log analysis, vulnerability detection, file-integrity monitoring and incident response",
        "default_enabled": True,
    },
}


@dataclass
class StageConfig:
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)


def resolve_target_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    p = str(path).strip()
    if not p:
        return None

    # Expand user home ~
    p = os.path.expanduser(p)

    # 1. Direct match (absolute or relative to current working directory)
    if os.path.exists(p):
        return os.path.abspath(p)

    cwd_candidate = os.path.abspath(os.path.join(os.getcwd(), p))
    if os.path.exists(cwd_candidate):
        return cwd_candidate

    # 2. Sibling directory relative to cwd (e.g. ../python-genievrse-integration-hub)
    parent_dir = os.path.dirname(os.getcwd())
    sibling_candidate = os.path.abspath(os.path.join(parent_dir, p))
    if os.path.exists(sibling_candidate):
        return sibling_candidate

    # 3. User Desktop directory and subdirectories
    desktop = os.path.expanduser("~/Desktop")
    if os.path.exists(desktop):
        desktop_candidate = os.path.join(desktop, p)
        if os.path.exists(desktop_candidate):
            return desktop_candidate
        try:
            for root, dirs, _ in os.walk(desktop):
                if p in dirs:
                    return os.path.join(root, p)
                if root.count(os.sep) - desktop.count(os.sep) >= 2:
                    dirs.clear()
        except Exception:
            pass

    # 4. User home directory
    home = os.path.expanduser("~")
    home_candidate = os.path.join(home, p)
    if os.path.exists(home_candidate):
        return home_candidate

    return p


@dataclass
class DKSecConfig:
    project_name: str = "Application Security Review"
    target_path: Optional[str] = "."   # None = URL-only mode (no source code provided)
    target_url: Optional[str] = None
    auth: AuthConfig = field(default_factory=AuthConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    git_repo_url: Optional[str] = None
    output_dir: str = "./reports"
    report_formats: List[str] = field(default_factory=lambda: ["html", "json", "markdown"])
    stages: Dict[int, StageConfig] = field(default_factory=dict)
    
    # Signoff gating criteria
    signoff_max_critical: int = 0
    signoff_max_high: int = 0
    signoff_min_score: float = 75.0
    
    # Integrations
    defectdojo_url: Optional[str] = None
    defectdojo_api_key: Optional[str] = None
    defectdojo_product_id: Optional[int] = None
    wazuh_api_url: Optional[str] = None
    wazuh_api_user: Optional[str] = None
    wazuh_api_password: Optional[str] = None

    def __post_init__(self):
        # Resolve target_path if specified
        if self.target_path:
            self.target_path = resolve_target_path(self.target_path)

        # Initialize default stages if not set
        for stage_id in range(1, 10):
            if stage_id not in self.stages:
                self.stages[stage_id] = StageConfig(enabled=True)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "DKSecConfig":
        config = cls()
        if config_path and os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                if "project_name" in data:
                    config.project_name = data["project_name"]
                if "target_path" in data:
                    config.target_path = data["target_path"]
                if "target_url" in data:
                    config.target_url = data["target_url"]
                if "auth" in data:
                    config.auth = AuthConfig.from_dict(data["auth"])
                if "llm" in data:
                    config.llm = LLMConfig.from_dict(data["llm"])
                if "git_repo_url" in data:
                    config.git_repo_url = data["git_repo_url"]
                if "output_dir" in data:
                    config.output_dir = data["output_dir"]
                if "report_formats" in data:
                    config.report_formats = data["report_formats"]
                if "signoff" in data:
                    signoff = data["signoff"]
                    config.signoff_max_critical = signoff.get("max_critical", config.signoff_max_critical)
                    config.signoff_max_high = signoff.get("max_high", config.signoff_max_high)
                    config.signoff_min_score = signoff.get("min_score", config.signoff_min_score)
                if "defectdojo" in data:
                    dd = data["defectdojo"]
                    config.defectdojo_url = dd.get("url")
                    config.defectdojo_api_key = dd.get("api_key")
                    config.defectdojo_product_id = dd.get("product_id")
                if "wazuh" in data:
                    wz = data["wazuh"]
                    config.wazuh_api_url = wz.get("url")
                    config.wazuh_api_user = wz.get("user")
                    config.wazuh_api_password = wz.get("password")
                if "stages" in data:
                    for s_id, s_conf in data["stages"].items():
                        try:
                            s_int = int(s_id)
                            config.stages[s_int] = StageConfig(
                                enabled=s_conf.get("enabled", True),
                                params=s_conf.get("params", {})
                            )
                        except ValueError:
                            pass
        return config

    def save(self, file_path: str):
        data = {
            "project_name": self.project_name,
            "target_path": self.target_path,
            "target_url": self.target_url,
            "auth": self.auth.to_dict(),
            "llm": self.llm.to_dict(),
            "git_repo_url": self.git_repo_url,
            "output_dir": self.output_dir,
            "report_formats": self.report_formats,
            "signoff": {

                "max_critical": self.signoff_max_critical,
                "max_high": self.signoff_max_high,
                "min_score": self.signoff_min_score,
            },
            "stages": {
                str(k): {"enabled": v.enabled, "params": v.params}
                for k, v in self.stages.items()
            }
        }
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False)

