"""
Enterprise-Grade Data models for DKSec Product Security Lifecycle Orchestrator.
Supports SARIF 2.1.0, CycloneDX 1.5 SBOM, OWASP ASVS 4.0, WSTG 4.2, STRIDE, OpenSSF Scorecard, and MITRE ATT&CK.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import datetime
import hashlib
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        return weights.get(self.value, 0)

    @property
    def color(self) -> str:
        colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#64748b",
        }
        return colors.get(self.value, "#64748b")

    @property
    def sarif_level(self) -> str:
        if self.value in ("CRITICAL", "HIGH"):
            return "error"
        elif self.value == "MEDIUM":
            return "warning"
        elif self.value == "LOW":
            return "note"
        return "none"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    RETESTED = "RETESTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RISK_ACCEPTED = "RISK_ACCEPTED"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    stage_id: int
    stage_name: str
    tool: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    target: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss_score: Optional[float] = None
    mitre_attack: Optional[str] = None  # e.g., T1190, T1078
    remediation: str = ""
    remediation_diff: Optional[str] = None  # Unified diff patch suggestion
    curl_command: Optional[str] = None  # Reproducible cURL PoC
    raw_request: Optional[str] = None   # Raw HTTP request evidence
    raw_response: Optional[str] = None  # Raw HTTP response evidence
    status: FindingStatus = FindingStatus.OPEN
    sla_days: int = 30
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    references: List[str] = field(default_factory=list)
    ai_triage: Optional[str] = None  # TRUE_POSITIVE, FALSE_POSITIVE, SUSPICIOUS
    ai_confidence: Optional[float] = None  # 0.0 to 1.0
    ai_analysis: Optional[str] = None  # Smart LLM contextual rationale


    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class SBOMComponent:
    name: str
    version: str
    purl: str
    ecosystem: str  # pypi, npm, golang, maven
    license: Optional[str] = None
    direct: bool = True
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_cyclonedx(self) -> Dict[str, Any]:
        comp = {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "bom-ref": self.purl
        }
        if self.license:
            comp["licenses"] = [{"license": {"id": self.license}}]
        return comp


@dataclass
class ThreatItem:
    id: str
    title: str
    category: str  # STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege
    component: str
    severity: Severity
    description: str
    impact: str
    mitigation: str
    mitre_attack: str = "T1190"
    status: str = "Identified"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ASVSRequirement:
    id: str
    chapter: str
    level: int  # 1, 2, 3
    description: str
    cwe: str
    status: str = "MANUAL_VERIFY"  # PASS, FAIL, MANUAL_VERIFY, NA
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WSTGChecklist:
    id: str
    category: str
    name: str
    status: str = "UNTESTED"  # PASS, FAIL, UNTESTED, NA
    tester_notes: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GateVerdict:
    approved: bool
    status: str  # APPROVED, CONDITIONAL_APPROVAL, BLOCKED
    score: float  # 0.0 to 100.0
    critical_count: int
    high_count: int
    reasons: List[str]
    signoff_hash: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StageResult:
    stage_id: int
    stage_name: str
    recommended_tools: str
    what_it_covers: str
    success: bool
    execution_time_seconds: float
    findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "stage_name": self.stage_name,
            "recommended_tools": self.recommended_tools,
            "what_it_covers": self.what_it_covers,
            "success": self.success,
            "execution_time_seconds": round(self.execution_time_seconds, 2),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "metrics": self.metrics,
            "details": self.details,
            "logs": self.logs,
        }


@dataclass
class DKSecReport:
    project_name: str
    target_path: str
    target_url: Optional[str]
    timestamp: str
    duration_seconds: float
    stages_executed: List[int]
    stage_results: Dict[int, StageResult]
    all_findings: List[Finding]
    severity_counts: Dict[str, int]
    overall_score: float
    gate_verdict: GateVerdict
    sbom_components: List[SBOMComponent] = field(default_factory=list)
    ai_executive_summary: Optional[str] = None
    tech_profile: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": self.project_name,
            "target_path": self.target_path,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "stages_executed": self.stages_executed,
            "overall_score": round(self.overall_score, 1),
            "severity_counts": self.severity_counts,
            "gate_verdict": self.gate_verdict.to_dict(),
            "ai_executive_summary": self.ai_executive_summary,
            "tech_profile": self.tech_profile,
            "stage_results": {k: v.to_dict() for k, v in self.stage_results.items()},
            "total_findings": len(self.all_findings),
            "findings": [f.to_dict() for f in self.all_findings],
            "sbom_components": [asdict(c) for c in self.sbom_components]
        }


