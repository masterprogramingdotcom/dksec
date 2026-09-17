"""
Data models for OmniSec Product Security Lifecycle Orchestrator.
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
        weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "INFO": 0,
        }
        return weights.get(self.value, 0)

    @property
    def color(self) -> str:
        colors = {
            "CRITICAL": "#dc2626", # Red
            "HIGH": "#ea580c",     # Orange
            "MEDIUM": "#eab308",   # Yellow
            "LOW": "#3b82f6",      # Blue
            "INFO": "#64748b",     # Slate
        }
        return colors.get(self.value, "#64748b")


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
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    sla_days: int = 30
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class ThreatItem:
    id: str
    title: str
    category: str  # STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
    component: str
    severity: Severity
    description: str
    impact: str
    mitigation: str
    status: str = "Identified"  # Identified, Mitigated, Accepted

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
    status: str  # PASS, FAIL, MANUAL_VERIFY, NA
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WSTGChecklist:
    id: str
    category: str
    name: str
    status: str = "UNTESTED"
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
class OmniSecReport:
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
            "stage_results": {k: v.to_dict() for k, v in self.stage_results.items()},
            "total_findings": len(self.all_findings),
            "findings": [f.to_dict() for f in self.all_findings],
        }
