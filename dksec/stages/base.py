"""
Base Stage class for all 9 Product Security lifecycle phases.
"""

import abc
import shutil
import subprocess
import time
from typing import Dict, Any, List, Optional, Tuple
from dksec.models import StageResult, Finding, Severity, FindingStatus
from dksec.config import DKSecConfig, STAGE_METADATA


class BaseStage(abc.ABC):
    def __init__(self, stage_id: int):
        self.stage_id = stage_id
        meta = STAGE_METADATA.get(stage_id, {})
        self.stage_name = meta.get("name", f"Stage {stage_id}")
        self.recommended_tools = meta.get("recommended_repo", "")
        self.what_it_covers = meta.get("what_it_covers", "")
        self.logs: List[str] = []

    def log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{self.stage_name}] {message}"
        self.logs.append(entry)

    def is_tool_installed(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def execute_command(self, cmd: List[str], cwd: Optional[str] = None, timeout: int = 120) -> Tuple[int, str, str]:
        """Safely execute an external CLI command with timeout."""
        try:
            res = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return -1, "", f"Timeout after {timeout}s"
        except Exception as e:
            self.log(f"Command execution error: {str(e)}")
            return -1, "", str(e)

    def create_finding(
        self,
        finding_id: str,
        title: str,
        severity: Severity,
        description: str,
        tool: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        target: Optional[str] = None,
        cwe: Optional[str] = None,
        owasp: Optional[str] = None,
        cvss_score: Optional[float] = None,
        remediation: str = "",
        status: FindingStatus = FindingStatus.OPEN,
        references: Optional[List[str]] = None,
        remediation_diff: Optional[str] = None,
        curl_command: Optional[str] = None,
        raw_request: Optional[str] = None,
        raw_response: Optional[str] = None
    ) -> Finding:
        # Default SLA based on severity
        sla_map = {
            Severity.CRITICAL: 7,
            Severity.HIGH: 14,
            Severity.MEDIUM: 30,
            Severity.LOW: 90,
            Severity.INFO: 180,
        }
        return Finding(
            id=finding_id,
            title=title,
            severity=severity,
            description=description,
            stage_id=self.stage_id,
            stage_name=self.stage_name,
            tool=tool,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            target=target,
            cwe=cwe,
            owasp=owasp,
            cvss_score=cvss_score,
            remediation=remediation,
            remediation_diff=remediation_diff,
            curl_command=curl_command,
            raw_request=raw_request,
            raw_response=raw_response,
            status=status,
            sla_days=sla_map.get(severity, 30),
            references=references or []
        )

    def execute(self, config: DKSecConfig, context: Dict[str, Any]) -> StageResult:
        """Wrapper around run() to measure execution time, catch errors, and package StageResult."""
        self.logs.clear()
        self.log(f"Starting {self.stage_name} ({self.recommended_tools})")
        start_time = time.time()
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        details: Dict[str, Any] = {}
        success = True

        try:
            findings, metrics, details = self.run(config, context)
            self.log(f"Completed with {len(findings)} findings.")
        except Exception as e:
            success = False
            self.log(f"ERROR executing stage: {str(e)}")
            details["error"] = str(e)

        elapsed = time.time() - start_time
        return StageResult(
            stage_id=self.stage_id,
            stage_name=self.stage_name,
            recommended_tools=self.recommended_tools,
            what_it_covers=self.what_it_covers,
            success=success,
            execution_time_seconds=elapsed,
            findings=findings,
            metrics=metrics,
            details=details,
            logs=list(self.logs),
        )

    @abc.abstractmethod
    def run(self, config: DKSecConfig, context: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any], Dict[str, Any]]:
        """
        Execute the stage logic.
        Returns: (findings_list, metrics_dict, details_dict)
        """
        pass
