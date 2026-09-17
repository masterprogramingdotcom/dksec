"""
Workflow Orchestration Engine for OmniSec.
Coordinates sequential or selective execution of all 9 Product Security lifecycle stages.
"""

import time
import os
import datetime
from typing import List, Dict, Any, Optional, Callable
from omnisec.config import OmniSecConfig, STAGE_METADATA
from omnisec.models import (
    StageResult, Finding, Severity, FindingStatus,
    GateVerdict, OmniSecReport
)
from omnisec.stages import get_stage_instance


class OmniSecRunner:
    def __init__(self, config: OmniSecConfig, event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.config = config
        self.event_callback = event_callback or (lambda evt, payload: None)
        self.context: Dict[str, Any] = {
            "stage_results": {},
            "all_findings": [],
            "deduped_findings": []
        }

    def emit(self, event_type: str, **kwargs):
        payload = {"timestamp": time.time(), **kwargs}
        self.event_callback(event_type, payload)

    def run(self, selected_stages: Optional[List[int]] = None) -> OmniSecReport:
        start_time = time.time()
        
        # Determine stages to run
        stages_to_run = selected_stages or [
            s_id for s_id in range(1, 10)
            if self.config.stages.get(s_id) and self.config.stages[s_id].enabled
        ]
        stages_to_run.sort()

        self.emit("run_started", project=self.config.project_name, stages=stages_to_run)
        stage_results: Dict[int, StageResult] = {}
        all_raw_findings: List[Finding] = []

        for stage_id in stages_to_run:
            meta = STAGE_METADATA.get(stage_id, {})
            self.emit("stage_started", stage_id=stage_id, stage_name=meta.get("name"))

            try:
                stage_inst = get_stage_instance(stage_id)
                res = stage_inst.execute(self.config, self.context)
                stage_results[stage_id] = res
                self.context["stage_results"][stage_id] = res

                # Collect findings
                all_raw_findings.extend(res.findings)
                self.context["all_findings"] = all_raw_findings

                self.emit(
                    "stage_completed",
                    stage_id=stage_id,
                    success=res.success,
                    findings_count=len(res.findings),
                    duration=res.execution_time_seconds
                )
            except Exception as e:
                self.emit("stage_error", stage_id=stage_id, error=str(e))
                res = StageResult(
                    stage_id=stage_id,
                    stage_name=meta.get("name", f"Stage {stage_id}"),
                    recommended_tools=meta.get("recommended_repo", ""),
                    what_it_covers=meta.get("what_it_covers", ""),
                    success=False,
                    execution_time_seconds=0.0,
                    findings=[],
                    metrics={"error": str(e)},
                    details={"exception": str(e)},
                    logs=[f"Fatal exception during stage execution: {str(e)}"]
                )
                stage_results[stage_id] = res
                self.context["stage_results"][stage_id] = res

        # Post-run aggregation & Gate Verdict calculation
        total_duration = time.time() - start_time
        deduped = self.context.get("deduped_findings") or all_raw_findings

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in deduped:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        overall_score = self.context.get("overall_score")
        if overall_score is None:
            # Fallback score calculation if stage 8 was not run
            penalty = (counts["CRITICAL"] * 15) + (counts["HIGH"] * 5) + (counts["MEDIUM"] * 2)
            overall_score = max(0.0, min(100.0, 100.0 - penalty))

        verdict = self.context.get("gate_verdict")
        if verdict is None:
            # Generate default verdict
            approved = counts["CRITICAL"] == 0 and counts["HIGH"] == 0
            verdict = GateVerdict(
                approved=approved,
                status="APPROVED" if approved else "BLOCKED",
                score=round(overall_score, 1),
                critical_count=counts["CRITICAL"],
                high_count=counts["HIGH"],
                reasons=["Threshold check evaluated."] if approved else [f"Found {counts['CRITICAL']} Critical, {counts['HIGH']} High."],
                signoff_hash="omnisec-" + os.urandom(8).hex(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
            )

        report = OmniSecReport(
            project_name=self.config.project_name,
            target_path=self.config.target_path,
            target_url=self.config.target_url,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            duration_seconds=total_duration,
            stages_executed=stages_to_run,
            stage_results=stage_results,
            all_findings=deduped,
            severity_counts=counts,
            overall_score=round(overall_score, 1),
            gate_verdict=verdict
        )

        self.emit("run_completed", total_findings=len(deduped), overall_score=report.overall_score)
        return report
