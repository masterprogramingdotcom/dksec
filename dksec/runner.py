"""
Workflow Orchestration Engine for DKSec.
Coordinates sequential or selective execution of all 9 Product Security lifecycle stages.
"""

import time
import os
import datetime
from typing import List, Dict, Any, Optional, Callable
from dksec.config import DKSecConfig, STAGE_METADATA
from dksec.models import (
    StageResult, Finding, Severity, FindingStatus,
    GateVerdict, DKSecReport, SBOMComponent
)
from dksec.stages import get_stage_instance


class DKSecRunner:
    def __init__(self, config: DKSecConfig, event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.config = config
        self.event_callback = event_callback or (lambda evt, payload: None)
        self.context: Dict[str, Any] = {
            "stage_results": {},
            "all_findings": [],
            "deduped_findings": [],
            "sbom_components": []
        }

    def emit(self, event_type: str, **kwargs):
        payload = {"timestamp": time.time(), **kwargs}
        self.event_callback(event_type, payload)

    def run(self, selected_stages: Optional[List[int]] = None) -> DKSecReport:
        start_time = time.time()
        
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

        total_duration = time.time() - start_time
        deduped = self.context.get("deduped_findings") or all_raw_findings

        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in deduped:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        overall_score = self.context.get("overall_score")
        if overall_score is None:
            # Weighted penalty (normalized by total findings to prevent excessive punishment
            # on large scans with many low-severity items)
            import math as _math
            n_crit = counts["CRITICAL"]
            n_high = counts["HIGH"]
            n_med  = counts["MEDIUM"]
            n_low  = counts["LOW"]
            # Raw penalty per severity tier
            raw_penalty = (n_crit * 20) + (n_high * 7) + (n_med * 2) + (n_low * 0.5)
            # Logarithmic decay: score = 100 * e^(-k*penalty)
            # k chosen so that 1 critical → ~82, 3 criticals → ~55, 7 criticals → ~25
            k = 0.01
            overall_score = round(max(0.0, min(100.0, 100.0 * _math.exp(-k * raw_penalty))), 1)


        verdict = self.context.get("gate_verdict")
        if verdict is None:
            approved = counts["CRITICAL"] == 0 and counts["HIGH"] == 0
            verdict = GateVerdict(
                approved=approved,
                status="APPROVED" if approved else "BLOCKED",
                score=round(overall_score, 1),
                critical_count=counts["CRITICAL"],
                high_count=counts["HIGH"],
                reasons=["Threshold check evaluated."] if approved else [f"Found {counts['CRITICAL']} Critical, {counts['HIGH']} High."],
                signoff_hash="dksec-" + os.urandom(8).hex(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
            )

        sbom_components = self.context.get("sbom_components", [])
        tech_profile = self.context.get("tech_profile", {})

        # Execute Smart LLM Analysis if enabled
        ai_summary = None
        if self.config.llm and self.config.llm.enabled:
            try:
                self.emit("llm_started", provider=self.config.llm.provider, model=self.config.llm.model)
                from dksec.llm import LLMAssistant
                assistant = LLMAssistant(self.config.llm)

                # 1. Triage top findings
                if self.config.llm.triage_findings:
                    for f in deduped:
                        if f.severity in (Severity.CRITICAL, Severity.HIGH) or len(deduped) <= 8:
                            triage_verdict, conf, analysis = assistant.triage_finding(f)
                            f.ai_triage = triage_verdict
                            f.ai_confidence = conf
                            f.ai_analysis = analysis

                # 2. Executive AI Summary
                if self.config.llm.generate_executive_summary:
                    temp_rep = DKSecReport(
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
                        gate_verdict=verdict,
                        sbom_components=sbom_components,
                        tech_profile=tech_profile
                    )
                    ai_summary = assistant.generate_executive_summary(temp_rep)
                self.emit("llm_completed")
            except Exception as e:
                self.emit("llm_error", error=str(e))

        report = DKSecReport(
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
            gate_verdict=verdict,
            sbom_components=sbom_components,
            ai_executive_summary=ai_summary,
            tech_profile=tech_profile
        )


        self.emit("run_completed", total_findings=len(deduped), overall_score=report.overall_score)
        return report

