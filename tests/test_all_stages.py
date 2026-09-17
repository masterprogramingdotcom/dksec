"""
Unit and integration tests for OmniSec 9-stage orchestrator.
"""

import unittest
import os
import tempfile
from omnisec.config import OmniSecConfig
from omnisec.runner import OmniSecRunner
from omnisec.models import Severity, FindingStatus
from omnisec.stages import (
    Stage1ThreatModel, Stage2Requirements, Stage3SastScaSecrets,
    Stage4DastApi, Stage5ManualWstg, Stage6Vapt,
    Stage7FixRetest, Stage8Signoff, Stage9Monitoring
)
from omnisec.reporters import HtmlReporter, JsonReporter, MarkdownReporter


class TestOmniSecStages(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config = OmniSecConfig(
            project_name="Unit Test App",
            target_path="samples/app",
            output_dir=self.tmp_dir
        )
        self.context = {"stage_results": {}, "all_findings": [], "deduped_findings": []}

    def test_stage1_threat_model(self):
        stage = Stage1ThreatModel()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(len(findings) > 0)
        self.assertIn("threat_dragon_model_file", metrics)
        self.assertTrue(os.path.exists(metrics["threat_dragon_model_file"]))

    def test_stage2_requirements_asvs(self):
        stage = Stage2Requirements()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("compliance_percentage", metrics)
        self.assertTrue(metrics["total_requirements"] >= 10)

    def test_stage3_sast_sca_secrets(self):
        stage = Stage3SastScaSecrets()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(metrics["secret_leaks_found"] > 0)
        self.assertTrue(metrics["sast_vulnerabilities_found"] > 0)
        self.assertTrue(metrics["sca_vulnerabilities_found"] > 0)

    def test_stage4_dast_api_static(self):
        stage = Stage4DastApi()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertEqual(metrics["scan_mode"], "Static API Surface & Spec Audit")

    def test_stage5_manual_wstg(self):
        stage = Stage5ManualWstg()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(metrics["total_test_cases"] > 0)

    def test_stage6_vapt_static(self):
        stage = Stage6Vapt()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("attack_surface", details)

    def test_stage7_fix_retest(self):
        # Populate context with mock findings
        s3 = Stage3SastScaSecrets()
        f_list, _, _ = s3.run(self.config, self.context)
        from omnisec.models import StageResult
        self.context["stage_results"][3] = StageResult(
            stage_id=3, stage_name="SAST", recommended_tools="Semgrep",
            what_it_covers="SAST", success=True, execution_time_seconds=0.1,
            findings=f_list
        )
        stage = Stage7FixRetest()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(metrics["total_deduplicated_findings"] > 0)
        self.assertTrue(os.path.exists(metrics["defectdojo_export_file"]))

    def test_stage8_signoff(self):
        stage = Stage8Signoff()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("gate_status", metrics)
        self.assertIn("signoff_hash", metrics)

    def test_stage9_monitoring(self):
        stage = Stage9Monitoring()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(os.path.exists(metrics["wazuh_rules_file"]))
        self.assertTrue(os.path.exists(metrics["incident_runbook_file"]))

    def test_full_runner_and_reports(self):
        runner = OmniSecRunner(self.config)
        report = runner.run()
        self.assertIsNotNone(report)
        self.assertEqual(len(report.stages_executed), 9)

        html_path = os.path.join(self.tmp_dir, "report.html")
        json_path = os.path.join(self.tmp_dir, "report.json")
        md_path = os.path.join(self.tmp_dir, "report.md")

        HtmlReporter.generate(report, html_path)
        JsonReporter.generate(report, json_path)
        MarkdownReporter.generate(report, md_path)

        self.assertTrue(os.path.exists(html_path))
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(md_path))


if __name__ == "__main__":
    unittest.main()
