"""
Unit and integration tests for OmniSec 9-stage orchestrator (Enterprise Edition).
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
from omnisec.reporters import (
    HtmlReporter, JsonReporter, MarkdownReporter,
    SarifReporter, CycloneDXReporter
)


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
        self.assertIn("mermaid_dfd", details)

    def test_stage2_requirements_asvs(self):
        stage = Stage2Requirements()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("overall_compliance_rate", metrics)
        self.assertTrue(metrics["total_requirements"] >= 15)

    def test_stage3_sast_sca_secrets(self):
        stage = Stage3SastScaSecrets()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(metrics["secret_leaks_count"] > 0)
        self.assertTrue(metrics["sast_vulnerabilities_count"] > 0)
        self.assertTrue(metrics["sca_vulnerabilities_count"] > 0)
        self.assertTrue(metrics["total_dependencies_inventoried"] > 0)

    def test_stage4_dast_api_static(self):
        stage = Stage4DastApi()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("code_routes_audited", metrics)

    def test_stage5_manual_wstg(self):
        stage = Stage5ManualWstg()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(metrics["total_test_cases"] >= 15)

    def test_stage6_vapt_static(self):
        stage = Stage6Vapt()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("attack_surface", details)

    def test_stage7_fix_retest(self):
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
        self.assertTrue(os.path.exists(metrics["jira_export_file"]))

    def test_stage8_signoff(self):
        stage = Stage8Signoff()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertIn("gate_decision", metrics)
        self.assertIn("signoff_audit_hash", metrics)
        self.assertEqual(len(details["scorecard_18_checks"]), 18)

    def test_stage9_monitoring(self):
        stage = Stage9Monitoring()
        findings, metrics, details = stage.run(self.config, self.context)
        self.assertTrue(os.path.exists(metrics["wazuh_rules_file"]))
        self.assertTrue(os.path.exists(metrics["sigma_rules_file"]))
        self.assertTrue(os.path.exists(metrics["incident_runbook_file"]))

    def test_full_runner_and_all_reporters(self):
        runner = OmniSecRunner(self.config)
        report = runner.run()
        self.assertIsNotNone(report)
        self.assertEqual(len(report.stages_executed), 9)

        html_path = os.path.join(self.tmp_dir, "report.html")
        json_path = os.path.join(self.tmp_dir, "report.json")
        md_path = os.path.join(self.tmp_dir, "report.md")
        sarif_path = os.path.join(self.tmp_dir, "results.sarif")
        sbom_path = os.path.join(self.tmp_dir, "cyclonedx.json")

        HtmlReporter.generate(report, html_path)
        JsonReporter.generate(report, json_path)
        MarkdownReporter.generate(report, md_path)
        SarifReporter.generate(report, sarif_path)
        CycloneDXReporter.generate(report, sbom_path)

        self.assertTrue(os.path.exists(html_path))
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(md_path))
        self.assertTrue(os.path.exists(sarif_path))
        self.assertTrue(os.path.exists(sbom_path))


if __name__ == "__main__":
    unittest.main()
