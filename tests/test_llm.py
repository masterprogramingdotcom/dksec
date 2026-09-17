"""
Unit and integration tests for DKSec Dynamic LLM Smartness Engine.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import json
from dksec.models import Finding, Severity, FindingStatus, DKSecReport, GateVerdict
from dksec.config import DKSecConfig
from dksec.llm import LLMConfig, LLMAssistant
from dksec.runner import DKSecRunner


class TestDKSecLLM(unittest.TestCase):
    def test_llm_config_defaults_and_serialization(self):
        cfg = LLMConfig(
            enabled=True,
            provider="gemini",
            model="gemini-1.5-pro",
            api_key="test-key-123",
            api_base_url="https://custom.endpoint/v1"
        )
        d = cfg.to_dict()
        self.assertTrue(d["enabled"])
        self.assertEqual(d["provider"], "gemini")
        self.assertEqual(d["model"], "gemini-1.5-pro")
        self.assertEqual(d["api_key"], "test-key-123")

        reloaded = LLMConfig.from_dict(d)
        self.assertTrue(reloaded.enabled)
        self.assertEqual(reloaded.provider, "gemini")
        self.assertEqual(reloaded.model, "gemini-1.5-pro")
        self.assertEqual(reloaded.api_key, "test-key-123")
        self.assertEqual(reloaded.api_base_url, "https://custom.endpoint/v1")

    def test_provider_url_and_key_resolution(self):
        # 1. Ollama local
        ollama_cfg = LLMConfig(provider="ollama", model="llama3")
        assistant = LLMAssistant(ollama_cfg)
        self.assertEqual(assistant.base_url, "http://localhost:11434/v1")
        self.assertEqual(assistant.api_key, "ollama-local")

        # 2. OpenAI default url
        openai_cfg = LLMConfig(provider="openai", model="gpt-4o", api_key="sk-mock")
        assistant = LLMAssistant(openai_cfg)
        self.assertEqual(assistant.base_url, "https://api.openai.com/v1")
        self.assertEqual(assistant.api_key, "sk-mock")

        # 3. Gemini default url
        gemini_cfg = LLMConfig(provider="gemini", model="gemini-1.5-pro", api_key="gemini-mock")
        assistant = LLMAssistant(gemini_cfg)
        self.assertEqual(assistant.base_url, "https://generativelanguage.googleapis.com/v1beta")

    def test_heuristic_triage_fallback(self):
        cfg = LLMConfig(enabled=True)
        assistant = LLMAssistant(cfg)

        f_sql = Finding(
            id="SAST-SQLI",
            title="SQL Injection in user search query",
            stage_id=3,
            stage_name="SAST",
            tool="Semgrep",
            severity=Severity.CRITICAL,
            description="Raw concatenation in SELECT query"
        )
        verdict, conf, rationale = assistant._heuristic_triage(f_sql)
        self.assertEqual(verdict, "TRUE_POSITIVE")
        self.assertGreaterEqual(conf, 0.9)
        self.assertIn("Confirmed", rationale)

        f_header = Finding(
            id="DAST-HDR",
            title="Server Banner Header Disclosed",
            stage_id=4,
            stage_name="DAST",
            tool="ZAP",
            severity=Severity.LOW,
            description="Server header present"
        )
        verdict, conf, rationale = assistant._heuristic_triage(f_header)
        self.assertEqual(verdict, "TRUE_POSITIVE")
        self.assertIn("hygiene", rationale)

    @patch("dksec.llm.requests.post")
    def test_mock_llm_triage_positive(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "verdict": "TRUE_POSITIVE",
                        "confidence": 0.98,
                        "analysis": "Exploitable SQL injection vulnerability without query parameterization.",
                        "patch_diff": "--- a/app.py\n+++ b/app.py\n- db.execute(f'SELECT {q}')\n+ db.execute('SELECT ?', (q,))"
                    })
                }
            }]
        }
        mock_post.return_value = mock_resp

        cfg = LLMConfig(enabled=True, provider="openai", model="gpt-4o", api_key="mock-key")
        assistant = LLMAssistant(cfg)

        f = Finding(
            id="TEST-1",
            title="SQL Injection Vulnerability",
            stage_id=3,
            stage_name="SAST",
            tool="Semgrep",
            severity=Severity.CRITICAL,
            description="User input passed directly into database query"
        )

        verdict, conf, analysis = assistant.triage_finding(f)
        self.assertEqual(verdict, "TRUE_POSITIVE")
        self.assertEqual(conf, 0.98)
        self.assertIn("Exploitable SQL injection", analysis)
        self.assertIsNotNone(f.remediation_diff)
        self.assertIn("+ db.execute('SELECT ?', (q,))", f.remediation_diff)

    @patch("dksec.llm.requests.post")
    def test_mock_executive_summary(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": "### 🛡️ Executive Summary\n\nSecurity review passed release gate with minor recommendations."
                }
            }]
        }
        mock_post.return_value = mock_resp

        cfg = LLMConfig(enabled=True, provider="openai", model="gpt-4o", api_key="mock-key")
        assistant = LLMAssistant(cfg)

        rep = DKSecReport(
            project_name="Core Banking",
            target_path=".",
            target_url="http://localhost:5000",
            timestamp="2026-09-17T12:00:00Z",
            duration_seconds=3.5,
            stages_executed=[1, 2],
            stage_results={},
            all_findings=[],
            severity_counts={"CRITICAL": 0, "HIGH": 0},
            overall_score=95.0,
            gate_verdict=GateVerdict(
                approved=True,
                status="APPROVED",
                score=95.0,
                critical_count=0,
                high_count=0,
                reasons=["Clean code"],
                signoff_hash="hash123",
                timestamp="2026-09-17T12:00:00Z"
            )
        )

        summary = assistant.generate_executive_summary(rep)
        self.assertIn("Executive Summary", summary)

    def test_runner_with_llm_enabled(self):
        # Run runner with mock/heuristic LLM
        config = DKSecConfig(
            project_name="LLM Integration Test",
            target_path="samples/app",
            llm=LLMConfig(
                enabled=True,
                provider="openai",
                model="gpt-4o",
                triage_findings=True,
                generate_executive_summary=True
            )
        )
        runner = DKSecRunner(config)
        # Run stages 1 and 3
        report = runner.run(selected_stages=[1, 3])

        self.assertIsNotNone(report.ai_executive_summary)
        self.assertIn("Executive Security Briefing", report.ai_executive_summary)
        # Verify findings were triaged
        crit_high = [f for f in report.all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if crit_high:
            self.assertIsNotNone(crit_high[0].ai_triage)
            self.assertIsNotNone(crit_high[0].ai_confidence)

    def test_html_reporter_renders_ai_components(self):
        from dksec.reporters import HtmlReporter
        import tempfile

        finding = Finding(
            id="TEST-AI-1",
            title="SQL Injection",
            stage_id=3,
            stage_name="SAST",
            tool="Semgrep",
            severity=Severity.CRITICAL,
            description="Vulnerable query",
            ai_triage="TRUE_POSITIVE",
            ai_confidence=0.98,
            ai_analysis="Confirmed high-risk attack surface pattern."
        )

        rep = DKSecReport(
            project_name="AI HTML Test",
            target_path=".",
            target_url="http://localhost:5000",
            timestamp="2026-09-17T12:00:00Z",
            duration_seconds=2.0,
            stages_executed=[3],
            stage_results={},
            all_findings=[finding],
            severity_counts={"CRITICAL": 1, "HIGH": 0},
            overall_score=85.0,
            gate_verdict=GateVerdict(
                approved=False,
                status="BLOCKED",
                score=85.0,
                critical_count=1,
                high_count=0,
                reasons=["Found critical issue"],
                signoff_hash="hash123",
                timestamp="2026-09-17T12:00:00Z"
            ),
            ai_executive_summary="### 🛡️ AI Executive Briefing\n\nHigh risk findings detected."
        )

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            tf_path = tf.name

        try:
            HtmlReporter.generate(rep, tf_path)
            with open(tf_path, "r", encoding="utf-8") as f:
                html = f.read()

            self.assertIn("ai-briefing-card", html)
            self.assertIn("DKSec AI Security Intelligence", html)
            self.assertIn("AI Executive Briefing", html)
            self.assertIn("ai-analysis-box", html)
            self.assertIn("TRUE_POSITIVE", html)
            self.assertIn("98%", html)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()
