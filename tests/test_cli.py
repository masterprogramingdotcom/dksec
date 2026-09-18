"""
Unit tests for CLI commands and subparser operations.
"""

import unittest
import subprocess
import os
import shutil


class TestDKSecCLI(unittest.TestCase):
    def test_cli_list(self):
        res = subprocess.run(["python3", "dksec.py", "list"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Architecture & Threat Model", res.stdout)
        self.assertIn("Wazuh", res.stdout)
        self.assertIn("OpenSSF Scorecard", res.stdout)

    def test_cli_init(self):
        test_yml = "test_dksec.yml"
        if os.path.exists(test_yml):
            os.remove(test_yml)
        res = subprocess.run(["python3", "dksec.py", "init"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(os.path.exists("dksec.yml"))

    def test_cli_scan_stages(self):
        out_dir = "reports/cli_test"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        res = subprocess.run([
            "python3", "dksec.py", "scan",
            "-p", "CLI Unit Test",
            "-t", "samples/app",
            "-s", "1,2",
            "-o", out_dir
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dksec-report.html")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dksec-report.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dksec-report.md")))

    def test_cli_scan_with_llm(self):
        out_dir = "reports/cli_llm_test"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        res = subprocess.run([
            "python3", "dksec.py", "scan",
            "-p", "CLI LLM Test",
            "-t", "samples/app",
            "-s", "1,3",
            "--llm",
            "--llm-provider", "openai",
            "--llm-model", "gpt-4o",
            "-o", out_dir
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Smart AI:", res.stdout)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dksec-report.html")))

    def test_cli_scan_single_stage_named_vapt(self):
        out_dir = "reports/cli_vapt_test"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        res = subprocess.run([
            "python3", "dksec.py", "scan",
            "-p", "CLI VAPT Test",
            "-t", "samples/app",
            "-s", "vapt",
            "-o", out_dir
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Starting Penetration Test / VAPT", res.stdout)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dksec-report.html")))
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)

    def test_cli_scan_multi_stage_named(self):
        out_dir = "reports/cli_multi_test"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        res = subprocess.run([
            "python3", "dksec.py", "scan",
            "-p", "CLI Multi Stage Test",
            "-t", "samples/app",
            "-s", "sast,vapt",
            "-o", out_dir
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Starting SAST + SCA + Secret Scanning", res.stdout)
        self.assertIn("Starting Penetration Test / VAPT", res.stdout)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dksec-report.html")))
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)

    def test_cli_scan_preset_vapt(self):
        out_dir = "reports/cli_preset_test"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        res = subprocess.run([
            "python3", "dksec.py", "scan",
            "-p", "CLI Preset Test",
            "-t", "samples/app",
            "--preset", "vapt",
            "-o", out_dir
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Starting Penetration Test / VAPT", res.stdout)
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)


if __name__ == "__main__":
    unittest.main()

