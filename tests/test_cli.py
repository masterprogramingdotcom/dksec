"""
Unit tests for CLI commands and subparser operations.
"""

import unittest
import subprocess
import os
import shutil


class TestOmniSecCLI(unittest.TestCase):
    def test_cli_list(self):
        res = subprocess.run(["./omnisec_cli.py", "list"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Architecture & Threat Model", res.stdout)
        self.assertIn("Wazuh", res.stdout)
        self.assertIn("OpenSSF Scorecard", res.stdout)

    def test_cli_init(self):
        test_yml = "test_omnisec.yml"
        if os.path.exists(test_yml):
            os.remove(test_yml)
        res = subprocess.run(["./omnisec_cli.py", "init"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(os.path.exists("omnisec.yml"))

    def test_cli_scan_stages(self):
        out_dir = "reports/cli_test"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        res = subprocess.run([
            "./omnisec_cli.py", "scan",
            "-p", "CLI Unit Test",
            "-t", "samples/app",
            "-s", "1,2",
            "-o", out_dir
        ], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "omnisec-report.html")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "omnisec-report.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "omnisec-report.md")))


if __name__ == "__main__":
    unittest.main()
