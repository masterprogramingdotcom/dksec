"""
Unit tests for UniversalMultiTechScanner.
Verifies multi-technology scanning across Python, JavaScript/TypeScript, Java, PHP, Go, Docker, and IaC.
"""

import unittest
import os
import tempfile
import shutil
from dksec.stages.base import BaseStage
from dksec.multi_tech_scanner import UniversalMultiTechScanner, TechStackDetector
from dksec.models import Finding, Severity, FindingStatus


class DummyStage(BaseStage):
    def __init__(self):
        super().__init__(3)

    def run(self, config, context):
        return [], {}, {}


class TestMultiTechScanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.stage = DummyStage()
        self.scanner = UniversalMultiTechScanner(self.stage)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_python_and_requirements(self):
        with open(os.path.join(self.tmp, "app.py"), "w") as f:
            f.write("import os\nos.system('echo test')\nDEBUG = True\n")
        with open(os.path.join(self.tmp, "requirements.txt"), "w") as f:
            f.write("django==4.1.7\nrequests==2.19.1\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("os.system" in f.title for f in findings))
        self.assertTrue(any("Production Debug Mode" in f.title for f in findings))
        self.assertTrue(any("django" in f.title for f in findings))
        self.assertEqual(len(comps), 2)

    def test_nodejs_and_package_json(self):
        with open(os.path.join(self.tmp, "index.js"), "w") as f:
            f.write("const cp = require('child_process');\ncp.exec('ls ' + req.query.dir);\n")
        with open(os.path.join(self.tmp, "package.json"), "w") as f:
            f.write('{"dependencies": {"lodash": "4.17.15", "axios": "0.21.1"}}')

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("child_process.exec" in f.title for f in findings))
        self.assertTrue(any("lodash" in f.title for f in findings))
        self.assertEqual(len(comps), 2)

    def test_java_pom_xml(self):
        with open(os.path.join(self.tmp, "Service.java"), "w") as f:
            f.write("public class Service {\n  void bad(ObjectInputStream ois) throws Exception { ois.readObject(); }\n}\n")
        with open(os.path.join(self.tmp, "pom.xml"), "w") as f:
            f.write('<project><dependency><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></project>')

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("ObjectInputStream" in f.title for f in findings))
        self.assertTrue(any("log4j-core" in f.title for f in findings))
        self.assertEqual(len(comps), 1)

    def test_php_composer(self):
        with open(os.path.join(self.tmp, "index.php"), "w") as f:
            f.write("<?php\nsystem($_GET['cmd']);\n")
        with open(os.path.join(self.tmp, "composer.json"), "w") as f:
            f.write('{"require": {"laravel/framework": "9.1.8"}}')

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("PHP Remote Command Execution" in f.title for f in findings))
        self.assertTrue(any("laravel/framework" in f.title for f in findings))
        self.assertEqual(len(comps), 1)

    def test_go_mod(self):
        with open(os.path.join(self.tmp, "main.go"), "w") as f:
            f.write("package main\nimport \"fmt\"\nfunc q(db any, s string) { db.Query(fmt.Sprintf(\"SELECT * FROM u WHERE id = %s\", s)) }\n")
        with open(os.path.join(self.tmp, "go.mod"), "w") as f:
            f.write("module testmod\ngo 1.20\nrequire github.com/gin-gonic/gin v1.7.7\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("fmt.Sprintf" in f.title for f in findings))
        self.assertTrue(any("gin" in f.title for f in findings))
        self.assertEqual(len(comps), 1)

    def test_docker_and_secrets(self):
        with open(os.path.join(self.tmp, "Dockerfile"), "w") as f:
            f.write("FROM alpine:latest\nCOPY .env /app/.env\nCMD [\"./app\"]\n")
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("latest" in f.title for f in findings))
        self.assertTrue(any("AWS Access Key" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
