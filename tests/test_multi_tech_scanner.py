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

    def test_web_server_nginx_and_apache(self):
        with open(os.path.join(self.tmp, "nginx.conf"), "w") as f:
            f.write("""
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    autoindex on;
    add_header Access-Control-Allow-Origin $http_origin;
}
""")
        with open(os.path.join(self.tmp, ".htaccess"), "w") as f:
            f.write("Options +Indexes\nAllowOverride All\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("Nginx Insecure Legacy TLS/SSL" in f.title for f in findings))
        self.assertTrue(any("Nginx Insecure CORS Header" in f.title for f in findings))
        self.assertTrue(any("Nginx Directory Listing Enabled" in f.title for f in findings))
        self.assertTrue(any("Apache Directory Indexing" in f.title for f in findings))

    def test_web_server_iis_caddy_haproxy(self):
        with open(os.path.join(self.tmp, "web.config"), "w") as f:
            f.write('<configuration><system.web><customErrors mode="Off"/><compilation debug="true"/></system.web></configuration>')
        with open(os.path.join(self.tmp, "Caddyfile"), "w") as f:
            f.write("{\n    admin 0.0.0.0:2019\n}\nlocalhost:8080 {\n    reverse_proxy 127.0.0.1:8000\n}\n")
        with open(os.path.join(self.tmp, "haproxy.cfg"), "w") as f:
            f.write("listen stats\n    bind :9000\n    stats enable\n    stats uri /\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("IIS ASP.NET Custom Errors" in f.title for f in findings))
        self.assertTrue(any("Caddy Admin API Exposed" in f.title for f in findings))
        self.assertTrue(any("HAProxy Statistics Dashboard" in f.title for f in findings))

    def test_rust_cargo_and_sast(self):
        with open(os.path.join(self.tmp, "Cargo.toml"), "w") as f:
            f.write("""[package]
name = "myrustapp"
version = "0.1.0"
[dependencies]
openssl = "0.10.45"
""")
        with open(os.path.join(self.tmp, "main.rs"), "w") as f:
            f.write("fn main() { unsafe { let x: u32 = std::mem::transmute(1.0f32); } }\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(len(comps) >= 1)
        self.assertTrue(any("transmute" in f.title for f in findings))
        self.assertTrue(any(c.ecosystem == "cargo" for c in comps))


    def test_dotnet_csproj_and_sast(self):
        with open(os.path.join(self.tmp, "App.csproj"), "w") as f:
            f.write("""<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.2" />
  </ItemGroup>
</Project>
""")
        with open(os.path.join(self.tmp, "Program.cs"), "w") as f:
            f.write("using System.Xml;\nclass P { void X() { var doc = new XmlDocument(); doc.LoadXml(\"<test/>\"); } }\n")

        findings, comps, summary = self.scanner.scan_all(self.tmp)
        self.assertTrue(any("Newtonsoft.Json" in f.title or "newtonsoft" in f.title.lower() for f in findings))
        self.assertTrue(any("XmlDocument" in f.title for f in findings))
        self.assertTrue(any(c.ecosystem == "nuget" for c in comps))

    def test_tech_stack_detector_extended(self):
        with open(os.path.join(self.tmp, "nginx.conf"), "w") as f:
            f.write("events {}\n")
        with open(os.path.join(self.tmp, "tasks.py"), "w") as f:
            f.write("from celery import Celery\napp = Celery('tasks')\n")
        with open(os.path.join(self.tmp, "db.py"), "w") as f:
            f.write("import psycopg2\nconn = psycopg2.connect('postgres://localhost/db')\n")

        profile = TechStackDetector.detect(self.tmp)
        self.assertIn("nginx", profile.get("servers", []))
        self.assertIn("celery", profile.get("frameworks", []))
        self.assertIn("postgresql", profile.get("databases", []))


if __name__ == "__main__":
    unittest.main()

