"""
Main Command Line Interface for OmniSec (Advanced Enterprise Edition).
Supports automated CLI scans, interactive terminal wizard, CI/CD pipeline gating, and web dashboard.
"""

import sys
import os
import argparse
import time
from typing import List, Optional
from omnisec import __version__
from omnisec.config import OmniSecConfig, STAGE_METADATA
from omnisec.runner import OmniSecRunner
from omnisec.models import Severity
from omnisec.reporters import (
    HtmlReporter, JsonReporter, MarkdownReporter,
    SarifReporter, CycloneDXReporter
)
from omnisec.web.server import start_server


class Colors:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = rf"""{Colors.CYAN}{Colors.BOLD}
   ____                      _  _____           
  / __ \                    (_)/ ____|          
 | |  | |_ __ ___  _ __  _  _| (___   ___  ___  
 | |  | | '_ ` _ \| '_ \| || |\___ \ / _ \/ __| 
 | |__| | | | | | | | | | || |____) |  __/ (__  
  \____/|_| |_| |_|_| |_|_||_|_____/ \___|\___| 
{Colors.BLUE}   Enterprise Product Security Lifecycle Platform (v{__version__})
   1: Threat Model (STRIDE)  | 2: ASVS Requirements  | 3: SAST/SCA/Secrets
   4: DAST & API Security    | 5: WSTG Manual Tests   | 6: VAPT & Attack Surface
   7: DefectDojo Fix/Retest  | 8: OpenSSF Signoff    | 9: Wazuh & Sigma SIEM
{Colors.RESET}"""


def print_banner():
    print(BANNER)


def print_stage_catalog():
    print(f"\n{Colors.BOLD}📋 Supported Enterprise Product Security Stages:{Colors.RESET}")
    print(f"{'#':<3} {'Stage Name':<32} {'Recommended Tool(s)':<35} {'What it covers'}")
    print("-" * 110)
    for s_id, meta in sorted(STAGE_METADATA.items()):
        print(f"{Colors.BOLD}{s_id:<3}{Colors.RESET} {Colors.CYAN}{meta['name']:<32}{Colors.RESET} {Colors.YELLOW}{meta['recommended_repo']:<35}{Colors.RESET} {Colors.DIM}{meta['what_it_covers'][:40]}...{Colors.RESET}")
    print("-" * 110 + "\n")


def run_interactive_wizard():
    print_banner()
    print(f"{Colors.BOLD}🧙 OmniSec Interactive Setup & Execution Wizard{Colors.RESET}\n")

    project_name = input(f"{Colors.BOLD}Enter Project Name{Colors.RESET} [Enterprise Application Audit]: ").strip()
    if not project_name:
        project_name = "Enterprise Application Audit"

    target_path = input(f"{Colors.BOLD}Target Source Code Directory{Colors.RESET} [.]: ").strip()
    if not target_path:
        target_path = "."

    target_url = input(f"{Colors.BOLD}Live Target URL / API Endpoint (Optional for DAST & VAPT){Colors.RESET} [none]: ").strip()
    if not target_url:
        target_url = None

    output_dir = input(f"{Colors.BOLD}Output Directory for Reports{Colors.RESET} [./reports]: ").strip()
    if not output_dir:
        output_dir = "./reports"

    print(f"\n{Colors.BOLD}Select which stages you want to perform:{Colors.RESET}")
    print(" [A] ALL 9 Stages (Complete End-to-End Enterprise Lifecycle)")
    for s_id, meta in sorted(STAGE_METADATA.items()):
        print(f" [{s_id}] Stage {s_id}: {meta['name']} ({meta['recommended_repo']})")

    choice = input(f"\n{Colors.BOLD}Enter stage numbers separated by commas (or 'A' for all){Colors.RESET} [A]: ").strip().upper()
    if not choice or choice == "A":
        selected_stages = list(range(1, 10))
    else:
        selected_stages = []
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit() and 1 <= int(part) <= 9:
                selected_stages.append(int(part))
        if not selected_stages:
            print(f"{Colors.YELLOW}No valid stages entered, defaulting to ALL 9 stages.{Colors.RESET}")
            selected_stages = list(range(1, 10))

    selected_stages = sorted(list(set(selected_stages)))
    print(f"\n{Colors.GREEN}✓ Configured {len(selected_stages)} stages to execute: {selected_stages}{Colors.RESET}\n")

    cfg = OmniSecConfig(
        project_name=project_name,
        target_path=target_path,
        target_url=target_url,
        output_dir=output_dir
    )
    execute_pipeline(cfg, selected_stages)


def execute_pipeline(config: OmniSecConfig, stages_to_run: List[int], fail_on_gate: bool = False):
    print(f"{Colors.BOLD}🚀 Launching OmniSec Enterprise Pipeline...{Colors.RESET}")
    print(f"   Project:     {config.project_name}")
    print(f"   Target Code: {os.path.abspath(config.target_path)}")
    if config.target_url:
        print(f"   Target URL:  {config.target_url}")
    print(f"   Outputs:     {os.path.abspath(config.output_dir)}\n")

    def event_logger(evt: str, payload: dict):
        if evt == "stage_started":
            s_id = payload.get("stage_id")
            s_name = payload.get("stage_name")
            print(f"\n{Colors.BLUE}▶ [Stage {s_id}/9] Starting {s_name}...{Colors.RESET}")
        elif evt == "stage_completed":
            s_id = payload.get("stage_id")
            count = payload.get("findings_count", 0)
            dur = payload.get("duration", 0.0)
            status_color = Colors.GREEN if count == 0 else Colors.YELLOW
            print(f"  {status_color}✔ Stage {s_id} complete ({dur:.2f}s) — {count} findings identified.{Colors.RESET}")
        elif evt == "stage_error":
            s_id = payload.get("stage_id")
            err = payload.get("error")
            print(f"  {Colors.RED}✖ Stage {s_id} encountered an error: {err}{Colors.RESET}")

    runner = OmniSecRunner(config, event_callback=event_logger)
    report = runner.run(selected_stages=stages_to_run)

    # Generate All Industry Standard Reports
    os.makedirs(config.output_dir, exist_ok=True)
    html_file = os.path.join(config.output_dir, "omnisec-report.html")
    json_file = os.path.join(config.output_dir, "omnisec-report.json")
    md_file = os.path.join(config.output_dir, "omnisec-report.md")
    sarif_file = os.path.join(config.output_dir, "omnisec-results.sarif")
    sbom_file = os.path.join(config.output_dir, "cyclonedx-sbom.json")

    HtmlReporter.generate(report, html_file)
    JsonReporter.generate(report, json_file)
    MarkdownReporter.generate(report, md_file)
    SarifReporter.generate(report, sarif_file)
    CycloneDXReporter.generate(report, sbom_file)

    # Terminal Executive Summary
    print(f"\n" + "=" * 76)
    verdict_color = Colors.GREEN if report.gate_verdict.status == "APPROVED" else (Colors.YELLOW if report.gate_verdict.status == "CONDITIONAL_APPROVAL" else Colors.RED)
    print(f"{Colors.BOLD}🛡️  SECURITY RELEASE GATE DECISION: {verdict_color}{report.gate_verdict.status}{Colors.RESET}")
    print(f"   Security Posture Score: {verdict_color}{report.overall_score:.1f} / 100{Colors.RESET}")
    print(f"   Findings Breakdown:     {Colors.RED}CRITICAL: {report.severity_counts.get('CRITICAL', 0)}{Colors.RESET} | {Colors.YELLOW}HIGH: {report.severity_counts.get('HIGH', 0)}{Colors.RESET} | MEDIUM: {report.severity_counts.get('MEDIUM', 0)} | LOW: {report.severity_counts.get('LOW', 0)}")
    print(f"   SBOM Dependencies:      {Colors.CYAN}{len(report.sbom_components)} packages tracked{Colors.RESET}")
    print(f"   Audit Certificate Hash: {Colors.CYAN}{report.gate_verdict.signoff_hash[:32]}...{Colors.RESET}")
    print("=" * 76)
    print(f"\n{Colors.BOLD}📄 Generated Industry-Standard Artifacts:{Colors.RESET}")
    print(f"   🌐 Interactive HTML:   {Colors.CYAN}{html_file}{Colors.RESET}")
    print(f"   📦 CycloneDX 1.5 SBOM: {Colors.CYAN}{sbom_file}{Colors.RESET}")
    print(f"   📥 OASIS SARIF 2.1.0:  {Colors.CYAN}{sarif_file}{Colors.RESET}")
    print(f"   📝 Markdown Summary:   {Colors.CYAN}{md_file}{Colors.RESET}")
    print(f"   📊 Machine JSON:       {Colors.CYAN}{json_file}{Colors.RESET}")
    if os.path.exists(os.path.join(config.output_dir, "defectdojo-findings.json")):
        print(f"   🎯 DefectDojo Sync:    {Colors.CYAN}{os.path.join(config.output_dir, 'defectdojo-findings.json')}{Colors.RESET}")
    if os.path.exists(os.path.join(config.output_dir, "threat-dragon-model.json")):
        print(f"   📐 Threat Dragon v2:   {Colors.CYAN}{os.path.join(config.output_dir, 'threat-dragon-model.json')}{Colors.RESET}")
    if os.path.exists(os.path.join(config.output_dir, "wazuh-local_rules.xml")):
        print(f"   🛡️ Wazuh SIEM XML:     {Colors.CYAN}{os.path.join(config.output_dir, 'wazuh-local_rules.xml')}{Colors.RESET}")
    if os.path.exists(os.path.join(config.output_dir, "sigma-rules.yml")):
        print(f"   ⚡ Sigma YAML Rules:   {Colors.CYAN}{os.path.join(config.output_dir, 'sigma-rules.yml')}{Colors.RESET}\n")

    if fail_on_gate and report.gate_verdict.status == "BLOCKED":
        print(f"{Colors.RED}❌ CI Gate Failed: Release blocked by security gatekeeper policy.{Colors.RESET}")
        sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="OmniSec - Unified 9-Stage Product Security Lifecycle Platform",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run security audit pipeline")
    scan_parser.add_argument("-p", "--project", default="Enterprise Security Audit", help="Project name")
    scan_parser.add_argument("-t", "--target", default=".", help="Target source code directory")
    scan_parser.add_argument("-u", "--url", default=None, help="Live target URL / API endpoint")
    scan_parser.add_argument("-o", "--output", default="./reports", help="Output directory for reports")
    scan_parser.add_argument("-c", "--config", default=None, help="Path to omnisec.yml configuration file")
    scan_parser.add_argument(
        "-s", "--stages",
        default="all",
        help="Comma-separated stage IDs (e.g. '1,2,3' or '3,4,6') or 'all' [default: all]"
    )
    scan_parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="Exit with non-zero status code if release gate is BLOCKED (for CI/CD gates)"
    )

    # Command: interactive
    subparsers.add_parser("interactive", help="Launch interactive step-by-step terminal wizard")

    # Command: list
    subparsers.add_parser("list", help="List all 9 lifecycle stages and recommended GitHub repos")

    # Command: ui / web
    web_parser = subparsers.add_parser("ui", help="Launch interactive Web GUI dashboard")
    web_parser.add_argument("--port", type=int, default=8080, help="Web dashboard port (default: 8080)")
    web_parser.add_argument("--host", default="127.0.0.1", help="Web dashboard bind host (default: 127.0.0.1)")

    # Command: init
    subparsers.add_parser("init", help="Generate template omnisec.yml configuration file")

    args = parser.parse_args()

    if args.command == "list":
        print_banner()
        print_stage_catalog()
        return

    if args.command == "ui":
        print_banner()
        start_server(port=args.port, host=args.host)
        return

    if args.command == "init":
        cfg = OmniSecConfig()
        cfg.save("omnisec.yml")
        print(f"{Colors.GREEN}✔ Created omnisec.yml with full 9-stage configuration.{Colors.RESET}")
        return

    if args.command == "interactive" or args.command is None:
        if len(sys.argv) == 1:
            run_interactive_wizard()
            return

    if args.command == "scan":
        print_banner()
        cfg = OmniSecConfig.load(args.config) if args.config else OmniSecConfig()
        if args.project:
            cfg.project_name = args.project
        if args.target:
            cfg.target_path = args.target
        if args.url:
            cfg.target_url = args.url
        if args.output:
            cfg.output_dir = args.output

        if args.stages.lower() == "all":
            stages = list(range(1, 10))
        else:
            stages = [int(s.strip()) for s in args.stages.split(",") if s.strip().isdigit() and 1 <= int(s.strip()) <= 9]

        if not stages:
            stages = list(range(1, 10))

        execute_pipeline(cfg, stages, fail_on_gate=args.fail_on_gate)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
