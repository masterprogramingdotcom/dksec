"""
DKSec - Unified 9-Stage Product Security Lifecycle Platform
Supports automated CLI scans, preset workflows, interactive terminal wizard,
authenticated live URL testing, CI/CD gating, and web dashboard.
"""

import sys
import os
import argparse
import time
import urllib.parse
from typing import List, Optional
from dksec import __version__
from dksec.config import DKSecConfig, STAGE_METADATA
from dksec.auth import AuthConfig
from dksec.llm import LLMConfig
from dksec.runner import DKSecRunner
from dksec.models import Severity
from dksec.reporters import (
    HtmlReporter, JsonReporter, MarkdownReporter,
    SarifReporter, CycloneDXReporter
)
from dksec.web.server import start_server


class Colors:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = rf"""{Colors.CYAN}{Colors.BOLD}
  _____  _  ______           
 |  __ \| |/ / ___|          
 | |  | | ' /| (___   ___  ___ 
 | |  | |  <  \___ \ / _ \/ __|
 | |__| | . \ ____) |  __/ (__ 
 |_____/|_|\_\_____/ \___|\___|
{Colors.BLUE}   Unified Enterprise Product Security Lifecycle Platform (v{__version__})
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


STAGE_ALIAS_MAP = {
    "1": 1, "threat": 1, "threat-model": 1, "threat_model": 1, "dfd": 1, "stride": 1,
    "2": 2, "asvs": 2, "requirements": 2, "reqs": 2,
    "3": 3, "sast": 3, "sca": 3, "secrets": 3, "gitleaks": 3, "semgrep": 3, "trivy": 3,
    "4": 4, "dast": 4, "api": 4, "zap": 4, "apisec": 4,
    "5": 5, "wstg": 5, "manual": 5, "checklist": 5,
    "6": 6, "vapt": 6, "pentest": 6, "nuclei": 6, "amass": 6, "attack-surface": 6,
    "7": 7, "defectdojo": 7, "dojo": 7, "fix": 7, "retest": 7, "jira": 7,
    "8": 8, "signoff": 8, "scorecard": 8, "openssf": 8, "gate": 8,
    "9": 9, "wazuh": 9, "siem": 9, "sigma": 9, "monitoring": 9, "ir": 9,
}


def resolve_stages(stage_str: Optional[str] = None, preset: Optional[str] = None) -> List[int]:
    """Resolve stage numbers from comma-separated names/numbers or presets."""
    if preset:
        p = preset.lower().strip()
        if p in ("full", "all"):
            return list(range(1, 10))
        elif p == "pr":
            return [1, 3, 8]
        elif p in ("api", "web"):
            return [4, 5, 6]
        elif p in ("sbom", "compliance"):
            return [2, 3, 8]
        elif p in ("vapt", "pentest"):
            return [6]
        elif p in ("sast", "code"):
            return [3]
        elif p in ("dast", "dynamic"):
            return [4]
        elif p in ("threat", "threat-model"):
            return [1]

    if not stage_str:
        return list(range(1, 10))

    if stage_str.lower().strip() == "all":
        return list(range(1, 10))

    stages = set()
    for token in stage_str.split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token in STAGE_ALIAS_MAP:
            stages.add(STAGE_ALIAS_MAP[token])
        elif token.isdigit() and 1 <= int(token) <= 9:
            stages.add(int(token))

    return sorted(list(stages)) if stages else list(range(1, 10))


PRESETS = {
    "1": ("Full 9-Stage DevSecOps Lifecycle (End-to-End)", list(range(1, 10))),
    "2": ("Pull Request / Fast CI Gate (Threat Model, SAST, Secrets, Signoff)", [1, 3, 8]),
    "3": ("Dynamic Web & API Pentest (DAST, API Fuzzing, WSTG, VAPT)", [4, 5, 6]),
    "4": ("Supply Chain & Compliance Audit (ASVS, SCA, CycloneDX SBOM, OpenSSF)", [2, 3, 8]),
    "5": ("🎯 Penetration Test / VAPT Surface Discovery Only (Stage 6)", [6]),
    "6": ("🔍 Static Code Analysis Only (SAST + SCA + Secrets - Stage 3)", [3]),
    "7": ("📐 Architecture & Threat Model DFD Only (Stage 1)", [1]),
}


def run_interactive_wizard():
    print_banner()
    print(f"{Colors.BOLD}🧙 DKSec Interactive Setup & Execution Wizard{Colors.RESET}\n")

    print(f"{Colors.BOLD}Choose an audit workflow preset:{Colors.RESET}")
    for key, (label, stgs) in PRESETS.items():
        print(f" [{key}] {label}")
    print(" [8] Custom Stage Selection (enter numbers 1-9 or names like 'sast,vapt')")

    choice = input(f"\n{Colors.BOLD}Select workflow profile [1]: {Colors.RESET}").strip()
    if choice in PRESETS:
        selected_stages = PRESETS[choice][1]
    elif choice == "8":
        print(f"\n{Colors.BOLD}Available 9 Lifecycle Stages:{Colors.RESET}")
        for s_id, meta in sorted(STAGE_METADATA.items()):
            print(f"   [{s_id}] Stage {s_id}: {meta['name']} ({meta['recommended_repo']})")
        custom_input = input(f"\n{Colors.BOLD}Enter comma-separated stage numbers or names (e.g. '3,6' or 'sast,vapt'): {Colors.RESET}").strip()
        selected_stages = resolve_stages(custom_input)
    else:
        selected_stages = list(range(1, 10))

    project_name = input(f"\n{Colors.BOLD}Enter Project Name{Colors.RESET} [Enterprise Application Audit]: ").strip()
    if not project_name:
        project_name = "Enterprise Application Audit"

    target_path = input(f"{Colors.BOLD}Target Source Code Directory{Colors.RESET} [.]: ").strip()
    if not target_path:
        target_path = "."

    target_url = input(f"{Colors.BOLD}Live Target URL / API Endpoint (Optional for DAST & VAPT){Colors.RESET} [none]: ").strip()
    if not target_url:
        target_url = None

    auth_cfg = AuthConfig()
    if target_url:
        auth_needed = input(f"{Colors.BOLD}Does the target application require authentication?{Colors.RESET} (y/N): ").strip().lower()
        if auth_needed in ("y", "yes"):
            print(f"\n{Colors.BOLD}Select Authentication Method:{Colors.RESET}")
            print(" [1] Automated Login URL (JSON or Form POST)")
            print(" [2] Bearer Token / JWT (Authorization: Bearer <token>)")
            print(" [3] Session Cookies (e.g. session=abc...; auth=123...)")
            print(" [4] Custom Header (e.g. X-API-Key: secret123)")
            auth_choice = input(f"\n{Colors.BOLD}Select method [1]: {Colors.RESET}").strip()

            if auth_choice == "2":
                tok = input(f"{Colors.BOLD}Enter Bearer Token / JWT: {Colors.RESET}").strip()
                auth_cfg = AuthConfig(enabled=True, auth_type="bearer", bearer_token=tok)
            elif auth_choice == "3":
                ck = input(f"{Colors.BOLD}Enter Session Cookie String: {Colors.RESET}").strip()
                auth_cfg = AuthConfig(enabled=True, auth_type="cookie", cookies=ck)
            elif auth_choice == "4":
                hdr = input(f"{Colors.BOLD}Enter Custom Header (Name: Value): {Colors.RESET}").strip()
                auth_cfg = AuthConfig(enabled=True, auth_type="header", custom_header=hdr)
            else:
                default_login = urllib.parse.urljoin(target_url, "/api/v1/login")
                l_url = input(f"{Colors.BOLD}Login URL{Colors.RESET} [{default_login}]: ").strip() or default_login
                u_name = input(f"{Colors.BOLD}Username / Email: {Colors.RESET}").strip()
                p_word = input(f"{Colors.BOLD}Password: {Colors.RESET}").strip()
                auth_cfg = AuthConfig(enabled=True, auth_type="login", login_url=l_url, username=u_name, password=p_word)

    # Dynamic LLM Smartness configuration
    llm_ask = input(f"\n{Colors.BOLD}Enable Dynamic AI / LLM Security Assistant?{Colors.RESET} (y/N): ").strip().lower()
    llm_cfg = LLMConfig()
    if llm_ask in ("y", "yes"):
        print(f"\n{Colors.BOLD}Select LLM Provider:{Colors.RESET}")
        print(" [1] OpenAI (GPT-4o / GPT-4o-mini)")
        print(" [2] Google Gemini (gemini-1.5-pro / flash)")
        print(" [3] Anthropic Claude (Claude 3.5 Sonnet)")
        print(" [4] Ollama Local / Private (Zero cloud telemetry)")
        print(" [5] Custom OpenAI-Compatible Endpoint")
        llm_p_choice = input(f"\n{Colors.BOLD}Select provider [1]: {Colors.RESET}").strip()
        prov_map = {
            "1": ("openai", "gpt-4o"),
            "2": ("gemini", "gemini-1.5-pro"),
            "3": ("anthropic", "claude-3-5-sonnet-20240620"),
            "4": ("ollama", "llama3"),
            "5": ("custom", "default")
        }
        prov, def_mod = prov_map.get(llm_p_choice, ("openai", "gpt-4o"))
        mod = input(f"{Colors.BOLD}Model name{Colors.RESET} [{def_mod}]: ").strip() or def_mod
        key = None
        if prov != "ollama":
            key = input(f"{Colors.BOLD}API Key (press Enter to use {prov.upper()}_API_KEY from environment){Colors.RESET}: ").strip() or None
        url = None
        if prov in ("ollama", "custom"):
            def_url = "http://localhost:11434/v1" if prov == "ollama" else "http://localhost:8000/v1"
            url = input(f"{Colors.BOLD}Base URL{Colors.RESET} [{def_url}]: ").strip() or def_url
        llm_cfg = LLMConfig(enabled=True, provider=prov, model=mod, api_key=key, api_base_url=url)

    output_dir = input(f"\n{Colors.BOLD}Output Directory for Reports{Colors.RESET} [./reports]: ").strip()
    if not output_dir:
        output_dir = "./reports"

    selected_stages = sorted(list(set(selected_stages)))
    print(f"\n{Colors.GREEN}✓ Configured {len(selected_stages)} stages to execute: {selected_stages}{Colors.RESET}\n")

    cfg = DKSecConfig(
        project_name=project_name,
        target_path=target_path,
        target_url=target_url,
        auth=auth_cfg,
        llm=llm_cfg,
        output_dir=output_dir
    )
    execute_pipeline(cfg, selected_stages)


def execute_pipeline(config: DKSecConfig, stages_to_run: List[int], fail_on_gate: bool = False):
    print(f"{Colors.BOLD}🚀 Launching DKSec Pipeline...{Colors.RESET}")
    print(f"   Project:     {config.project_name}")
    if config.target_path:
        print(f"   Target Code: {os.path.abspath(config.target_path)}")
    else:
        print(f"   Target Code: {Colors.YELLOW}[None — URL-only mode, SAST/SCA skipped]{Colors.RESET}")
    if config.target_url:
        print(f"   Target URL:  {config.target_url}")
        if config.auth and config.auth.enabled:
            print(f"   Session Auth:{Colors.GREEN} Enabled ({config.auth.auth_type.upper()}){Colors.RESET}")
            if config.auth.login_url:
                print(f"   Login Endpoint: {config.auth.login_url} (User: {config.auth.username})")
            elif config.auth.bearer_token:
                print(f"   Bearer Token: {config.auth.bearer_token[:20]}...")
    if config.llm and config.llm.enabled:
        print(f"   Smart AI:    {Colors.GREEN}Enabled ({config.llm.provider.upper()} - {config.llm.model}){Colors.RESET}")
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
        elif evt == "llm_started":
            provider = payload.get("provider", "AI").upper()
            model = payload.get("model", "")
            print(f"\n{Colors.PURPLE}🤖 [Dynamic AI Smartness] Triaging findings and synthesizing CISO executive briefing ({provider} {model})...{Colors.RESET}")
        elif evt == "llm_completed":
            print(f"  {Colors.GREEN}✔ AI triage and executive intelligence synthesis complete.{Colors.RESET}")
        elif evt == "llm_error":
            err = payload.get("error")
            print(f"  {Colors.YELLOW}⚠ AI engine warning ({err}) - activated high-confidence heuristic fallback.{Colors.RESET}")

    runner = DKSecRunner(config, event_callback=event_logger)
    report = runner.run(selected_stages=stages_to_run)

    # Generate All Industry Standard Reports
    os.makedirs(config.output_dir, exist_ok=True)
    html_file = os.path.join(config.output_dir, "dksec-report.html")
    json_file = os.path.join(config.output_dir, "dksec-report.json")
    md_file = os.path.join(config.output_dir, "dksec-report.md")
    sarif_file = os.path.join(config.output_dir, "dksec-results.sarif")
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

    try:
        from dksec.remediation import enrich_findings_with_patches
        enrich_findings_with_patches(report.all_findings, config.target_path)
    except Exception as e:
        pass

    if hasattr(config, 'diff_against') and config.diff_against:
        try:
            from dksec.diff import compare_reports
            diff_result = compare_reports(report, config.diff_against)
            print(f"\n{Colors.BOLD}🔍 Delta Scan Comparison Results:{Colors.RESET}")
            print(f"   New Findings: {len(diff_result['new_findings'])}")
            print(f"   Resolved Findings: {len(diff_result['resolved_findings'])}")
            
            diff_file = os.path.join(config.output_dir, "dksec-diff.json")
            with open(diff_file, "w") as f_diff:
                import json
                json.dump(diff_result, f_diff, indent=2)
            print(f"   Diff Report: {Colors.CYAN}{diff_file}{Colors.RESET}")
        except Exception as e:
            print(f"Error diffing reports: {e}")

    if hasattr(config, 'webhook_url') and config.webhook_url:
        try:
            from dksec.notifications import dispatch_webhook
            dispatch_webhook(report, config.webhook_url)
            print(f"\n{Colors.GREEN}✔ Webhook notification sent to {config.webhook_url}{Colors.RESET}")
        except Exception as e:
            print(f"Error sending webhook: {e}")


    if fail_on_gate and report.gate_verdict.status == "BLOCKED":
        print(f"{Colors.RED}❌ CI Gate Failed: Release blocked by security gatekeeper policy.{Colors.RESET}")
        sys.exit(1)

    return report


def run_demo():
    print_banner()
    print(f"{Colors.BOLD}🚀 Running DKSec One-Click Demonstration on Sample Fintech App...{Colors.RESET}\n")
    cfg = DKSecConfig(
        project_name="Fintech Core Banking Demo",
        target_path="samples/app",
        output_dir="reports/demo"
    )
    execute_pipeline(cfg, list(range(1, 10)))


def main():
    parser = argparse.ArgumentParser(
        prog="dksec",
        description="DKSec - Unified 9-Stage Product Security Lifecycle Platform",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: demo
    subparsers.add_parser("demo", help="Run complete 9-stage audit against built-in sample app")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run security audit pipeline")
    scan_parser.add_argument("-p", "--project", default="DKSec Security Audit", help="Project name")
    scan_parser.add_argument("-t", "--target", default=None, help="Target source code directory (omit for URL-only mode)")
    scan_parser.add_argument("-u", "--url", default=None, help="Live target URL / API endpoint")
    scan_parser.add_argument("-o", "--output", default="./reports", help="Output directory for reports")
    scan_parser.add_argument("-c", "--config", default=None, help="Path to dksec.yml configuration file")
    scan_parser.add_argument(
        "--preset",
        choices=["full", "pr", "api", "sbom", "vapt", "sast", "dast", "threat", "all"],
        default=None,
        help="Quick workflow preset: full (1-9), pr (1,3,8), api (4,5,6), sbom (2,3,8), vapt (6), sast (3), dast (4), threat (1)"
    )
    scan_parser.add_argument(
        "-s", "--stages",
        default=None,
        help="Comma-separated stage IDs (e.g. '1,2,3' or '3,4,6') or 'all'"
    )
    scan_parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="Exit with non-zero status code if release gate is BLOCKED (for CI/CD pipelines)"
    )
    
    # Authentication arguments
    scan_parser.add_argument("--token", "--bearer", default=None, help="Bearer token or JWT for authenticated scanning")
    scan_parser.add_argument("--login-url", default=None, help="Target login endpoint URL for automated session login")
    scan_parser.add_argument("--username", default=None, help="Username for automated login")
    scan_parser.add_argument("--password", default=None, help="Password for automated login")
    scan_parser.add_argument("--cookie", default=None, help="Session cookies (e.g. 'session=xyz; token=123')")
    scan_parser.add_argument("--header", default=None, help="Custom authorization header (e.g. 'X-API-Key: secret')")

    # Dynamic LLM Smartness arguments
    scan_parser.add_argument("--llm", action="store_true", help="Enable Dynamic AI / LLM Security Assistant for triage & executive briefing")
    scan_parser.add_argument("--llm-provider", choices=["openai", "gemini", "anthropic", "ollama", "custom"], default=None, help="LLM provider (default: openai)")
    scan_parser.add_argument("--llm-model", default=None, help="LLM model name (e.g., gpt-4o, gemini-1.5-pro, claude-3-5-sonnet, llama3)")
    scan_parser.add_argument("--llm-key", default=None, help="API key for LLM provider (or use environment variable)")
    scan_parser.add_argument("--llm-url", default=None, help="Custom base URL for OpenAI-compatible endpoint or local Ollama")

    # Enterprise Enhancements
    scan_parser.add_argument("--user-b-token", default=None, help="Second user token for RBAC / BOLA matrix testing")
    scan_parser.add_argument("--diff-against", default=None, help="Path to previous JSON report to diff against")
    scan_parser.add_argument("--webhook-url", default=None, help="Slack/Teams/Discord webhook URL for notifications")

    # Command: interactive / wizard
    subparsers.add_parser("wizard", help="Launch interactive terminal wizard with preset selection")
    subparsers.add_parser("interactive", help="Launch interactive step-by-step terminal wizard")

    # Command: list
    subparsers.add_parser("list", help="List all 9 lifecycle stages and recommended GitHub repos")

    # Command: ui / web
    web_parser = subparsers.add_parser("ui", help="Launch interactive Web GUI dashboard")
    web_parser.add_argument("--port", type=int, default=8080, help="Web dashboard port (default: 8080)")
    web_parser.add_argument("--host", default="127.0.0.1", help="Web dashboard bind host (default: 127.0.0.1)")

    # Command: init
    subparsers.add_parser("init", help="Generate template dksec.yml configuration file")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
        return

    if args.command == "list":
        print_banner()
        print_stage_catalog()
        return

    if args.command == "ui":
        print_banner()
        start_server(port=args.port, host=args.host)
        return

    if args.command == "init":
        cfg = DKSecConfig()
        cfg.save("dksec.yml")
        print(f"{Colors.GREEN}✔ Created dksec.yml with full 9-stage configuration.{Colors.RESET}")
        return

    if args.command in ("wizard", "interactive") or args.command is None:
        if len(sys.argv) == 1:
            run_interactive_wizard()
            return

    if args.command == "scan":
        print_banner()
        cfg_file = args.config
        if not cfg_file and os.path.exists("dksec.yml"):
            cfg_file = "dksec.yml"
        elif not cfg_file and os.path.exists("omnisec.yml"):
            cfg_file = "omnisec.yml"

        cfg = DKSecConfig.load(cfg_file) if cfg_file else DKSecConfig()
        if args.project:
            cfg.project_name = args.project

        # Target path resolution:
        # - --target given explicitly → use it
        # - --url given, no --target → URL-only mode (skip SAST/SCA)
        # - neither → fallback to "." (code-only scan of current directory)
        if args.target:
            cfg.target_path = args.target
        elif args.url and not args.target:
            cfg.target_path = None  # URL-only mode: skip source-code scanning
        elif not args.target and not args.url:
            cfg.target_path = cfg.target_path or "."  # keep YAML value or default to "."

        if args.url:
            cfg.target_url = args.url
        if args.output:
            cfg.output_dir = args.output

        if hasattr(args, 'user_b_token') and args.user_b_token:
            cfg.auth.user_b_token = args.user_b_token
        if hasattr(args, 'diff_against') and args.diff_against:
            cfg.diff_against = args.diff_against
        if hasattr(args, 'webhook_url') and args.webhook_url:
            cfg.webhook_url = args.webhook_url

        # Configure Authentication parameters if provided
        if args.token:
            cfg.auth.enabled = True
            cfg.auth.auth_type = "bearer"
            cfg.auth.bearer_token = args.token
        if args.cookie:
            cfg.auth.enabled = True
            cfg.auth.auth_type = "cookie"
            cfg.auth.cookies = args.cookie
        if args.header:
            cfg.auth.enabled = True
            cfg.auth.auth_type = "header"
            cfg.auth.custom_header = args.header
        if args.login_url or (args.username and args.password):
            cfg.auth.enabled = True
            cfg.auth.auth_type = "login"
            if args.login_url:
                cfg.auth.login_url = args.login_url
            if args.username:
                cfg.auth.username = args.username
            if args.password:
                cfg.auth.password = args.password

        # Configure Dynamic LLM parameters if provided
        if args.llm or args.llm_provider or args.llm_key or args.llm_url:
            cfg.llm.enabled = True
            if args.llm_provider:
                cfg.llm.provider = args.llm_provider
            if args.llm_model:
                cfg.llm.model = args.llm_model
            if args.llm_key:
                cfg.llm.api_key = args.llm_key
            if args.llm_url:
                cfg.llm.api_base_url = args.llm_url

        # Determine stages (supports names like 'vapt', 'sast,vapt', numbers '1,3,6', or presets)
        stages = resolve_stages(args.stages, preset=args.preset)

        execute_pipeline(cfg, stages, fail_on_gate=args.fail_on_gate)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
