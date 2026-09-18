import sys

with open("dksec/cli.py", "r") as f:
    content = f.read()

# Add args
args_hook = """
    # Dynamic LLM Smartness arguments
    scan_parser.add_argument("--llm", action="store_true", help="Enable Dynamic AI / LLM Security Assistant for triage & executive briefing")
    scan_parser.add_argument("--llm-provider", choices=["openai", "gemini", "anthropic", "ollama", "custom"], default=None, help="LLM provider (default: openai)")
    scan_parser.add_argument("--llm-model", default=None, help="LLM model name (e.g., gpt-4o, gemini-1.5-pro, claude-3-5-sonnet, llama3)")
    scan_parser.add_argument("--llm-key", default=None, help="API key for LLM provider (or use environment variable)")
    scan_parser.add_argument("--llm-url", default=None, help="Custom base URL for OpenAI-compatible endpoint or local Ollama")
"""
new_args = args_hook + """
    # Enterprise Enhancements
    scan_parser.add_argument("--user-b-token", default=None, help="Second user token for RBAC / BOLA matrix testing")
    scan_parser.add_argument("--diff-against", default=None, help="Path to previous JSON report to diff against")
    scan_parser.add_argument("--webhook-url", default=None, help="Slack/Teams/Discord webhook URL for notifications")
"""
content = content.replace(args_hook, new_args)

# Add to config assignment
cfg_assign_hook = """
        if args.output:
            cfg.output_dir = args.output
"""
new_cfg_assign = cfg_assign_hook + """
        if hasattr(args, 'user_b_token') and args.user_b_token:
            cfg.auth.user_b_token = args.user_b_token
        if hasattr(args, 'diff_against') and args.diff_against:
            cfg.diff_against = args.diff_against
        if hasattr(args, 'webhook_url') and args.webhook_url:
            cfg.webhook_url = args.webhook_url
"""
content = content.replace(cfg_assign_hook, new_cfg_assign)

# Add post-scan processing
post_scan_hook = """
    if fail_on_gate and report.gate_verdict.status == "BLOCKED":
"""
new_post_scan = """
    try:
        from dksec.remediation import enrich_findings_with_patches
        enrich_findings_with_patches(report.all_findings, config.target_path)
    except Exception as e:
        pass

    if hasattr(config, 'diff_against') and config.diff_against:
        try:
            from dksec.diff import compare_reports
            diff_result = compare_reports(config.diff_against, report)
            print(f"\\n{Colors.BOLD}🔍 Delta Scan Comparison Results:{Colors.RESET}")
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
            print(f"\\n{Colors.GREEN}✔ Webhook notification sent to {config.webhook_url}{Colors.RESET}")
        except Exception as e:
            print(f"Error sending webhook: {e}")

""" + post_scan_hook
content = content.replace(post_scan_hook, new_post_scan)

with open("dksec/cli.py", "w") as f:
    f.write(content)
