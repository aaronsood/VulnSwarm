#!/usr/bin/env python3
"""
VulnSwarm CLI - Interactive terminal interface
"""

import os
import sys
import argparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from vulnswarm.default_config import DEFAULT_CONFIG, PROVIDER_MODELS, SCAN_DEPTHS
from vulnswarm.graph import VulnSwarm


console = Console() if RICH_AVAILABLE else None


BANNER = r"""
 __   ___   _    _  _ _____      __   _   ___ __  __
 \ \ / / | | |  | \| / __\ \    / /  /_\ | _ \  \/  |
  \ V /| |_| |__| .` \__ \\ \/\/ /  / _ \|   / |\/| |
   \_/ |____|____|_|\_|___/ \_/\_/  /_/ \_\_|_\_|  |_|

  Multi-Agent AI Security Testing Framework
  github.com/aaronsood/VulnSwarm
"""


def print_banner():
    if RICH_AVAILABLE:
        console.print(Panel(BANNER, style="bold red", subtitle="[dim]Scan smarter. Fix faster.[/dim]"))
    else:
        print(BANNER)


def select_provider() -> tuple[str, str, str]:
    """Interactive provider selection."""
    providers = list(PROVIDER_MODELS.keys())

    if RICH_AVAILABLE:
        table = Table(title="Select LLM Provider", show_header=True)
        table.add_column("#", style="dim")
        table.add_column("Provider")
        table.add_column("Models")
        table.add_column("API Key Required")

        key_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "ollama": "None (local)",
        }

        for i, p in enumerate(providers, 1):
            m = PROVIDER_MODELS[p]
            has_key = "✅" if (p == "ollama" or os.getenv(key_map.get(p, ""))) else "❌ not set"
            table.add_row(str(i), m["display"], f"{m['deep']} / {m['quick']}", has_key)

        console.print(table)
        choice = Prompt.ask("Choose provider", choices=[str(i) for i in range(1, len(providers)+1)], default="1")
        provider = providers[int(choice) - 1]
    else:
        for i, p in enumerate(providers, 1):
            print(f"  {i}. {PROVIDER_MODELS[p]['display']}")
        choice = input("Choose provider [1]: ").strip() or "1"
        provider = providers[int(choice) - 1]

    models = PROVIDER_MODELS[provider]
    return provider, models["deep"], models["quick"]


def select_scan_depth() -> str:
    """Interactive scan depth selection."""
    if RICH_AVAILABLE:
        table = Table(title="Scan Depth")
        table.add_column("#")
        table.add_column("Depth")
        table.add_column("Description")
        table.add_column("Checks")

        for i, (depth, info) in enumerate(SCAN_DEPTHS.items(), 1):
            table.add_row(str(i), depth.upper(), info["description"], str(len(info["checks"])) + " checks")

        console.print(table)
        choice = Prompt.ask("Choose scan depth", choices=["1", "2", "3"], default="2")
        return list(SCAN_DEPTHS.keys())[int(choice) - 1]
    else:
        for i, (depth, info) in enumerate(SCAN_DEPTHS.items(), 1):
            print(f"  {i}. {depth.upper()} - {info['description']}")
        choice = input("Choose depth [2]: ").strip() or "2"
        return list(SCAN_DEPTHS.keys())[int(choice) - 1]


def get_targets() -> tuple[str, str]:
    """Get scan targets from user."""
    if RICH_AVAILABLE:
        console.print("\n[bold]Target Configuration[/bold]")
        target_path = Prompt.ask("  Codebase path to scan", default="").strip() or None
        target_url = Prompt.ask("  Local web app URL (localhost only)", default="").strip() or None
    else:
        target_path = input("  Codebase path (leave blank to skip): ").strip() or None
        target_url = input("  Local web app URL (leave blank to skip): ").strip() or None

    return target_path, target_url


def run_interactive():
    """Run interactive CLI mode."""
    print_banner()

    if RICH_AVAILABLE:
        console.print("\n[bold yellow]⚠️  VulnSwarm is for testing YOUR OWN applications only.[/bold yellow]")
        console.print("[dim]Only localhost URLs are permitted for web scanning.\n[/dim]")
    else:
        print("\n⚠️  VulnSwarm scans YOUR OWN apps only. Localhost only for web scanning.\n")

    # Provider
    provider, deep_model, quick_model = select_provider()

    # Depth
    depth = select_scan_depth()

    # Targets
    target_path, target_url = get_targets()

    if not target_path and not target_url:
        print("❌ No target provided. Exiting.")
        sys.exit(1)

    # Confirm
    if RICH_AVAILABLE:
        console.print(f"\n[bold]Starting scan with:[/bold]")
        console.print(f"  Provider: {PROVIDER_MODELS[provider]['display']}")
        console.print(f"  Depth:    {depth.upper()}")
        if target_path:
            console.print(f"  Code:     {target_path}")
        if target_url:
            console.print(f"  Web:      {target_url}")
        if not Confirm.ask("\nProceed?", default=True):
            sys.exit(0)
    else:
        print(f"\nProvider: {provider} | Depth: {depth}")
        if input("Proceed? [Y/n]: ").lower() == "n":
            sys.exit(0)

    # Build config
    config = {
        **DEFAULT_CONFIG,
        "llm_provider": provider,
        "deep_think_llm": deep_model,
        "quick_think_llm": quick_model,
        "scan_depth": depth,
    }

    # Run
    vs = VulnSwarm(config=config, verbose=True)
    result = vs.scan(target_path=target_path, target_url=target_url)

    # Print summary
    if RICH_AVAILABLE:
        findings = result["findings"]
        total = sum(len(v) for v in findings.values())
        console.print(Panel(
            f"[bold]Total findings: {total}[/bold]\n"
            f"Secrets: {len(findings['secrets'])}  |  "
            f"Code: {len(findings['code'])}  |  "
            f"SQLi: {len(findings['sqli'])}  |  "
            f"XSS: {len(findings['xss'])}\n\n"
            f"Report: {result['report_path']}",
            title="✅ Scan Complete",
            style="bold green"
        ))
    else:
        print(f"\n✅ Done. Report: {result['report_path']}")


def run_cli():
    """Entry point for vulnswarm command."""
    parser = argparse.ArgumentParser(
        description="VulnSwarm - Multi-Agent AI Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--path", "-p", help="Path to codebase to scan")
    parser.add_argument("--url", "-u", help="Local web app URL (localhost only)")
    parser.add_argument("--provider", default="anthropic",
                        choices=list(PROVIDER_MODELS.keys()),
                        help="LLM provider to use")
    parser.add_argument("--depth", default="medium",
                        choices=list(SCAN_DEPTHS.keys()),
                        help="Scan depth")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Run interactive CLI (default if no args)")

    args = parser.parse_args()

    if args.interactive or (not args.path and not args.url):
        run_interactive()
        return

    models = PROVIDER_MODELS.get(args.provider, PROVIDER_MODELS["anthropic"])
    config = {
        **DEFAULT_CONFIG,
        "llm_provider": args.provider,
        "deep_think_llm": models["deep"],
        "quick_think_llm": models["quick"],
        "scan_depth": args.depth,
    }

    vs = VulnSwarm(config=config, verbose=args.verbose)
    vs.scan(target_path=args.path, target_url=args.url)


if __name__ == "__main__":
    run_cli()
