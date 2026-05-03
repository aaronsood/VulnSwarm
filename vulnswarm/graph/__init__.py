"""
VulnSwarm Graph - Main orchestration pipeline
Coordinates all agents through the security assessment workflow.
"""

import os
from pathlib import Path
from datetime import datetime

from vulnswarm.default_config import DEFAULT_CONFIG, PROVIDER_MODELS
from vulnswarm.providers import get_llm_client
from vulnswarm.tools import (
    scan_code_for_secrets,
    scan_code_for_vulns,
    scan_dependencies,
    check_security_headers,
    probe_xss,
    probe_sqli,
    crawl_endpoints,
    _is_localhost,
)
from vulnswarm.agents import (
    run_recon_agent,
    run_exploit_agent,
    run_red_team_agent,
    run_blue_team_agent,
    run_report_agent,
)


class VulnSwarm:
    """
    Main VulnSwarm orchestrator.
    Coordinates the multi-agent security assessment pipeline.
    """

    def __init__(self, config: dict = None, verbose: bool = False):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.verbose = verbose or self.config.get("verbose", False)

        provider = self.config["llm_provider"]
        models = PROVIDER_MODELS.get(provider, PROVIDER_MODELS["anthropic"])

        self.deep_llm = get_llm_client(provider, self.config.get("deep_think_llm", models["deep"]))
        self.quick_llm = get_llm_client(provider, self.config.get("quick_think_llm", models["quick"]))

    def _log(self, msg: str, icon: str = "→"):
        if self.verbose:
            print(f"  {icon} {msg}")

    def scan(self, target_path: str = None, target_url: str = None) -> dict:
        """
        Run the full VulnSwarm assessment pipeline.

        Args:
            target_path: Path to codebase to scan
            target_url:  URL of local web app to probe (localhost only)

        Returns:
            dict with 'report' (markdown string) and 'findings' (raw data)
        """
        if not target_path and not target_url:
            raise ValueError("Provide at least one of: target_path, target_url")

        if target_url and not _is_localhost(target_url):
            raise ValueError(
                "VulnSwarm only scans localhost URLs for safety. "
                "Use target_url='http://localhost:PORT' to scan your local app."
            )

        print("\n🔍 VulnSwarm starting assessment...\n")
        scan_data = {"target": target_path or "none", "url": target_url or "none"}

        # ── Phase 1: Passive scanning ──────────────────────────────────
        print("⚡ Phase 1: Passive Scanning")

        if target_path:
            self._log("Scanning for hardcoded secrets...")
            scan_data["secret_findings"] = scan_code_for_secrets(target_path)
            self._log(f"  Found {len(scan_data['secret_findings'])} secret(s)")

            self._log("Scanning for dangerous code patterns...")
            scan_data["code_findings"] = scan_code_for_vulns(target_path)
            self._log(f"  Found {len(scan_data['code_findings'])} code issue(s)")

            self._log("Scanning dependencies...")
            scan_data["dep_findings"] = scan_dependencies(target_path)
            self._log(f"  Found {len(scan_data['dep_findings'])} dependency issue(s)")
        else:
            scan_data["secret_findings"] = []
            scan_data["code_findings"] = []
            scan_data["dep_findings"] = []

        # ── Phase 2: Active web scanning (localhost only) ──────────────
        print("⚡ Phase 2: Active Web Scanning")
        active_findings = {"xss": [], "sqli": [], "headers": []}

        if target_url:
            self._log("Checking security headers...")
            active_findings["headers"] = check_security_headers(target_url)
            scan_data["header_findings"] = active_findings["headers"]

            self._log("Crawling endpoints...")
            endpoints = crawl_endpoints(target_url, max_pages=20)
            scan_data["endpoints"] = endpoints
            self._log(f"  Found {len(endpoints)} endpoint(s)")

            if self.config.get("enable_active_scanning", True):
                # Try to extract params from endpoints
                import re
                all_params = set()
                for ep in endpoints:
                    params = re.findall(r'[?&](\w+)=', ep)
                    all_params.update(params)

                if all_params:
                    self._log(f"Probing {len(all_params)} parameter(s) for XSS...")
                    active_findings["xss"] = probe_xss(target_url, list(all_params))

                    self._log(f"Probing {len(all_params)} parameter(s) for SQLi...")
                    active_findings["sqli"] = probe_sqli(target_url, list(all_params))
        else:
            scan_data["header_findings"] = []
            scan_data["endpoints"] = []

        # ── Phase 3: AI Agent Pipeline ─────────────────────────────────
        print("🤖 Phase 3: AI Agent Analysis\n")
        all_reports = {}

        print("  [1/4] 🔭 Recon Agent analyzing attack surface...")
        all_reports["recon"] = run_recon_agent(self.quick_llm, scan_data)

        print("  [2/4] 💥 Exploit Agent assessing vulnerabilities...")
        all_reports["exploit"] = run_exploit_agent(self.deep_llm, all_reports["recon"], active_findings)

        print("  [3/4] 🗡️  Red Team Agent thinking like an attacker...")
        all_reports["red_team"] = run_red_team_agent(self.deep_llm, all_reports["exploit"])

        print("  [4/4] 🛡️  Blue Team Agent generating fixes...")
        all_reports["blue_team"] = run_blue_team_agent(self.deep_llm, all_reports["red_team"], all_reports["exploit"])

        # ── Phase 4: Report Generation ─────────────────────────────────
        print("\n📄 Phase 4: Generating Report...")
        target_label = target_path or target_url
        final_report = run_report_agent(self.deep_llm, all_reports, target_label)

        # Save report
        output_dir = Path(self.config.get("output_dir", "./vulnswarm_reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = output_dir / f"vulnswarm_report_{timestamp}.md"
        report_path.write_text(final_report)

        print(f"\n✅ Assessment complete!")
        print(f"📋 Report saved: {report_path}\n")

        return {
            "report": final_report,
            "report_path": str(report_path),
            "findings": {
                "secrets": scan_data.get("secret_findings", []),
                "code": scan_data.get("code_findings", []),
                "dependencies": scan_data.get("dep_findings", []),
                "xss": active_findings.get("xss", []),
                "sqli": active_findings.get("sqli", []),
                "headers": active_findings.get("headers", []),
            },
            "agent_reports": all_reports,
        }
