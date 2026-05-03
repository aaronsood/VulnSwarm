"""
VulnSwarm Agents
Each agent has a specialized role in the security assessment pipeline.
"""

from langchain_core.messages import HumanMessage, SystemMessage


# ─────────────────────────────────────────────
#  RECON AGENT
# ─────────────────────────────────────────────

RECON_SYSTEM = """You are the Recon Agent for VulnSwarm, an AI-powered penetration testing framework.
Your job is to analyze the target and identify the attack surface.

Given raw scan results (files, endpoints, dependencies), produce a structured recon report:
1. List all identified entry points (form fields, URL params, file upload endpoints, API endpoints)
2. Identify the technology stack (language, framework, database clues)
3. Flag the highest-risk areas to investigate first
4. Assign a preliminary risk score (1-10)

Be precise. Output as structured text with clear sections. Do not hallucinate findings."""


def run_recon_agent(llm, scan_data: dict) -> str:
    messages = [
        SystemMessage(content=RECON_SYSTEM),
        HumanMessage(content=f"""
Analyze this raw scan data and produce a recon report:

Code findings: {scan_data.get('code_findings', [])}
Secret findings: {scan_data.get('secret_findings', [])}
Dependency findings: {scan_data.get('dep_findings', [])}
Web endpoints found: {scan_data.get('endpoints', [])}
Security header issues: {scan_data.get('header_findings', [])}
Target path: {scan_data.get('target', 'unknown')}
Target URL: {scan_data.get('url', 'none')}
""")
    ]
    response = llm.invoke(messages)
    return response.content


# ─────────────────────────────────────────────
#  EXPLOIT AGENT
# ─────────────────────────────────────────────

EXPLOIT_SYSTEM = """You are the Exploit Agent for VulnSwarm, an AI-powered penetration testing framework.
Your role is to analyze the recon report and active scan results, then determine which vulnerabilities are exploitable and how severe they are.

For each finding:
1. Assess exploitability (Easy / Medium / Hard)
2. Assess impact (Low / Medium / High / Critical)
3. Calculate CVSS-like severity
4. Describe the exploitation chain in plain English
5. Provide a proof-of-concept description (NOT actual weaponized code)

Focus on: SQLi, XSS, IDOR, auth bypass, path traversal, secrets exposure, RCE risks.
Be technical but clear. Do not provide working malware or weaponized exploits."""


def run_exploit_agent(llm, recon_report: str, active_findings: dict) -> str:
    messages = [
        SystemMessage(content=EXPLOIT_SYSTEM),
        HumanMessage(content=f"""
Recon Report:
{recon_report}

Active Scan Results:
XSS findings: {active_findings.get('xss', [])}
SQLi findings: {active_findings.get('sqli', [])}
Header issues: {active_findings.get('headers', [])}

Analyze each finding. Determine exploitability and impact. Output a structured vulnerability list with severity ratings.
""")
    ]
    response = llm.invoke(messages)
    return response.content


# ─────────────────────────────────────────────
#  RED TEAM AGENT
# ─────────────────────────────────────────────

RED_TEAM_SYSTEM = """You are the Red Team Agent for VulnSwarm. You think like an attacker.
Given the exploit analysis, your job is to:
1. Identify attack chains - how could multiple vulnerabilities be combined?
2. Assess business impact - what could a real attacker actually achieve?
3. Identify the most critical path to compromise
4. Challenge any assumptions in the exploit analysis - are there worse scenarios?
5. Rate overall security posture: CRITICAL / HIGH / MEDIUM / LOW

Think adversarially. Be thorough. Assume the attacker is skilled and motivated."""


def run_red_team_agent(llm, exploit_report: str) -> str:
    messages = [
        SystemMessage(content=RED_TEAM_SYSTEM),
        HumanMessage(content=f"""
Exploit Analysis:
{exploit_report}

As a red team attacker: identify attack chains, worst-case scenarios, and the most critical path to full compromise.
What would a skilled attacker do with these findings?
""")
    ]
    response = llm.invoke(messages)
    return response.content


# ─────────────────────────────────────────────
#  BLUE TEAM AGENT
# ─────────────────────────────────────────────

BLUE_TEAM_SYSTEM = """You are the Blue Team Agent for VulnSwarm. You think like a defender.
Given the red team analysis, your job is to:
1. Provide specific, actionable fixes for every vulnerability found
2. Prioritize fixes by effort vs. impact (quick wins first)
3. Recommend security controls to prevent future issues
4. Provide code-level fix examples where possible
5. Suggest security testing to add to the CI/CD pipeline

Be practical. Developers need to implement these fixes. Give concrete recommendations, not vague advice."""


def run_blue_team_agent(llm, red_team_report: str, exploit_report: str) -> str:
    messages = [
        SystemMessage(content=BLUE_TEAM_SYSTEM),
        HumanMessage(content=f"""
Red Team Analysis:
{red_team_report}

Exploit Findings:
{exploit_report}

Provide a prioritized remediation plan with specific fixes for each vulnerability.
Include code examples where relevant. Focus on actionable steps a developer can implement today.
""")
    ]
    response = llm.invoke(messages)
    return response.content


# ─────────────────────────────────────────────
#  REPORT AGENT
# ─────────────────────────────────────────────

REPORT_SYSTEM = """You are the Report Agent for VulnSwarm. You synthesize all findings into a professional security report.

Produce a complete penetration testing report with:
1. Executive Summary (non-technical, 1 paragraph)
2. Risk Score (0-100) with justification  
3. Critical Findings (if any) - needs immediate action
4. High Findings
5. Medium Findings
6. Low/Informational Findings
7. Remediation Roadmap (week 1, month 1, quarter 1)
8. Security Score Card

Format as clean Markdown. Be professional - this report could go to a CTO or security team.
Include severity badges: 🔴 CRITICAL  🟠 HIGH  🟡 MEDIUM  🔵 LOW  ⚪ INFO"""


def run_report_agent(llm, all_reports: dict, target: str) -> str:
    messages = [
        SystemMessage(content=REPORT_SYSTEM),
        HumanMessage(content=f"""
Target: {target}

Recon Report:
{all_reports.get('recon', '')}

Exploit Analysis:
{all_reports.get('exploit', '')}

Red Team Analysis:
{all_reports.get('red_team', '')}

Blue Team Remediation:
{all_reports.get('blue_team', '')}

Synthesize all of this into a professional penetration testing report in Markdown format.
""")
    ]
    response = llm.invoke(messages)
    return response.content
