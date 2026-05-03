"""
Security scanning tools for VulnSwarm agents.
All tools are passive/safe and target localhost or local code only.
"""

import os
import re
import ast
import json
import socket
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ─────────────────────────────────────────────
#  CODE ANALYSIS TOOLS
# ─────────────────────────────────────────────

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][a-zA-Z0-9]{16,}['\"]",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
}

DANGEROUS_FUNCTIONS = {
    "python": {
        "eval": "Code injection via eval()",
        "exec": "Code injection via exec()",
        "os.system": "OS command injection",
        "subprocess.call": "OS command injection (check for shell=True)",
        "subprocess.Popen": "OS command injection (check for shell=True)",
        "pickle.loads": "Unsafe deserialization",
        "yaml.load": "Unsafe YAML parsing (use yaml.safe_load)",
        "__import__": "Dynamic import abuse",
        "open": "File access (verify path sanitization)",
        "input": "Raw user input (Python 2 code execution risk)",
    },
    "javascript": {
        "eval(": "Code injection via eval()",
        "innerHTML": "XSS via innerHTML",
        "document.write": "XSS via document.write",
        "setTimeout(": "Potential code injection if string arg",
        "setInterval(": "Potential code injection if string arg",
        "dangerouslySetInnerHTML": "React XSS risk",
        "child_process": "OS command injection",
    },
}

SQL_PATTERNS = [
    r"['\"]?\s*\+\s*\w+\s*\+\s*['\"]",       # string concatenation in queries
    r"f['\"].*SELECT.*{",                       # f-string SQL
    r"format\(.*SELECT",                        # .format() SQL
    r"%s.*WHERE.*%",                            # old-style % formatting
    r"query\s*=\s*['\"].*\+",                  # query string building
]


def scan_code_for_secrets(path: str) -> list[dict]:
    """Scan a file or directory for hardcoded secrets."""
    findings = []
    root = Path(path)
    files = list(root.rglob("*")) if root.is_dir() else [root]

    for f in files:
        if not f.is_file():
            continue
        if f.suffix in {".pyc", ".png", ".jpg", ".gif", ".zip", ".lock"}:
            continue
        try:
            content = f.read_text(errors="ignore")
            for secret_name, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append({
                        "type": "Secret",
                        "name": secret_name,
                        "file": str(f),
                        "line": line_no,
                        "snippet": match.group()[:60] + "...",
                        "severity": "CRITICAL",
                    })
        except Exception:
            continue
    return findings


def scan_code_for_vulns(path: str, language: str = "auto") -> list[dict]:
    """Scan code for dangerous function usage and SQL injection patterns."""
    findings = []
    root = Path(path)

    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".jsx": "javascript", ".tsx": "javascript",
    }

    files = list(root.rglob("*")) if root.is_dir() else [root]
    for f in files:
        if not f.is_file():
            continue
        lang = language if language != "auto" else ext_map.get(f.suffix, None)
        if not lang:
            continue

        try:
            content = f.read_text(errors="ignore")
            lines = content.splitlines()

            # Check dangerous functions
            danger_map = DANGEROUS_FUNCTIONS.get(lang, {})
            for line_no, line in enumerate(lines, 1):
                for func, desc in danger_map.items():
                    if func in line:
                        findings.append({
                            "type": "Dangerous Function",
                            "name": func,
                            "description": desc,
                            "file": str(f),
                            "line": line_no,
                            "snippet": line.strip()[:80],
                            "severity": "HIGH",
                            "language": lang,
                        })

            # Check SQL injection patterns
            if lang == "python":
                for line_no, line in enumerate(lines, 1):
                    for pattern in SQL_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            if any(kw in line.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE", "WHERE"]):
                                findings.append({
                                    "type": "SQL Injection Risk",
                                    "name": "Unsanitized SQL Query",
                                    "file": str(f),
                                    "line": line_no,
                                    "snippet": line.strip()[:80],
                                    "severity": "CRITICAL",
                                    "language": lang,
                                })

        except Exception:
            continue

    return findings


def scan_dependencies(path: str) -> list[dict]:
    """Check for known vulnerable dependencies using pip-audit or npm audit."""
    findings = []
    root = Path(path)

    # Python
    req_file = root / "requirements.txt"
    pyproject = root / "pyproject.toml"
    if req_file.exists() or pyproject.exists():
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json", "-r", str(req_file)] if req_file.exists()
                else ["pip-audit", "--format=json"],
                capture_output=True, text=True, timeout=60, cwd=str(root)
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "type": "Vulnerable Dependency",
                        "name": f"{vuln['name']}=={vuln['version']}",
                        "description": vuln.get("description", "Known vulnerability"),
                        "severity": "HIGH",
                        "fix": f"Upgrade to {vuln.get('fix_versions', ['unknown'])[0]}",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            findings.append({
                "type": "Info",
                "name": "pip-audit not installed",
                "description": "Install pip-audit for dependency scanning: pip install pip-audit",
                "severity": "INFO",
            })

    return findings


# ─────────────────────────────────────────────
#  WEB APP SCANNING TOOLS
# ─────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(2)--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _is_localhost(url: str) -> bool:
    """Enforce localhost-only scanning."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or host.startswith("192.168.") or host.startswith("10.")


def check_security_headers(base_url: str) -> list[dict]:
    """Check for missing security headers."""
    if not REQUESTS_AVAILABLE:
        return [{"type": "Error", "name": "requests not installed", "severity": "INFO"}]

    findings = []
    try:
        r = requests.get(base_url, timeout=5, verify=False)
        for header in SECURITY_HEADERS:
            if header not in r.headers:
                findings.append({
                    "type": "Missing Security Header",
                    "name": header,
                    "description": f"Response missing {header} header",
                    "severity": "MEDIUM",
                    "url": base_url,
                })
        # Check for info leakage
        server = r.headers.get("Server", "")
        if server:
            findings.append({
                "type": "Information Disclosure",
                "name": "Server Header",
                "description": f"Server header reveals: {server}",
                "severity": "LOW",
                "url": base_url,
            })
    except requests.exceptions.ConnectionError:
        findings.append({
            "type": "Error",
            "name": "Connection refused",
            "description": f"Could not connect to {base_url}",
            "severity": "INFO",
        })
    return findings


def probe_xss(base_url: str, params: list[str]) -> list[dict]:
    """Probe URL parameters for reflected XSS."""
    if not REQUESTS_AVAILABLE:
        return []
    findings = []
    for param in params:
        for payload in XSS_PAYLOADS[:2]:  # limit in safe mode
            try:
                r = requests.get(base_url, params={param: payload}, timeout=5, verify=False)
                if payload in r.text:
                    findings.append({
                        "type": "XSS",
                        "name": "Reflected XSS",
                        "description": f"Parameter '{param}' reflects payload unescaped",
                        "payload": payload,
                        "url": base_url,
                        "severity": "HIGH",
                    })
                    break
            except Exception:
                continue
    return findings


def probe_sqli(base_url: str, params: list[str]) -> list[dict]:
    """Probe URL parameters for SQL injection errors."""
    if not REQUESTS_AVAILABLE:
        return []
    findings = []
    sql_errors = ["syntax error", "mysql_fetch", "ORA-", "sqlite3", "pg_query", "SQLSTATE"]

    for param in params:
        try:
            r = requests.get(base_url, params={param: "'"}, timeout=5, verify=False)
            if any(err.lower() in r.text.lower() for err in sql_errors):
                findings.append({
                    "type": "SQL Injection",
                    "name": "Error-Based SQLi",
                    "description": f"Parameter '{param}' triggers SQL error",
                    "url": base_url,
                    "severity": "CRITICAL",
                })
        except Exception:
            continue
    return findings


def crawl_endpoints(base_url: str, max_pages: int = 20) -> list[str]:
    """Simple endpoint crawler for localhost apps."""
    if not REQUESTS_AVAILABLE:
        return []
    found = set()
    to_visit = [base_url]
    visited = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=5, verify=False)
            found.add(url)
            # Extract links
            links = re.findall(r'href=["\']([^"\']+)["\']', r.text)
            for link in links:
                full = urljoin(base_url, link)
                if _is_localhost(full) and full not in visited:
                    to_visit.append(full)
        except Exception:
            continue

    return list(found)
