"""
Default configuration for VulnSwarm
"""

DEFAULT_CONFIG = {
    # LLM Provider settings
    "llm_provider": "openrouter",       # anthropic, openai, google, openrouter, ollama
    "deep_think_llm": "nvidia/nemotron-3-super:free",   # Model for complex reasoning (exploit chaining, report)
    "quick_think_llm": "openai/gpt-oss-20b:free",  # Model for fast tasks (recon, scanning)

    # Agent settings
    "max_debate_rounds": 2,            # Red team vs blue team debate rounds
    "scan_depth": "medium",            # quick, medium, deep
    "enable_active_scanning": True,    # Enable active web app probing (localhost only)

    # Target settings
    "target_type": "auto",             # auto, code, webapp, both
    "report_format": "markdown",       # markdown, html, json

    # Safety settings
    "localhost_only": True,            # Enforce localhost-only for web scanning
    "safe_mode": True,                 # Prevent any destructive payloads

    # Output settings
    "output_dir": "./vulnswarm_reports",
    "verbose": False,
}

PROVIDER_MODELS = {
    "anthropic": {
        "deep": "claude-sonnet-4-5",
        "quick": "claude-haiku-4-5-20251001",
        "display": "Claude (Anthropic)",
    },
    "openai": {
        "deep": "gpt-4o",
        "quick": "gpt-4o-mini",
        "display": "GPT-4o (OpenAI)",
    },
    "google": {
        "deep": "gemini-1.5-pro",
        "quick": "gemini-1.5-flash",
        "display": "Gemini (Google)",
    },
    "openrouter": {
        "deep": "anthropic/claude-sonnet-4-5",
        "quick": "anthropic/claude-haiku-4-5",
        "display": "OpenRouter",
    },
    "ollama": {
    "deep": "llama3.2:3b",
    "quick": "llama3.2:3b",
    "display": "Ollama (Local)",
    },
}

SCAN_DEPTHS = {
    "quick": {
        "description": "Fast surface scan (~2 min)",
        "checks": ["sqli_basic", "xss_reflected", "secrets", "headers"],
    },
    "medium": {
        "description": "Balanced scan (~5 min)",
        "checks": ["sqli_basic", "sqli_blind", "xss_reflected", "xss_stored",
                   "secrets", "headers", "idor", "auth_bypass", "path_traversal"],
    },
    "deep": {
        "description": "Comprehensive scan (~15 min)",
        "checks": ["sqli_basic", "sqli_blind", "sqli_union", "xss_reflected",
                   "xss_stored", "xss_dom", "secrets", "headers", "idor",
                   "auth_bypass", "path_traversal", "ssrf", "rce", "xxe",
                   "open_redirect", "csrf", "broken_auth", "misconfig"],
    },
}
