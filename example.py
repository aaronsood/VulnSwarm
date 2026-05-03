"""
VulnSwarm - Quick start example
"""

from vulnswarm.graph import VulnSwarm
from vulnswarm.default_config import DEFAULT_CONFIG

# ── Example 1: Scan a codebase ─────────────────────────────────────────
vs = VulnSwarm(
    config={
        **DEFAULT_CONFIG,
        "llm_provider": "anthropic",   # or: openai, google, openrouter, ollama
        "scan_depth": "medium",
    },
    verbose=True,
)

result = vs.scan(target_path="./my_project")

print(result["report"])          # Full markdown report
print(result["report_path"])     # Path to saved report file
print(result["findings"])        # Raw findings dict


# ── Example 2: Scan a local web app ────────────────────────────────────
result = vs.scan(target_url="http://localhost:3000")


# ── Example 3: Scan both ───────────────────────────────────────────────
result = vs.scan(
    target_path="./my_project",
    target_url="http://localhost:8000",
)


# ── Example 4: Use OpenAI instead ─────────────────────────────────────
vs_gpt = VulnSwarm(config={
    **DEFAULT_CONFIG,
    "llm_provider": "openai",
    "deep_think_llm": "gpt-4o",
    "quick_think_llm": "gpt-4o-mini",
})
result = vs_gpt.scan(target_path="./my_project")


# ── Example 5: Use local Ollama (no API key) ──────────────────────────
vs_local = VulnSwarm(config={
    **DEFAULT_CONFIG,
    "llm_provider": "ollama",
    "deep_think_llm": "llama3",
    "quick_think_llm": "llama3",
})
result = vs_local.scan(target_path="./my_project")
