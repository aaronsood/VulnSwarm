"""
Multi-provider LLM abstraction for VulnSwarm.
Supports Anthropic, OpenAI, Google, OpenRouter, and Ollama.
"""

import os
from typing import Optional


def get_llm_client(provider: str, model: str, temperature: float = 0.3):
    """
    Returns a LangChain-compatible LLM client for the given provider.
    """
    provider = provider.lower()

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        return ChatAnthropic(model=model, temperature=temperature, api_key=api_key)

    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set")
        return ChatOpenAI(model=model, temperature=temperature, api_key=api_key)

    elif provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not set")
        return ChatGoogleGenerativeAI(model=model, temperature=temperature, google_api_key=api_key)

    elif provider == "openrouter":
        from langchain_openai import ChatOpenAI
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY not set")
        return ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )

    elif provider == "ollama":
        from langchain_ollama import ChatOllama
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        return ChatOllama(model=model, temperature=temperature, base_url=host)

    else:
        raise ValueError(f"Unknown provider: {provider}. Choose from: anthropic, openai, google, openrouter, ollama")


def test_provider(provider: str, model: str) -> tuple[bool, str]:
    """Test if a provider is reachable and returns a success/error tuple."""
    try:
        llm = get_llm_client(provider, model)
        response = llm.invoke("Reply with only: OK")
        return True, "Connected"
    except Exception as e:
        return False, str(e)
