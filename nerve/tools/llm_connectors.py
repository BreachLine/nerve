"""LLM connector tools — speak Ollama, OpenAI-compat, vLLM protocols."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()


async def ollama_chat(
    target: str = "",
    model: str = "",
    prompt: str = "",
    system_prompt: str = "",
    timeout: float = 30.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Send a prompt to an Ollama instance via /api/chat."""
    if rate_limiter:
        await rate_limiter.acquire()

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {"model": model, "messages": messages, "stream": False}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(f"{target.rstrip('/')}/api/chat", json=payload)
            if r.status_code == 200:
                data = r.json()
                content = data.get("message", {}).get("content", "")
                eval_dur = data.get("eval_duration", 0)
                return (
                    f"MODEL: {model}\n"
                    f"RESPONSE:\n{content}\n"
                    f"EVAL_DURATION: {eval_dur}ns"
                )
            return f"ERROR: Status {r.status_code}\nBODY: {r.text[:2000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def openai_chat(
    target: str = "",
    model: str = "",
    messages_json: str = "",
    api_key: str = "",
    temperature: float = 0.7,
    max_tokens: int = 1024,
    timeout: float = 30.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Send messages to an OpenAI-compatible endpoint (/v1/chat/completions)."""
    if rate_limiter:
        await rate_limiter.acquire()

    try:
        messages = json.loads(messages_json) if messages_json else [{"role": "user", "content": "Hello"}]
    except json.JSONDecodeError:
        return "ERROR: Invalid messages JSON"

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(
                f"{target.rstrip('/')}/v1/chat/completions",
                json=payload,
                headers=headers,
            )
            if r.status_code == 200:
                data = r.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                usage = data.get("usage", {})
                return (
                    f"MODEL: {model}\n"
                    f"RESPONSE:\n{content}\n"
                    f"USAGE: {json.dumps(usage)}"
                )
            return f"ERROR: Status {r.status_code}\nBODY: {r.text[:2000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def ollama_list_models(
    target: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """List all models on an Ollama instance."""
    if rate_limiter:
        await rate_limiter.acquire()

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.get(f"{target.rstrip('/')}/api/tags")
            if r.status_code == 200:
                data = r.json()
                models = data.get("models", [])
                lines = [f"Found {len(models)} model(s):"]
                for m in models:
                    name = m.get("name", "unknown")
                    size = m.get("size", 0)
                    lines.append(f"  - {name} ({size / 1e9:.1f}GB)")
                return "\n".join(lines)
            return f"ERROR: Status {r.status_code}\nBODY: {r.text[:1000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def openai_list_models(
    target: str = "",
    api_key: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """List models on an OpenAI-compatible endpoint."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.get(f"{target.rstrip('/')}/v1/models", headers=headers)
            if r.status_code == 200:
                data = r.json()
                models = data.get("data", [])
                lines = [f"Found {len(models)} model(s):"]
                for m in models:
                    lines.append(f"  - {m.get('id', 'unknown')} (owner: {m.get('owned_by', 'N/A')})")
                return "\n".join(lines)
            return f"ERROR: Status {r.status_code} — {r.text[:1000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def embedding_request(
    target: str = "",
    model: str = "",
    input_text: str = "",
    api_key: str = "",
    timeout: float = 15.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Send text to an embedding endpoint, get vector dimensions back."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {"model": model, "input": input_text}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(
                f"{target.rstrip('/')}/v1/embeddings",
                json=payload,
                headers=headers,
            )
            if r.status_code == 200:
                data = r.json()
                emb = data.get("data", [{}])[0].get("embedding", [])
                usage = data.get("usage", {})
                return (
                    f"MODEL: {model}\n"
                    f"DIMENSIONS: {len(emb)}\n"
                    f"FIRST_5: {emb[:5]}\n"
                    f"USAGE: {json.dumps(usage)}"
                )
            return f"ERROR: Status {r.status_code}\nBODY: {r.text[:1000]}"
    except Exception as e:
        return f"ERROR: {e}"
