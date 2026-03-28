"""Bridge between ReactSwarm's LLMRouter and actual LLM provider APIs.

ReactSwarm's LLMRouter requires a `call_fn` callback. This module provides
the actual API calls to Anthropic, OpenAI, Google, and OpenAI-compatible endpoints.
"""

from __future__ import annotations

import asyncio
import json
import random
from typing import Any

import httpx
import structlog
from reactswarm.llm.providers import LLMProvider, ProviderConfig

logger = structlog.get_logger()

_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503})
_MAX_RETRIES = 3
_BASE_DELAY = 1.0


async def _request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    """Execute an HTTP request with exponential backoff on transient failures.

    Retries on 429/500/502/503 status codes and connection/timeout errors.
    """
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            r = await client.request(method, url, **kwargs)
            if r.status_code not in _RETRYABLE_STATUS_CODES or attempt == _MAX_RETRIES:
                r.raise_for_status()
                return r
            # Retryable status — fall through to backoff
            last_exc = httpx.HTTPStatusError(
                f"HTTP {r.status_code}",
                request=r.request,
                response=r,
            )
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as e:
            last_exc = e
            if attempt == _MAX_RETRIES:
                raise

        delay = _BASE_DELAY * (2**attempt) + random.uniform(0, 0.5)  # noqa: S311
        logger.warning(
            "llm_request_retry",
            attempt=attempt + 1,
            delay=f"{delay:.1f}s",
            error=str(last_exc),
        )
        await asyncio.sleep(delay)

    # Should not reach here, but satisfy type checker
    raise last_exc  # type: ignore[misc]


async def llm_call_fn(
    config: ProviderConfig,
    messages: list[dict[str, str]],
    **kwargs: Any,
) -> str:
    """Universal LLM call function for all providers.

    Routes to the correct API based on config.provider.
    """
    provider = config.provider

    if provider == LLMProvider.GOOGLE:
        return await _call_google(config, messages, **kwargs)
    elif provider == LLMProvider.ANTHROPIC:
        return await _call_anthropic(config, messages, **kwargs)
    elif provider in (LLMProvider.OPENAI, LLMProvider.CUSTOM):
        return await _call_openai_compat(config, messages, **kwargs)
    else:
        return await _call_openai_compat(config, messages, **kwargs)


async def _call_google(
    config: ProviderConfig,
    messages: list[dict[str, str]],
    **kwargs: Any,
) -> str:
    """Call Google Gemini via REST API."""
    api_key = config.api_key
    model = config.model or "gemini-2.5-flash"
    temperature = kwargs.get("temperature", config.temperature)
    max_tokens = kwargs.get("max_tokens", config.max_tokens)

    # Convert messages to Gemini format
    system_instruction = None
    contents: list[dict] = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            system_instruction = content
        else:
            gemini_role = "model" if role == "assistant" else "user"
            contents.append({"role": gemini_role, "parts": [{"text": content}]})

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        },
    }
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

    # Handle tool schemas if provided
    tools = kwargs.get("tools")
    if tools:
        gemini_tools = _convert_tools_to_gemini(tools)
        if gemini_tools:
            payload["tools"] = gemini_tools

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        r = await _request_with_retry(client, "POST", url, json=payload)
        data = r.json()

    # Extract text from response
    candidates = data.get("candidates", [])
    if not candidates:
        raise ValueError(f"No candidates in Gemini response: {data}")

    parts = candidates[0].get("content", {}).get("parts", [])
    text_parts: list[str] = []
    for part in parts:
        if "text" in part:
            text_parts.append(part["text"])
        elif "functionCall" in part:
            fc = part["functionCall"]
            text_parts.append(f'ACTION: {{"tool": "{fc["name"]}", "parameters": {json.dumps(fc.get("args", {}))}}}')

    return "\n".join(text_parts)


async def _call_anthropic(
    config: ProviderConfig,
    messages: list[dict[str, str]],
    **kwargs: Any,
) -> str:
    """Call Anthropic Claude via REST API."""
    api_key = config.api_key
    model = config.model or "claude-sonnet-4-5-20250514"
    temperature = kwargs.get("temperature", config.temperature)
    max_tokens = kwargs.get("max_tokens", config.max_tokens) or 4096

    # Extract system message
    system_text = ""
    api_messages: list[dict] = []
    for msg in messages:
        if msg.get("role") == "system":
            system_text = msg.get("content", "")
        else:
            api_messages.append({"role": msg["role"], "content": msg.get("content", "")})

    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": api_messages,
    }
    if system_text:
        payload["system"] = system_text

    tools = kwargs.get("tools")
    if tools:
        payload["tools"] = tools

    url = config.base_url or "https://api.anthropic.com"
    url = f"{url.rstrip('/')}/v1/messages"

    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        r = await _request_with_retry(
            client,
            "POST",
            url,
            json=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        data = r.json()

    # Extract text
    content = data.get("content", [])
    text_parts: list[str] = []
    for block in content:
        if block.get("type") == "text":
            text_parts.append(block["text"])
        elif block.get("type") == "tool_use":
            text_parts.append(
                f'ACTION: {{"tool": "{block["name"]}", "parameters": {json.dumps(block.get("input", {}))}}}'
            )

    return "\n".join(text_parts)


async def _call_openai_compat(
    config: ProviderConfig,
    messages: list[dict[str, str]],
    **kwargs: Any,
) -> str:
    """Call OpenAI or any OpenAI-compatible endpoint (vLLM, Ollama, LiteLLM, etc.)."""
    api_key = config.api_key
    model = config.model or "gpt-4o"
    temperature = kwargs.get("temperature", config.temperature)
    max_tokens = kwargs.get("max_tokens", config.max_tokens)

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    tools = kwargs.get("tools")
    if tools:
        payload["tools"] = tools

    base_url = config.base_url or "https://api.openai.com"
    url = f"{base_url.rstrip('/')}/v1/chat/completions"

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        r = await _request_with_retry(client, "POST", url, json=payload, headers=headers)
        data = r.json()

    choice = data.get("choices", [{}])[0]
    msg = choice.get("message", {})
    content = msg.get("content", "")

    # Handle tool calls
    tool_calls = msg.get("tool_calls", [])
    if tool_calls:
        parts: list[str] = []
        if content:
            parts.append(content)
        for tc in tool_calls:
            fn = tc.get("function", {})
            parts.append(f'ACTION: {{"tool": "{fn.get("name", "")}", "parameters": {fn.get("arguments", "{}")}}}')
        return "\n".join(parts)

    return content or ""


def _convert_tools_to_gemini(tools: list[dict]) -> list[dict]:
    """Convert OpenAI-style tool schemas to Gemini format."""
    declarations: list[dict] = []
    for tool in tools:
        if tool.get("type") == "function":
            fn = tool["function"]
            declarations.append(
                {
                    "name": fn["name"],
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {}),
                }
            )
    if declarations:
        return [{"functionDeclarations": declarations}]
    return []
