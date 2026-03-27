"""HTTP tools — full request control for agent probing."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.utils.rate_limiter import RateLimiter
from nerve.utils.sanitizer import sanitize

logger = structlog.get_logger()

_MAX_RESPONSE_SIZE = 50_000  # 50KB max response for agent consumption


async def http_request(
    method: str = "GET",
    url: str = "",
    headers: str = "",
    body: str = "",
    cookies: str = "",
    timeout: float = 15.0,
    follow_redirects: bool = False,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Make an HTTP request with full control. Headers/cookies as 'key:value' pairs separated by '|'."""
    if rate_limiter:
        await rate_limiter.acquire()

    h: dict[str, str] = {}
    if headers:
        for pair in headers.split("|"):
            if ":" in pair:
                k, v = pair.split(":", 1)
                h[k.strip()] = v.strip()

    c: dict[str, str] = {}
    if cookies:
        for pair in cookies.split("|"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                c[k.strip()] = v.strip()

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=follow_redirects
        ) as client:
            r = await client.request(
                method=method.upper(),
                url=url,
                headers=h or None,
                content=body.encode() if body else None,
                cookies=c or None,
            )
            response_body = r.text[:_MAX_RESPONSE_SIZE]
            return (
                f"STATUS: {r.status_code}\n"
                f"HEADERS: {json.dumps(dict(r.headers), indent=2)}\n"
                f"BODY:\n{response_body}"
            )
    except Exception as e:
        return f"ERROR: {e}"


async def http_post_json(
    url: str = "",
    json_body: str = "",
    headers: str = "",
    timeout: float = 15.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """POST JSON to URL. Convenience wrapper for LLM tool calling."""
    if rate_limiter:
        await rate_limiter.acquire()

    h: dict[str, str] = {"Content-Type": "application/json"}
    if headers:
        for pair in headers.split("|"):
            if ":" in pair:
                k, v = pair.split(":", 1)
                h[k.strip()] = v.strip()

    try:
        data = json.loads(json_body) if json_body else {}
    except json.JSONDecodeError:
        return "ERROR: Invalid JSON body"

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(url, json=data, headers=h)
            response_body = r.text[:_MAX_RESPONSE_SIZE]
            return (
                f"STATUS: {r.status_code}\n"
                f"BODY:\n{response_body}"
            )
    except Exception as e:
        return f"ERROR: {e}"
