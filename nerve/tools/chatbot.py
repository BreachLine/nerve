"""Chatbot testing tools — multi-turn conversation, session management."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()


async def chatbot_send(
    url: str = "",
    message: str = "",
    message_field: str = "content",
    response_field: str = "reply",
    session_cookie: str = "",
    headers_str: str = "",
    timeout: float = 30.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Send a single message to a chatbot endpoint."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    cookies: dict[str, str] = {}
    if session_cookie:
        cookies["session"] = session_cookie
    if headers_str:
        for pair in headers_str.split("|"):
            if ":" in pair:
                k, v = pair.split(":", 1)
                headers[k.strip()] = v.strip()

    payload = {message_field: message}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(url, json=payload, headers=headers, cookies=cookies)
            if r.status_code == 200:
                try:
                    data = r.json()
                    reply = data.get(response_field, data)
                    return f"CHATBOT RESPONSE:\n{json.dumps(reply, indent=2) if isinstance(reply, dict) else reply}"
                except json.JSONDecodeError:
                    return f"CHATBOT RESPONSE (raw):\n{r.text[:5000]}"
            return f"ERROR: Status {r.status_code}\nBody: {r.text[:2000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def chatbot_multi_turn(
    url: str = "",
    messages_json: str = "[]",
    message_field: str = "content",
    response_field: str = "reply",
    delay_seconds: float = 1.0,
    timeout: float = 30.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Send a multi-turn conversation to a chatbot and collect all responses."""
    import asyncio

    try:
        messages = json.loads(messages_json) if messages_json else []
    except json.JSONDecodeError:
        return "ERROR: Invalid messages JSON"

    results: list[str] = [f"Multi-turn conversation ({len(messages)} turns):"]

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        session_cookies: dict[str, str] = {}

        for i, msg in enumerate(messages):
            if rate_limiter:
                await rate_limiter.acquire()

            payload = {message_field: msg}
            try:
                r = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    cookies=session_cookies,
                )
                # Capture session cookies
                for name, value in r.cookies.items():
                    session_cookies[name] = value

                if r.status_code == 200:
                    try:
                        data = r.json()
                        reply = data.get(response_field, str(data))
                    except json.JSONDecodeError:
                        reply = r.text[:2000]
                    results.append(f"\n  Turn {i + 1}:")
                    results.append(f"    USER: {msg[:200]}")
                    results.append(f"    BOT: {str(reply)[:500]}")
                else:
                    results.append(f"\n  Turn {i + 1}: ERROR {r.status_code}")

            except Exception as e:
                results.append(f"\n  Turn {i + 1}: ERROR {e}")

            if delay_seconds > 0 and i < len(messages) - 1:
                await asyncio.sleep(delay_seconds)

    return "\n".join(results)


async def chatbot_session_test(
    url: str = "",
    session_endpoint: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Test chatbot session management — creation, isolation, fixation."""
    if rate_limiter:
        await rate_limiter.acquire()

    results: list[str] = ["Session Security Test:"]

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            # Create two sessions
            s1 = await client.post(session_endpoint or url, json={"content": "session test 1"})
            s2 = await client.post(session_endpoint or url, json={"content": "session test 2"})

            s1_cookies = dict(s1.cookies)
            s2_cookies = dict(s2.cookies)

            results.append(f"  Session 1 cookies: {list(s1_cookies.keys())}")
            results.append(f"  Session 2 cookies: {list(s2_cookies.keys())}")

            # Test cross-session with session 1's cookies on session 2's endpoint
            if s1_cookies:
                r = await client.post(url, json={"content": "What was my first message?"}, cookies=s1_cookies)
                results.append(f"  Cross-session test: Status {r.status_code}")
                results.append(f"  Response: {r.text[:500]}")
            else:
                results.append("  No session cookies set — stateless or no session management")

    except Exception as e:
        results.append(f"  ERROR: {e}")

    return "\n".join(results)
