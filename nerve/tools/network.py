"""Network scanning tools — port scan, fingerprint, DNS, TLS."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import socket

import httpx
import structlog

from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()

# AI-related ports
AI_PORTS = [11434, 8000, 8080, 3000, 4000, 6333, 8001, 8888, 9090, 50051, 19530]


async def port_scan(
    target: str,
    ports: str = "",
    timeout: float = 3.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Scan target for open ports. Returns JSON-like summary of open ports."""
    port_list = [int(p) for p in ports.split(",")] if ports else AI_PORTS
    open_ports: list[dict] = []

    async def _check(host: str, port: int) -> dict | None:
        if rate_limiter:
            await rate_limiter.acquire()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return {"host": host, "port": port, "state": "open"}
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return None

    # Handle CIDR ranges
    hosts: list[str] = []
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()][:256]  # Cap at /24
    except ValueError:
        hosts = [target]

    tasks = [_check(h, p) for h in hosts for p in port_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            open_ports.append(r)

    if not open_ports:
        return "No open AI-related ports found."

    lines = [f"Found {len(open_ports)} open port(s):"]
    for p in open_ports:
        lines.append(f"  {p['host']}:{p['port']} — OPEN")
    return "\n".join(lines)


async def http_fingerprint(
    url: str,
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Identify AI service type from HTTP response patterns."""
    if rate_limiter:
        await rate_limiter.acquire()

    results: dict = {"url": url, "service_type": "unknown", "version": "", "details": {}}

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Try Ollama
        try:
            r = await client.get(url.rstrip("/") + "/api/tags")
            if r.status_code == 200 and "models" in r.text:
                data = r.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                results["service_type"] = "ollama"
                results["details"] = {"models": models}
                return f"SERVICE: Ollama\nURL: {url}\nModels: {', '.join(models)}"
        except Exception:
            pass

        # Try OpenAI-compatible (vLLM, LiteLLM, etc.)
        try:
            r = await client.get(url.rstrip("/") + "/v1/models")
            if r.status_code == 200:
                data = r.json()
                models = [m.get("id", "") for m in data.get("data", [])]
                results["service_type"] = "openai_compatible"
                results["details"] = {"models": models}
                return f"SERVICE: OpenAI-Compatible API\nURL: {url}\nModels: {', '.join(models)}"
        except Exception:
            pass

        # Try MCP (SSE transport)
        try:
            r = await client.get(url.rstrip("/") + "/sse")
            if r.status_code in (200, 204) or "text/event-stream" in r.headers.get("content-type", ""):
                results["service_type"] = "mcp_server"
                return f"SERVICE: MCP Server (SSE)\nURL: {url}"
        except Exception:
            pass

        # Try generic health/info endpoint
        try:
            r = await client.get(url)
            headers = dict(r.headers)
            body = r.text[:500]
            return f"SERVICE: Unknown\nURL: {url}\nStatus: {r.status_code}\nHeaders: {headers}\nBody: {body}"
        except Exception as e:
            return f"SERVICE: Unreachable\nURL: {url}\nError: {e}"


async def dns_resolve(hostname: str, record_types: str = "A,AAAA") -> str:
    """Resolve hostname DNS records."""
    results: list[str] = [f"DNS Resolution for {hostname}:"]
    try:
        addrs = socket.getaddrinfo(hostname, None)
        seen: set[str] = set()
        for _, _, _, _, addr in addrs:
            ip = addr[0]
            if ip not in seen:
                seen.add(ip)
                results.append(f"  {ip}")
    except socket.gaierror as e:
        results.append(f"  Resolution failed: {e}")
    return "\n".join(results)


async def tls_check(host: str, port: int = 443) -> str:
    """Check TLS certificate and cipher configuration."""
    results: list[str] = [f"TLS Check for {host}:{port}:"]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                results.append(f"  Protocol: {ssock.version()}")
                results.append(f"  Cipher: {ssock.cipher()}")
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    results.append(f"  Subject: {subject.get('commonName', 'N/A')}")
                    results.append(f"  Issuer: {dict(x[0] for x in cert.get('issuer', []))}")
                    results.append(f"  Expires: {cert.get('notAfter', 'N/A')}")
    except Exception as e:
        results.append(f"  Error: {e}")
    return "\n".join(results)
