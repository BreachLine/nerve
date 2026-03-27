"""MCP protocol tools — connect, enumerate, and test MCP servers."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()


async def mcp_connect(
    target: str = "",
    transport: str = "sse",
    token: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Establish connection to an MCP server and return server info."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if transport == "sse":
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try MCP initialize handshake
                init_payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "nerve-audit", "version": "0.1.0"},
                    },
                }
                # Try POST endpoint first
                r = await client.post(target.rstrip("/"), json=init_payload, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    server_info = data.get("result", {}).get("serverInfo", {})
                    capabilities = data.get("result", {}).get("capabilities", {})
                    return (
                        f"MCP SERVER CONNECTED\n"
                        f"Transport: SSE\n"
                        f"Server: {json.dumps(server_info)}\n"
                        f"Capabilities: {json.dumps(capabilities)}\n"
                        f"Auth Required: {'yes' if token else 'NO — connected without auth!'}"
                    )
                return f"MCP CONNECT FAILED\nStatus: {r.status_code}\nBody: {r.text[:1000]}"
        except Exception as e:
            return f"MCP CONNECT ERROR: {e}"
    else:
        return f"MCP stdio transport: command-based connection not available via HTTP tools. Use mcp SDK directly."


async def mcp_list_tools(
    target: str = "",
    token: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """List all tools on an MCP server with their schemas."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(target.rstrip("/"), json=payload, headers=headers)
            if r.status_code == 200:
                data = r.json()
                tools = data.get("result", {}).get("tools", [])
                lines = [f"Found {len(tools)} MCP tool(s):"]
                for t in tools:
                    name = t.get("name", "unknown")
                    desc = t.get("description", "No description")
                    schema = json.dumps(t.get("inputSchema", {}), indent=2)
                    lines.append(f"\n  TOOL: {name}")
                    lines.append(f"  Description: {desc}")
                    lines.append(f"  Schema: {schema}")
                return "\n".join(lines)
            return f"ERROR listing tools: Status {r.status_code}\nBody: {r.text[:1000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def mcp_call_tool(
    target: str = "",
    tool_name: str = "",
    arguments_json: str = "{}",
    token: str = "",
    timeout: float = 15.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Call a specific tool on an MCP server."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        args = json.loads(arguments_json) if arguments_json else {}
    except json.JSONDecodeError:
        return "ERROR: Invalid arguments JSON"

    payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(target.rstrip("/"), json=payload, headers=headers)
            if r.status_code == 200:
                data = r.json()
                result = data.get("result", {})
                error = data.get("error", None)
                if error:
                    return f"TOOL ERROR: {json.dumps(error)}"
                content = result.get("content", [])
                text_parts = [c.get("text", str(c)) for c in content]
                return f"TOOL RESULT ({tool_name}):\n{''.join(text_parts)}"
            return f"ERROR: Status {r.status_code}\nBody: {r.text[:2000]}"
    except Exception as e:
        return f"ERROR: {e}"


async def mcp_list_resources(
    target: str = "",
    token: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """List all resources exposed by an MCP server."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(target.rstrip("/"), json=payload, headers=headers)
            if r.status_code == 200:
                data = r.json()
                resources = data.get("result", {}).get("resources", [])
                lines = [f"Found {len(resources)} MCP resource(s):"]
                for res in resources:
                    lines.append(f"  - {res.get('uri', 'N/A')}: {res.get('name', '')} ({res.get('mimeType', '')})")
                return "\n".join(lines)
            return f"ERROR: Status {r.status_code}"
    except Exception as e:
        return f"ERROR: {e}"
