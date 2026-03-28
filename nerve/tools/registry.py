"""Master tool registry — registers all Nerve tools into ReactSwarm ToolRegistry."""

from __future__ import annotations

from typing import Any

import structlog
from reactswarm import ToolRegistry

from nerve.tools.chatbot import chatbot_multi_turn, chatbot_send, chatbot_session_test
from nerve.tools.http import http_post_json, http_request
from nerve.tools.intelligence import cve_lookup, web_fetch, web_search
from nerve.tools.llm_connectors import (
    embedding_request,
    ollama_chat,
    ollama_list_models,
    openai_chat,
    openai_list_models,
)
from nerve.tools.mcp_connector import (
    mcp_call_tool,
    mcp_connect,
    mcp_list_resources,
    mcp_list_tools,
)
from nerve.tools.network import dns_resolve, http_fingerprint, port_scan, tls_check
from nerve.tools.vector_db import vector_insert, vector_list_collections, vector_search
from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()

# Tools that can modify external state and should be blocked in --dry-run mode.
# vector_insert: writes to vector databases
# mcp_call_tool: executes arbitrary MCP server tools (may have side effects)
# http_post_json: sends POST requests that could modify external state
_WRITE_TOOLS = frozenset({"vector_insert", "mcp_call_tool", "http_post_json"})


def _dry_run_stub(tool_name: str) -> Any:
    """Return an async stub that logs the blocked call instead of executing."""

    async def _blocked(**kwargs: Any) -> str:
        safe_keys = list(kwargs.keys())
        logger.info("dry_run_blocked", tool=tool_name, arg_keys=safe_keys)
        return (
            f"DRY-RUN: {tool_name} was not executed because --dry-run is active. "
            f"This tool modifies external state. Provided args: {safe_keys}"
        )

    return _blocked


def create_tool_registry(
    rate_limiter: RateLimiter | None = None,
    *,
    dry_run: bool = False,
) -> ToolRegistry:
    """Create and populate the Nerve tool registry with all 24 tools.

    When *dry_run* is ``True``, tools that modify external state
    (vector_insert, mcp_call_tool) are replaced with safe stubs that
    log the call but perform no I/O.
    """
    registry = ToolRegistry()
    rl = rate_limiter or RateLimiter(rate=10.0)

    # ─── Network tools ───────────────────────────────────────────
    registry.register(
        "port_scan",
        handler=lambda target="", ports="", timeout=3.0: port_scan(target, ports, timeout, rl),
        category="network",
        description="Scan target host/CIDR for open AI-related ports (11434, 8000, 8080, 3000, etc.)",
    )
    registry.register(
        "http_fingerprint",
        handler=lambda url="": http_fingerprint(url, rate_limiter=rl),
        category="network",
        description="Identify AI service type (Ollama, vLLM, MCP, etc.) from HTTP response patterns.",
    )
    registry.register(
        "dns_resolve",
        handler=dns_resolve,
        category="network",
        description="Resolve hostname DNS records (A, AAAA, CNAME).",
    )
    registry.register(
        "tls_check",
        handler=tls_check,
        category="network",
        description="Check TLS certificate, cipher suites, and protocol versions.",
    )

    # ─── HTTP tools ──────────────────────────────────────────────
    registry.register(
        "http_request",
        handler=lambda method="GET", url="", headers="", body="", cookies="", timeout=15.0, follow_redirects=False: http_request(
            method, url, headers, body, cookies, timeout, follow_redirects, rl
        ),
        category="http",
        description="Make HTTP request with full control (method, headers, body, cookies). Headers as 'Key:Value' separated by '|'.",
    )
    registry.register(
        "http_post_json",
        handler=(
            _dry_run_stub("http_post_json")
            if dry_run
            else lambda url="", json_body="", headers="": http_post_json(
                url, json_body, headers, rate_limiter=rl,
            )
        ),
        category="http",
        description=(
            "POST JSON to a URL. Convenience wrapper for LLM probing."
            + (" [BLOCKED in --dry-run mode]" if dry_run else "")
        ),
    )

    # ─── LLM connector tools ────────────────────────────────────
    registry.register(
        "ollama_chat",
        handler=lambda target="", model="", prompt="", system_prompt="": ollama_chat(
            target, model, prompt, system_prompt, rate_limiter=rl
        ),
        category="llm",
        description="Send prompt to Ollama /api/chat. Returns model response.",
    )
    registry.register(
        "openai_chat",
        handler=lambda target="", model="", messages_json="", api_key="", temperature=0.7, max_tokens=1024: openai_chat(
            target, model, messages_json, api_key, temperature, max_tokens, rate_limiter=rl
        ),
        category="llm",
        description="Send messages to OpenAI-compatible /v1/chat/completions endpoint.",
    )
    registry.register(
        "ollama_list_models",
        handler=lambda target="": ollama_list_models(target, rate_limiter=rl),
        category="llm",
        description="List all models on an Ollama instance.",
    )
    registry.register(
        "openai_list_models",
        handler=lambda target="", api_key="": openai_list_models(target, api_key, rate_limiter=rl),
        category="llm",
        description="List models on an OpenAI-compatible endpoint.",
    )
    registry.register(
        "embedding_request",
        handler=lambda target="", model="", input_text="", api_key="": embedding_request(
            target, model, input_text, api_key, rate_limiter=rl
        ),
        category="llm",
        description="Send text to embedding endpoint, get vector dimensions back.",
    )

    # ─── MCP tools ───────────────────────────────────────────────
    registry.register(
        "mcp_connect",
        handler=lambda target="", transport="sse", token="": mcp_connect(target, transport, token, rate_limiter=rl),
        category="mcp",
        description="Connect to MCP server (SSE transport). Returns server info and capabilities.",
    )
    registry.register(
        "mcp_list_tools",
        handler=lambda target="", token="": mcp_list_tools(target, token, rate_limiter=rl),
        category="mcp",
        description="List all tools on an MCP server with their schemas and descriptions.",
    )
    registry.register(
        "mcp_call_tool",
        handler=(
            _dry_run_stub("mcp_call_tool")
            if dry_run
            else lambda target="", tool_name="", arguments_json="{}", token="": mcp_call_tool(
                target, tool_name, arguments_json, token, rate_limiter=rl
            )
        ),
        category="mcp",
        description=(
            "Call a specific tool on an MCP server with given arguments."
            + (" [BLOCKED in --dry-run mode]" if dry_run else "")
        ),
    )
    registry.register(
        "mcp_list_resources",
        handler=lambda target="", token="": mcp_list_resources(target, token, rate_limiter=rl),
        category="mcp",
        description="List all resources exposed by an MCP server.",
    )

    # ─── Vector DB tools ─────────────────────────────────────────
    registry.register(
        "vector_list_collections",
        handler=lambda db_type="qdrant", url="", api_key="": vector_list_collections(
            db_type, url, api_key, rate_limiter=rl
        ),
        category="vector_db",
        description="List collections in a vector database (Qdrant, Weaviate).",
    )
    registry.register(
        "vector_search",
        handler=lambda db_type="qdrant", url="", api_key="", collection="", query_text="", limit=5: vector_search(
            db_type, url, api_key, collection, query_text, limit, rate_limiter=rl
        ),
        category="vector_db",
        description="Query vector database — tests access controls and data exposure.",
    )
    registry.register(
        "vector_insert",
        handler=(
            _dry_run_stub("vector_insert")
            if dry_run
            else lambda db_type="qdrant", url="", api_key="", collection="", text="", metadata="{}": vector_insert(
                db_type, url, api_key, collection, text, metadata, rate_limiter=rl
            )
        ),
        category="vector_db",
        description=(
            "Insert test document into vector DB — tests write access control."
            + (" [BLOCKED in --dry-run mode]" if dry_run else "")
        ),
    )

    # ─── Chatbot tools ───────────────────────────────────────────
    registry.register(
        "chatbot_send",
        handler=lambda url="", message="", message_field="content", response_field="reply", session_cookie="", headers_str="": chatbot_send(
            url, message, message_field, response_field, session_cookie, headers_str, rate_limiter=rl
        ),
        category="chatbot",
        description="Send a message to a chatbot endpoint and get the response.",
    )
    registry.register(
        "chatbot_multi_turn",
        handler=lambda url="", messages_json="[]", message_field="content", response_field="reply": chatbot_multi_turn(
            url, messages_json, message_field, response_field, rate_limiter=rl
        ),
        category="chatbot",
        description="Send multi-turn conversation to chatbot. messages_json is a JSON list of strings.",
    )
    registry.register(
        "chatbot_session_test",
        handler=lambda url="", session_endpoint="": chatbot_session_test(url, session_endpoint, rate_limiter=rl),
        category="chatbot",
        description="Test chatbot session management — creation, isolation, cross-session leakage.",
    )

    # ─── Intelligence tools ──────────────────────────────────────
    registry.register(
        "web_search",
        handler=web_search,
        category="intelligence",
        description="Search the web for latest CVEs, techniques, and security advisories.",
    )
    registry.register(
        "web_fetch",
        handler=web_fetch,
        category="intelligence",
        description="Fetch and read content from a URL (CVE details, documentation, advisories).",
    )
    registry.register(
        "cve_lookup",
        handler=cve_lookup,
        category="intelligence",
        description="Look up known CVEs for AI products (Ollama, vLLM, LangChain, etc.).",
    )

    return registry
