# Extending Nerve

Nerve is designed to be extended. Add custom tools, agents, and attack techniques.

## Adding a Custom Tool

Tools are async functions registered in the `ToolRegistry`. Create a new file in `nerve/tools/`:

```python
# nerve/tools/my_custom_tool.py

import httpx
from nerve.utils.rate_limiter import RateLimiter


async def my_scanner(
    target: str = "",
    param: str = "",
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Scan target for something specific."""
    if rate_limiter:
        await rate_limiter.acquire()

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        r = await client.get(f"{target}/{param}")
        return f"STATUS: {r.status_code}\nBODY: {r.text[:5000]}"
```

Register it in `nerve/tools/registry.py`:

```python
from nerve.tools.my_custom_tool import my_scanner

# In create_tool_registry():
registry.register(
    "my_scanner",
    handler=lambda target="", param="": my_scanner(target, param, rate_limiter=rl),
    category="custom",
    description="Scan target for something specific.",
)
```

The tool is now available to all agents via the ToolRegistry.

## Adding Attack Techniques

Add methodology to the knowledge base in `nerve/knowledge/techniques.py`:

```python
TECHNIQUE_LIBRARY["my_category"] = [
    {
        "name": "my_technique",
        "description": "What this technique does.",
        "methodology": (
            "Step-by-step instructions for the LLM agent. "
            "Be specific — the LLM will follow these instructions."
        ),
        "indicators": ["what success looks like", "what failure looks like"],
        "escalation": "What to try if this technique fails.",
        "owasp": "LLM01",
        "atlas": "AML.T0051",
        "cwe": "CWE-74",
    },
]
```

## Adding a Custom Agent

Agents extend `NerveAgent` (which extends ReactSwarm's `LoopAgent`):

```python
# nerve/agents/my_agent.py

from reactswarm import AgentHandoff, AgentResult, ToolRegistry
from nerve.agents.base import NerveAgent


class MyAgent(NerveAgent):
    def __init__(
        self,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 15,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        super().__init__(
            name="my_agent",
            tool_registry=tool_registry,
            max_iterations=max_iterations,
            llm_call=llm_call,
            intel_pool=intel_pool,
        )
        self._target = ""
        self._handoff = None

    def configure(self, target: str, handoff=None) -> None:
        self._target = target
        self._handoff = handoff

    async def run(self, task: str, **kwargs) -> AgentResult:
        # Build your custom system prompt
        system_prompt = f"""You are MyAgent, an AI security specialist.

        OBJECTIVE: Test {self._target} for [specific vulnerability class].

        Available tools will be listed below. Use them to:
        1. Enumerate the target
        2. Test for vulnerabilities
        3. Report findings using FINDING: {{json}} format

        When done, say TASK_COMPLETE.
        """

        self.set_system_prompt(system_prompt)
        return await super().run(task, **kwargs)
```

Wire it into the orchestrator in `nerve/orchestrator.py`.

## Adding CVEs

Add known vulnerabilities in `nerve/knowledge/cve_db.py`:

```python
CVE_DATABASE.append({
    "cve": "CVE-2026-XXXXX",
    "product": "product_name",
    "title": "Description of the vulnerability",
    "severity": "critical",
    "cvss": 9.8,
    "affected_versions": "<=1.0.0",
    "description": "Detailed description.",
    "cwe": "CWE-XXX",
})
```

## Project Structure

```
nerve/
├── agents/           # 6 specialist agents
│   ├── base.py       # NerveAgent base class
│   ├── prompts.py    # System prompts for all agents
│   ├── discovery.py  # Phase 1: Find AI services
│   ├── model_probe.py# Phase 2a: Test LLM security
│   ├── mcp_audit.py  # Phase 2b: Test MCP servers
│   ├── infra_audit.py# Phase 2c: Test infrastructure
│   ├── rag_audit.py  # Phase 2d: Test RAG pipelines
│   └── chain_auditor.py # Phase 3: Build kill chains
├── tools/            # 24 security tools
│   ├── registry.py   # Master tool registry
│   ├── network.py    # port_scan, http_fingerprint, dns, tls
│   ├── http.py       # http_request, http_post_json
│   ├── llm_connectors.py # ollama_chat, openai_chat, etc.
│   ├── mcp_connector.py  # mcp_connect, mcp_list_tools, etc.
│   ├── vector_db.py  # vector_search, vector_insert, etc.
│   ├── chatbot.py    # chatbot_send, chatbot_multi_turn
│   └── intelligence.py # web_search, web_fetch, cve_lookup
├── knowledge/        # Attack methodology
│   ├── owasp_llm.py  # OWASP Top 10 for LLM 2025
│   ├── owasp_mcp.py  # OWASP MCP Top 10 2025
│   ├── mitre_atlas.py# MITRE ATLAS v5.4.0
│   ├── cve_db.py     # Known AI CVEs
│   ├── cwe_mapping.py# CWE identifiers
│   └── techniques.py # Attack technique library
├── models/           # Pydantic v2 data models
│   ├── finding.py    # Finding, Evidence, Severity
│   ├── scan.py       # ScanResult, ScanStatus
│   └── target.py     # Target, Endpoint, AIServiceType
├── report/           # Report generation
│   ├── engine.py     # ReportEngine orchestrator
│   ├── json_report.py
│   ├── html_report.py
│   └── sarif_report.py
├── config.py         # YAML + env + CLI config merging
├── orchestrator.py   # Full scan lifecycle
├── llm_bridge.py     # LLM provider API calls
├── main.py           # Typer CLI
└── utils/
    ├── rate_limiter.py
    └── sanitizer.py
```
