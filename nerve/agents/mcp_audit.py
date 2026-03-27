"""MCP audit agent — tests MCP servers for tool poisoning, SSRF, auth bypass."""

from __future__ import annotations

from reactswarm import AgentHandoff, AgentResult, ToolRegistry

from nerve.agents.base import NerveAgent
from nerve.agents.prompts import build_mcp_audit_prompt


class MCPAuditAgent(NerveAgent):
    """Phase 2b: Audit MCP servers for security vulnerabilities."""

    def __init__(
        self,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 20,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        super().__init__(
            name="mcp_audit",
            tool_registry=tool_registry,
            max_iterations=max_iterations,
            llm_call=llm_call,
            intel_pool=intel_pool,
        )
        self._target = ""
        self._rate_limit = 10
        self._handoff: AgentHandoff | None = None

    def configure(
        self,
        target: str,
        rate_limit: int = 10,
        handoff: AgentHandoff | None = None,
    ) -> None:
        self._target = target
        self._rate_limit = rate_limit
        self._handoff = handoff

    async def run(self, task: str, **kwargs) -> AgentResult:
        handoff_context = self._handoff.to_compact_prompt() if self._handoff else ""
        intel_context = ""
        if self._intel_pool:
            intel_context = await self._intel_pool.get_context_for_agent("mcp_audit")

        system_prompt = build_mcp_audit_prompt(
            target=self._target or task,
            handoff_context=handoff_context,
            intel_context=intel_context,
            rate_limit=self._rate_limit,
            max_iterations=self._config.max_iterations,
        )
        self._config.system_prompt = system_prompt
        return await super().run(task, **kwargs)
