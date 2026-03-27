"""Infrastructure audit agent — API auth, CVEs, supply chain, rate limiting."""

from __future__ import annotations

from reactswarm import AgentHandoff, AgentResult, ToolRegistry

from nerve.agents.base import NerveAgent
from nerve.agents.prompts import build_infra_audit_prompt


class InfraAuditAgent(NerveAgent):
    """Phase 2c: Audit AI infrastructure security."""

    def __init__(
        self,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 20,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        super().__init__(
            name="infra_audit",
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
            intel_context = await self._intel_pool.get_context_for_agent("infra_audit")

        system_prompt = build_infra_audit_prompt(
            target=self._target or task,
            handoff_context=handoff_context,
            intel_context=intel_context,
            rate_limit=self._rate_limit,
            max_iterations=self.config.max_iterations,
        )
        self.set_system_prompt(system_prompt)
        return await super().run(task, **kwargs)
