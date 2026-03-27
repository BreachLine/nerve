"""Model probe agent — tests LLM security: injection, jailbreak, extraction."""

from __future__ import annotations

from reactswarm import AgentHandoff, AgentResult, ToolRegistry

from nerve.agents.base import NerveAgent
from nerve.agents.prompts import build_model_probe_prompt


class ModelProbeAgent(NerveAgent):
    """Phase 2a: Probe LLM endpoints for security vulnerabilities."""

    def __init__(
        self,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 20,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        super().__init__(
            name="model_probe",
            tool_registry=tool_registry,
            max_iterations=max_iterations,
            llm_call=llm_call,
            intel_pool=intel_pool,
        )
        self._target = ""
        self._rate_limit = 10

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
        handoff_context = ""
        if self._handoff:
            handoff_context = self._handoff.to_compact_prompt()

        intel_context = ""
        if self._intel_pool:
            intel_context = await self._intel_pool.get_context_for_agent("model_probe")

        system_prompt = build_model_probe_prompt(
            target=self._target or task,
            handoff_context=handoff_context,
            intel_context=intel_context,
            rate_limit=self._rate_limit,
            max_iterations=self._config.max_iterations,
        )
        self._config.system_prompt = system_prompt
        return await super().run(task, **kwargs)
