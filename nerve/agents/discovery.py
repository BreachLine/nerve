"""Discovery agent — finds all AI services on the target network."""

from __future__ import annotations

from reactswarm import AgentHandoff, AgentResult, ToolRegistry

from nerve.agents.base import NerveAgent
from nerve.agents.prompts import build_discovery_prompt


class DiscoveryAgent(NerveAgent):
    """Phase 1: Discover AI endpoints on the target."""

    def __init__(
        self,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 15,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        super().__init__(
            name="discovery",
            tool_registry=tool_registry,
            max_iterations=max_iterations,
            llm_call=llm_call,
            intel_pool=intel_pool,
        )
        self._target = ""
        self._rate_limit = 10

    def configure(self, target: str, rate_limit: int = 10) -> None:
        self._target = target
        self._rate_limit = rate_limit

    async def run(self, task: str, **kwargs) -> AgentResult:
        """Run discovery scan. System prompt drives the LLM to find endpoints."""
        system_prompt = build_discovery_prompt(
            target=self._target or task,
            rate_limit=self._rate_limit,
            max_iterations=self.config.max_iterations,
        )
        self.set_system_prompt(system_prompt)
        return await super().run(task, **kwargs)

    def create_handoff(self, to_agent: str) -> AgentHandoff:
        """Create handoff with discovered endpoints for the next phase."""
        discoveries = []
        for f in self._findings:
            discoveries.append(f"{f.title}: {f.evidence.raw_data}" if f.evidence.raw_data else f.title)

        return AgentHandoff(
            from_agent=self.name,
            to_agent=to_agent,
            task_summary=f"Discovered {len(self._findings)} AI endpoints on {self._target}",
            discoveries=discoveries,
            confirmed_results=[f.to_agent_dict() for f in self._findings],
        )
