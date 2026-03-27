"""Chain auditor agent — builds kill chains from all Phase 2 findings."""

from __future__ import annotations

import json

from reactswarm import AgentResult, ToolRegistry

from nerve.agents.base import NerveAgent
from nerve.agents.prompts import build_chain_auditor_prompt
from nerve.models.finding import Finding, KillChain


class ChainAuditorAgent(NerveAgent):
    """Phase 3: Analyze findings and construct multi-hop kill chains."""

    def __init__(
        self,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 10,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        super().__init__(
            name="chain_auditor",
            tool_registry=tool_registry,
            max_iterations=max_iterations,
            llm_call=llm_call,
            intel_pool=intel_pool,
        )
        self._all_findings: list[Finding] = []
        self._kill_chains: list[KillChain] = []

    def configure(self, all_findings: list[Finding]) -> None:
        self._all_findings = all_findings

    @property
    def kill_chains(self) -> list[KillChain]:
        return self._kill_chains

    async def run(self, task: str, **kwargs) -> AgentResult:
        # Build findings summary for the prompt
        findings_summary_parts: list[str] = []
        for f in self._all_findings:
            findings_summary_parts.append(
                f"[{f.id}] {f.severity.value.upper()} | {f.module} | {f.title} | "
                f"Target: {f.target} | Category: {f.category}"
            )
        findings_summary = "\n".join(findings_summary_parts) if findings_summary_parts else "No findings from Phase 2."

        intel_context = ""
        if self._intel_pool:
            intel_context = await self._intel_pool.get_context_for_agent("agent_chain")

        system_prompt = build_chain_auditor_prompt(
            findings_summary=findings_summary,
            intel_context=intel_context,
            max_iterations=self._config.max_iterations,
        )
        self._config.system_prompt = system_prompt

        result = await super().run(task, **kwargs)

        # Parse kill chains from output
        if result.output:
            raw_chains = self._parse_kill_chains(result.output)
            for rc in raw_chains:
                chain = KillChain(
                    title=rc.get("title", "Unnamed Chain"),
                    findings=rc.get("findings", []),
                    total_cvss=rc.get("total_cvss", 0.0),
                    description=rc.get("description", ""),
                    attack_graph=rc.get("attack_graph", {}),
                )
                self._kill_chains.append(chain)

        return result
