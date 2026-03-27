"""Base agent for Nerve — extends ReactSwarm LoopAgent with finding parsing."""

from __future__ import annotations

import json
import re

import structlog
from reactswarm import AgentResult, ToolRegistry
from reactswarm.team import AgentRole, LoopAgent, LoopConfig

from nerve.agents.prompts import REASONING_STEP_TEMPLATE
from nerve.models.finding import Evidence, Finding, Severity

logger = structlog.get_logger()


class NerveAgent(LoopAgent):
    """Base class for all Nerve security audit agents."""

    def __init__(
        self,
        name: str,
        tool_registry: ToolRegistry,
        *,
        max_iterations: int = 20,
        llm_call=None,
        intel_pool=None,
    ) -> None:
        config = LoopConfig(
            role=AgentRole.AI_SECURITY,
            max_iterations=max_iterations,
            stop_phrases=["TASK_COMPLETE", "NO_MORE_ACTIONS"],
        )
        super().__init__(
            name=name,
            config=config,
            llm_call=llm_call,
            tool_registry=tool_registry,
            intel_pool=intel_pool,
        )
        self._findings: list[Finding] = []
        self._action_history: list[str] = []
        self._failed_approaches: list[str] = []

    @property
    def findings(self) -> list[Finding]:
        return self._findings

    def _parse_findings_from_output(self, text: str) -> list[Finding]:
        """Extract Finding JSON objects from agent output."""
        findings: list[Finding] = []
        # Find JSON blocks after FINDING: markers
        pattern = r"FINDING:\s*(\{[^}]+(?:\{[^}]*\}[^}]*)*\})"
        for match in re.finditer(pattern, text, re.DOTALL):
            try:
                data = json.loads(match.group(1))
                finding = Finding(
                    title=data.get("title", "Untitled Finding"),
                    severity=Severity(data.get("severity", "info")),
                    category=data.get("category", ""),
                    description=data.get("description", ""),
                    target=data.get("target", ""),
                    module=self.name,
                    evidence=Evidence(
                        request=data.get("evidence", {}).get("request"),
                        response=data.get("evidence", {}).get("response"),
                        payload=data.get("evidence", {}).get("payload"),
                    ),
                    remediation=data.get("remediation", ""),
                    owasp_llm=data.get("owasp_llm"),
                    owasp_mcp=data.get("owasp_mcp"),
                    mitre_atlas=data.get("mitre_atlas"),
                    cwe=data.get("cwe"),
                    confidence=data.get("confidence", 0.5),
                    agent=self.name,
                )
                findings.append(finding)
                self._findings.append(finding)
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning("failed_to_parse_finding", error=str(e), raw=match.group(1)[:200])
        return findings

    def _parse_kill_chains(self, text: str) -> list[dict]:
        """Extract kill chain JSON from chain auditor output."""
        chains: list[dict] = []
        pattern = r"KILL_CHAIN:\s*(\{[^}]+(?:\{[^}]*\}[^}]*)*\})"
        for match in re.finditer(pattern, text, re.DOTALL):
            try:
                chains.append(json.loads(match.group(1)))
            except json.JSONDecodeError:
                pass
        return chains

    def build_reasoning_context(self, intel_context: str = "") -> str:
        """Build the per-iteration reasoning context."""
        findings_summary = "None yet."
        if self._findings:
            counts = {}
            for f in self._findings:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            findings_summary = ", ".join(f"{s}: {c}" for s, c in counts.items())
            findings_summary += f" ({len(self._findings)} total)"

        return REASONING_STEP_TEMPLATE.format(
            iteration=len(self._action_history) + 1,
            max_iterations=self._config.max_iterations,
            action_history="\n".join(self._action_history[-10:]) if self._action_history else "None yet",
            findings_summary=findings_summary,
            failed_approaches="\n".join(self._failed_approaches[-5:]) if self._failed_approaches else "None",
            intel_context=intel_context or "No intelligence shared yet.",
        )

    async def observe(self, observation: str) -> list[dict]:
        """Parse findings from observation and share via intel pool."""
        self._action_history.append(observation[:500])
        findings = self._parse_findings_from_output(observation)

        # Share findings with other agents via intelligence pool
        if findings and self._intel_pool:
            for f in findings:
                await self._intel_pool.share_finding(f.to_agent_dict(), source=self.name)

        return [f.to_agent_dict() for f in findings]
