"""Base agent for Nerve — extends ReactSwarm LoopAgent with custom prompts + finding parsing."""

from __future__ import annotations

import json
import re
from typing import Any

import structlog
from reactswarm import AgentResult, ToolRegistry
from reactswarm.team import AgentRole, LoopAgent, LoopConfig

from nerve.models.finding import Evidence, Finding, Severity

logger = structlog.get_logger()


class NerveAgent(LoopAgent):
    """Base class for all Nerve security audit agents.

    Overrides reason() to inject Nerve's custom system prompt on iteration 1.
    ReactSwarm's LoopAgent.reason() ignores config.system_prompt and always
    builds its own via build_react_prompt(). We override just the prompt
    injection part, then delegate tool parsing + LLM calling to the parent.
    """

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
            metadata={"target": ""},
        )
        super().__init__(
            name=name,
            config=config,
            llm_call=llm_call,
            tool_registry=tool_registry,
            intel_pool=intel_pool,
        )
        self._nerve_findings: list[Finding] = []
        self._nerve_system_prompt: str = ""

    @property
    def findings(self) -> list[Finding]:
        return self._nerve_findings

    def set_system_prompt(self, prompt: str) -> None:
        """Set the Nerve-specific system prompt."""
        self._nerve_system_prompt = prompt

    async def reason(self, task: str, iteration: int) -> dict[str, Any]:
        """Override to inject Nerve's system prompt on iteration 1.

        On iteration 1: set self._history to our custom system prompt (with
        OWASP methodology, MITRE ATLAS, attack techniques, tool descriptions).
        Then delegate to the parent for LLM calling and tool call parsing.
        """
        if iteration == 1 and self._nerve_system_prompt:
            # Build tool descriptions to append to our system prompt
            tool_descriptions = ""
            if self._tool_registry:
                schemas = self._tool_registry.get_all_schemas()
                tool_descriptions = "\n".join(
                    f"- {s['name']}: {s.get('description', '')}"
                    for s in schemas
                )

            system_prompt = self._nerve_system_prompt
            if tool_descriptions:
                system_prompt += f"\n\nAVAILABLE TOOLS:\n{tool_descriptions}"

            # Set the history BEFORE the parent's reason() runs.
            # The parent checks `if iteration == 1` to build the system prompt,
            # but if _history is already set, we need to pre-empt it.
            self._history = [{"role": "system", "content": system_prompt}]

            # Now call the parent's reason() which will:
            # 1. See iteration == 1, but _history is already set (it overwrites anyway)
            # So we need a workaround: set iteration > 1 behavior by calling
            # the parent's reasoning prompt builder directly.

        # The parent always overwrites _history on iteration 1 with its own prompt.
        # So we must fully handle iteration 1 ourselves.
        if iteration == 1 and self._nerve_system_prompt:
            return await self._nerve_reason_iter1(task)

        # For iteration > 1, delegate to parent (it appends reasoning prompt to existing history)
        return await super().reason(task, iteration)

    async def _nerve_reason_iter1(self, task: str) -> dict[str, Any]:
        """Handle the first iteration with Nerve's custom system prompt."""
        from reactswarm.llm.prompts import build_reasoning_prompt

        # Build tool descriptions
        tool_descriptions = ""
        if self._tool_registry:
            schemas = self._tool_registry.get_all_schemas()
            tool_descriptions = "\n".join(
                f"- {s['name']}: {s.get('description', '')}"
                for s in schemas
            )

        system_prompt = self._nerve_system_prompt
        if tool_descriptions:
            system_prompt += f"\n\nAVAILABLE TOOLS:\n{tool_descriptions}"

        self._history = [{"role": "system", "content": system_prompt}]

        # Build reasoning prompt
        reasoning_prompt = build_reasoning_prompt(
            iteration=1,
            max_iterations=self.config.max_iterations,
            action_history="None yet",
            findings_summary="No findings yet",
            failed_approaches="None",
        )
        self._history.append({"role": "user", "content": reasoning_prompt})

        # Call LLM
        response = await self._llm_call(messages=self._history, model=self.config.model)
        content = response if isinstance(response, str) else str(response)

        # Parse tool call using same logic as parent
        action = self._parse_tool_call(content)
        self._history.append({"role": "assistant", "content": content})

        return {"thought": content, "action": action}

    def _parse_tool_call(self, content: str) -> dict | None:
        """Parse tool call from LLM response — supports multiple formats."""
        import re as _re

        # Format 1: ```json {"tool": "...", "args": {...}} ```
        json_blocks = _re.findall(r'```(?:json)?\s*(\{[^`]+\})\s*```', content, _re.DOTALL)
        for block in json_blocks:
            try:
                parsed = json.loads(block.strip())
                if "tool" in parsed or "name" in parsed:
                    return parsed
            except json.JSONDecodeError:
                continue

        # Format 2: ACTION: {"tool": "...", "parameters": {...}}
        action_match = _re.search(r'ACTION:\s*(\{[^}]+(?:\{[^}]*\}[^}]*)*\})', content, _re.DOTALL)
        if action_match:
            try:
                parsed = json.loads(action_match.group(1))
                if "tool" in parsed:
                    # Normalize "parameters" → "args" for ReactSwarm compatibility
                    if "parameters" in parsed and "args" not in parsed:
                        parsed["args"] = parsed.pop("parameters")
                    return parsed
            except json.JSONDecodeError:
                pass

        # Format 3: Inline JSON {"tool": "...", ...}
        json_matches = _re.findall(r'\{[^{}]*"(?:tool|name)"[^{}]*\}', content)
        for match in json_matches:
            try:
                parsed = json.loads(match)
                if "tool" in parsed or "name" in parsed:
                    return parsed
            except json.JSONDecodeError:
                continue

        # Format 4: tool_name(key="value") — Gemini function call format
        if self._tool_registry:
            tool_names = self._tool_registry.list_tools()
            for tn in tool_names:
                pattern = rf'{_re.escape(tn)}\s*\(([^)]*)\)'
                fn_match = _re.search(pattern, content)
                if fn_match:
                    args_str = fn_match.group(1)
                    args = {}
                    for kv in _re.findall(r'(\w+)\s*=\s*["\']([^"\']*)["\']', args_str):
                        args[kv[0]] = kv[1]
                    return {"tool": tn, "args": args}

        # Format 5: Fallback — find any tool name mentioned
        if self._tool_registry:
            tool_names = self._tool_registry.list_tools()
            for tn in tool_names:
                if tn in content:
                    args = {}
                    urls = _re.findall(r'https?://[^\s"\'`,\)\]]+', content)
                    if urls:
                        args = {"url": urls[0].rstrip('.')}
                    return {"tool": tn, "args": args}

        return None

    async def observe(self, observation: str, iteration: int = 0) -> bool:
        """Parse findings from observations, share via intel pool, then delegate."""
        self._parse_findings_from_output(observation)

        # Also parse findings from the LLM's thought/response in history
        if self._history:
            last_assistant = [h for h in self._history if h.get("role") == "assistant"]
            if last_assistant:
                self._parse_findings_from_output(last_assistant[-1].get("content", ""))

        # Share latest finding with other agents via intelligence pool
        if self._nerve_findings and self._intel_pool:
            try:
                await self._intel_pool.share_finding(
                    self._nerve_findings[-1].to_agent_dict(), source=self.name
                )
            except Exception:
                pass

        return await super().observe(observation, iteration)

    def _extract_balanced_json(self, text: str, start: int) -> str | None:
        """Extract a balanced JSON object starting at position `start` (which must be '{')."""
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        return None

    def _parse_findings_from_output(self, text: str) -> list[Finding]:
        """Extract Finding JSON objects from any text.

        Handles multi-line JSON with nested braces and escaped strings.
        """
        findings: list[Finding] = []

        for marker in re.finditer(r"FINDING:\s*\{", text):
            brace_start = marker.end() - 1
            json_str = self._extract_balanced_json(text, brace_start)
            if not json_str:
                # Fallback: close unclosed braces
                json_str = text[brace_start:]
                open_count = json_str.count("{") - json_str.count("}")
                if open_count > 0:
                    json_str += "}" * open_count

            # Clean LLM formatting issues
            json_str = re.sub(r",\s*}", "}", json_str)  # trailing commas

            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                # Last resort: collapse newlines and retry
                json_str = json_str.replace("\n", " ")
                try:
                    data = json.loads(json_str)
                except json.JSONDecodeError as e:
                    logger.warning("failed_to_parse_finding", error=str(e), raw=json_str[:200])
                    continue

            title = data.get("title", "")
            if any(f.title == title for f in self._nerve_findings):
                continue

            finding = Finding(
                title=title or "Untitled Finding",
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
            self._nerve_findings.append(finding)

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
