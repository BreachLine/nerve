"""Nerve orchestrator — drives the full scan lifecycle using ReactSwarm SwarmRunner."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import structlog
from reactswarm import LLMProvider, LLMRouter, ProviderConfig, ToolRegistry
from reactswarm.team import IntelligencePool, create_store

from nerve.agents.chain_auditor import ChainAuditorAgent
from nerve.agents.discovery import DiscoveryAgent
from nerve.agents.infra_audit import InfraAuditAgent
from nerve.agents.mcp_audit import MCPAuditAgent
from nerve.agents.model_probe import ModelProbeAgent
from nerve.agents.rag_audit import RAGAuditAgent
from nerve.config import NerveConfig
from nerve.llm_bridge import llm_call_fn
from nerve.models.finding import Finding
from nerve.models.scan import ScanResult, ScanStatus
from nerve.tools.registry import create_tool_registry
from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings across agents.

    Two findings are considered duplicates when they share the same title
    and target.  When duplicates exist the finding with the higher severity
    is kept (or the first occurrence if severity is equal).
    """
    from nerve.models.finding import SEVERITY_ORDER

    seen: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.title.lower().strip(), f.target.lower().strip())
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        elif SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[existing.severity]:
            seen[key] = f
    return list(seen.values())


# Map string provider names to ReactSwarm LLMProvider enum
_PROVIDER_MAP = {
    "anthropic": LLMProvider.ANTHROPIC,
    "openai": LLMProvider.OPENAI,
    "google": LLMProvider.GOOGLE,
    "custom": LLMProvider.CUSTOM,
}


class _NerveRouter(LLMRouter):
    """LLMRouter with refusal detection disabled for security audit context."""

    @staticmethod
    def _is_refusal(text: str) -> bool:
        return False


class NerveOrchestrator:
    """Drives the complete Nerve scan lifecycle."""

    def __init__(self, config: NerveConfig) -> None:
        self.config = config
        self.scan_result = ScanResult(target=config.target.url or config.target.cidr)
        self._rate_limiter = RateLimiter(rate=float(config.scan.rate_limit))
        self._registry: ToolRegistry | None = None
        self._llm_router: LLMRouter | None = None
        self._intel_pool: IntelligencePool | None = None
        self._store = None

    async def initialize(self) -> None:
        """Set up tools, LLM router, and intelligence sharing."""
        # Tool registry
        self._registry = create_tool_registry(
            self._rate_limiter,
            dry_run=self.config.scan.dry_run,
        )

        # LLM router
        providers = [
            ProviderConfig(
                provider=_PROVIDER_MAP.get(self.config.llm.provider, LLMProvider.OPENAI),
                model=self.config.llm.model,
                api_key=self.config.llm.api_key,
                base_url=self.config.llm.base_url,
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
            )
        ]
        # Add fallbacks
        for fb in self.config.llm.fallback:
            providers.append(
                ProviderConfig(
                    provider=_PROVIDER_MAP.get(fb.provider, LLMProvider.OPENAI),
                    model=fb.model,
                    api_key=fb.api_key,
                    base_url=fb.base_url,
                    priority=2,
                )
            )
        self._llm_router = _NerveRouter(providers, call_fn=llm_call_fn)

        # Store + intelligence pool
        self._store = create_store(
            redis_url=self.config.redis.url,
        )
        await self._store.initialize()
        self._intel_pool = IntelligencePool(self._store)

        logger.info(
            "nerve_initialized",
            target=self.scan_result.target,
            llm_provider=self.config.llm.provider,
            llm_model=self.config.llm.model,
            tools=len(self._registry),
        )

    async def _llm_call(self, messages: list[dict], **kwargs) -> str:
        """Wrapper for LLM calls through the router."""
        return await self._llm_router.call(messages, **kwargs)

    def _make_agent_kwargs(self) -> dict:
        return {
            "tool_registry": self._registry,
            "llm_call": self._llm_call,
            "intel_pool": self._intel_pool,
        }

    async def run_scan(self, on_progress=None) -> ScanResult:
        """Execute the full scan lifecycle."""
        self.scan_result.status = ScanStatus.RUNNING
        self.scan_result.started_at = datetime.now(UTC)
        start_time = time.monotonic()

        target = self.config.target.url or self.config.target.cidr
        skip = set(self.config.scan.skip_categories)
        agent_kwargs = self._make_agent_kwargs()

        try:
            # ── Phase 1: Discovery ───────────────────────────────
            all_findings: list[Finding] = []

            if "discovery" not in skip:
                if on_progress:
                    on_progress("Phase 1: Discovery", "running")

                discovery = DiscoveryAgent(**agent_kwargs, max_iterations=15)
                discovery.configure(target=target, rate_limit=self.config.scan.rate_limit)
                await discovery.run(f"Discover all AI services on {target}")
                all_findings.extend(discovery.findings)
                self.scan_result.agents_run.append("discovery")

                handoff = discovery.create_handoff("phase2")
                if on_progress:
                    on_progress("Phase 1: Discovery", "complete", findings=len(discovery.findings))
            else:
                handoff = None

            # ── Phase 2: Parallel Testing ────────────────────────
            phase2_tasks = []

            if "model_probe" not in skip:
                probe = ModelProbeAgent(**agent_kwargs)
                probe.configure(target=target, rate_limit=self.config.scan.rate_limit, handoff=handoff)
                phase2_tasks.append(("model_probe", probe))

            if "mcp_audit" not in skip:
                mcp = MCPAuditAgent(**agent_kwargs)
                mcp.configure(target=target, rate_limit=self.config.scan.rate_limit, handoff=handoff)
                phase2_tasks.append(("mcp_audit", mcp))

            if "infra_audit" not in skip:
                infra = InfraAuditAgent(**agent_kwargs)
                infra.configure(target=target, rate_limit=self.config.scan.rate_limit, handoff=handoff)
                phase2_tasks.append(("infra_audit", infra))

            if "rag_audit" not in skip and self.config.target.vector_dbs:
                rag = RAGAuditAgent(**agent_kwargs, max_iterations=15)
                rag.configure(target=target, rate_limit=self.config.scan.rate_limit, handoff=handoff)
                phase2_tasks.append(("rag_audit", rag))

            if phase2_tasks:
                if on_progress:
                    on_progress("Phase 2: Parallel Testing", "running", agents=[n for n, _ in phase2_tasks])

                async def _run_agent(name: str, agent) -> tuple[str, list[Finding]]:
                    try:
                        await agent.run(f"Audit {target} for {name} vulnerabilities")
                        return name, agent.findings
                    except Exception as e:
                        logger.error("agent_failed", agent=name, error=str(e))
                        return name, []

                results = await asyncio.gather(
                    *[_run_agent(n, a) for n, a in phase2_tasks],
                    return_exceptions=True,
                )

                for r in results:
                    if isinstance(r, tuple):
                        name, findings = r
                        all_findings.extend(findings)
                        self.scan_result.agents_run.append(name)

                if on_progress:
                    on_progress("Phase 2: Parallel Testing", "complete", findings=len(all_findings))

            # ── Deduplicate before chain analysis ───────────────
            all_findings = _deduplicate_findings(all_findings)

            # ── Phase 3: Chain Analysis ──────────────────────────
            if "agent_chain" not in skip and all_findings:
                if on_progress:
                    on_progress("Phase 3: Chain Analysis", "running")

                chain_agent = ChainAuditorAgent(**agent_kwargs, max_iterations=10)
                chain_agent.configure(all_findings=all_findings)
                await chain_agent.run(f"Analyze {len(all_findings)} findings for kill chains")
                self.scan_result.kill_chains = chain_agent.kill_chains
                self.scan_result.agents_run.append("chain_auditor")

                if on_progress:
                    on_progress("Phase 3: Chain Analysis", "complete", chains=len(chain_agent.kill_chains))

            # ── Finalize ─────────────────────────────────────────
            for f in all_findings:
                self.scan_result.add_finding(f)
            self.scan_result.compute_risk_score()
            self.scan_result.status = ScanStatus.COMPLETED
            self.scan_result.completed_at = datetime.now(UTC)
            self.scan_result.duration_seconds = time.monotonic() - start_time

        except Exception as e:
            logger.error("scan_failed", error=str(e))
            self.scan_result.status = ScanStatus.FAILED
            self.scan_result.duration_seconds = time.monotonic() - start_time
            raise

        finally:
            if self._store:
                await self._store.stop()

        return self.scan_result

    async def shutdown(self) -> None:
        if self._store:
            await self._store.stop()
