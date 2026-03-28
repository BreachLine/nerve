"""Core finding model — every vulnerability discovered by Nerve agents."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Evidence(BaseModel):
    """Proof that a vulnerability exists."""

    request: str | None = None
    response: str | None = None
    payload: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list)
    raw_data: dict = Field(default_factory=dict)


class Finding(BaseModel):
    """A single security finding discovered by a Nerve agent."""

    id: str = Field(default_factory=lambda: uuid4().hex[:12])

    # What
    title: str
    description: str = ""
    severity: Severity
    cvss: float = 0.0
    confidence: float = 0.0

    # Where
    target: str = ""
    module: str = ""
    category: str = ""

    # Evidence
    evidence: Evidence = Field(default_factory=Evidence)

    # Classification
    cwe: str | None = None
    owasp_llm: str | None = None
    owasp_mcp: str | None = None
    mitre_atlas: str | None = None

    # Remediation
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    # Chain linking
    chain_id: str | None = None
    chain_position: int = 0

    # Metadata
    agent: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_agent_dict(self) -> dict:
        """Convert to dict format compatible with ReactSwarm AgentResult.findings."""
        return self.model_dump(mode="json", exclude_none=True)

    @classmethod
    def from_agent_dict(cls, data: dict) -> Finding:
        """Create Finding from a dict (e.g. from LLM structured output)."""
        return cls.model_validate(data)


class KillChain(BaseModel):
    """A multi-hop exploitation path chaining multiple findings."""

    chain_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    title: str
    findings: list[str] = Field(default_factory=list)
    total_cvss: float = 0.0
    description: str = ""
    attack_graph: dict = Field(default_factory=dict)
