"""Scan result model — aggregates all findings from a full Nerve audit."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field

from nerve.models.finding import Finding, KillChain, Severity


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanResult(BaseModel):
    """Complete results from a Nerve security audit."""

    scan_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    target: str = ""
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float = 0.0

    # Results
    findings: list[Finding] = Field(default_factory=list)
    kill_chains: list[KillChain] = Field(default_factory=list)

    # Coverage
    agents_run: list[str] = Field(default_factory=list)
    tests_executed: int = 0
    categories_covered: list[str] = Field(default_factory=list)

    # Cost tracking
    llm_tokens_used: int = 0
    llm_cost_usd: float = 0.0

    # Risk score
    risk_score: float = 0.0

    @computed_field
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @computed_field
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @computed_field
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @computed_field
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @computed_field
    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.tests_executed += 1

    def compute_risk_score(self) -> float:
        """0-100 risk score based on findings."""
        if not self.findings:
            self.risk_score = 0.0
            return 0.0
        weights = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 8.0,
            Severity.LOW: 3.0,
            Severity.INFO: 0.5,
        }
        raw = sum(weights.get(f.severity, 0) for f in self.findings)
        # Kill chains amplify risk
        raw += len(self.kill_chains) * 10.0
        self.risk_score = min(100.0, raw)
        return self.risk_score

    def has_severity_at_least(self, threshold: Severity) -> bool:
        """Check if any finding meets or exceeds severity threshold."""
        from nerve.models.finding import SEVERITY_ORDER

        threshold_order = SEVERITY_ORDER[threshold]
        return any(SEVERITY_ORDER[f.severity] >= threshold_order for f in self.findings)
