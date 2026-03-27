"""Tests for Nerve data models."""

from __future__ import annotations

import json

from nerve.models.finding import Evidence, Finding, KillChain, Severity
from nerve.models.scan import ScanResult, ScanStatus
from nerve.models.target import AIServiceType, Endpoint, Target


class TestFinding:
    def test_create_finding(self):
        f = Finding(title="Test", severity=Severity.HIGH, cvss=7.5)
        assert f.title == "Test"
        assert f.severity == Severity.HIGH
        assert f.cvss == 7.5
        assert len(f.id) == 12

    def test_finding_to_agent_dict(self):
        f = Finding(title="XSS via Output", severity=Severity.MEDIUM, cwe="CWE-79")
        d = f.to_agent_dict()
        assert d["title"] == "XSS via Output"
        assert d["severity"] == "medium"
        assert d["cwe"] == "CWE-79"

    def test_finding_from_agent_dict(self):
        data = {
            "title": "SSRF in MCP Tool",
            "severity": "critical",
            "cvss": 9.0,
            "target": "http://mcp:3000",
            "module": "mcp_audit",
        }
        f = Finding.from_agent_dict(data)
        assert f.title == "SSRF in MCP Tool"
        assert f.severity == Severity.CRITICAL
        assert f.cvss == 9.0

    def test_evidence_model(self):
        e = Evidence(
            request="GET /api/tags",
            response='{"models":[]}',
            payload="test payload",
            reproduction_steps=["Step 1", "Step 2"],
        )
        assert e.request == "GET /api/tags"
        assert len(e.reproduction_steps) == 2

    def test_kill_chain(self):
        kc = KillChain(
            title="SSRF → Ollama → Cloud",
            findings=["f1", "f2", "f3"],
            total_cvss=9.8,
            description="Multi-hop chain",
        )
        assert len(kc.findings) == 3
        assert kc.total_cvss == 9.8


class TestScanResult:
    def test_empty_scan(self):
        r = ScanResult(target="http://test:11434")
        assert r.critical_count == 0
        assert r.risk_score == 0.0

    def test_add_finding(self):
        r = ScanResult(target="test")
        r.add_finding(Finding(title="A", severity=Severity.CRITICAL))
        r.add_finding(Finding(title="B", severity=Severity.HIGH))
        assert r.critical_count == 1
        assert r.high_count == 1
        assert r.tests_executed == 2

    def test_risk_score(self):
        r = ScanResult(target="test")
        r.add_finding(Finding(title="Crit", severity=Severity.CRITICAL))
        r.add_finding(Finding(title="High", severity=Severity.HIGH))
        score = r.compute_risk_score()
        assert score > 30  # 25 + 15 = 40

    def test_has_severity_at_least(self):
        r = ScanResult(target="test")
        r.add_finding(Finding(title="Med", severity=Severity.MEDIUM))
        assert r.has_severity_at_least(Severity.MEDIUM) is True
        assert r.has_severity_at_least(Severity.HIGH) is False

    def test_json_serialization(self):
        r = ScanResult(target="test")
        r.add_finding(Finding(title="Test", severity=Severity.LOW))
        j = r.model_dump_json()
        parsed = json.loads(j)
        assert parsed["target"] == "test"
        assert len(parsed["findings"]) == 1

    def test_status_transitions(self):
        r = ScanResult(target="test")
        assert r.status == ScanStatus.PENDING
        r.status = ScanStatus.RUNNING
        assert r.status == ScanStatus.RUNNING


class TestTarget:
    def test_target_auth_headers(self):
        t = Target(url="http://test", api_key="sk-123", headers={"X-Custom": "val"})
        h = t.get_auth_headers()
        assert h["Authorization"] == "Bearer sk-123"
        assert h["X-Custom"] == "val"

    def test_endpoint_model(self):
        e = Endpoint(
            url="http://ollama:11434",
            service_type=AIServiceType.OLLAMA,
            version="0.12.3",
            models=["llama3.1", "codellama"],
        )
        assert e.service_type == AIServiceType.OLLAMA
        assert len(e.models) == 2
