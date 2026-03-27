"""Tests for report generation."""

from __future__ import annotations

import json

from nerve.models.scan import ScanResult
from nerve.report.html_report import render_html
from nerve.report.json_report import render_json
from nerve.report.sarif_report import render_sarif


class TestJSONReport:
    def test_renders_valid_json(self, sample_scan_result: ScanResult):
        output = render_json(sample_scan_result)
        parsed = json.loads(output)
        assert parsed["target"] == "http://localhost:11434"
        assert len(parsed["findings"]) == 3

    def test_empty_scan(self):
        result = ScanResult(target="test")
        output = render_json(result)
        parsed = json.loads(output)
        assert len(parsed["findings"]) == 0


class TestHTMLReport:
    def test_renders_html(self, sample_scan_result: ScanResult):
        output = render_html(sample_scan_result)
        assert "<!DOCTYPE html>" in output
        assert "Nerve AI Security Audit" in output
        assert "System Prompt Extracted" in output
        assert "CRITICAL" in output.upper() or "critical" in output

    def test_escapes_html(self, sample_scan_result: ScanResult):
        # Ensure no raw HTML injection
        output = render_html(sample_scan_result)
        assert "<script>" not in output

    def test_severity_styling(self, sample_scan_result: ScanResult):
        output = render_html(sample_scan_result)
        assert "severity-critical" in output
        assert "severity-high" in output


class TestSARIFReport:
    def test_valid_sarif(self, sample_scan_result: ScanResult):
        output = render_sarif(sample_scan_result)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "Nerve"

    def test_sarif_results(self, sample_scan_result: ScanResult):
        output = render_sarif(sample_scan_result)
        parsed = json.loads(output)
        results = parsed["runs"][0]["results"]
        assert len(results) == 3
        # Critical finding should map to "error"
        levels = {r["level"] for r in results}
        assert "error" in levels

    def test_sarif_rules(self, sample_scan_result: ScanResult):
        output = render_sarif(sample_scan_result)
        parsed = json.loads(output)
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 2  # At least 2 unique rule IDs
