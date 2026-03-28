"""SARIF 2.1.0 report output — compatible with GitHub Code Scanning."""

from __future__ import annotations

import json

from nerve.models.finding import SEVERITY_ORDER, Severity
from nerve.models.scan import ScanResult

_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(result: ScanResult) -> str:
    from nerve import __version__

    rules: list[dict] = []
    results: list[dict] = []
    rule_ids_seen: set[str] = set()

    for finding in result.findings:
        rule_id = f"nerve/{finding.module}/{finding.category or 'general'}"
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "helpUri": finding.references[0] if finding.references else "",
                "properties": {
                    "tags": [
                        t for t in [finding.owasp_llm, finding.owasp_mcp, finding.mitre_atlas, finding.cwe]
                        if t
                    ],
                },
            })

        sarif_result: dict = {
            "ruleId": rule_id,
            "level": _SARIF_SEVERITY_MAP.get(finding.severity, "note"),
            "message": {"text": f"{finding.title}\n\n{finding.description}\n\nRemediation: {finding.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.target or result.target},
                    },
                }
            ],
            "properties": {
                "nerve-id": finding.id,
                "severity": finding.severity.value,
                "cvss": finding.cvss,
                "confidence": finding.confidence,
                "agent": finding.agent,
            },
        }
        results.append(sarif_result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Nerve",
                        "version": __version__,
                        "informationUri": "https://github.com/BreachLine/nerve",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
