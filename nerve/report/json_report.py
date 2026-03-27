"""JSON report output."""

from __future__ import annotations

from nerve.models.scan import ScanResult


def render_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)
