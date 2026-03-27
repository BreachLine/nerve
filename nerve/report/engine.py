"""Report engine — orchestrates output generation in all formats."""

from __future__ import annotations

from pathlib import Path

import structlog

from nerve.models.scan import ScanResult
from nerve.report.html_report import render_html
from nerve.report.json_report import render_json
from nerve.report.sarif_report import render_sarif

logger = structlog.get_logger()


class ReportEngine:
    """Generate scan reports in multiple formats."""

    def __init__(self, scan_result: ScanResult, output_dir: str = "./nerve-reports") -> None:
        self.result = scan_result
        self.output_dir = Path(output_dir)

    def generate(self, formats: list[str]) -> dict[str, str]:
        """Generate reports in specified formats. Returns {format: filepath}."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        generated: dict[str, str] = {}

        for fmt in formats:
            fmt = fmt.strip().lower()
            if fmt == "json":
                path = self.output_dir / f"nerve-{self.result.scan_id}.json"
                path.write_text(render_json(self.result))
                generated["json"] = str(path)
                logger.info("report_generated", format="json", path=str(path))

            elif fmt == "html":
                path = self.output_dir / f"nerve-{self.result.scan_id}.html"
                path.write_text(render_html(self.result))
                generated["html"] = str(path)
                logger.info("report_generated", format="html", path=str(path))

            elif fmt == "sarif":
                path = self.output_dir / f"nerve-{self.result.scan_id}.sarif"
                path.write_text(render_sarif(self.result))
                generated["sarif"] = str(path)
                logger.info("report_generated", format="sarif", path=str(path))

        return generated
