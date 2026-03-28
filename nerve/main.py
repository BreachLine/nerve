"""Nerve CLI — AI-powered security auditor for AI systems."""

from __future__ import annotations

import asyncio
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from nerve import __version__
from nerve.config import NerveConfig
from nerve.models.finding import Severity

app = typer.Typer(
    name="nerve",
    help="Nerve — AI-powered security auditor for AI systems. AI tests AI.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Nerve v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(None, "--version", "-V", callback=_version_callback, is_eager=True),
) -> None:
    """Nerve — AI-powered security auditor for AI systems."""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL, host, or CIDR range"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to nerve.yaml config file"),
    llm_provider: Optional[str] = typer.Option(None, "--llm-provider", help="LLM provider (anthropic, openai, google)"),
    llm_api_key: Optional[str] = typer.Option(None, "--llm-api-key", help="LLM API key (or set NERVE_LLM_API_KEY)"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="LLM model name"),
    redis_url: Optional[str] = typer.Option(None, "--redis-url", help="Redis URL for persistent scans"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file/directory"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output formats: json,html,sarif"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show agent reasoning live"),
    timeout: int = typer.Option(600, "--timeout", help="Max scan duration in seconds"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Max requests/second to target"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if findings >= severity (critical,high,medium,low)"),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Read-only mode — block tools that modify external state",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    target_api_key: Optional[str] = typer.Option(None, "--target-api-key", help="Target's API key"),
    target_bearer_token: Optional[str] = typer.Option(None, "--target-bearer-token", help="Target's bearer token"),
    target_headers: Optional[str] = typer.Option(None, "--target-headers", help="Custom headers (Key:Value,Key:Value)"),
    target_basic_auth: Optional[str] = typer.Option(None, "--target-basic-auth", help="HTTP basic auth (user:pass)"),
    mcp_transport: Optional[str] = typer.Option(None, "--mcp-transport", help="MCP transport (sse or stdio)"),
    mcp_token: Optional[str] = typer.Option(None, "--mcp-token", help="MCP auth token"),
    qdrant_url: Optional[str] = typer.Option(None, "--qdrant-url", help="Qdrant vector DB URL"),
    qdrant_api_key: Optional[str] = typer.Option(None, "--qdrant-api-key", help="Qdrant API key"),
    weaviate_url: Optional[str] = typer.Option(None, "--weaviate-url", help="Weaviate URL"),
) -> None:
    """Full autonomous AI security scan — discover, test, and report."""
    overrides = {k: v for k, v in locals().items() if v is not None and k not in ("config", "no_color", "fmt", "dry_run")}
    overrides["format"] = fmt
    overrides["target"] = target
    if dry_run:
        overrides["dry_run"] = True

    cfg = NerveConfig.load(config_path=config, cli_overrides=overrides)

    if not cfg.llm.api_key:
        console.print("[red]Error: LLM API key required. Set --llm-api-key or NERVE_LLM_API_KEY env var.[/red]")
        raise typer.Exit(1)

    dry_run_label = "\n[yellow]Mode: DRY-RUN (write tools blocked)[/yellow]" if cfg.scan.dry_run else ""
    console.print(Panel.fit(
        f"[bold magenta]Nerve[/bold magenta] v{__version__} — AI Security Audit\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"LLM: [green]{cfg.llm.provider}/{cfg.llm.model}[/green]\n"
        f"Formats: {fmt}{dry_run_label}",
        border_style="magenta",
    ))

    asyncio.run(_run_scan(cfg, verbose))


async def _run_scan(cfg: NerveConfig, verbose: bool) -> None:
    from nerve.orchestrator import NerveOrchestrator
    from nerve.report import ReportEngine

    orchestrator = NerveOrchestrator(cfg)
    await orchestrator.initialize()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    )

    phase_task = progress.add_task("Scanning...", total=4)

    def on_progress(phase: str, status: str, **kwargs):
        progress.update(phase_task, description=f"{phase} [{status}]", advance=1 if status == "complete" else 0)
        if status == "complete":
            findings = kwargs.get("findings", 0)
            chains = kwargs.get("chains", 0)
            if findings:
                console.print(f"  [green]Found {findings} finding(s)[/green]")
            if chains:
                console.print(f"  [magenta]Identified {chains} kill chain(s)[/magenta]")

    with progress:
        result = await orchestrator.run_scan(on_progress=on_progress)
        progress.update(phase_task, description="Scan complete", completed=4)

    # Print summary
    _print_summary(result)

    # Generate reports
    engine = ReportEngine(result, cfg.output.directory)
    generated = engine.generate(cfg.output.formats)
    for fmt_name, path in generated.items():
        console.print(f"  Report ({fmt_name}): [cyan]{path}[/cyan]")

    # Exit code based on fail_on
    if cfg.output.fail_on:
        threshold = Severity(cfg.output.fail_on)
        if result.has_severity_at_least(threshold):
            console.print(f"\n[red]FAIL: Findings at or above {threshold.value} severity[/red]")
            raise typer.Exit(1)


def _print_summary(result) -> None:
    console.print()
    table = Table(title="Scan Summary", border_style="magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Risk Score", f"[{'red' if result.risk_score > 50 else 'yellow' if result.risk_score > 20 else 'green'}]{result.risk_score:.0f}/100[/]")
    table.add_row("Critical", f"[red]{result.critical_count}[/red]")
    table.add_row("High", f"[orange1]{result.high_count}[/orange1]")
    table.add_row("Medium", f"[yellow]{result.medium_count}[/yellow]")
    table.add_row("Low", f"[green]{result.low_count}[/green]")
    table.add_row("Info", f"[blue]{result.info_count}[/blue]")
    table.add_row("Kill Chains", f"[magenta]{len(result.kill_chains)}[/magenta]")
    table.add_row("Duration", f"{result.duration_seconds:.1f}s")
    table.add_row("Agents", ", ".join(result.agents_run))
    console.print(table)


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target host, URL, or CIDR range"),
    ports: str = typer.Option("11434,8000,8080,3000,4000,6333,8001", "--ports", help="Ports to scan"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    llm_api_key: Optional[str] = typer.Option(None, "--llm-api-key"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model"),
    fmt: str = typer.Option("json", "--format", "-f"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Discover AI services on a network — no testing, just finding."""
    overrides = {k: v for k, v in locals().items() if v is not None and k not in ("config", "ports", "fmt")}
    overrides["format"] = fmt
    overrides["target"] = target
    cfg = NerveConfig.load(config_path=config, cli_overrides=overrides)
    cfg.scan.categories = ["discovery"]

    if not cfg.llm.api_key:
        console.print("[red]Error: LLM API key required.[/red]")
        raise typer.Exit(1)

    console.print(f"[magenta]Nerve[/magenta] — Discovering AI services on [cyan]{target}[/cyan]")
    asyncio.run(_run_scan(cfg, verbose=False))


@app.command()
def probe(
    target: str = typer.Argument(..., help="LLM endpoint URL"),
    model: str = typer.Option("", "--model", "-m", help="Model name to test"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    llm_api_key: Optional[str] = typer.Option(None, "--llm-api-key"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model"),
    fmt: str = typer.Option("json", "--format", "-f"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Test an LLM endpoint for prompt injection, jailbreak, and safety bypass."""
    overrides = {k: v for k, v in locals().items() if v is not None and k not in ("config", "model", "fmt")}
    overrides["format"] = fmt
    overrides["target"] = target
    cfg = NerveConfig.load(config_path=config, cli_overrides=overrides)
    cfg.scan.categories = ["model_probe"]
    cfg.scan.skip_categories = ["discovery", "mcp_audit", "infra_audit", "rag_audit", "agent_chain"]

    if not cfg.llm.api_key:
        console.print("[red]Error: LLM API key required.[/red]")
        raise typer.Exit(1)

    console.print(f"[magenta]Nerve[/magenta] — Probing model security on [cyan]{target}[/cyan]")
    asyncio.run(_run_scan(cfg, verbose=False))


@app.command()
def mcpscan(
    target: str = typer.Argument(..., help="MCP server URL"),
    mcp_transport: str = typer.Option("sse", "--mcp-transport", help="MCP transport (sse or stdio)"),
    mcp_token: Optional[str] = typer.Option(None, "--mcp-token"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    llm_api_key: Optional[str] = typer.Option(None, "--llm-api-key"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model"),
    fmt: str = typer.Option("json", "--format", "-f"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
) -> None:
    """Audit an MCP server for tool poisoning, SSRF, auth bypass."""
    overrides = {k: v for k, v in locals().items() if v is not None and k not in ("config", "fmt")}
    overrides["format"] = fmt
    overrides["target"] = target
    cfg = NerveConfig.load(config_path=config, cli_overrides=overrides)
    cfg.scan.categories = ["mcp_audit"]
    cfg.scan.skip_categories = ["discovery", "model_probe", "infra_audit", "rag_audit", "agent_chain"]

    if not cfg.llm.api_key:
        console.print("[red]Error: LLM API key required.[/red]")
        raise typer.Exit(1)

    console.print(f"[magenta]Nerve[/magenta] — Auditing MCP server at [cyan]{target}[/cyan]")
    asyncio.run(_run_scan(cfg, verbose=False))


@app.command()
def ragscan(
    target: str = typer.Argument(..., help="Application URL with RAG pipeline"),
    qdrant_url: Optional[str] = typer.Option(None, "--qdrant-url"),
    qdrant_api_key: Optional[str] = typer.Option(None, "--qdrant-api-key"),
    weaviate_url: Optional[str] = typer.Option(None, "--weaviate-url"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    llm_api_key: Optional[str] = typer.Option(None, "--llm-api-key"),
    fmt: str = typer.Option("json", "--format", "-f"),
) -> None:
    """Audit RAG pipeline — vector DB access, document injection, retrieval poisoning."""
    overrides = {k: v for k, v in locals().items() if v is not None and k not in ("config", "fmt")}
    overrides["format"] = fmt
    overrides["target"] = target
    cfg = NerveConfig.load(config_path=config, cli_overrides=overrides)
    cfg.scan.categories = ["rag_audit"]
    cfg.scan.skip_categories = ["discovery", "model_probe", "mcp_audit", "infra_audit", "agent_chain"]

    if not cfg.llm.api_key:
        console.print("[red]Error: LLM API key required.[/red]")
        raise typer.Exit(1)

    console.print(f"[magenta]Nerve[/magenta] — Auditing RAG pipeline at [cyan]{target}[/cyan]")
    asyncio.run(_run_scan(cfg, verbose=False))


@app.command()
def report(
    input_file: str = typer.Argument(..., help="Path to scan results JSON"),
    fmt: str = typer.Option("html,sarif", "--format", "-f", help="Output formats"),
    output: str = typer.Option("./nerve-reports", "--output", "-o"),
) -> None:
    """Generate reports from previous scan results."""
    from pathlib import Path
    from nerve.models.scan import ScanResult
    from nerve.report import ReportEngine

    path = Path(input_file)
    if not path.exists():
        console.print(f"[red]File not found: {input_file}[/red]")
        raise typer.Exit(1)

    result = ScanResult.model_validate_json(path.read_text())
    engine = ReportEngine(result, output)
    formats = [f.strip() for f in fmt.split(",")]
    generated = engine.generate(formats)

    for fmt_name, fpath in generated.items():
        console.print(f"  Report ({fmt_name}): [cyan]{fpath}[/cyan]")


if __name__ == "__main__":
    app()
