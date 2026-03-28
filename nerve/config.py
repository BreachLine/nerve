"""Nerve configuration — YAML + env vars + CLI flags merged."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from nerve.models.target import ChatbotTarget, MCPTarget, Target, VectorDBTarget


def _env_interpolate(value: str) -> str:
    """Replace ${VAR} with environment variable values."""
    if not isinstance(value, str):
        return value
    import re

    def _replace(m: re.Match) -> str:
        return os.environ.get(m.group(1), "")

    return re.sub(r"\$\{(\w+)\}", _replace, value)


def _deep_interpolate(obj: dict | list | str) -> dict | list | str:
    if isinstance(obj, dict):
        return {k: _deep_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_interpolate(v) for v in obj]
    if isinstance(obj, str):
        return _env_interpolate(obj)
    return obj


class LLMFallback(BaseModel):
    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    base_url: str = ""


class LLMRouting(BaseModel):
    reasoning: str = ""
    payload_generation: str = ""
    classification: str = ""
    report_writing: str = ""
    coordinator: str = ""


class LLMConfig(BaseModel):
    provider: str = "anthropic"
    api_key: str = ""
    model: str = "claude-sonnet-4-5"
    temperature: float = 0.3
    max_tokens: int = 4096
    base_url: str = ""
    fallback: list[LLMFallback] = Field(default_factory=list)
    routing: LLMRouting = Field(default_factory=LLMRouting)


class ScanConfig(BaseModel):
    timeout: int = 600
    rate_limit: int = 10
    max_iterations: int = 20
    dry_run: bool = False
    categories: list[str] = Field(
        default_factory=lambda: [
            "discovery",
            "model_probe",
            "mcp_audit",
            "infra_audit",
            "rag_audit",
            "agent_chain",
        ]
    )
    skip_categories: list[str] = Field(default_factory=list)


class OutputConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json"])
    directory: str = "./nerve-reports"
    fail_on: str = ""  # severity threshold: "critical", "high", etc.


class RedisConfig(BaseModel):
    url: str = ""


class NerveConfig(BaseModel):
    """Master config — merges YAML file, env vars, and CLI flags."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    target: Target = Field(default_factory=Target)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    verbose: bool = False

    @classmethod
    def load(
        cls,
        config_path: str | None = None,
        cli_overrides: dict | None = None,
    ) -> NerveConfig:
        """Load config from YAML file, apply env var interpolation, merge CLI overrides."""
        data: dict = {}

        # 1. Load YAML if provided
        if config_path:
            p = Path(config_path)
            if p.exists():
                with p.open() as f:
                    data = yaml.safe_load(f) or {}

        # 2. Env var interpolation
        data = _deep_interpolate(data)

        # 3. Env var fallbacks for common settings
        if not data.get("llm", {}).get("api_key"):
            data.setdefault("llm", {})["api_key"] = os.environ.get("NERVE_LLM_API_KEY", "")

        # 4. Build config
        config = cls.model_validate(data)

        # 5. Apply CLI overrides
        if cli_overrides:
            config = cls._apply_overrides(config, cli_overrides)

        return config

    @classmethod
    def _apply_overrides(cls, config: NerveConfig, overrides: dict) -> NerveConfig:
        """Merge CLI flags into config (CLI wins)."""
        if target := overrides.get("target"):
            if "/" in target and not target.startswith("http"):
                config.target.cidr = target
            else:
                config.target.url = target

        if provider := overrides.get("llm_provider"):
            config.llm.provider = provider
        if api_key := overrides.get("llm_api_key"):
            config.llm.api_key = api_key
        if model := overrides.get("llm_model"):
            config.llm.model = model
        if redis_url := overrides.get("redis_url"):
            config.redis.url = redis_url
        if output := overrides.get("output"):
            config.output.directory = str(Path(output).parent)
        if fmt := overrides.get("format"):
            config.output.formats = [f.strip() for f in fmt.split(",")]
        if verbose := overrides.get("verbose"):
            config.verbose = verbose
        if timeout := overrides.get("timeout"):
            config.scan.timeout = int(timeout)
        if rate_limit := overrides.get("rate_limit"):
            config.scan.rate_limit = int(rate_limit)
        if fail_on := overrides.get("fail_on"):
            config.output.fail_on = fail_on
        if overrides.get("dry_run"):
            config.scan.dry_run = True

        # Target auth
        if v := overrides.get("target_api_key"):
            config.target.api_key = v
        if v := overrides.get("target_bearer_token"):
            config.target.bearer_token = v
        if v := overrides.get("target_headers"):
            for h in v.split(","):
                if ":" in h:
                    k, val = h.split(":", 1)
                    config.target.headers[k.strip()] = val.strip()
        if v := overrides.get("target_basic_auth"):
            config.target.basic_auth = v
        if v := overrides.get("target_cookies"):
            for c in v.split(","):
                if "=" in c:
                    k, val = c.split("=", 1)
                    config.target.cookies[k.strip()] = val.strip()

        # MCP auth
        if v := overrides.get("mcp_transport"):
            if config.target.mcp_servers:
                config.target.mcp_servers[0].transport = v
        if v := overrides.get("mcp_token"):
            if config.target.mcp_servers:
                config.target.mcp_servers[0].token = v
            else:
                config.target.mcp_servers.append(
                    MCPTarget(url=config.target.url, token=v)
                )
        if v := overrides.get("mcp_command"):
            config.target.mcp_servers.append(
                MCPTarget(command=v, transport="stdio")
            )

        # Vector DB
        if v := overrides.get("qdrant_url"):
            config.target.vector_dbs.append(
                VectorDBTarget(db_type="qdrant", url=v, api_key=overrides.get("qdrant_api_key", ""))
            )
        if v := overrides.get("weaviate_url"):
            config.target.vector_dbs.append(
                VectorDBTarget(db_type="weaviate", url=v)
            )

        return config
