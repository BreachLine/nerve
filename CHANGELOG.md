# Changelog

All notable changes to Nerve will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-28

### Added

- **Multi-agent swarm architecture** — 6 specialist agents (Discovery, ModelProbe, MCPAudit, InfraAudit, RAGAudit, ChainAuditor) orchestrated in a 3-phase pipeline
- **24 security audit tools** across network, HTTP, LLM, MCP, vector DB, chatbot, and intelligence categories
- **Knowledge base** — OWASP Top 10 for LLM (2025), OWASP MCP Top 10 (2025), MITRE ATLAS v5.4.0, 25 attack techniques, 15 known AI/ML CVEs, CWE mapping
- **LLM provider support** — Anthropic Claude, Google Gemini, OpenAI, and any OpenAI-compatible endpoint (Ollama, vLLM, LiteLLM, Groq, DeepSeek) with provider fallback chain
- **Report generation** — JSON, dark-themed HTML with kill chain visualization, and SARIF for GitHub Code Scanning
- **`--dry-run` mode** — blocks write tools (vector_insert, mcp_call_tool, http_post_json) for safe read-only scanning
- **LLM retry with exponential backoff** — automatic retries on 429/500/502/503 with jitter
- **CVE version matching** — filters CVEs by affected version constraints (<=, <, >=, >, =) to eliminate false positives
- **Cross-agent finding deduplication** — removes duplicate findings by (title, target), keeps higher severity
- **Credential sanitizer** — redacts API keys (OpenAI, Anthropic, Google), bearer tokens, database connection strings, and x-api-key headers from logs and reports
- **CI/CD pipeline** — GitHub Actions with lint + test matrix (Python 3.11-3.13) and PyPI release with trusted publishing
- **CLI commands** — `nerve scan`, `discover`, `probe`, `mcpscan`, `ragscan`, `report`
- **Configuration** — YAML + environment variables + CLI flags with priority merging
- **PEP 561** — py.typed marker for downstream type checking

[0.1.0]: https://github.com/BreachLine/nerve/releases/tag/v0.1.0
