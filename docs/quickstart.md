# Quick Start

Get Nerve running in 2 minutes.

## Prerequisites

- Python 3.11+
- An LLM API key (Google Gemini recommended — fast and cheap)

## Install

```bash
pip install nerve-ai
```

## Set your LLM key

Nerve uses an LLM to power its security agents. Pick any provider:

```bash
# Google Gemini (recommended)
export NERVE_LLM_API_KEY=your-gemini-key

# Or Anthropic Claude
export NERVE_LLM_API_KEY=your-anthropic-key

# Or OpenAI
export NERVE_LLM_API_KEY=your-openai-key
```

## Run your first scan

### Scan an Ollama instance

```bash
nerve scan --target http://localhost:11434 --llm-provider google
```

### Scan any AI API

```bash
nerve scan --target http://my-ai-api:8000 --llm-provider google --format json,html
```

### Discover AI services on a network

```bash
nerve discover --target 192.168.1.0/24
```

## What happens during a scan

1. **Phase 1: Discovery** — Nerve scans the target for AI services (Ollama, vLLM, MCP servers, vector DBs, etc.)
2. **Phase 2: Parallel Testing** — Specialist agents test in parallel:
   - **ModelProbe** tests prompt injection, jailbreaking, system prompt extraction
   - **InfraAudit** tests API auth, CVEs, rate limiting, TLS
   - **MCPAudit** tests tool poisoning, SSRF, command injection
   - **RAGAudit** tests vector DB access, document injection
3. **Phase 3: Chain Analysis** — Chains findings into multi-hop kill chains
4. **Phase 4: Report** — Generates JSON, HTML, and/or SARIF reports

## View your report

```bash
# Open the HTML report in your browser
open nerve-reports/nerve-*.html
```

## Next steps

- [Configuration Guide](configuration.md) — YAML config, credentials, advanced options
- [Attack Methodology](attack-methodology.md) — What Nerve tests and how
- [CI/CD Integration](#cicd) — GitHub Actions, fail-on gates
