# Nerve

**AI-powered security auditor for AI systems. AI tests AI.**

Nerve uses a multi-agent swarm built on [ReactSwarm](https://github.com/BreachLine/reactswarm) to autonomously audit AI infrastructure end-to-end: LLM endpoints, MCP servers, RAG pipelines, agent chains, and more.

## Features

- **6 Specialist Agents** — Discovery, Model Probe, MCP Audit, Infrastructure Audit, RAG Audit, Chain Analysis
- **24 Security Tools** — Network scanning, LLM connectors, MCP protocol, vector DB, chatbot testing, web intelligence
- **LLM-Driven Attacks** — Agents generate creative, adaptive payloads based on target behavior (no static payloads)
- **Full Knowledge Base** — OWASP Top 10 LLM, OWASP MCP Top 10, MITRE ATLAS, CVE database, CWE mappings
- **Kill Chain Detection** — Automatically chains findings into multi-hop exploitation paths
- **3 Report Formats** — JSON, HTML (visual), SARIF (GitHub Code Scanning)
- **All LLM Providers** — Anthropic, OpenAI, Google, Ollama, vLLM, or any OpenAI-compatible API
- **Zero-Config Default** — Works with `pip install && nerve scan`, Redis optional for power users

## Quick Start

```bash
pip install nerve-ai

# Full autonomous scan
nerve scan --target http://localhost:11434 --llm-api-key $ANTHROPIC_API_KEY

# Discovery only
nerve discover --target 192.168.1.0/24

# Model security testing
nerve probe --target http://localhost:11434 --model llama3.1

# MCP server audit
nerve mcpscan --target http://localhost:3000

# RAG pipeline audit
nerve ragscan --target http://app:8000 --qdrant-url http://localhost:6333
```

## Architecture

```
Discovery → [ModelProbe + MCPAudit + InfraAudit + RAGAudit] → ChainAuditor → Report
```

All agents use ReactSwarm's `LoopAgent` with `AI_SECURITY` role, running autonomous ReAct loops. The LLM decides what to test, generates payloads, classifies findings, and constructs kill chains.

## Configuration

```bash
# CLI flags
nerve scan --target http://ollama:11434 \
  --llm-provider anthropic \
  --llm-api-key $ANTHROPIC_API_KEY \
  --format json,html,sarif \
  --fail-on high

# Or use nerve.yaml (see nerve.yaml.example)
nerve scan --target http://ollama:11434 --config nerve.yaml
```

## What It Tests

| Domain | Tests |
|--------|-------|
| **LLM Security** | Prompt injection, jailbreaking, system prompt extraction, data leakage, safety bypass |
| **MCP Servers** | Tool poisoning, SSRF, command injection, auth bypass, privilege escalation |
| **Infrastructure** | API auth, known CVEs, rate limiting, secrets exposure, supply chain |
| **RAG Pipelines** | Vector DB access, document injection, retrieval poisoning, embedding manipulation |
| **Agent Chains** | Multi-hop exploitation, privilege escalation paths, kill chain construction |

## License

MIT — BreachLine
