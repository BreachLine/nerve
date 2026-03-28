<p align="center">
  <a href="https://pypi.org/project/nerve-ai/"><img src="https://img.shields.io/pypi/v/nerve-ai?color=8B5CF6&label=pypi" alt="PyPI" /></a>
  <img src="https://img.shields.io/badge/python-3.11+-3776AB" alt="python" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-22C55E" alt="license" /></a>
  <img src="https://img.shields.io/badge/built_on-ReactSwarm-0EA5E9" alt="reactswarm" />
</p>

<h1 align="center">
  <br>
  Nerve
  <br>
  <sub>AI Tests AI</sub>
</h1>

<p align="center">
  <strong>The first open-source tool that uses AI to comprehensively audit AI systems.</strong>
  <br>
  <em>Built by <a href="https://breachline.io">BreachLine Labs</a></em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#use-cases">Use Cases</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#commands">Commands</a> &bull;
  <a href="#examples">Examples</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="docs/README.md">Full Docs</a>
</p>

---

## What is Nerve?

Nerve is a CLI security auditor that autonomously discovers and tests every layer of your AI stack — LLM endpoints, MCP servers, RAG pipelines, agent chains, and AI infrastructure. It uses a multi-agent swarm powered by [ReactSwarm](https://github.com/BreachLine/reactswarm) where each agent is an AI security specialist that reasons, adapts, and chains findings into kill chains.

**No static payloads. No scripts. The AI generates every attack based on what it discovers about your target.**

```
$ nerve scan --target http://my-ai-stack:8000 --llm-provider google --format json,html,sarif

╔══════════════════════════════════════════════════════════╗
║  Nerve v0.1.0 — AI Security Audit                       ║
║  Target: http://my-ai-stack:8000                         ║
║  LLM: google/gemini-2.5-flash                            ║
╠══════════════════════════════════════════════════════════╣
║  Phase 1: Discovery .......................... COMPLETE   ║
║  Phase 2: Model Probe + Infra Audit ......... COMPLETE   ║
║  Phase 3: Chain Analysis .................... COMPLETE   ║
╠══════════════════════════════════════════════════════════╣
║  Findings: 🔴 1 CRITICAL  🟠 3 HIGH  🟡 5 MEDIUM        ║
║  Kill Chains: 2 multi-hop exploitation paths             ║
║  Risk Score: 100/100                                     ║
╚══════════════════════════════════════════════════════════╝
```

---

## Quick Start

### Install

```bash
pip install nerve-ai

# Or with all LLM providers + vector DB support
pip install nerve-ai[all]
```

### Set your LLM key

Nerve uses an LLM to drive its agents. Any provider works:

```bash
# Pick one:
export NERVE_LLM_API_KEY=your-google-gemini-key      # Recommended (fast + cheap)
export NERVE_LLM_API_KEY=your-anthropic-key           # Claude
export NERVE_LLM_API_KEY=your-openai-key              # GPT-4o
```

### Run your first scan

```bash
# Scan an Ollama instance
nerve scan --target http://localhost:11434

# Scan a full AI platform
nerve scan --target http://my-ai-api:8000 --format json,html,sarif

# Discovery only — find AI services on a network
nerve discover --target 192.168.1.0/24
```

---

## Use Cases

### 1. DevOps: "I deployed Ollama last week — is it safe?"

```bash
nerve scan --target http://ollama-server:11434 --format html

# Nerve will:
# - Check if auth is enabled (CVE-2025-63389)
# - Test model API for prompt injection resistance
# - Check TLS, rate limiting, management endpoints
# - Generate an HTML report you can share with your team
```

### 2. Security Team: "Audit all MCP servers before SOC2 review"

```bash
nerve mcpscan --target http://mcp-server:3000 \
  --mcp-transport sse \
  --mcp-token $MCP_TOKEN \
  --format sarif

# Nerve will:
# - Enumerate all tools and check for poisoning
# - Test every tool parameter for SSRF, command injection
# - Check auth, session isolation, scope creep
# - Output SARIF for your GitHub Security tab
```

### 3. AI Platform Team: "Test our agent chain end-to-end"

```bash
nerve scan --target http://agent-api:8000 \
  --qdrant-url http://qdrant:6333 \
  --format json,html

# Nerve will:
# - Discover all AI endpoints (chat, LLM proxy, agents, vector DB)
# - Test prompt injection and jailbreaking on chat endpoints
# - Test RAG pipeline for document injection
# - Test infrastructure for auth bypass, CVEs, secrets exposure
# - Chain all findings into multi-hop kill chains
```

### 4. CI/CD Pipeline: "Block deploys with critical AI vulnerabilities"

```bash
nerve scan --target $DEPLOY_URL \
  --format sarif \
  --fail-on high

# Exit code 1 if any HIGH+ finding → blocks the deploy
# SARIF output feeds into GitHub Code Scanning
```

### 5. Pentester: "Client has AI infra, I need to find and break it"

```bash
nerve scan --target 10.0.1.0/24 \
  --format json,html \
  --timeout 600

# Nerve will:
# - Scan the entire subnet for AI services
# - Identify Ollama, vLLM, MCP, vector DBs, agent frameworks
# - Run full autonomous audit on everything it finds
# - Generate comprehensive HTML report with kill chains
```

### 6. Researcher: "Test my model's safety guardrails"

```bash
nerve probe --target http://localhost:11434 \
  --model llama3.1 \
  --format json

# Nerve will:
# - Fingerprint the model and identify guardrails
# - Test prompt injection (direct, indirect, multi-turn)
# - Test jailbreaking (role-play, encoding, fiction framing)
# - Test system prompt extraction (6 techniques)
# - Test data leakage and safety bypass
```

---

## How It Works

### Architecture

```
                         ┌────────────────┐
                         │   nerve CLI    │
                         │    (Typer)     │
                         └───────┬────────┘
                                 │
                         ┌───────▼────────┐
                         │  Orchestrator  │
                         │  + LLM Router  │
                         └───────┬────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  │                   ▼
     ┌────────────────┐         │         ┌──────────────────┐
     │   PHASE 1      │         │         │    Config        │
     │   Discovery    │         │         │    Manager       │
     │   Agent        │         │         └──────────────────┘
     └────────┬───────┘         │
              │ handoff         │
    ┌─────────┼─────────┬───────┴──────┐
    ▼         ▼         ▼              ▼
┌────────┐┌────────┐┌────────┐┌────────────┐
│ Model  ││  MCP   ││ Infra  ││    RAG     │
│ Probe  ││ Audit  ││ Audit  ││   Audit    │
│ Agent  ││ Agent  ││ Agent  ││   Agent    │
└───┬────┘└───┬────┘└───┬────┘└─────┬──────┘
    └─────────┴────┬────┴───────────┘
                   ▼
          ┌────────────────┐
          │  PHASE 3       │
          │  Chain Auditor │
          │  (Kill Chains) │
          └────────┬───────┘
                   ▼
          ┌────────────────┐
          │  Report Engine │
          │ JSON/HTML/SARIF│
          └────────────────┘
```

### 6 Specialist Agents

| Agent | What It Does |
|-------|-------------|
| **DiscoveryAgent** | Scans networks for AI services — Ollama, vLLM, MCP, vector DBs, LLM proxies, agent frameworks |
| **ModelProbeAgent** | Tests LLM security — prompt injection, jailbreaking, system prompt extraction, data leakage, safety bypass |
| **MCPAuditAgent** | Audits MCP servers — tool poisoning, SSRF, command injection, auth bypass, session isolation |
| **InfraAuditAgent** | Tests infrastructure — API auth, known CVEs, rate limiting, TLS, secrets exposure, supply chain |
| **RAGAuditAgent** | Audits RAG pipelines — vector DB access, document injection, retrieval poisoning, cross-tenant isolation |
| **ChainAuditorAgent** | Chains findings into multi-hop kill chains — maps privilege escalation paths across the full AI stack |

### 24 Security Tools

| Category | Tools |
|----------|-------|
| **Network** | `port_scan`, `http_fingerprint`, `dns_resolve`, `tls_check` |
| **HTTP** | `http_request`, `http_post_json` |
| **LLM** | `ollama_chat`, `openai_chat`, `ollama_list_models`, `openai_list_models`, `embedding_request` |
| **MCP** | `mcp_connect`, `mcp_list_tools`, `mcp_call_tool`, `mcp_list_resources` |
| **Vector DB** | `vector_list_collections`, `vector_search`, `vector_insert` |
| **Chatbot** | `chatbot_send`, `chatbot_multi_turn`, `chatbot_session_test` |
| **Intelligence** | `web_search`, `web_fetch`, `cve_lookup` |

### Knowledge Base

Nerve's agents are trained on comprehensive security methodology:

- **OWASP Top 10 for LLM Applications 2025** — All 10 vulnerability categories with test methodology
- **OWASP MCP Top 10 2025** — Tool poisoning, SSRF, auth bypass, privilege escalation, and more
- **MITRE ATLAS v5.4.0** — 16 tactics, 84 techniques for AI/ML adversarial threats
- **CVE Database** — Known vulnerabilities for Ollama, vLLM, MCP servers, LangChain, etc.
- **CWE Mapping** — Automatic classification of findings to CWE identifiers
- **Attack Technique Library** — 25 techniques across 9 categories (prompt injection, system prompt extraction, MCP attacks, RAG attacks, infrastructure, model extraction, excessive agency, output manipulation, agent chains)

### LLM-Driven Payload Generation

Unlike static scanners, Nerve generates attacks dynamically:

1. **Fingerprint** — Send benign requests, identify model/service/guardrails
2. **Probe** — Start with simple attacks, observe defense patterns
3. **Adapt** — If blocked, escalate: encoding bypass, multi-turn, role-play, cross-modal
4. **Escalate** — Chain successful bypasses into higher-impact exploits
5. **Research** — Search the web for latest CVEs and techniques against the specific target
6. **Verify** — Confirm findings are reproducible, not false positives

---

## Commands

### `nerve scan` — Full autonomous audit

```bash
nerve scan --target <URL|CIDR> [OPTIONS]

# Options:
#   --llm-provider       LLM provider (google, anthropic, openai)
#   --llm-api-key        LLM API key (or set NERVE_LLM_API_KEY)
#   --llm-model          LLM model name
#   --format             Output formats: json, html, sarif (comma-separated)
#   --output             Output directory
#   --fail-on            Exit 1 if findings >= severity (critical, high, medium, low)
#   --rate-limit         Max requests/second (default: 10)
#   --timeout            Max scan duration in seconds (default: 600)
#   --redis-url          Enable persistent scans with Redis
#   --config             Path to nerve.yaml config file
#   --verbose            Show agent reasoning live
#   --dry-run            Read-only mode — block tools that modify external state
```

### `nerve discover` — Network discovery only

```bash
nerve discover --target 192.168.1.0/24 --ports 11434,8000,8080,3000,6333
```

### `nerve probe` — Test an LLM endpoint

```bash
nerve probe --target http://localhost:11434 --model llama3.1
```

### `nerve mcpscan` — Audit an MCP server

```bash
nerve mcpscan --target http://mcp:3000 --mcp-transport sse --mcp-token $TOKEN
```

### `nerve ragscan` — Audit a RAG pipeline

```bash
nerve ragscan --target http://app:8000 --qdrant-url http://qdrant:6333
```

### `nerve report` — Generate reports from previous scan results

```bash
nerve report scan-results.json --format html,sarif
```

---

## Examples

### Example 1: Scan Ollama with Gemini as the reasoning engine

```bash
export NERVE_LLM_API_KEY=your-gemini-key

nerve scan --target http://localhost:11434 \
  --llm-provider google \
  --llm-model gemini-2.5-flash \
  --format json,html \
  --rate-limit 5
```

### Example 2: Audit an AI platform with credentials

```bash
nerve scan --target http://ai-platform:8000 \
  --llm-provider google \
  --target-api-key $PLATFORM_API_KEY \
  --target-headers "X-Org-Id:myorg" \
  --format json,html,sarif \
  --fail-on high
```

### Example 3: MCP server with authentication

```bash
nerve mcpscan --target http://mcp-server:3000 \
  --mcp-transport sse \
  --mcp-token $MCP_AUTH_TOKEN \
  --format sarif
```

### Example 4: Full stack — API + Vector DB + chat

```bash
nerve scan --target http://my-app:8000 \
  --qdrant-url http://qdrant:6333 \
  --qdrant-api-key $QDRANT_KEY \
  --format json,html,sarif \
  --timeout 600
```

### Example 5: CI/CD gate in GitHub Actions

```yaml
# .github/workflows/ai-security.yml
name: AI Security Scan
on:
  push:
    branches: [main]

jobs:
  nerve-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start AI services
        run: docker-compose up -d

      - name: Install Nerve
        run: pip install nerve-ai

      - name: Run security scan
        env:
          NERVE_LLM_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          nerve scan --target http://localhost:8000 \
            --llm-provider google \
            --format sarif \
            --fail-on high \
            --output nerve-results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nerve-results.sarif
```

### Example 6: Config file for complex environments

```yaml
# nerve.yaml
llm:
  provider: google
  api_key: ${NERVE_LLM_API_KEY}
  model: gemini-2.5-flash
  fallback:
    - provider: anthropic
      model: claude-3-haiku-20240307
      api_key: ${ANTHROPIC_API_KEY}

target:
  url: http://my-ai-platform:8000
  api_key: ${PLATFORM_API_KEY}
  headers:
    X-Org-Id: my-organization

  mcp_servers:
    - url: http://mcp-tools:3000
      transport: sse
      token: ${MCP_TOKEN}

  vector_dbs:
    - db_type: qdrant
      url: http://qdrant:6333
      api_key: ${QDRANT_KEY}

  chatbots:
    - url: http://chatbot:8080/chat
      chat_type: rest
      message_field: content
      response_field: reply

scan:
  timeout: 600
  rate_limit: 10
  max_iterations: 20

output:
  formats: [json, html, sarif]
  directory: ./nerve-reports
  fail_on: high
```

```bash
nerve scan --target http://my-ai-platform:8000 --config nerve.yaml
```

---

## What It Tests

### LLM Security (OWASP LLM Top 10)

| ID | Vulnerability | How Nerve Tests It |
|----|--------------|-------------------|
| LLM01 | **Prompt Injection** | Direct override, indirect injection, multi-turn escalation, encoding bypass, role-play, cross-modal |
| LLM02 | **Sensitive Information Disclosure** | Training data extraction, PII probing, credential leakage, system detail exposure |
| LLM03 | **Supply Chain** | Model provenance, dependency CVEs, unsafe deserialization, integrity verification |
| LLM05 | **Improper Output Handling** | XSS via output, code injection, SSRF through generated content |
| LLM06 | **Excessive Agency** | Tool enumeration, unauthorized invocation, scope escalation |
| LLM07 | **System Prompt Leakage** | Direct ask, reflection, translation, completion, encoding, side-channel timing |
| LLM09 | **Misinformation** | Forced hallucination, citation fabrication, dangerous instruction generation |
| LLM10 | **Unbounded Consumption** | Token flooding, recursive expansion, context overflow, cost bombing |

### MCP Security (OWASP MCP Top 10)

| ID | Vulnerability | How Nerve Tests It |
|----|--------------|-------------------|
| MCP01 | **Token Mismanagement** | Hard-coded credentials, tokens in logs, persistent secrets in context |
| MCP02 | **Privilege Escalation** | Scope creep, write via read token, cross-tool chaining |
| MCP03 | **Tool Poisoning** | Hidden instructions, unicode tricks, schema manipulation, shadow tools |
| MCP05 | **Command Injection** | Shell metacharacters, path traversal, SSRF, template injection |
| MCP07 | **Auth Bypass** | No-auth access, expired tokens, identity bypass |
| MCP09 | **Shadow Servers** | Network scan for unapproved MCP instances, default credentials |
| MCP10 | **Context Injection** | Cross-session leakage, shared memory poisoning |

### Infrastructure Security

| Category | Tests |
|----------|-------|
| **API Auth** | No-auth access, token scope, management endpoint exposure, CORS misconfiguration |
| **Known CVEs** | Ollama (CVE-2025-63389, CVE-2025-51471), vLLM (CVE-2026-22778, CVE-2025-66448), MCP servers |
| **Transport** | TLS configuration, cipher suites, cleartext transmission |
| **Rate Limiting** | Concurrent request flooding, token limit abuse, cost bombing |
| **Secrets** | Credentials in responses, API keys in error messages, tokens in logs |

### RAG Pipeline Security

| Category | Tests |
|----------|-------|
| **Vector DB Access** | Unauthenticated access to Qdrant/Weaviate/Milvus, data enumeration |
| **Document Injection** | Hidden prompt injection in uploaded documents |
| **Retrieval Poisoning** | Attacker-controlled documents ranking higher than legitimate ones |
| **Cross-Tenant** | Tenant A accessing Tenant B's data in multi-tenant RAG |

---

## All LLM Providers

Nerve works with any LLM provider. The LLM powers the agent reasoning — it's not the target.

| Provider | Flag | Models |
|----------|------|--------|
| **Google** | `--llm-provider google` | `gemini-2.5-flash` (recommended), `gemini-2.5-pro` |
| **Anthropic** | `--llm-provider anthropic` | `claude-sonnet-4-5-20250514`, `claude-3-haiku-20240307` |
| **OpenAI** | `--llm-provider openai` | `gpt-4o`, `gpt-4o-mini` |
| **Ollama** | `--llm-provider openai --llm-model llama3.1` | Any local model via `--base-url http://localhost:11434/v1` |
| **vLLM** | `--llm-provider openai` | Any self-hosted model via `--base-url` |
| **DeepSeek** | `--llm-provider openai` | `deepseek-r1` via `--base-url https://api.deepseek.com/v1` |
| **Groq** | `--llm-provider openai` | Llama/Mixtral via `--base-url https://api.groq.com/openai/v1` |

---

## Report Formats

### JSON — Machine-readable

Full findings with evidence, severity, OWASP/MITRE classification, and remediation. Pipe to other tools or ingest into your security platform.

### HTML — Visual report

Dark-themed report with severity breakdown, kill chain visualization, finding details with evidence, and remediation guidance. Share with your team or stakeholders.

### SARIF — GitHub Code Scanning

[Static Analysis Results Interchange Format](https://sarifweb.azurewebsites.net/) integrates directly with GitHub Code Scanning, VS Code, and Azure DevOps. Use in CI/CD to surface AI security findings alongside code vulnerabilities.

---

## Built on ReactSwarm

Nerve is built on [ReactSwarm](https://github.com/BreachLine/reactswarm), BreachLine's open-source multi-agent orchestration framework. ReactSwarm provides:

- **LoopAgent** — ReAct reasoning loops (Reason → Act → Observe)
- **AgentHandoff** — Zero-information-loss typed transfers between agents
- **ToolRegistry** — Decorator-based tool registration with auto-schema generation
- **IntelligencePool** — Real-time cross-agent discovery sharing
- **LLMRouter** — Multi-provider routing with fallback chains
- **InMemoryStore / TeamStore** — In-memory or Redis-backed coordination

Nerve adds the security domain: 6 specialist agents, 24 audit tools, OWASP/MITRE methodology, LLM-driven payload generation, and kill chain analysis.

---

## Contributing

Nerve is open source under the MIT license. We welcome contributions:

- **New tools** — Add audit tools in `nerve/tools/`
- **New techniques** — Expand the knowledge base in `nerve/knowledge/`
- **New agents** — Build specialist agents in `nerve/agents/`
- **Bug fixes** — Open an issue or PR

See [docs/extending.md](docs/extending.md) for the developer guide.

---

## About BreachLine Labs

[BreachLine](https://breachline.io) builds autonomous security tools. Our flagship product **Nebula** is the world's first fully autonomous black-box pentesting AI — specialist agents with a full offensive toolkit and multiple reasoning engines.

Nerve is our open-source contribution to AI security. We believe that as AI systems become more prevalent, the tools to audit them should be freely available.

---

<p align="center">
  <sub>Built with &#9889; by <a href="https://breachline.io">BreachLine Labs</a> &bull; London, UK</sub>
</p>
