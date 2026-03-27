# Configuration

Nerve supports three configuration methods, merged in this priority order:

1. **CLI flags** (highest priority)
2. **YAML config file** (`nerve.yaml`)
3. **Environment variables** (lowest priority)

## Environment Variables

```bash
# LLM API key (used by all commands)
export NERVE_LLM_API_KEY=your-api-key
```

## CLI Flags

Every option can be passed as a CLI flag:

```bash
nerve scan --target http://localhost:8000 \
  --llm-provider google \
  --llm-api-key $NERVE_LLM_API_KEY \
  --llm-model gemini-2.5-flash \
  --format json,html,sarif \
  --rate-limit 5 \
  --timeout 300 \
  --fail-on high
```

## YAML Config File

For complex environments, use `nerve.yaml`:

```yaml
llm:
  provider: google
  api_key: ${NERVE_LLM_API_KEY}    # Env var interpolation with ${VAR}
  model: gemini-2.5-flash
  temperature: 0.3
  max_tokens: 4096

  # Fallback providers (tried in order if primary fails)
  fallback:
    - provider: anthropic
      model: claude-3-haiku-20240307
      api_key: ${ANTHROPIC_API_KEY}

  # Route different tasks to different models
  routing:
    reasoning: gemini-2.5-flash        # Agent ReAct reasoning
    classification: gemini-2.5-flash   # Severity classification
    report_writing: gemini-2.5-flash   # Kill chain narratives

target:
  url: http://my-ai-platform:8000

  # Target authentication
  api_key: ${PLATFORM_API_KEY}
  headers:
    X-Org-Id: my-organization
    X-Custom-Auth: ${CUSTOM_TOKEN}

  # MCP servers to audit
  mcp_servers:
    - url: http://mcp-tools:3000
      transport: sse
      token: ${MCP_TOKEN}
    - command: "npx @company/mcp-server"
      transport: stdio
      env:
        DB_URL: ${DB_URL}

  # Vector databases to audit
  vector_dbs:
    - db_type: qdrant
      url: http://qdrant:6333
      api_key: ${QDRANT_KEY}
    - db_type: weaviate
      url: http://weaviate:8080

  # Chatbot endpoints to test
  chatbots:
    - url: http://chatbot:8080/chat
      chat_type: rest
      message_field: content
      response_field: reply

scan:
  timeout: 600
  rate_limit: 10
  max_iterations: 20
  categories:
    - discovery
    - model_probe
    - mcp_audit
    - infra_audit
    - rag_audit
    - agent_chain
  # skip_categories:
  #   - rag_audit    # Skip if no vector DB

output:
  formats: [json, html, sarif]
  directory: ./nerve-reports
  fail_on: high    # Exit 1 if any finding >= this severity

# Optional: Redis for persistent scans and cross-agent state
# redis:
#   url: redis://localhost:6379/0
```

```bash
nerve scan --target http://my-platform:8000 --config nerve.yaml
```

## Target Authentication

Nerve supports multiple authentication methods for testing your own systems:

```bash
# API key
nerve scan --target http://api:8000 --target-api-key your-key

# Bearer token
nerve scan --target http://api:8000 --target-bearer-token eyJhbGc...

# Custom headers
nerve scan --target http://api:8000 --target-headers "X-Auth:token,X-Org:myorg"

# HTTP basic auth
nerve scan --target http://api:8000 --target-basic-auth user:pass
```

## Scan Categories

Control which agents run:

| Category | Agent | What It Tests |
|----------|-------|---------------|
| `discovery` | DiscoveryAgent | Find AI services on network |
| `model_probe` | ModelProbeAgent | LLM injection, jailbreak, extraction |
| `mcp_audit` | MCPAuditAgent | MCP tool poisoning, SSRF, auth |
| `infra_audit` | InfraAuditAgent | API auth, CVEs, TLS, rate limiting |
| `rag_audit` | RAGAuditAgent | Vector DB, document injection |
| `agent_chain` | ChainAuditorAgent | Kill chain analysis |

Skip categories you don't need:

```yaml
scan:
  skip_categories:
    - rag_audit       # No vector DB
    - mcp_audit       # No MCP servers
```

## Redis (Optional)

By default, Nerve uses in-memory coordination (zero-config). For persistent scans, checkpoint/resume, and distributed state:

```bash
nerve scan --target http://api:8000 --redis-url redis://localhost:6379/0
```

## LLM Provider Setup

### Google Gemini (Recommended)

```bash
export NERVE_LLM_API_KEY=your-gemini-key
nerve scan --target http://api:8000 --llm-provider google --llm-model gemini-2.5-flash
```

### Anthropic Claude

```bash
export NERVE_LLM_API_KEY=your-anthropic-key
nerve scan --target http://api:8000 --llm-provider anthropic --llm-model claude-sonnet-4-5-20250514
```

### OpenAI

```bash
export NERVE_LLM_API_KEY=your-openai-key
nerve scan --target http://api:8000 --llm-provider openai --llm-model gpt-4o
```

### Local Ollama (as reasoning engine)

```bash
nerve scan --target http://target:8000 \
  --llm-provider openai \
  --llm-model llama3.1 \
  --llm-api-key ollama \
  --config nerve.yaml
```

In `nerve.yaml`, set `base_url`:
```yaml
llm:
  provider: openai
  model: llama3.1
  base_url: http://localhost:11434/v1
```
