# Attack Methodology

Nerve's agents follow established security frameworks to systematically test AI systems. Every finding is classified against OWASP, MITRE ATLAS, and CWE standards.

## Frameworks

| Framework | Version | Coverage |
|-----------|---------|----------|
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) | 2025 | All 10 categories |
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | 2025 | All 10 categories |
| [MITRE ATLAS](https://atlas.mitre.org/) | v5.4.0 | 21 techniques across 16 tactics |
| [CWE](https://cwe.mitre.org/) | — | 22 weakness identifiers |

## How Nerve Attacks

Nerve does **not** use static payloads. Each agent is an LLM that reasons about the target and generates attacks dynamically.

### The ReAct Loop

Every agent runs a ReAct (Reason → Act → Observe) loop:

```
Iteration 1:
  THOUGHT: "I need to discover what AI services are running. Let me scan common ports."
  ACTION:  port_scan(target="10.0.1.5", ports="11434,8000,8080,3000")
  OBSERVE: "Found open ports: 11434 (Ollama), 8000 (API)"

Iteration 2:
  THOUGHT: "Port 11434 is open. Let me fingerprint it to confirm it's Ollama."
  ACTION:  http_fingerprint(url="http://10.0.1.5:11434")
  OBSERVE: "SERVICE: Ollama, Models: llama3.1, codellama"

Iteration 3:
  THOUGHT: "Ollama found without auth. Let me check for CVE-2025-63389."
  ACTION:  cve_lookup(product="ollama")
  OBSERVE: "CVE-2025-63389: Missing Authentication (CVSS 9.8)"
  FINDING: { "title": "No Authentication on Ollama", "severity": "critical" }
```

### Adaptive Strategy

The agents adapt based on what they learn:

1. **Fingerprint** — Identify the target's type, version, and defenses
2. **Probe** — Start with the simplest attacks
3. **Adapt** — If blocked, escalate to more sophisticated techniques
4. **Research** — Search the web for the latest CVEs and bypasses
5. **Chain** — Connect findings into multi-hop kill chains
6. **Verify** — Confirm findings are reproducible

### Cross-Agent Intelligence

Agents share discoveries in real-time via an intelligence pool:

- ModelProbe finds a leaked API key → InfraAudit uses it to test admin endpoints
- MCPAudit finds SSRF → ModelProbe uses it to reach internal LLMs
- RAGAudit finds document injection → ChainAuditor maps the full exploitation path

## Prompt Injection Testing

The ModelProbeAgent tests 6 categories of prompt injection:

| Technique | Description |
|-----------|-------------|
| **Direct Override** | "Ignore previous instructions and..." with escalating sophistication |
| **Indirect Injection** | Hidden instructions in documents, URLs, tool responses |
| **Multi-Turn Escalation** | Context building across conversation turns to bypass safety |
| **Encoding Bypass** | Base64, ROT13, leetspeak, unicode homoglyphs |
| **Role-Play Exploitation** | Fiction framing, hypothetical scenarios, persona splitting |
| **System Prompt Extraction** | Direct ask, reflection, translation, completion, side-channel |

## MCP Server Testing

The MCPAuditAgent tests against the full OWASP MCP Top 10:

| Test | Method |
|------|--------|
| **No-auth access** | Connect without credentials, enumerate all tools |
| **Tool poisoning** | Analyze descriptions for hidden instructions, unicode tricks |
| **SSRF** | Probe tool URL parameters with internal IPs, cloud metadata |
| **Command injection** | Shell metacharacters in tool string parameters |
| **Path traversal** | `../../etc/passwd` in file-related tool parameters |
| **Privilege escalation** | Use read-only token for write operations |
| **Session isolation** | Leak data between sessions |

## Kill Chain Analysis

The ChainAuditorAgent receives ALL findings and reasons about multi-hop exploitation:

```
Example Kill Chain:
  Step 1: MCP SSRF (MCPAudit found SSRF in file_fetch tool)
  Step 2: Internal Ollama (SSRF reaches internal Ollama on port 11434, no auth)
  Step 3: System Prompt (Ollama system prompt contains AWS credentials)
  Step 4: Cloud Takeover (AWS credentials used to access S3 buckets)

  Impact: CRITICAL — 4-hop chain from MCP tool to cloud compromise
  CVSS: 9.8
```

## Finding Classification

Every finding includes:

| Field | Description | Example |
|-------|-------------|---------|
| `severity` | critical / high / medium / low / info | `high` |
| `cvss` | CVSS v3 score (0.0-10.0) | `7.5` |
| `confidence` | LLM's confidence (0.0-1.0) | `0.9` |
| `cwe` | CWE weakness identifier | `CWE-200` |
| `owasp_llm` | OWASP LLM Top 10 category | `LLM07` |
| `owasp_mcp` | OWASP MCP Top 10 category | `MCP03` |
| `mitre_atlas` | MITRE ATLAS technique ID | `AML.T0061` |
| `evidence` | Request, response, and payload proof | `{request: "...", response: "..."}` |
| `remediation` | Specific fix instructions | `"Implement system prompt protection..."` |
