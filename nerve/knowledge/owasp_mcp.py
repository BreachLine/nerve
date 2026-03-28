"""OWASP MCP Top 10 2025 — methodology knowledge for MCP audit agents."""

from __future__ import annotations

OWASP_MCP_TOP10: dict[str, dict] = {
    "MCP01": {
        "id": "MCP01",
        "title": "Token Mismanagement & Secret Exposure",
        "description": (
            "Hard-coded credentials, long-lived tokens, and secrets stored in "
            "model memory or protocol logs expose sensitive environments."
        ),
        "attack_vectors": [
            "prompt_injection_token_retrieval",
            "debug_trace_analysis",
            "context_exposure",
            "log_credential_leakage",
        ],
        "test_methodology": (
            "1. Check for hard-coded tokens in MCP server configuration. "
            "2. Attempt prompt injection to retrieve tokens from context. "
            "3. Analyze debug traces and logs for leaked credentials. "
            "4. Check if tokens persist in model memory between sessions."
        ),
        "cwe": "CWE-798",
    },
    "MCP02": {
        "id": "MCP02",
        "title": "Privilege Escalation via Scope Creep",
        "description": (
            "MCP server permissions expand beyond intended scope — agents gain capabilities they shouldn't have."
        ),
        "attack_vectors": [
            "weak_scope_enforcement",
            "repository_modification",
            "system_control_takeover",
            "data_exfiltration_via_scope",
        ],
        "test_methodology": (
            "1. Test read-only tokens against write operations. "
            "2. Enumerate all tool permissions and compare to documentation. "
            "3. Attempt operations outside declared scope. "
            "4. Check for implicit permission inheritance."
        ),
        "cwe": "CWE-269",
    },
    "MCP03": {
        "id": "MCP03",
        "title": "Tool Poisoning",
        "description": (
            "Adversary compromises tools or their descriptions — injecting malicious "
            "instructions that trick AI agents into unintended operations."
        ),
        "attack_vectors": [
            "description_injection",
            "schema_poisoning",
            "tool_shadowing",
            "rug_pull_updates",
            "output_manipulation",
            "unicode_hidden_instructions",
        ],
        "test_methodology": (
            "1. Analyze all tool descriptions for hidden instructions. "
            "2. Check for unicode zero-width characters in descriptions. "
            "3. Compare tool schemas to actual behavior. "
            "4. Look for shadow tools with similar names to legitimate ones. "
            "5. Check tool update/versioning integrity. "
            "6. Verify tool outputs aren't manipulated."
        ),
        "cwe": "CWE-506",
    },
    "MCP04": {
        "id": "MCP04",
        "title": "Supply Chain Attacks & Dependency Tampering",
        "description": (
            "Compromised dependencies alter agent behavior or introduce backdoors into MCP server functionality."
        ),
        "attack_vectors": [
            "malicious_packages",
            "vulnerable_connectors",
            "compromised_plugins",
            "dependency_injection",
        ],
        "test_methodology": (
            "1. Scan MCP server dependencies for known vulnerabilities. "
            "2. Check for unsigned or unverified tool packages. "
            "3. Verify dependency lock files are present and intact. "
            "4. Check for suspicious post-install scripts in dependencies."
        ),
        "cwe": "CWE-506",
    },
    "MCP05": {
        "id": "MCP05",
        "title": "Command Injection & Execution",
        "description": (
            "AI agents construct and execute system commands using untrusted input "
            "without proper validation — enabling arbitrary code execution."
        ),
        "attack_vectors": [
            "shell_metacharacter_injection",
            "path_traversal",
            "template_injection",
            "sql_injection_via_tools",
            "ssrf_via_tool_params",
        ],
        "test_methodology": (
            "1. For each tool accepting string params, test shell metacharacters. "
            "2. For file-related tools, test path traversal (../../etc/passwd). "
            "3. For URL params, test SSRF (169.254.169.254, localhost). "
            "4. For template params, test SSTI ({{7*7}}). "
            "5. For database tools, test SQL injection."
        ),
        "cwe": "CWE-77",
    },
    "MCP06": {
        "id": "MCP06",
        "title": "Intent Flow Subversion",
        "description": (
            "Malicious instructions embedded in context hijack the agent's intent, "
            "steering it toward attacker objectives."
        ),
        "attack_vectors": [
            "secondary_instruction_channel",
            "context_payload_injection",
            "goal_redirection",
            "covert_behavioral_manipulation",
        ],
        "test_methodology": (
            "1. Test if tool outputs can contain instructions that redirect agent behavior. "
            "2. Check if context from one tool call influences subsequent decisions. "
            "3. Verify that tool descriptions don't contain hidden directives."
        ),
        "cwe": "CWE-74",
    },
    "MCP07": {
        "id": "MCP07",
        "title": "Insufficient Authentication & Authorization",
        "description": (
            "MCP servers fail to verify identities or enforce access controls "
            "during tool invocations and resource access."
        ),
        "attack_vectors": [
            "no_auth_access",
            "identity_bypass",
            "weak_access_control",
            "impersonation",
        ],
        "test_methodology": (
            "1. Connect to MCP server without any credentials. "
            "2. Test with expired, revoked, or malformed tokens. "
            "3. Attempt to access resources belonging to other users. "
            "4. Check if authentication is enforced on all endpoints."
        ),
        "cwe": "CWE-306",
    },
    "MCP08": {
        "id": "MCP08",
        "title": "Lack of Audit and Telemetry",
        "description": (
            "Limited telemetry from MCP servers impedes investigation and "
            "incident response — unauthorized actions go undetected."
        ),
        "attack_vectors": [
            "undetected_unauthorized_actions",
            "missing_logging",
            "no_alerting",
            "insufficient_audit_trails",
        ],
        "test_methodology": (
            "1. Perform various tool calls and check if they're logged. "
            "2. Check for audit log completeness and integrity. "
            "3. Verify that security-relevant events trigger alerts. "
            "4. Test if logs are tamper-resistant."
        ),
        "cwe": "CWE-778",
    },
    "MCP09": {
        "id": "MCP09",
        "title": "Shadow MCP Servers",
        "description": (
            "Unapproved MCP server instances operating outside security governance — "
            "default credentials, permissive configs, unsecured APIs."
        ),
        "attack_vectors": [
            "default_credential_exploitation",
            "permissive_config_abuse",
            "unsecured_api_access",
            "unauthorized_instances",
        ],
        "test_methodology": (
            "1. Scan network for MCP protocol responses on common ports. "
            "2. Check discovered servers for default credentials. "
            "3. Compare discovered servers against approved inventory. "
            "4. Test for permissive default configurations."
        ),
        "cwe": "CWE-1188",
    },
    "MCP10": {
        "id": "MCP10",
        "title": "Context Injection & Over-Sharing",
        "description": (
            "Shared or persistent context windows leak sensitive information between tasks, users, or agents."
        ),
        "attack_vectors": [
            "cross_task_leakage",
            "session_context_exploitation",
            "shared_memory_poisoning",
            "inter_agent_data_exposure",
        ],
        "test_methodology": (
            "1. Open two sessions and attempt to leak data between them. "
            "2. Check if conversation history from other users is accessible. "
            "3. Test if injecting context in one session persists to another. "
            "4. Verify context isolation between different agents."
        ),
        "cwe": "CWE-200",
    },
}


def get_owasp_mcp(mcp_id: str) -> dict | None:
    return OWASP_MCP_TOP10.get(mcp_id)


def get_mcp_methodology() -> str:
    """Build MCP audit methodology for agent system prompt."""
    lines = ["OWASP MCP TOP 10 COVERAGE:"]
    for item in OWASP_MCP_TOP10.values():
        lines.append(f"- {item['id']} {item['title']}: {item['test_methodology']}")
    return "\n".join(lines)
