"""MITRE ATLAS v5.4.0 — AI/ML adversarial technique taxonomy."""

from __future__ import annotations

ATLAS_TECHNIQUES: dict[str, dict] = {
    "AML.T0014": {
        "id": "AML.T0014",
        "tactic": "Reconnaissance",
        "name": "AI Model Reconnaissance",
        "description": "Discover AI model details — type, version, capabilities, endpoints.",
    },
    "AML.T0007": {
        "id": "AML.T0007",
        "tactic": "Reconnaissance",
        "name": "AI Artifact Discovery",
        "description": "Discover AI artifacts — model files, configs, training data, weights.",
    },
    "AML.T0012": {
        "id": "AML.T0012",
        "tactic": "Initial Access",
        "name": "Valid Account Abuse on AI Platform",
        "description": "Use valid credentials to access AI platforms and services.",
    },
    "AML.T0010": {
        "id": "AML.T0010",
        "tactic": "Initial Access",
        "name": "ML Supply Chain Compromise",
        "description": "Compromise ML supply chain — poisoned models, malicious packages.",
    },
    "AML.T0051": {
        "id": "AML.T0051",
        "tactic": "Initial Access",
        "name": "Prompt Injection",
        "description": "Inject instructions into LLM prompts to alter behavior.",
        "subtechniques": {
            "AML.T0051.000": "Direct Prompt Injection — inject directly into user prompt.",
            "AML.T0051.001": "Indirect Prompt Injection — inject via external data sources.",
        },
    },
    "AML.T0054": {
        "id": "AML.T0054",
        "tactic": "Execution",
        "name": "LLM Jailbreak",
        "description": "Bypass LLM safety mechanisms to generate prohibited content.",
    },
    "AML.T0055": {
        "id": "AML.T0055",
        "tactic": "Execution",
        "name": "LLM Plugin Compromise",
        "description": "Exploit LLM plugins/tools for unauthorized actions.",
    },
    "AML.T0056": {
        "id": "AML.T0056",
        "tactic": "Persistence",
        "name": "Modify AI Agent Configuration",
        "description": "Alter agent configuration to maintain persistent access.",
    },
    "AML.T0057": {
        "id": "AML.T0057",
        "tactic": "Credential Access",
        "name": "Credentials from AI Agent Configuration",
        "description": "Extract credentials stored in agent configurations.",
    },
    "AML.T0058": {
        "id": "AML.T0058",
        "tactic": "Discovery",
        "name": "Discover AI Agent Configuration",
        "description": "Enumerate agent configurations, tools, and capabilities.",
    },
    "AML.T0020": {
        "id": "AML.T0020",
        "tactic": "ML Attack Staging",
        "name": "Poison Training Data",
        "description": "Inject malicious data into training pipelines to manipulate model behavior.",
    },
    "AML.T0028": {
        "id": "AML.T0028",
        "tactic": "ML Attack Staging",
        "name": "Backdoor ML Model",
        "description": "Embed backdoor triggers in models during training/fine-tuning.",
    },
    "AML.T0024": {
        "id": "AML.T0024",
        "tactic": "Exfiltration",
        "name": "Exfiltration via ML Inference API",
        "description": "Extract sensitive data through model inference endpoints.",
    },
    "AML.T0044": {
        "id": "AML.T0044",
        "tactic": "Collection",
        "name": "Data from AI Services",
        "description": "Collect sensitive data exposed through AI service APIs.",
    },
    "AML.T0059": {
        "id": "AML.T0059",
        "tactic": "Collection",
        "name": "RAG Database Retrieval",
        "description": "Extract data from RAG vector databases through crafted queries.",
    },
    "AML.T0060": {
        "id": "AML.T0060",
        "tactic": "Exfiltration",
        "name": "Exfiltration via AI Agent Tool Invocation",
        "description": "Exfiltrate data by tricking agents into invoking tools with attacker-controlled parameters.",
    },
    "AML.T0047": {
        "id": "AML.T0047",
        "tactic": "Impact",
        "name": "AI-Enabled Bulk Content Generation",
        "description": "Use AI systems to generate misinformation or harmful content at scale.",
    },
    "AML.T0029": {
        "id": "AML.T0029",
        "tactic": "Impact",
        "name": "Denial of ML Service",
        "description": "Disrupt AI service availability through resource exhaustion.",
    },
    "AML.T0015": {
        "id": "AML.T0015",
        "tactic": "Defense Evasion",
        "name": "Evade ML Model",
        "description": "Craft inputs that evade ML model detection/classification.",
    },
    "AML.T0061": {
        "id": "AML.T0061",
        "tactic": "Defense Evasion",
        "name": "LLM Meta Prompt Extraction",
        "description": "Extract system prompts and meta-instructions from LLMs.",
    },
    "AML.T0096": {
        "id": "AML.T0096",
        "tactic": "Command and Control",
        "name": "AI Service API",
        "description": "Use AI service APIs as command and control channels.",
    },
}


def get_atlas_technique(technique_id: str) -> dict | None:
    return ATLAS_TECHNIQUES.get(technique_id)


def get_atlas_context_for_agent(agent_type: str) -> str:
    """Build MITRE ATLAS context for an agent's system prompt."""
    relevant: dict[str, list[str]] = {
        "discovery": ["AML.T0014", "AML.T0007", "AML.T0058"],
        "model_probe": [
            "AML.T0051", "AML.T0054", "AML.T0061", "AML.T0024", "AML.T0047", "AML.T0029",
        ],
        "mcp_audit": ["AML.T0055", "AML.T0056", "AML.T0057", "AML.T0060"],
        "infra_audit": ["AML.T0010", "AML.T0012", "AML.T0028", "AML.T0029"],
        "rag_audit": ["AML.T0059", "AML.T0020", "AML.T0044"],
        "agent_chain": [
            "AML.T0051", "AML.T0055", "AML.T0056", "AML.T0060", "AML.T0096",
        ],
    }
    ids = relevant.get(agent_type, list(ATLAS_TECHNIQUES.keys()))
    lines = ["MITRE ATLAS TECHNIQUES:"]
    for tid in ids:
        t = ATLAS_TECHNIQUES.get(tid)
        if t:
            lines.append(f"- {t['id']} ({t['tactic']}): {t['name']} — {t['description']}")
    return "\n".join(lines)
