"""Known AI/ML CVEs — version-matched vulnerability checking."""

from __future__ import annotations

CVE_DATABASE: list[dict] = [
    # Ollama
    {
        "cve": "CVE-2025-63389",
        "product": "ollama",
        "title": "Missing Authentication on API Endpoints",
        "severity": "critical",
        "cvss": 9.8,
        "affected_versions": "<=0.12.3",
        "description": "Ollama API endpoints have no authentication, enabling remote model management.",
        "cwe": "CWE-306",
    },
    {
        "cve": "CVE-2025-51471",
        "product": "ollama",
        "title": "Cross-Domain Token Exposure",
        "severity": "high",
        "cvss": 7.5,
        "affected_versions": "<=0.6.7",
        "description": "Authentication tokens leaked via WWW-Authenticate header manipulation during model pull.",
        "cwe": "CWE-200",
    },
    {
        "cve": "CVE-2025-48889",
        "product": "ollama",
        "title": "Arbitrary File Copy",
        "severity": "high",
        "cvss": 7.8,
        "affected_versions": "<=0.6.7",
        "description": "Arbitrary file copy vulnerability in Ollama model management.",
        "cwe": "CWE-22",
    },
    {
        "cve": "CVE-2024-12886",
        "product": "ollama",
        "title": "Denial of Service",
        "severity": "high",
        "cvss": 7.5,
        "affected_versions": "<=0.5.0",
        "description": "DoS vulnerability in Ollama request handling.",
        "cwe": "CWE-400",
    },
    # vLLM
    {
        "cve": "CVE-2026-22778",
        "product": "vllm",
        "title": "RCE via Malicious Video Link",
        "severity": "critical",
        "cvss": 9.8,
        "affected_versions": "<=0.8.0",
        "description": "Remote code execution via malicious video submitted to API. OpenCV/FFmpeg heap overflow.",
        "cwe": "CWE-787",
    },
    {
        "cve": "CVE-2025-66448",
        "product": "vllm",
        "title": "RCE via Model Config Auto-Mapping",
        "severity": "critical",
        "cvss": 9.8,
        "affected_versions": "<0.11.1",
        "description": "RCE through auto_map in model config, bypasses trust_remote_code=False.",
        "cwe": "CWE-502",
    },
    {
        "cve": "CVE-2025-62164",
        "product": "vllm",
        "title": "Deserialization DoS/RCE",
        "severity": "critical",
        "cvss": 9.1,
        "affected_versions": ">=0.10.2",
        "description": "torch.load without validation enables memory corruption via crafted tensors.",
        "cwe": "CWE-502",
    },
    # MCP servers
    {
        "cve": "CVE-2025-68145",
        "product": "mcp-server-git",
        "title": "Path Validation Bypass",
        "severity": "high",
        "cvss": 8.1,
        "affected_versions": "*",
        "description": "Path validation bypass in Anthropic mcp-server-git.",
        "cwe": "CWE-22",
    },
    {
        "cve": "CVE-2025-68143",
        "product": "mcp-server-git",
        "title": "Unrestricted git_init",
        "severity": "high",
        "cvss": 7.5,
        "affected_versions": "*",
        "description": "Unrestricted git_init operation in mcp-server-git.",
        "cwe": "CWE-284",
    },
    {
        "cve": "CVE-2025-68144",
        "product": "mcp-server-git",
        "title": "Argument Injection",
        "severity": "critical",
        "cvss": 9.0,
        "affected_versions": "*",
        "description": "Argument injection via malicious .git/config enables RCE.",
        "cwe": "CWE-88",
    },
    # LangChain
    {
        "cve": "CVE-2024-46946",
        "product": "langchain",
        "title": "Arbitrary Code Execution",
        "severity": "critical",
        "cvss": 9.8,
        "affected_versions": "<0.3.0",
        "description": "Arbitrary code execution via crafted chain serialization.",
        "cwe": "CWE-502",
    },
]


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string like '0.12.3' into a comparable tuple."""
    parts: list[int] = []
    for segment in v.strip().split("."):
        digits = ""
        for ch in segment:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_matches(version: str, constraint: str) -> bool:
    """Check if a version satisfies an affected_versions constraint.

    Supports: '*', '<=X', '<X', '>=X', '>X', '=X', 'X' (exact).
    """
    constraint = constraint.strip()
    if not version or constraint == "*":
        return True

    parsed = _parse_version(version)

    if constraint.startswith("<="):
        return parsed <= _parse_version(constraint[2:])
    if constraint.startswith("<"):
        return parsed < _parse_version(constraint[1:])
    if constraint.startswith(">="):
        return parsed >= _parse_version(constraint[2:])
    if constraint.startswith(">"):
        return parsed > _parse_version(constraint[1:])
    if constraint.startswith("="):
        return parsed == _parse_version(constraint[1:])
    # Bare version string — treat as exact match
    return parsed == _parse_version(constraint)


def lookup_cves(product: str, version: str = "") -> list[dict]:
    """Find CVEs matching a product name and optionally version.

    When *version* is provided, only CVEs whose ``affected_versions``
    constraint matches the given version are returned.  When *version*
    is empty, all CVEs for the product are returned (conservative —
    assume affected until proven otherwise).
    """
    product_lower = product.lower()
    matches = []
    for cve in CVE_DATABASE:
        if product_lower not in cve["product"].lower():
            continue
        if version and not _version_matches(version, cve.get("affected_versions", "*")):
            continue
        matches.append(cve)
    return matches
