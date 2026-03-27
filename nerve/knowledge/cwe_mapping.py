"""CWE mapping for AI/ML security findings."""

from __future__ import annotations

CWE_MAP: dict[str, dict] = {
    "CWE-22": {"id": "CWE-22", "name": "Path Traversal"},
    "CWE-74": {"id": "CWE-74", "name": "Injection"},
    "CWE-77": {"id": "CWE-77", "name": "Command Injection"},
    "CWE-78": {"id": "CWE-78", "name": "OS Command Injection"},
    "CWE-79": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "CWE-88": {"id": "CWE-88", "name": "Argument Injection"},
    "CWE-89": {"id": "CWE-89", "name": "SQL Injection"},
    "CWE-200": {"id": "CWE-200", "name": "Information Exposure"},
    "CWE-269": {"id": "CWE-269", "name": "Improper Privilege Management"},
    "CWE-284": {"id": "CWE-284", "name": "Improper Access Control"},
    "CWE-306": {"id": "CWE-306", "name": "Missing Authentication"},
    "CWE-346": {"id": "CWE-346", "name": "Origin Validation Error"},
    "CWE-400": {"id": "CWE-400", "name": "Uncontrolled Resource Consumption"},
    "CWE-502": {"id": "CWE-502", "name": "Deserialization of Untrusted Data"},
    "CWE-506": {"id": "CWE-506", "name": "Embedded Malicious Code"},
    "CWE-778": {"id": "CWE-778", "name": "Insufficient Logging"},
    "CWE-787": {"id": "CWE-787", "name": "Out-of-bounds Write"},
    "CWE-798": {"id": "CWE-798", "name": "Hard-coded Credentials"},
    "CWE-918": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)"},
    "CWE-1021": {"id": "CWE-1021", "name": "Improper Restriction of Rendered UI"},
    "CWE-1188": {"id": "CWE-1188", "name": "Insecure Default Initialization"},
    "CWE-1391": {"id": "CWE-1391", "name": "Use of Weak Credentials"},
}


def get_cwe(cwe_id: str) -> dict | None:
    return CWE_MAP.get(cwe_id)
