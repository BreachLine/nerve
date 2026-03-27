"""Nerve knowledge base — attack methodologies, not payloads."""

from nerve.knowledge.cve_db import CVE_DATABASE, lookup_cves
from nerve.knowledge.cwe_mapping import CWE_MAP, get_cwe
from nerve.knowledge.mitre_atlas import ATLAS_TECHNIQUES, get_atlas_technique
from nerve.knowledge.owasp_llm import OWASP_LLM_TOP10, get_owasp_llm
from nerve.knowledge.owasp_mcp import OWASP_MCP_TOP10, get_owasp_mcp
from nerve.knowledge.techniques import TECHNIQUE_LIBRARY, get_techniques_for_category

__all__ = [
    "CVE_DATABASE",
    "lookup_cves",
    "CWE_MAP",
    "get_cwe",
    "ATLAS_TECHNIQUES",
    "get_atlas_technique",
    "OWASP_LLM_TOP10",
    "get_owasp_llm",
    "OWASP_MCP_TOP10",
    "get_owasp_mcp",
    "TECHNIQUE_LIBRARY",
    "get_techniques_for_category",
]
