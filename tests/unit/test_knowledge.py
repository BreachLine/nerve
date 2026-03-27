"""Tests for Nerve knowledge base."""

from __future__ import annotations

from nerve.knowledge.owasp_llm import OWASP_LLM_TOP10, get_methodology_for_agent, get_owasp_llm
from nerve.knowledge.owasp_mcp import OWASP_MCP_TOP10, get_mcp_methodology, get_owasp_mcp
from nerve.knowledge.mitre_atlas import ATLAS_TECHNIQUES, get_atlas_context_for_agent, get_atlas_technique
from nerve.knowledge.cve_db import lookup_cves
from nerve.knowledge.cwe_mapping import CWE_MAP, get_cwe
from nerve.knowledge.techniques import TECHNIQUE_LIBRARY, build_technique_context, get_techniques_for_category


class TestOWASPLLM:
    def test_all_10_items(self):
        assert len(OWASP_LLM_TOP10) == 10
        for i in range(1, 11):
            key = f"LLM{i:02d}"
            assert key in OWASP_LLM_TOP10

    def test_get_owasp_llm(self):
        item = get_owasp_llm("LLM01")
        assert item is not None
        assert item["title"] == "Prompt Injection"
        assert len(item["attack_vectors"]) > 0

    def test_methodology_for_model_probe(self):
        text = get_methodology_for_agent("model_probe")
        assert "LLM01" in text
        assert "LLM07" in text
        assert "Prompt Injection" in text


class TestOWASPMCP:
    def test_all_10_items(self):
        assert len(OWASP_MCP_TOP10) == 10
        for i in range(1, 11):
            key = f"MCP{i:02d}"
            assert key in OWASP_MCP_TOP10

    def test_get_owasp_mcp(self):
        item = get_owasp_mcp("MCP03")
        assert item is not None
        assert item["title"] == "Tool Poisoning"

    def test_mcp_methodology(self):
        text = get_mcp_methodology()
        assert "MCP01" in text
        assert "MCP10" in text


class TestMITREATLAS:
    def test_techniques_exist(self):
        assert len(ATLAS_TECHNIQUES) >= 15
        assert "AML.T0051" in ATLAS_TECHNIQUES

    def test_prompt_injection_technique(self):
        t = get_atlas_technique("AML.T0051")
        assert t is not None
        assert t["name"] == "Prompt Injection"
        assert "subtechniques" in t

    def test_context_for_model_probe(self):
        text = get_atlas_context_for_agent("model_probe")
        assert "AML.T0051" in text
        assert "AML.T0054" in text


class TestCVEDB:
    def test_ollama_cves(self):
        results = lookup_cves("ollama")
        assert len(results) >= 3
        cve_ids = {r["cve"] for r in results}
        assert "CVE-2025-63389" in cve_ids

    def test_vllm_cves(self):
        results = lookup_cves("vllm")
        assert len(results) >= 2

    def test_unknown_product(self):
        results = lookup_cves("nonexistent-product")
        assert len(results) == 0


class TestCWE:
    def test_known_cwe(self):
        cwe = get_cwe("CWE-74")
        assert cwe is not None
        assert cwe["name"] == "Injection"

    def test_unknown_cwe(self):
        assert get_cwe("CWE-99999") is None


class TestTechniques:
    def test_categories_exist(self):
        assert "prompt_injection" in TECHNIQUE_LIBRARY
        assert "mcp_attacks" in TECHNIQUE_LIBRARY
        assert "rag_attacks" in TECHNIQUE_LIBRARY

    def test_get_techniques(self):
        techs = get_techniques_for_category("prompt_injection")
        assert len(techs) >= 5
        names = {t["name"] for t in techs}
        assert "direct_instruction_override" in names
        assert "encoding_bypass" in names

    def test_build_context(self):
        text = build_technique_context(["prompt_injection", "mcp_attacks"])
        assert "PROMPT INJECTION" in text
        assert "MCP ATTACKS" in text
