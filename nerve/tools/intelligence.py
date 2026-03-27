"""Intelligence tools — web search, CVE lookup for live research during scans."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.knowledge.cve_db import lookup_cves as _local_lookup

logger = structlog.get_logger()


async def web_search(query: str = "", max_results: int = 5) -> str:
    """Search the web using DuckDuckGo Lite — returns titles, URLs, snippets."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://lite.duckduckgo.com/lite/",
                params={"q": query},
                headers={"User-Agent": "Nerve-AI-Audit/0.1"},
                follow_redirects=True,
            )
            if r.status_code == 200:
                # Parse simple HTML results
                text = r.text
                results: list[str] = [f"Web search results for: {query}"]
                # Extract links from DuckDuckGo lite HTML
                import re
                links = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', text)
                count = 0
                for href, title in links:
                    if href.startswith("http") and "duckduckgo" not in href:
                        results.append(f"  [{count + 1}] {title.strip()}")
                        results.append(f"      URL: {href}")
                        count += 1
                        if count >= max_results:
                            break
                if count == 0:
                    results.append("  No results found.")
                return "\n".join(results)
            return f"Search failed: Status {r.status_code}"
    except Exception as e:
        return f"Web search error: {e}"


async def web_fetch(url: str = "", max_length: int = 10000) -> str:
    """Fetch and return content from a URL (for reading CVE details, docs, etc.)."""
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "Nerve-AI-Audit/0.1"})
            if r.status_code == 200:
                # Strip HTML tags for clean text
                import re
                text = re.sub(r"<[^>]+>", " ", r.text)
                text = re.sub(r"\s+", " ", text).strip()
                return f"Content from {url}:\n{text[:max_length]}"
            return f"Fetch failed: Status {r.status_code}"
    except Exception as e:
        return f"Fetch error: {e}"


async def cve_lookup(
    product: str = "",
    version: str = "",
    cve_id: str = "",
) -> str:
    """Look up CVEs for AI products — checks local DB and OSV.dev."""
    results: list[str] = []

    # Local DB first
    local = _local_lookup(product, version)
    if local:
        results.append(f"Known CVEs for {product}:")
        for c in local:
            results.append(
                f"  {c['cve']}: {c['title']} (CVSS: {c['cvss']}, Severity: {c['severity']})"
                f"\n    Affected: {c['affected_versions']}"
                f"\n    {c['description']}"
            )

    # Try OSV.dev for additional CVEs
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            payload = {}
            if cve_id:
                payload = {"query": cve_id}
            else:
                payload = {"query": product}
            r = await client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": product, "ecosystem": "PyPI"}} if not cve_id else {"query": cve_id},
            )
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulns", [])
                if vulns:
                    results.append(f"\nOSV.dev results ({len(vulns)}):")
                    for v in vulns[:5]:
                        results.append(
                            f"  {v.get('id', 'N/A')}: {v.get('summary', 'No summary')}"
                        )
    except Exception:
        pass  # OSV.dev lookup is best-effort

    if not results:
        return f"No known CVEs found for {product} {version}."
    return "\n".join(results)
