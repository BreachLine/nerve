"""Intelligence tools — web search, CVE lookup for live research during scans."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.knowledge.cve_db import lookup_cves as _local_lookup

logger = structlog.get_logger()


async def web_search(query: str = "", max_results: int = 5) -> str:
    """Search the web using DuckDuckGo JSON API — returns titles, URLs, snippets."""
    import re

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            # Use DuckDuckGo HTML search and parse results
            r = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    ),
                },
            )
            if r.status_code == 200:
                text = r.text
                results: list[str] = [f"Web search results for: {query}"]
                # Parse result blocks from DuckDuckGo HTML
                result_blocks = re.findall(
                    r'<a[^>]+class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?'
                    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
                    text,
                    re.DOTALL,
                )
                count = 0
                for href, title, snippet in result_blocks:
                    # Clean HTML tags from title and snippet
                    clean_title = re.sub(r"<[^>]+>", "", title).strip()
                    clean_snippet = re.sub(r"<[^>]+>", "", snippet).strip()
                    # DuckDuckGo wraps actual URLs in redirect URLs
                    actual_url = href
                    url_match = re.search(r"uddg=([^&]+)", href)
                    if url_match:
                        from urllib.parse import unquote
                        actual_url = unquote(url_match.group(1))
                    if clean_title:
                        results.append(f"  [{count + 1}] {clean_title}")
                        results.append(f"      URL: {actual_url}")
                        if clean_snippet:
                            results.append(f"      {clean_snippet[:200]}")
                        count += 1
                        if count >= max_results:
                            break
                if count == 0:
                    results.append("  No results found from HTML parsing.")
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
