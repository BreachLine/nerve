"""Vector database tools — query, list, and test vector DBs."""

from __future__ import annotations

import json

import httpx
import structlog

from nerve.utils.rate_limiter import RateLimiter

logger = structlog.get_logger()


async def vector_list_collections(
    db_type: str = "qdrant",
    url: str = "",
    api_key: str = "",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """List collections/indices in a vector database."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {}
    if api_key:
        headers["api-key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            if db_type == "qdrant":
                r = await client.get(f"{url.rstrip('/')}/collections", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    collections = data.get("result", {}).get("collections", [])
                    lines = [f"Qdrant — {len(collections)} collection(s):"]
                    for c in collections:
                        lines.append(f"  - {c.get('name', 'unknown')}")
                    if not api_key:
                        lines.append("  WARNING: Accessed WITHOUT authentication!")
                    return "\n".join(lines)
                return f"ERROR: Status {r.status_code}\nBody: {r.text[:500]}"

            elif db_type == "weaviate":
                r = await client.get(f"{url.rstrip('/')}/v1/schema", headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    classes = data.get("classes", [])
                    lines = [f"Weaviate — {len(classes)} class(es):"]
                    for c in classes:
                        lines.append(f"  - {c.get('class', 'unknown')}")
                    if not api_key:
                        lines.append("  WARNING: Accessed WITHOUT authentication!")
                    return "\n".join(lines)
                return f"ERROR: Status {r.status_code}"

            return f"Unsupported vector DB type: {db_type}"
    except Exception as e:
        return f"ERROR: {e}"


async def vector_search(
    db_type: str = "qdrant",
    url: str = "",
    api_key: str = "",
    collection: str = "",
    query_text: str = "",
    limit: int = 5,
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Query a vector database with text — tests access controls."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["api-key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            if db_type == "qdrant":
                # Scroll endpoint (no vector needed, tests raw data access)
                r = await client.post(
                    f"{url.rstrip('/')}/collections/{collection}/points/scroll",
                    json={"limit": limit, "with_payload": True},
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    points = data.get("result", {}).get("points", [])
                    lines = [f"Qdrant scroll — {len(points)} point(s) from '{collection}':"]
                    for p in points[:5]:
                        payload = json.dumps(p.get("payload", {}))[:200]
                        lines.append(f"  ID: {p.get('id')} — {payload}")
                    if not api_key:
                        lines.append("  WARNING: Data accessed WITHOUT authentication!")
                    return "\n".join(lines)
                return f"ERROR: Status {r.status_code}\nBody: {r.text[:500]}"

            return f"Unsupported: {db_type}"
    except Exception as e:
        return f"ERROR: {e}"


async def vector_insert(
    db_type: str = "qdrant",
    url: str = "",
    api_key: str = "",
    collection: str = "",
    text: str = "",
    metadata: str = "{}",
    timeout: float = 10.0,
    rate_limiter: RateLimiter | None = None,
) -> str:
    """Insert a test document into a vector DB — tests write access control."""
    if rate_limiter:
        await rate_limiter.acquire()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["api-key"] = api_key

    try:
        meta = json.loads(metadata) if metadata else {}
    except json.JSONDecodeError:
        meta = {}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            if db_type == "qdrant":
                # Try to create a point with a dummy vector
                import random

                dummy_vector = [random.random() for _ in range(384)]  # noqa: S311
                payload = {
                    "points": [
                        {
                            "id": random.randint(900000, 999999),  # noqa: S311
                            "vector": dummy_vector,
                            "payload": {"text": text, "nerve_test": True, **meta},
                        }
                    ]
                }
                r = await client.put(
                    f"{url.rstrip('/')}/collections/{collection}/points",
                    json=payload,
                    headers=headers,
                )
                if r.status_code == 200:
                    return (
                        f"WRITE ACCESS CONFIRMED on Qdrant collection '{collection}'\n"
                        f"Inserted test point with payload: {text[:100]}\n"
                        f"Auth: {'with key' if api_key else 'WITHOUT AUTH — CRITICAL FINDING!'}"
                    )
                return f"Write rejected: Status {r.status_code}\nBody: {r.text[:500]}"

            return f"Unsupported: {db_type}"
    except Exception as e:
        return f"ERROR: {e}"
