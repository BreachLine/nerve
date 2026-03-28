"""Sanitize credentials from logs and reports."""

from __future__ import annotations

import re

_PATTERNS = [
    # Anthropic keys: sk-ant-api03-... (must precede generic sk- pattern)
    (re.compile(r"(sk-ant-[a-zA-Z0-9\-]{20,})"), "sk-ant-***REDACTED***"),
    # OpenAI project keys: sk-proj-...
    (re.compile(r"(sk-proj-[a-zA-Z0-9\-_]{20,})"), "sk-proj-***REDACTED***"),
    # OpenAI keys: sk-...
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})"), "sk-***REDACTED***"),
    # Bearer tokens
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9\-_.]+"), r"\1***REDACTED***"),
    # API key assignments in config/logs
    (re.compile(r"(api[_-]?key['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9\-_.]+"), r"\1***REDACTED***"),
    # Password assignments
    (re.compile(r"(password['\"]?\s*[:=]\s*['\"]?)[^\s'\"]+"), r"\1***REDACTED***"),
    # Token assignments
    (re.compile(r"(token['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9\-_.]+"), r"\1***REDACTED***"),
    # Database connection strings with credentials: proto://user:pass@host
    (re.compile(r"(://\w+:)[^@]+(@)"), r"\1***REDACTED***\2"),
    # Google API keys
    (re.compile(r"(AIzaSy[a-zA-Z0-9\-_]{33})"), "AIzaSy***REDACTED***"),
    # x-api-key header values
    (
        re.compile(r"(x-api-key['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9\-_.]+", re.IGNORECASE),
        r"\1***REDACTED***",
    ),
]


def sanitize(text: str) -> str:
    """Remove credentials from text for safe logging/reporting."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
