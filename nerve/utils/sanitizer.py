"""Sanitize credentials from logs and reports."""

from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})"), "sk-***REDACTED***"),
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9\-_.]+"), r"\1***REDACTED***"),
    (re.compile(r"(api[_-]?key['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9\-_.]+"), r"\1***REDACTED***"),
    (re.compile(r"(password['\"]?\s*[:=]\s*['\"]?)[^\s'\"]+"), r"\1***REDACTED***"),
    (re.compile(r"(token['\"]?\s*[:=]\s*['\"]?)[a-zA-Z0-9\-_.]+"), r"\1***REDACTED***"),
]


def sanitize(text: str) -> str:
    """Remove credentials from text for safe logging/reporting."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
