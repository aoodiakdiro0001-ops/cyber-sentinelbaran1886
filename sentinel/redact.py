"""Mandatory redaction: no secret value ever reaches a report, a log or an alert."""

from __future__ import annotations

import re
from typing import Tuple

_MASK = "•" * 6

PATTERNS = [
    ("aws-access-key", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("openai-style", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("stripe", re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("supabase-key", re.compile(r"\bsb_secret_[A-Za-z0-9_\-]{20,}\b|\bsbp_[A-Za-z0-9_\-]{20,}\b")),
    ("telegram-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("generic-secret", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
        r"\s*[:=]\s*[\"']?([^\s\"',;]{8,})")),
]


def mask_value(value: str) -> str:
    """Show enough to recognise a secret, never enough to replay it."""
    if len(value) <= 6:
        return _MASK
    return f"{value[:4]}…{_MASK}({len(value)})"


def redact(text: str) -> Tuple[str, int]:
    """Replace every recognised secret in `text`. Returns (clean_text, hits)."""
    if not text:
        return "", 0
    hits = 0
    out = text
    for _, rx in PATTERNS:
        def _sub(m: "re.Match[str]") -> str:
            nonlocal hits
            hits += 1
            g = m.group(0)
            if m.lastindex:
                return m.group(0).replace(m.group(m.lastindex), mask_value(m.group(m.lastindex)))
            return mask_value(g)

        out = rx.sub(_sub, out)
    return out, hits


def contains_secret(text: str) -> bool:
    return redact(text)[1] > 0
