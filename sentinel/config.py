"""Configuration loader: .env file (stdlib parser) + process environment."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

# Keys the user must fill in .env — every one of them has a free tier.
OPTIONAL_KEYS = [
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "OLLAMA_URL",
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_ANON_KEY",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "SCAN_TARGETS",
    "GITHUB_TOKEN",
]


def load_dotenv(path: str = ".env") -> Dict[str, str]:
    """Tiny dependency-free .env reader. Existing env vars always win."""
    p = Path(path)
    if not p.is_file():
        return {}
    out: Dict[str, str] = {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        out[key] = value
        os.environ.setdefault(key, value)
    return out


def get(key: str, default: str = "") -> str:
    return os.environ.get(key, default) or default


def has(key: str) -> bool:
    return bool(os.environ.get(key))


def supabase_cfg() -> Optional[Dict[str, str]]:
    url = get("SUPABASE_URL")
    key = get("SUPABASE_SERVICE_ROLE_KEY") or get("SUPABASE_ANON_KEY")
    if url and key:
        return {"url": url.rstrip("/"), "key": key}
    return None


def telegram_cfg() -> Optional[Dict[str, str]]:
    token = get("TELEGRAM_BOT_TOKEN")
    chat = get("TELEGRAM_CHAT_ID")
    if token and chat:
        return {"token": token, "chat_id": chat}
    return None


def configured_summary() -> Dict[str, bool]:
    """What is wired up right now — printed by `sentinel doctor`."""
    return {
        "gemini": has("GEMINI_API_KEY"),
        "groq": has("GROQ_API_KEY"),
        "openrouter": has("OPENROUTER_API_KEY"),
        "ollama": has("OLLAMA_URL"),
        "supabase": supabase_cfg() is not None,
        "telegram": telegram_cfg() is not None,
        "targets": bool(get("SCAN_TARGETS")),
    }
