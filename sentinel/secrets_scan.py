"""Layer 1b — Secret exposure scan (git-tracked files, env files, configs).

Every captured value is masked by sentinel.redact before it can reach a report.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .models import Finding
from .redact import PATTERNS, redact

SCAN_EXT = {
    "", ".env", ".example", ".sample", ".template", ".yml", ".yaml", ".json",
    ".toml", ".ini", ".cfg", ".conf", ".sh", ".py", ".js", ".ts", ".tsx",
    ".md", ".txt", ".properties", ".tf", ".tfvars",
}
NAMES = {".env", ".env.local", ".env.production", "credentials", "id_rsa", "secrets.json"}

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next", "__pycache__", ".venv", "reports"}
MAX_BYTES = 600_000

ALLOWLIST = re.compile(r"(?i)(example|sample|template|placeholder|your[_-]?(key|token|secret|password)|xxx+|change[_-]?me)")


def scan_paths(paths: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file()
            and not any(part in SKIP_DIRS or part.startswith(".") and part != ".env" for part in p.parts)
            and (p.suffix.lower() in SCAN_EXT or p.name in NAMES or p.name.startswith(".env"))
        ]
        for f in candidates[:2000]:
            try:
                if f.is_file() and f.stat().st_size > MAX_BYTES:
                    continue
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = _rel(f, root)
            for label, rx in PATTERNS:
                for idx, line in enumerate(text.splitlines(), start=1):
                    if len(line) > 2000:
                        continue
                    m = rx.search(line)
                    if not m:
                        continue
                    if ALLOWLIST.search(line) and label == "generic-secret":
                        continue
                    key = (label, rel, idx)
                    if key in seen:
                        continue
                    seen.add(key)
                    clean, _ = redact(line.strip()[:240])
                    findings.append(Finding(
                        rule_id=f"SECRET-{label.upper()}",
                        title=f"سر مكشوف في ملف: {rel}",
                        severity="critical" if label in (
                            "private-key", "github-token", "aws-access-key",
                            "openai-style", "huggingface", "supabase-key") else "high",
                        category="secrets",
                        location=f"{rel}:{idx}",
                        evidence=clean,
                        owasp="A07:2021 – Identification and Authentication Failures",
                        remediation="احذف القيمة من المستودع، انقلها إلى متغيّر بيئة أو مستودع أسرار، "
                                    "ثم غيّر المفتاح فوراً لأن تاريخ Git يحتفظ بالنسخة القديمة.",
                    ))
                    if len(findings) >= 300:
                        return findings
    return findings


def _rel(f: Path, root: Path) -> str:
    try:
        if root.is_file():
            return root.name
        return str(f.relative_to(root))
    except ValueError:
        return str(f)


def git_tracked_and_env(repo_path: str) -> List[Finding]:
    """Scan what is actually committed plus local env files."""
    root = Path(repo_path)
    paths = [str(root)]
    return scan_paths(paths)
