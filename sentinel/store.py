"""Layer 3 — Persistence (Supabase PostgreSQL free tier) + local history.

All rows are written server-side with the service-role key; nothing is ever
embedded in the browser. Local JSON history keeps working with zero config.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

from . import config
from .models import ScanReport
from .redact import redact

HISTORY_DIR = Path("reports")


def _request(cfg: Dict[str, str], path: str, payload: Dict, method: str = "POST") -> tuple:
    url = f"{cfg['url']}/rest/v1/{path}"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method=method,
        headers={
            "Content-Type": "application/json",
            "apikey": cfg["key"],
            "Authorization": f"Bearer {cfg['key']}",
            "Prefer": "return=representation,resolution=merge-duplicates",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", "replace")
        return resp.status, (json.loads(body) if body.strip() else [])


def _redact_obj(obj):
    """Walk the structure and mask secrets inside every string value.

    Redacting the serialised JSON directly would corrupt it (a masked token can
    contain quotes/backslashes), so we clean the data before encoding.
    """
    if isinstance(obj, str):
        return redact(obj)[0]
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj


def push(report: ScanReport) -> str:
    """Persist the scan + findings. Returns status: 'supabase' | 'local' | 'skipped'."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    payload = _redact_obj(report.to_dict())

    (HISTORY_DIR / f"{int(time.time())}-{report.scan_id[:8]}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (HISTORY_DIR / "latest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    cfg = config.supabase_cfg()
    if not cfg:
        return "local"

    try:
        _request(cfg, "scans", {
            "scan_id": payload["scan_id"],
            "target": payload["target"][:500],
            "mode": payload["mode"],
            "score": payload["score"],
            "grade": payload["grade"],
            "counts": payload["counts"],
            "ai_provider": payload["ai_provider"],
            "engine_versions": payload["engine_versions"],
            "findings_count": len(payload["findings"]),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        rows = [{
            "scan_id": payload["scan_id"],
            "rule_id": f.get("rule_id", "")[:200],
            "key": f.get("key", ""),
            "title": (f.get("title") or "")[:400],
            "severity": f.get("severity", "info"),
            "category": f.get("category", "sast"),
            "location": (f.get("location") or "")[:500],
            "evidence": (f.get("evidence") or "")[:2000],
            "owasp": (f.get("owasp") or "")[:120],
            "remediation": (f.get("remediation") or "")[:2000],
            "ai_fix": (f.get("ai_fix") or "")[:4000],
            "cvss": f.get("cvss", 0.0),
        } for f in payload["findings"][:1000]]
        if rows:
            _request(cfg, "findings", rows)
        return "supabase"
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        report.errors.append(f"supabase push failed (local copy kept): {exc}")
        return "local"


def history(limit: int = 20) -> List[Dict]:
    """Past scans from the local history folder — for trending over time."""
    if not HISTORY_DIR.is_dir():
        return []
    out: List[Dict] = []
    for p in sorted(HISTORY_DIR.glob("*.json"), reverse=True):
        if p.name == "latest.json":
            continue
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
        if len(out) >= limit:
            break
    return out


def trend() -> Optional[Dict]:
    """Score of the last scans — used by the dashboard sparkline."""
    past = history(12)
    if not past:
        return None
    series = [{"t": d.get("finished_at", 0), "score": d.get("score", 0),
               "target": d.get("target", "")} for d in reversed(past)]
    return {"series": series, "delta": (series[-1]["score"] - series[0]["score"]) if len(series) > 1 else 0}
