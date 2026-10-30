"""Layer 4 — Instant delivery (Telegram Bot API) and CI annotations.

Nothing is sent unless TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID are configured.
Critical findings alert immediately; the rest are summarised once per scan.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List

from . import config
from .models import ScanReport
from .redact import redact

SEV_EMOJI = {"critical": "🚨", "high": "⚠️", "medium": "🟡", "low": "🔵", "info": "ℹ️"}


def _send(text: str) -> bool:
    cfg = config.telegram_cfg()
    if not cfg:
        return False
    payload = urllib.parse.urlencode({
        "chat_id": cfg["chat_id"],
        "text": text[:4000],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    url = f"https://api.telegram.org/bot{cfg['token']}/sendMessage"
    req = urllib.request.Request(url, data=payload, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _finding_block(f) -> str:
    clean, _ = redact(f"{f.title}\n📁 {f.location}\n🔎 {f.evidence or '—'}")
    fix = f"\n🛠️ الإصلاح المقترح: {f.remediation}" if f.remediation else ""
    ai = f"\n🤖 تصحيح ذكي:\n<code>{f.ai_fix[:700]}</code>" if f.ai_fix else ""
    return (f"{SEV_EMOJI.get(f.severity, '•')} <b>{f.title}</b>\n"
            f"<code>{f.location}</code>\n"
            f"🔎 {clean.split(chr(10), 1)[-1][:400]}\n"
            f"📐 {f.owasp}{fix}{ai}")


def notify(report: ScanReport, max_detail: int = 3) -> bool:
    counts = report.counts()
    crit = [f for f in report.findings if f.severity == "critical"]
    high = [f for f in report.findings if f.severity == "high"]

    head = (f"<b>🛡️ تقرير {report.target}</b>\n"
            f"الدرجة: <b>{report.score()}/100</b> (التصنيف {report.grade()})\n"
            f"حرجة: {counts['critical']} · عالية: {counts['high']} · "
            f"متوسطة: {counts['medium']} · منخفضة: {counts['low']} · معلوماتية: {counts['info']}\n"
            f"المحركات: {', '.join(f'{k} {v}' for k, v in report.engine_versions.items()) or 'محلي'}\n"
            f"الذكاء الاصطناعي: {report.ai_provider}")

    body = ""
    urgent = crit or high
    for f in urgent[:max_detail]:
        body += "\n\n" + _finding_block(f)
    if not urgent:
        body = "\n\n✅ لم تُكتشف ثغرات حرجة أو عالية الخطورة في هذه الجولة."

    overflow = len(urgent) - max_detail
    if overflow > 0:
        body += f"\n\n… و{overflow} إضافية موجودة في التقرير الكامل."

    ok = _send(head + body)

    if report.errors:
        _send("⚠️ <b>ملاحظات تشغيل</b>\n" + redact("\n".join(report.errors)[:900])[0])
    return ok


def doctor() -> Dict[str, object]:
    """Reachability check for the alert channel (used by `sentinel doctor`)."""
    cfg = config.telegram_cfg()
    if not cfg:
        return {"configured": False, "reason": "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID غير مضبوطين"}
    url = f"https://api.telegram.org/bot{cfg['token']}/getMe"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if data.get("ok"):
            return {"configured": True, "bot": data["result"].get("username"),
                    "chat_id": cfg["chat_id"], "reachable": True}
        return {"configured": True, "reachable": False, "reason": data.get("description")}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"configured": True, "reachable": False, "reason": str(exc)}
