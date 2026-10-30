"""Layer 4 — Report renderer: self-contained RTL Arabic HTML dashboard.

No CDN, no tracking, no external fonts — the file opens offline and can be
shared as an artifact or dropped straight into a GitHub Actions upload.
"""

from __future__ import annotations

import html
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional

from .models import ScanReport
from .redact import redact

# نزّل رموز الألوان (ANSI) التي قد تحملها نسخ الأدوات مثل nuclei
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

SEV_COLORS = {
    "critical": "#ff4d6d",
    "high": "#ff922b",
    "medium": "#f7c948",
    "low": "#4dabf7",
    "info": "#868e96",
}
SEV_LABEL = {
    "critical": "حرجة", "high": "عالية", "medium": "متوسطة",
    "low": "منخفضة", "info": "معلوماتية",
}

SUPPORT = {
    "email": "baranavisat@gmail.com",
    "phone": "+90 531 326 3722",
    "store": "https://baranavi.gumroad.com/",
    "ibtry": "TR10 0001 0090 1008 4013 0050 01",
    "ibusd": "TR80 0001 0090 1008 4013 0050 02",
    "owner": "Baran Avisat",
}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _ring(score: int) -> str:
    import math
    r, c, size = 66, 140, 100
    frac = max(0, min(100, score)) / 100.0
    circ = 2 * math.pi * r
    dash = circ * frac
    color = "#3ddc84" if score < 15 else ("#f7c948" if score < 55 else "#ff4d6d")
    return (
        f'<svg viewBox="0 0 {size} {size}" class="ring" role="img" aria-label="درجة {score}">'
        f'<circle cx="{c}" cy="{c}" r="{r}" class="ring-bg"/>'
        f'<circle cx="{c}" cy="{c}" r="{r}" class="ring-fg" '
        f'stroke="{color}" stroke-dasharray="{dash:.1f} {circ - dash:.1f}" '
        f'transform="rotate(-90 {c} {c})"/>'
        f'<text x="{c}" y="{c - 4}" class="ring-num" text-anchor="middle">{score}</text>'
        f'<text x="{c}" y="{c + 22}" class="ring-cap" text-anchor="middle">/100</text>'
        f"</svg>"
    )


def _bars(counts: Dict[str, int]) -> str:
    peak = max(list(counts.values()) + [1])
    out = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        pct = int(round(100.0 * n / peak)) if peak else 0
        out.append(
            f'<div class="bar-row" data-sev="{sev}">'
            f'<span class="bar-label" style="color:{SEV_COLORS[sev]}">{SEV_LABEL[sev]}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%;'
            f'background:{SEV_COLORS[sev]}"></span></span>'
            f'<span class="bar-n">{n}</span></div>')
    return "".join(out)


def _rows(report: ScanReport) -> str:
    rows = []
    for f in report.findings:
        ev, _ = redact(f.evidence or "")
        fix = f.ai_fix or ""
        rows.append(
            f'<tr data-sev="{_esc(f.severity)}" data-cat="{_esc(f.category)}">'
            f'<td><span class="pill" style="--c:{SEV_COLORS[f.severity]}">{SEV_LABEL.get(f.severity, f.severity)}</span></td>'
            f'<td><div class="ftitle">{_esc(f.title)}</div>'
            f'<div class="fmeta"><code>{_esc(f.location)}</code> · {_esc(f.rule_id)} · {_esc(f.category)}</div></td>'
            f'<td>{_esc(f.owasp)}</td>'
            f'<td><div class="ev">{_esc(ev[:260])}</div>'
            f'<div class="rem">{_esc(f.remediation)}</div>'
            + (f'<pre class="fix">{_esc(fix[:900])}</pre>' if fix else "") +
            f"</td></tr>")
    if not rows:
        return '<tr><td colspan="4" class="empty">✅ لم يعثر المحرّك على أي ثغرة — الموقع مُحصّن.</td></tr>'
    return "".join(rows)


def _history_block(trend: Optional[Dict]) -> str:
    if not trend or len(trend.get("series", [])) < 2:
        return '<div class="hist"><span class="muted">لا توجد عمليات سابقة للمقارنة بعد — الشجرة تبدأ من هذه الجولة.</span></div>'
    pts = trend["series"]
    w, h = 520, 90
    mx = max(max(p["score"] for p in pts), 1)
    coords = []
    for i, p in enumerate(pts):
        x = 10 + (w - 20) * i / max(1, len(pts) - 1)
        y = h - 14 - (h - 30) * p["score"] / mx
        coords.append(f"{x:.1f},{y:.1f}")
    delta = trend.get("delta", 0)
    cls = "down" if delta > 0 else "up"
    arrow = "▲" if delta > 0 else "▼"
    return (
        f'<div class="hist"><div class="hist-head"><b>تطوّر الدرجة عبر الزمن</b>'
        f'<span class="delta {cls}">{arrow} {abs(delta)} نقطة</span></div>'
        f'<svg viewBox="0 0 {w} {h}" class="spark"><polyline points="{" ".join(coords)}" '
        f'fill="none" stroke="#4dabf7" stroke-width="2.5"/></svg>'
        f'<div class="muted">أقدم ← الأحدث · {len(pts)} جولات محفوظة</div></div>')


def render(report: ScanReport, trend: Optional[Dict] = None) -> str:
    d = report.to_dict()
    counts = d["counts"]
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(d["finished_at"] or time.time()))
    engines = ", ".join(f"{k} {_ANSI.sub('', str(v)).strip()}" for k, v in d["engine_versions"].items()) or "المحرّك المدمج"
    total = sum(counts.values())

    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تقرير فحص أمني — {_esc(d["target"])}</title>
<style>
:root{{--bg:#070b14;--panel:#0e1524;--line:#1d2740;--fg:#e8edf7;--muted:#8b97b3;--accent:#3ddc84}}
*{{box-sizing:border-box}}
body{{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#16233f 0%,var(--bg) 60%);
color:var(--fg);font:15px/1.7 -apple-system,"Segoe UI",Tahoma,"Noto Sans Arabic",sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:34px 22px 70px}}
header.top{{display:flex;flex-wrap:wrap;gap:26px;align-items:center;justify-content:space-between;
border:1px solid var(--line);background:linear-gradient(180deg,#111a2e,#0b111f);border-radius:18px;padding:26px 28px}}
.brand h1{{margin:0;font-size:25px;letter-spacing:-.3px}}
.brand .sub{{color:var(--muted);font-size:13.5px;margin-top:6px}}
.brand .badge{{display:inline-block;margin-top:12px;padding:5px 12px;border-radius:999px;
background:#132a1f;border:1px solid #1f4d38;color:#8ef0bd;font-size:12.5px}}
.ring{{width:150px;height:150px}}
.ring-bg{{fill:none;stroke:#1d2740;stroke-width:14}}
.ring-fg{{fill:none;stroke-width:14;stroke-linecap:round}}
.ring-num{{font:700 40px/1 -apple-system,sans-serif;fill:#fff}}
.ring-cap{{font:400 14px/1 sans-serif;fill:#8b97b3}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:22px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px}}
.card .k{{font-size:12.5px;color:var(--muted)}}
.card .v{{font-size:27px;font-weight:700;margin-top:4px}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-bottom:20px}}
h2{{margin:0 0 14px;font-size:17px}}
.bar-row{{display:grid;grid-template-columns:78px 1fr 46px;gap:10px;align-items:center;margin:9px 0;font-size:13.5px}}
.bar-track{{background:#141d31;border-radius:6px;height:11px;overflow:hidden}}
.bar-fill{{display:block;height:100%;border-radius:6px}}
.bar-n{{text-align:left;font-variant-numeric:tabular-nums;color:var(--muted)}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:right;padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-size:12.5px;font-weight:600;position:sticky;top:0;background:#0e1524}}
.pill{{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;
background:color-mix(in srgb,var(--c) 18%,transparent);color:var(--c);
border:1px solid color-mix(in srgb,var(--c) 45%,transparent);white-space:nowrap}}
.ftitle{{font-weight:600}}
.fmeta{{color:var(--muted);font-size:12px;margin-top:3px}}
.fmeta code{{background:#141d31;padding:1px 6px;border-radius:5px}}
.ev{{color:#c3cee6;font-size:13px;word-break:break-word}}
.rem{{color:#9fe8c2;font-size:13px;margin-top:6px}}
pre.fix{{background:#0a1120;border:1px solid #1d2740;border-radius:10px;padding:10px 12px;
direction:ltr;text-align:left;overflow:auto;font-size:12.5px;color:#a5d6ff;margin:8px 0 0;white-space:pre-wrap}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
.filters button{{background:#141d31;color:var(--fg);border:1px solid var(--line);
border-radius:999px;padding:6px 14px;font-size:13px;cursor:pointer}}
.filters button:hover{{border-color:#3a4a72}}
.filters button.on{{background:#1c2b4d;border-color:#4d6df0}}
.hist-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.delta{{font-size:13px;font-weight:700}}
.delta.up{{color:#3ddc84}}.delta.down{{color:#ff4d6d}}
.spark{{width:100%;height:110px}}
.muted{{color:var(--muted);font-size:13px}}
.empty{{color:#9fe8c2;text-align:center;padding:26px}}
footer{{border-top:1px solid var(--line);padding-top:18px;margin-top:26px;color:var(--muted);font-size:13px;
display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between}}
footer b{{color:#e8edf7}}
.toc{{display:flex;gap:8px;flex-wrap:wrap;font-size:13px;color:var(--muted)}}
.toc span{{background:#141d31;border:1px solid var(--line);border-radius:8px;padding:4px 10px}}
@media(max-width:720px){{.ring{{width:118px;height:118px}} header.top{{padding:20px}} .ev,td{{font-size:13px}}}}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div class="brand">
    <h1>🛡️ Cyber-SentinelBaran1886</h1>
    <div class="sub">تقرير فحص أمني آلي — {_esc(d["target"])}</div>
    <div class="badge">التصنيف العام: {d["grade"]} · {total} نتيجة · {d["ai_provider"] if d["ai_enabled"] else "محرّك محلي"}</div>
    <div class="toc" style="margin-top:12px">
      <span>🕐 {generated}</span><span>⏱ {d["duration_sec"]} ثانية</span>
      <span>⚙️ {_esc(engines)}</span><span>🆔 {_esc(d["scan_id"][:12])}</span>
    </div>
  </div>
  {_ring(d["score"])}
</header>

<div class="grid">
  <div class="card"><div class="k">ثغرات حرجة</div><div class="v" style="color:{SEV_COLORS['critical']}">{counts['critical']}</div></div>
  <div class="card"><div class="k">عالية الخطورة</div><div class="v" style="color:{SEV_COLORS['high']}">{counts['high']}</div></div>
  <div class="card"><div class="k">متوسطة</div><div class="v" style="color:{SEV_COLORS['medium']}">{counts['medium']}</div></div>
  <div class="card"><div class="k">منخفضة</div><div class="v" style="color:{SEV_COLORS['low']}">{counts['low']}</div></div>
  <div class="card"><div class="k">معلوماتية</div><div class="v" style="color:{SEV_COLORS['info']}">{counts['info']}</div></div>
</div>

<div class="panel">
  <h2>توزيع الخطورة</h2>
  {_bars(counts)}
  {_history_block(trend)}
</div>

<div class="panel">
  <h2>سجل النتائج ({total})</h2>
  <div class="filters" id="filters">
    <button class="on" data-f="all">الكل</button>
    <button data-f="critical">حرجة</button>
    <button data-f="high">عالية</button>
    <button data-f="medium">متوسطة</button>
    <button data-f="low">منخفضة</button>
    <button data-f="info">معلوماتية</button>
  </div>
  <div style="overflow-x:auto;max-height:640px;overflow-y:auto">
  <table>
    <thead><tr><th style="width:104px">الخطورة</th><th>الثغرة والموقع</th><th style="width:170px">OWASP</th><th style="width:38%">الدليل والإصلاح</th></tr></thead>
    <tbody id="rows">{_rows(report)}</tbody>
  </table>
  </div>
</div>

<footer>
  <div>
    <b>الملكية:</b> © 2026 {SUPPORT['owner']} — ترخيص MIT · جميع الحقوق محفوظة<br>
    <b>الدعم الفني:</b> {SUPPORT['email']} · {SUPPORT['phone']} · <a style="color:#4dabf7" href="{SUPPORT['store']}">{SUPPORT['store']}</a>
  </div>
  <div style="text-align:left">
    <b>الدفع (اختياري):</b><br>
    ليرة TR — {SUPPORT['ibtry']}<br>
    دولار TR — {SUPPORT['ibusd']}
  </div>
</footer>

<div class="muted" style="margin-top:14px">
  كل الأسرار مُقنّعة تلقائياً قبل دخول هذا التقرير. الفحص نُفِّذ على أهداف استهدفها صاحب المستودع حصراً.
</div>

</div>
<script>
(function(){{
  var box=document.getElementById('filters');
  if(!box)return;
  box.addEventListener('click',function(e){{
    var b=e.target.closest('button'); if(!b)return;
    [].forEach.call(box.children,function(x){{x.classList.remove('on')}});
    b.classList.add('on');
    var f=b.getAttribute('data-f');
    [].forEach.call(document.querySelectorAll('#rows tr'),function(tr){{
      tr.style.display=(f==='all'||tr.getAttribute('data-sev')===f)?'':'none';
    }});
  }});
}})();
</script>
</body>
</html>"""


def write(report: ScanReport, trend: Optional[Dict] = None, out_dir: str = "reports") -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "report.html"
    html_path.write_text(render(report, trend), encoding="utf-8")
    (out / "report.json").write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return html_path
