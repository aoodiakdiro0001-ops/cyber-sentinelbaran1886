"""Command-line interface: scan · report · history · doctor · init."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List

from . import __project__, __version__, config, sast, secrets_scan, web, ports, ai, store, alert, report
from .models import ScanReport

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

BANNER = r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║   Cyber-SentinelBaran1886 — منظومة الفحص الأمني           ║
  ║   واختبار الاختراق والحماية الذاتية اللامركزية            ║
  ║   © 2026 Baran Avisat · MIT · zero paid tools             ║
  ╚═══════════════════════════════════════════════════════════╝
"""


def _engine_versions(report_obj: ScanReport) -> None:
    for name in ("nmap", "semgrep", "nuclei", "git"):
        binary = shutil.which(name)
        if not binary:
            continue
        try:
            if name == "nmap":
                out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15)
                first = (out.stdout or out.stderr).splitlines()[0]
            elif name == "nuclei":
                out = subprocess.run([binary, "-version"], capture_output=True, text=True, timeout=15)
                first = (out.stdout or out.stderr).splitlines()[0]
            else:
                out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15)
                first = (out.stdout or out.stderr).splitlines()[0]
            clean = ANSI_RE.sub("", first).strip()
            report_obj.engine_versions[name] = clean[:60]
        except (subprocess.SubprocessError, OSError, IndexError):
            report_obj.engine_versions[name] = "installed"


def _run_nuclei(target: str, report_obj: ScanReport) -> None:
    """Optional dynamic pass — only when nuclei is installed and target is a URL."""
    binary = shutil.which("nuclei")
    if not binary or not target.startswith(("http://", "https://")):
        return
    try:
        proc = subprocess.run(
            [binary, "-u", target, "-severity", "critical,high,medium",
             "-jsonl", "-silent", "-timeout", "10", "-retries", "1"],
            capture_output=True, text=True, timeout=600,
        )
    except (subprocess.SubprocessError, OSError):
        report_obj.errors.append("nuclei timed out — تم تجاوزه والانتقال إلى بقية الطبقات")
        return
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info", {})
        sev = str(info.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        from .models import Finding
        from .redact import redact
        name = str(info.get("name", item.get("template-id", "nuclei")))
        clean, _ = redact(f"{name} @ {item.get('matched-at', target)}")
        report_obj.add(Finding(
            rule_id=f"NUCLEI-{item.get('template-id', 'hit')}"[:90],
            title=clean[:160], severity=sev, category="web",
            location=str(item.get("matched-at", target))[:300],
            evidence=str(item.get("curl-command", ""))[:400],
            owasp="A06:2021 – Vulnerable and Outdated Components",
            remediation=str(info.get("description", ""))[:500] or
                        "راجع القالب المُكتشف وحدّث المكوّن المتأثر.",
        ))


def cmd_scan(args: argparse.Namespace) -> int:
    config.load_dotenv(args.env)
    targets: List[str] = []
    if args.target:
        targets.append(args.target)
    if args.targets_file:
        p = Path(args.targets_file)
        if p.is_file():
            targets += [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                        if ln.strip() and not ln.strip().startswith("#")]
    if not targets:
        targets = [t.strip() for t in config.get("SCAN_TARGETS", "").split(",") if t.strip()]
    if not targets:
        print("✖ لا يوجد هدف. استخدم --target أو --targets أو ضع SCAN_TARGETS في .env")
        return 2

    total = ScanReport(target=", ".join(targets)[:400], mode=args.mode)
    _engine_versions(total)

    for target in targets:
        print(f"\n🔎 {target}")
        if args.mode in ("all", "source") and (Path(target).exists() or args.mode == "source"):
            print("  ├─ فحص ساكن (SAST) …")
            total.extend(sast.scan(target, use_semgrep=not args.no_semgrep))
            print("  ├─ كشف الأسرار المكشوفة …")
            total.extend(secrets_scan.scan_paths([target]))
        if args.mode in ("all", "web") and target.startswith(("http://", "https://")):
            print("  ├─ تدقيق ترويسات الموقع والروابط …")
            total.extend(web.scan(target, follow_links=not args.no_links))
            print("  ├─ فحص المنافذ …")
            pf, engine = ports.scan(target.replace("https://", "").replace("http://", "").split("/")[0],
                                     engine="socket" if args.no_nmap else "auto")
            total.extend(pf)
            total.engine_versions["port-engine"] = engine
            if not args.no_nuclei:
                print("  └─ مسح Nuclei الديناميكي …")
                _run_nuclei(target, total)
        elif args.mode in ("all", "ports") and not target.startswith(("http://", "https://")):
            print("  └─ فحص المنافذ …")
            pf, engine = ports.scan(target, engine="socket" if args.no_nmap else "auto")
            total.extend(pf)

    total.finished_at = time.time()
    print("\n🤖 تحليل الذكاء الاصطناعي وتوليد الإصلاحات …")
    ai.enrich(total)
    total.sort()

    status = store.push(total)
    trend = store.trend()
    out = report.write(total, trend, out_dir=args.out)
    print(f"\n✅ {len(total.findings)} نتيجة · الدرجة {total.score()}/100 ({total.grade()}) · "
          f"التخزين: {status} · المحرّك الذكي: {total.ai_provider}")
    print(f"📊 تقرير HTML: {out}")
    print(f"📄 تقرير JSON: {Path(args.out) / 'report.json'}")

    if alert.notify(total):
        print("📨 تنبيه تليجرام أُرسل")
    elif config.telegram_cfg() is None:
        print("ℹ️  تنبيهات تليجرام غير مضبوطة (اختياري): اضبط TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID")

    if args.fail_on:
        worst = next((f.severity for f in total.findings if f.severity in ("critical", "high")), None)
        if worst in ("critical", "high"):
            print(f"✖ الإيقاف المحدد: وُجدت ثغرة {worst}")
            return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config.load_dotenv(args.env)
    src = Path(args.input)
    if not src.is_file():
        print(f"✖ العنصر غير موجود: {src}")
        return 2
    data = json.loads(src.read_text(encoding="utf-8"))
    rep = ScanReport.from_dict(data)
    out = report.write(rep, store.trend(), out_dir=args.out)
    print(f"📊 أُعيد بناء التقرير: {out}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    config.load_dotenv(args.env)
    rows = store.history(args.limit)
    if not rows:
        print("لا توجد سجلات بعد. نفّذ فحصاً واحداً أولاً.")
        return 0
    print(f"{'التاريخ':<21}{'الدرجة':>7}{'التصنيف':>8}  الهدف")
    for d in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(d.get("finished_at", 0)))
        print(f"{when:<21}{d.get('score', 0):>7}{d.get('grade', '-'):>8}  {d.get('target','')[:50]}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    loaded = config.load_dotenv(args.env)
    print(BANNER)
    print(f"📄 ملف البيئة: {'عُثر عليه وقُرئ (' + str(len(loaded)) + ' متغيّر)' if loaded else 'غير موجود — سيعمل الوضع المحلي فقط'}")
    for k, v in config.configured_summary().items():
        print(f"  {'✅' if v else '⚪'} {k}")
    print(f"\n  {'✅' if shutil.which('nmap') else '⚪'} nmap")
    print(f"  {'✅' if shutil.which('semgrep') else '⚪'} semgrep (اختياري)")
    print(f"  {'✅' if shutil.which('nuclei') else '⚪'} nuclei (اختياري)")
    print(f"  {'✅' if shutil.which('gh') else '⚪'} gh (اختياري — لتشغيل الفحص داخل Actions)")
    print("\nالقنوات:")
    print("  • AI:", ", ".join(k for k, v in config.configured_summary().items()
                             if k in ("gemini", "groq", "openrouter", "ollama") and v) or "المحرّك المحلي (بلا مفاتيح)")
    print("  • Supabase:", "متصل" if config.supabase_cfg() else "محلي (reports/*.json)")
    print("  • Telegram:", json.dumps(alert.doctor(), ensure_ascii=False))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    env = Path(args.env)
    if env.exists():
        print(f"ℹ️ {env} موجود — لم أعدّله")
    else:
        shutil.copy(Path(".env.example"), env)
        print(f"✍️  أنشأ {env} من .env.example — ضع مفاتيحك فيه (لن يُرفع إلى Git)")
    Path("reports").mkdir(exist_ok=True)
    print("✅ جاهز. الخطوة التالية:")
    print(f"   python3 -m sentinel scan --target {args.target or 'https://example.com'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{__project__} v{__version__} — فحص أمني مجاني بالكامل",
    )
    p.add_argument("--env", default=".env", help="ملف البيئة (افتراضي .env)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="تنفيذ فحص كامل")
    s.add_argument("--target", help="رابط / مسار مجلد / اسم مضيف")
    s.add_argument("--targets", dest="targets_file", help="ملف أهداف، هدف في كل سطر")
    s.add_argument("--mode", choices=["all", "source", "web", "ports"], default="all")
    s.add_argument("--out", default="reports", help="مجلد إخراج التقارير")
    s.add_argument("--fail-on", action="store_true", help="إرجاع رمز 1 عند وجود ثغرة حرجة/عالية")
    s.add_argument("--no-semgrep", action="store_true")
    s.add_argument("--no-nuclei", action="store_true")
    s.add_argument("--no-nmap", action="store_true")
    s.add_argument("--no-links", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="إعادة بناء تقرير HTML من JSON")
    r.add_argument("--input", default="reports/report.json")
    r.add_argument("--out", default="reports")
    r.set_defaults(func=cmd_report)

    h = sub.add_parser("history", help="عرض سجل الفحوصات")
    h.add_argument("--limit", type=int, default=20)
    h.set_defaults(func=cmd_history)

    d = sub.add_parser("doctor", help="تشغيل وتشخيص الربط")
    d.set_defaults(func=cmd_doctor)

    i = sub.add_parser("init", help="تهيئة ملف البيئة والمجلدات")
    i.add_argument("--target", help="الهدف الافتراضي")
    i.set_defaults(func=cmd_init)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd != "doctor":
        print(BANNER)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n⏹ أُوقف الفحص")
        return 130


if __name__ == "__main__":
    sys.exit(main())
