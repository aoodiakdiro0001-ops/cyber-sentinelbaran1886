"""Layer 1a — Static application security testing (SAST).

Built-in OWASP-aligned rule engine (zero dependencies) plus an optional
Semgrep pass when the binary is available on PATH.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from .config import ignore_rules, is_ignored
from .models import Finding
from .redact import redact

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", "__pycache__",
    ".venv", "venv", "env", ".terraform", "coverage", ".cache", "out", "target",
    ".idea", ".vscode", "logs", "reports",
}

CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".go", ".java", ".cs",
    ".cpp", ".c", ".h", ".rs", ".sh", ".bash", ".yaml", ".yml", ".json", ".env",
    ".toml", ".ini", ".cfg", ".conf", ".tf", ".sql", ".vue", ".svelte",
}

MAX_FILE_BYTES = 1_500_000
MAX_FILES = 8000

# (rule_id, severity, title, owasp, remediation, regex)
RULES = [
    ("SQL-INJECTION-CONCAT", "critical", "استعلام SQL مبني على تجميع نصوص (SQL Injection)",
     "A03:2021 – Injection",
     "استخدم معاملات مُهيّأة (parameterized queries / prepared statements) بدل دمج المدخلات في نص الاستعلام.",
     re.compile(r"(?i)(SELECT\s+.*FROM\s+[\w`\"'.]+.*(\+|\bformat\b|%\s*\(|f[\"']).*|"
                r"execute\s*\(\s*[\"'][^\"']*(%s|\{\w+\}|\"\s*\+))")),
    ("SQL-INJECTION-FSTRING", "high", "استعلام SQL داخل f-string",
     "A03:2021 – Injection",
     "مرّر القيم عبر cursor.execute(sql, params) ولا تُضمّنها داخل نص f-string.",
     re.compile(r"(?i)execute\s*\(\s*f[\"']|cursor\.execute\s*\(\s*f[\"']")),
    ("XSS-INNERHTML", "high", "حقن محتوى عبر innerHTML / dangerouslySetInnerHTML",
     "A03:2021 – Injection",
     "استخدم textContent أو تهيئة المحتوى (sanitize/escape) قبل حقنه في DOM.",
     re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(")),
    ("COMMAND-INJECTION", "critical", "تنفيذ أوامر نظام مع مدخلات خارجية",
     "A03:2021 – Injection",
     "استخدم قائمة معاملات subprocess بـ shell=False والتحقق من الهوية بـ shlex.quote.",
     re.compile(r"\bos\.system\s*\(|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True|"
                r"child_process\.exec\(|`[^`]*\$\{|\beval\s*\(")),
    ("PATH-TRAVERSAL", "high", "وصول ملفات بمسار مشتق من مدخلات المستخدم",
     "A01:2021 – Broken Access Control",
     "ارفض أي مسار يحتوي '..' وتحقّق أن المسار النهائي داخل الجذر المسموح (os.path.realpath).",
     re.compile(r"(?i)open\s*\(\s*(?:os\.path\.join\s*\()?\s*(?:request|params|user|input|path|file)")),
    ("HARDCODED-CREDENTIAL", "critical", "بيانات اعتماد مكتوبة داخل الكود",
     "A07:2021 – Identification and Authentication Failures",
     "احذف القيمة من الكود، احفظها في متغيّر بيئة/مستودع أسرار، وغيّرها فوراً.",
     re.compile(r"(?i)(password|passwd|pwd|secret|api_key|apikey|access_token)\s*[:=]\s*[\"'][^\"']{6,}[\"']")),
    ("WEAK-HASH", "medium", "خوارزمية تجزئة ضعيفة (MD5/SHA1) لبيانات حساسة",
     "A02:2021 – Cryptographic Failures",
     "استبدلها بـ bcrypt/argon2 للكلمات السرية و SHA-256+ للمشاهد.",
     re.compile(r"(?i)\b(md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\s*\(")),
    ("INSECURE-TLS", "high", "تعطيل التحقق من شهادات TLS",
     "A07:2021 – Identification and Authentication Failures",
     "أعد تفعيل التحقق من الشهادة؛ للاختبار المحلي فقط اجعلها خياراً صريحاً معطّلاً افتراضياً.",
     re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
                r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)")),
    ("DEBUG-TRUE", "high", "وضع التصحيح مفعّل في إنتاج",
     "A05:2021 – Security Misconfiguration",
     "اجعل DEBUG=False في الإنتاج وارفع الأخطاء عبر مُعالج أخطاء مركزي.",
     re.compile(r"(?i)DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True")),
    ("WILDCARD-CORS", "high", "سياسة CORS تسمح لأي مصدر",
     "A05:2021 – Security Misconfiguration",
     "قيّد النطاقات المسموحة صراحةً بقائمة بيضاء بدل Access-Control-Allow-Origin: *.",
     re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*|cors\s*\(\s*\)\s*[;)]|\*\s*,\s*['\"]*")),
    ("JWT-NO-VERIFY", "critical", "توقيع JWT دون تحقق من التوقيع",
     "A02:2021 – Cryptographic Failures",
     "تحقق دائماً من التوقيع والخوارزمية (algorithm != none) عبر مكتبة JWT موثوقة.",
     re.compile(r"(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*[\"']none")),
    ("PICKLE-DESERIALIZE", "critical", "فك تسلسل بيانات غير موثوقة (deserialization)",
     "A08:2021 – Software and Data Integrity Failures",
     "استبدل pickle/yaml.unsafe_load بـ json، أو تحقق من HMAC قبل الفك.",
     re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\([^)]*(?!Loader=)|unserialize\s*\(")),
    ("OPEN-REDIRECT", "medium", "إعادة توجيه إلى وجهة من مدخلات المستخدم",
     "A01:2021 – Broken Access Control",
     "تحقق أن الوجهة تبدأ بمسار نسبي وأن النطاق في قائمة بيضاء.",
     re.compile(r"(?i)(HttpResponseRedirect|redirect|window\.location(?:\.href)?)\s*\(\s*(?:request|params|next|url|redirect_to)")),
    ("BROAD-EXCEPTION", "low", "اعتراض استثناءات يخفي الأخطاء",
     "A09:2021 – Security Logging and Monitoring Failures",
     "سجّل الاستثناءات بمستوى مناسب ولا تبتلعها بصمت (except: pass).",
     re.compile(r"except\s*(?:Exception)?\s*:\s*(?:pass|\.\.\.)")),
    ("MISSING-AUTH-CHECK", "medium", "مسار API يقرأ من مدخلات الطلب دون تحقق من الهوية",
     "A01:2021 – Broken Access Control",
     "طبّق مصادقة وتفويضاً على كل مسار خاص قبل قراءة مدخلات الطلب.",
     re.compile(r"(?i)@(?:app|router)\.(?:route|get|post|put|delete)\s*\([\"'][^\"']*(admin|internal|debug|private)")),
    ("WEAK-RANDOM", "medium", "مولد عشوائي غير صالح للأمان",
     "A03:2021 – Injection",
     "استخدم secrets/os.urandom للرموز والأرقام السرية بدل random.",
     re.compile(r"(?i)\brandom\.(?:random|randint|choice|choices|randrange)\s*\(")),
    ("LOG-INJECTION", "low", "تسجيل مدخلات المستخدم دون تنظيف",
     "A09:2021 – Security Logging and Monitoring Failures",
     "اهرب تسلسلات السطور والتحكّم قبل كتابتها في السجلات.",
     re.compile(r"(?i)(?:logger|log|console)\.(?:info|warn|error|debug)\s*\(\s*(?:request|user|input|params)\b")),
    ("COOKIE-NOSECURE", "medium", "كوكي مُضبَط دون HttpOnly/Secure/SameSite",
     "A05:2021 – Security Misconfiguration",
     "اضبط HttpOnly و Secure و SameSite=Lax/Strict على كل الكوكيز الحساسة.",
     re.compile(r"(?i)(?:set_cookie|res\.cookie)\s*\((?![^)]*\bsecure\b)")),
    ("HARDCODED-URL-CREDENTIAL", "high", "بيانات اعتماد داخل رابط مضمّن",
     "A07:2021 – Identification and Authentication Failures",
     "انقل بيانات الاعتماد إلى متغيّرات بيئة واحذفها من سجلات Git (وبعد ذلك غيّرها).",
     re.compile(r"https?://[^/\s:]+:[^@/\s]+@")),
]

_SEMI_RULES = [
    ("semgrep", "medium", "Semgrep: ملاحظة أمنية في الكود", "A06:2021 – Vulnerable and Outdated Components",
     "راجع التوصية الصادرة عن Semgrep في الحقل evidence.", None),
]


def _iter_files(root: Path, limit: int = MAX_FILES):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() not in CODE_EXT and name not in (".env", "Dockerfile", "Makefile"):
                continue
            try:
                if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p
            count += 1
            if count >= limit:
                return


def scan_source(path: str, max_findings: int = 400) -> List[Finding]:
    root = Path(path).resolve()
    findings: List[Finding] = []
    if root.is_file():
        files = [root]
        base = root.parent
    else:
        files = list(_iter_files(root))
        base = root

    ignore = ignore_rules(base)

    for f in files:
        rel = str(f.relative_to(base)) if str(f).startswith(str(base)) else str(f)
        if is_ignored(rel, ignore):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for rule_id, severity, title, owasp, remediation, rx in RULES:
            for idx, line in enumerate(lines, start=1):
                if len(line) > 4000:
                    continue
                if rx.search(line):
                    clean, _ = redact(line.strip()[:300])
                    findings.append(Finding(
                        rule_id=rule_id, title=title, severity=severity,
                        category="sast", location=f"{rel}:{idx}",
                        evidence=clean, owasp=owasp, remediation=remediation,
                    ))
                    if len(findings) >= max_findings:
                        return findings
    return findings


def run_semgrep(path: str, timeout: int = 240) -> List[Finding]:
    """Optional second opinion — runs only when Semgrep is installed."""
    binary = shutil.which("semgrep")
    if not binary:
        return []
    cmd = [binary, "scan", "--json", "--quiet", "--metrics=off", "--timeout=30", path]
    if (Path(path) / ".semgrep.yml").is_file() or (Path(path) / ".semgrep.yaml").is_file():
        cmd += ["--config", str(Path(path) / ".semgrep.yml")]
    else:
        cmd += ["--config", "p/security-audit", "--config", "p/owasp-top-ten"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return []
    if not proc.stdout:
        return []
    import json

    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return []

    out: List[Finding] = []
    for res in data.get("results", [])[:200]:
        check_id = res.get("check_id", "semgrep")
        meta = res.get("extra", {})
        severity = str(meta.get("severity", "medium")).lower()
        if severity in ("error", "warning"):
            severity = "high" if severity == "error" else "medium"
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        msg = str(meta.get("message", check_id)).strip().replace("\n", " ")[:400]
        clean, _ = redact(msg)
        start = res.get("start", {})
        out.append(Finding(
            rule_id=f"SEMGREP-{check_id}"[:80],
            title=clean[:140],
            severity=severity,
            category="sast",
            location=f"{res.get('path','')}:{start.get('line','')}",
            evidence=clean,
            owasp="A06:2021 – Vulnerable and Outdated Components",
            remediation=str(meta.get("fix", ""))[:400] or
                        "راجع الوثائق الخاصة بقاعدة semgrep المذكورة وطبّق الإصلاح المقترح.",
        ))
    return out


def scan(path: str, use_semgrep: bool = True) -> List[Finding]:
    findings = scan_source(path)
    if use_semgrep:
        findings.extend(run_semgrep(path))
    return findings
