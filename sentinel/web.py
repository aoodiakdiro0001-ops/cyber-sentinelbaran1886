"""Layer 1d — Web posture & dead-link audit (stdlib urllib only).

Checks: HTTPS/redirects, security headers, cookie flags, TLS version,
server banner disclosure, robots.txt/sitemap, and same-origin links.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding
from .redact import redact

UA = "Cyber-SentinelBaran1886/1.0 (+security-scanner; free-tier)"
TIMEOUT = 12
MAX_LINKS = 25

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "high", "HSTS مفقود",
     "أضف Strict-Transport-Security: max-age=31536000; includeSubDomains لمنع خفض الاتصال إلى HTTP."),
    ("Content-Security-Policy", "high", "سياسة أمان المحتوى (CSP) مفقودة",
     "أضف Content-Security-Policy تحدّد مصادر الموارد وتمنع حقن السكربتات."),
    ("X-Frame-Options", "medium", "حماية من التضمين (Clickjacking) مفقودة",
     "أضف X-Frame-Options: DENY أو frame-ancestors 'none' في CSP."),
    ("X-Content-Type-Options", "medium", "X-Content-Type-Options مفقود",
     "أضف X-Content-Type-Options: nosniff لمنع المتصفح من تخمين نوع المحتوى."),
    ("Referrer-Policy", "low", "Referrer-Policy مفقود",
     "أضف Referrer-Policy: strict-origin-when-cross-origin لمنع تسريب الروابط الداخلية."),
    ("Permissions-Policy", "low", "Permissions-Policy مفقود",
     "أضف Permissions-Policy لتقييد الميكروفون والكاميرا والموقع."),
]


def _fetch(url: str, method: str = "GET", max_bytes: int = 300_000):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), b"", None
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, ValueError) as e:
        return None, {}, b"", str(e)
    try:
        body = resp.read(max_bytes)
    except (OSError, socket.timeout):
        body = b""
    code = getattr(resp, "status", None) or resp.getcode()
    return code, dict(resp.headers), body, None


def _tls_version(host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                return s.version(), None
    except Exception as exc:  # noqa: BLE001 — surface any handshake failure
        return None, str(exc)


def scan(url: str, follow_links: bool = True) -> List[Finding]:
    findings: List[Finding] = []
    if not re.match(r"^https?://", url):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or url
    scheme = parsed.scheme

    # --- TLS ------------------------------------------------------------
    if scheme == "https":
        ver, err = _tls_version(host, parsed.port or 443)
        if ver:
            if ver in ("TLSv1", "TLSv1.1", "TLSv1.2") and ver != "TLSv1.3":
                findings.append(Finding(
                    rule_id="TLS-OLD-VERSION", title=f"بروتوكول TLS قديم: {ver}",
                    severity="medium" if ver == "TLSv1.2" else "high",
                    category="web", location=host, evidence=ver,
                    owasp="A02:2021 – Cryptographic Failures",
                    remediation="فعّل TLS 1.3 وعطّل TLS 1.0/1.1 على الخادم.",
                ))
            elif ver == "TLSv1.3":
                findings.append(Finding(
                    rule_id="TLS-OK", title="اتصال TLS 1.3 سليم",
                    severity="info", category="web", location=host, evidence=ver,
                    owasp="A02:2021 – Cryptographic Failures",
                    remediation="لا إجراء مطلوب — بقي هذا التقييم محفوظاً للمقارنة التاريخية.",
                ))
        else:
            findings.append(Finding(
                rule_id="TLS-FAIL", title="فشل مصافحة TLS",
                severity="high", category="web", location=host, evidence=err or "",
                owasp="A02:2021 – Cryptographic Failures",
                remediation="أصلح السلسلة/الشهادة أو ربط الويبسيرفر بالشهادة الصحيحة.",
            ))
    else:
        findings.append(Finding(
            rule_id="NO-HTTPS", title="الموقع لا يستخدم HTTPS",
            severity="high", category="web", location=host, evidence=url,
            owasp="A02:2021 – Cryptographic Failures",
            remediation="أصدر شهادة Let's Encrypt مجانية وأعد توجيه كل المسارات إلى HTTPS.",
        ))

    # --- main response ---------------------------------------------------
    code, headers, body, err = _fetch(url)
    if code is None:
        findings.append(Finding(
            rule_id="WEB-UNREACHABLE", title="تعذّر الوصول إلى الموقع",
            severity="high", category="web", location=url, evidence=err or "",
            owasp="A05:2021 – Security Misconfiguration",
            remediation="تحقق من سجلات الخادم ومن اسم النطاق ومن جدار الحماية.",
        ))
        return findings

    lower = {k.lower(): v for k, v in headers.items()}
    server = lower.get("server", "")
    powered = lower.get("x-powered-by", "")
    if server or powered:
        findings.append(Finding(
            rule_id="WEB-BANNER-DISCLOSURE", title="كشف إصدار الخادم/الإطار",
            severity="low", category="web", location=host,
            evidence=(server + " " + powered).strip()[:160],
            owasp="A05:2021 – Security Misconfiguration",
            remediation="أخفِ ترويسات Server و X-Powered-Through خلف بروكسي أو عبر إعداد الخادم.",
        ))

    for name, severity, title, remediation in SECURITY_HEADERS:
        if name.lower() not in lower:
            findings.append(Finding(
                rule_id=f"WEB-HEADER-{name.upper().replace('-', '')}",
                title=title, severity=severity, category="web",
                location=host, evidence=f"missing: {name}",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=remediation,
            ))

    # --- cookies ---------------------------------------------------------
    for cookie in lower.get("set-cookie", "").split("\n") if lower.get("set-cookie") else []:
        low = cookie.lower()
        flags = []
        if "httponly" not in low:
            flags.append("HttpOnly")
        if scheme == "https" and "secure" not in low:
            flags.append("Secure")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            clean, _ = redact(cookie.strip()[:180])
            findings.append(Finding(
                rule_id="WEB-COOKIE-FLAGS", title="كوكي بعلم مفقود: " + ", ".join(flags),
                severity="medium", category="web", location=host, evidence=clean,
                owasp="A05:2021 – Security Misconfiguration",
                remediation="أضف " + ", ".join(flags) + " على الكوكيز الحساسة.",
            ))

    # --- HTTP→HTTPS redirect ---------------------------------------------
    if scheme == "https":
        alt = url.replace("https://", "http://", 1)
        acode, aheaders, _, _ = _fetch(alt, method="HEAD")
        if acode and acode < 300:
            findings.append(Finding(
                rule_id="WEB-NO-HTTPS-REDIRECT", title="HTTP لا يُعاد توجيهه إلى HTTPS",
                severity="medium", category="web", location=alt, evidence=f"status {acode}",
                owasp="A05:2021 – Security Misconfiguration",
                remediation="أعد توجيه http → 301 إلى https على مستوى الخادم قبل معالجة الطلب.",
            ))

    # --- robots / sitemap -------------------------------------------------
    base = f"{scheme}://{parsed.netloc}"
    for probe in ("/robots.txt", "/sitemap.xml"):
        pcode, _, pbody, _ = _fetch(base + probe, method="GET")
        if pcode in (404, 410) or pcode is None:
            findings.append(Finding(
                rule_id=f"WEB-MISSING-{probe.strip('/').replace('.', '-').upper()}",
                title=f"ملف {probe} غير موجود", severity="info", category="web",
                location=base + probe, evidence=f"status {pcode}",
                owasp="A05:2021 – Security Misconfiguration",
                remediation=f"أنشئ {probe} لتوجيه محركات البحث ومنع كشف مسارات داخلية.",
            ))
        elif pcode == 200 and probe == "/robots.txt":
            text = pbody.decode("utf-8", "replace")
            if re.search(r"(?im)^Disallow:\s*/\s*$", text):
                findings.append(Finding(
                    rule_id="WEB-ROBOTS-BLOCK-ALL", title="robots.txt يمنع فهرسة الموقع كاملاً",
                    severity="info", category="web", location=base + probe,
                    evidence="Disallow: /", owasp="A05:2021 – Security Misconfiguration",
                    remediation="راجع القاعدة؛ منع كامل الفهرسة قد يكون غير مقصود.",
                ))

    # --- dead links -------------------------------------------------------
    if follow_links and body:
        html = body.decode("utf-8", "replace")
        same_origin: Set[str] = set()
        for m in re.finditer(r'''(?i)href\s*=\s*["']([^"'#]+)["']''', html):
            link = urllib.parse.urljoin(base, m.group(1))
            if link.startswith(base) and not re.search(r"\.(png|jpg|jpeg|gif|svg|css|woff2?|ico)$", link, re.I):
                same_origin.add(link)
            if len(same_origin) >= MAX_LINKS:
                break
        for link in sorted(same_origin):
            lcode, lheaders, _, lerr = _fetch(link, method="HEAD")
            if lcode is None or lcode >= 400:
                findings.append(Finding(
                    rule_id="WEB-BROKEN-LINK", title="رابط مكسور داخل الموقع",
                    severity="medium" if (lcode in (404, 410, 500, 502, 503)) else "low",
                    category="web", location=link,
                    evidence=(f"status {lcode}" if lcode else (lerr or "unreachable"))[:160],
                    owasp="A05:2021 – Security Misconfiguration",
                    remediation="صحّح أو أزل الرابط المكسور؛ الروابط الميتة تخدش الثقة وتعرّض الزوار لصفحات خطأ.",
                ))
    return findings
