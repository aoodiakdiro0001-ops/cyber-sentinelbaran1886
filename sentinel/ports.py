"""Layer 1c — Network/port discovery.

Uses Nmap when installed (service + version detection), otherwise a pure-stdlib
socket connect scan over the top ports. No packets leave the machine unsolicited:
only hosts the operator passes on the command line are touched.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from typing import List, Tuple

from .models import Finding

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 4443, 4444, 5000,
    5432, 5601, 5900, 6379, 6443, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 11211, 15672, 27017, 27018,
]

SENSITIVE = {
    21: "FTP — قد يقبل تسجيل الدخول بـ anonymous",
    22: "SSH — تأكد من تعطيل الدخول بكلمة المرور إن أمكن",
    23: "Telnet — بروتوكول غير مشفّر، أغلقه واستبدل بـ SSH",
    25: "SMTP — تحقق من إعدادات SPF/DKIM/DMARC",
    445: "SMB — هدف شائع للansomware، اعزله عن الإنترنت",
    3389: "RDP — اجعله خلف VPN ولا تكشفه للإنترنت",
    3306: "MySQL — يجب ألّا يكون م曝حاً للعام",
    5432: "PostgreSQL — يجب ألّا يكون م曝حاً للعام",
    6379: "Redis — غالباً بدون مصادقة، اعزله فوراً",
    27017: "MongoDB — هدف شائع، اطلب مصادقة TLS",
    9200: "Elasticsearch — غالباً مفتوح بلا مصادقة",
    11211: "Memcached — تُستغل فيه حزم UDP في هجمات التضخيم (amplification)",
    2375: "Docker API غير مشفّر — تحكّم كامل بالمضيف",
    6443: "Kubernetes API",
    8080: "منفذ بديل للويب — تأكد من وجود مصادقة",
    9090: "لوحة تحكم/بروكسي — تحقق من الحماية",
}


# سطور التقرير النصي لنmap: عنوان الهدف ثم صف المنفذ
_REPORT_LINE = re.compile(r"^Nmap scan report for\s+(.+?)\s*\([^)]*\)\s*$")
_PORT_LINE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)$")


def _run_nmap(host: str, timeout: int = 420) -> Tuple[List[Finding], str]:
    binary = shutil.which("nmap")
    if not binary:
        return [], "nmap"
    # التقرير النصي القياسي فقط: لا XML ولا تحليل مسند — سهل القراءة
    # وبلا سطح حقن على الإطلاق.
    cmd = [binary, "-sV", "-Pn", "--top-ports", "1000", "-T4", "-oN", "-", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return [], "nmap"
    if not proc.stdout.strip():
        return [], "nmap"

    findings: List[Finding] = []
    name = host
    for raw in proc.stdout.splitlines():
        line = raw.rstrip()
        report = _REPORT_LINE.match(line)
        if report:
            name = report.group(1) or host
            continue
        m = _PORT_LINE.match(line.strip())
        if not m:
            continue
        port_id, proto, _state, service, rest = m.groups()
        port_id = int(port_id)
        banner = " ".join(x for x in (service, rest.strip()) if x)
        note = SENSITIVE.get(port_id)
        findings.append(Finding(
            rule_id=f"PORT-OPEN-{port_id}",
            title=f"منفذ {port_id}/{proto} مفتوح — {banner or 'خدمة مفتوحة'}",
            severity="high" if note else ("medium" if port_id in TOP_PORTS else "info"),
            category="ports",
            location=f"{name}:{port_id}",
            evidence=banner,
            owasp="A05:2021 – Security Misconfiguration",
            remediation=note or "أغلق المنفذ إن لم يكن مطلوباً، أو احجبه بجدار حماية.",
        ))
    return findings, "nmap"


def _socket_scan(host: str, timeout: float = 0.6) -> Tuple[List[Finding], str]:
    findings: List[Finding] = []
    try:
        infos = socket.getaddrinfo(host, None)
        ip = infos[0][4][0]
    except socket.gaierror:
        return [Finding(
            rule_id="DNS-RESOLVE-FAIL", title="تعذّر حل اسم النطاق",
            severity="info", category="ports", location=host,
            evidence="getaddrinfo failed", owasp="A03:2021 – Injection",
            remediation="تحقق من صحة اسم النطاق أو استخدم عنوان IP.",
        )], "socket"

    for port in TOP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            ok = s.connect_ex((ip, port)) == 0
        except OSError:
            ok = False
        finally:
            s.close()
        if not ok:
            continue
        banner = ""
        try:
            probe = socket.create_connection((ip, port), timeout=timeout)
            probe.settimeout(1.0)
            data = probe.recv(256, socket.MSG_PEEK)
            probe.close()
            banner = data.decode("utf-8", "replace").strip().splitlines()[0][:120] if data else ""
        except OSError:
            pass
        note = SENSITIVE.get(port)
        findings.append(Finding(
            rule_id=f"PORT-OPEN-{port}",
            title=f"منفذ {port}/tcp مفتوح — {banner or 'خدمة مفتوحة'}",
            severity="high" if note else "medium",
            category="ports", location=f"{ip}:{port}", evidence=banner,
            owasp="A05:2021 – Security Misconfiguration",
            remediation=note or "أغلق المنفذ إن لم يكن مطلوباً أو احجبه بجدار حماية.",
        ))
    return findings, "socket"


def scan(target: str, engine: str = "auto") -> Tuple[List[Finding], str]:
    use_nmap = engine in ("auto", "nmap") and shutil.which("nmap")
    if use_nmap:
        findings, name = _run_nmap(target)
        if findings or name == "nmap":
            return findings, "nmap"
    return _socket_scan(target)
