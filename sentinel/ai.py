"""Layer 2 — AI Security Core.

Free tiers only: Google Gemini, Groq, OpenRouter, or a local Ollama server.
If no key is configured the module falls back to a built-in rulebook so the
report still carries severity triage and a concrete patch.

The prompt never contains unmasked secrets: every string is passed through
sentinel.redact before it is sent anywhere.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from . import config
from .models import Finding, ScanReport
from .redact import redact

SYSTEM_PROMPT = (
    "You are a senior application security engineer. You receive a JSON list of "
    "findings from a static/dynamic scan. Reply with STRICT JSON only, an array "
    "with the same length as the input, each item: "
    '{"key": str, "severity": "critical|high|medium|low|info", "cvss": number, '
    '"ai_fix": "<short explanation in Arabic plus a concrete safe code patch>", '
    '"title_ar": "<one-line Arabic title>"} '
    "Rules: keep the key exactly as given; never invent findings; rank by real "
    "exploitability; write fixes for Python/JS/TS/PHP; answer in Arabic."
)

FIXBOOK = {
    "SQL-INJECTION-CONCAT": "cursor.execute(\"SELECT id FROM users WHERE email=%s\", (email,))",
    "SQL-INJECTION-FSTRING": "cursor.execute('SELECT * FROM t WHERE c=%s', (value,))",
    "XSS-INNERHTML": "el.textContent = userInput;  // بدل innerHTML",
    "COMMAND-INJECTION": "subprocess.run([\"ping\", host], shell=False, check=False)",
    "HARDCODED-CREDENTIAL": "api_key = os.environ[\"API_KEY\"]",
    "WEAK-HASH": "bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    "INSECURE-TLS": "requests.get(url, verify=True)  # شهادة موثقة",
    "DEBUG-TRUE": "DEBUG = os.environ.get(\"DEBUG\", \"false\").lower() == \"true\"",
    "WILDCARD-CORS": "app.use(cors({ origin: [\"https://yourdomain.com\"] }))",
    "JWT-NO-VERIFY": "jwt.decode(token, key, algorithms=[\"HS256\"])",
    "PICKLE-DESERIALIZE": "json.loads(payload)  # بدل pickle.loads",
    "WEAK-RANDOM": "secrets.token_urlsafe(32)",
    "SECRET-GITHUB-TOKEN": "انقل الرمز إلى GitHub → Settings → Secrets ثم ألغِ صلاحيته فوراً.",
    "SECRET-PRIVATE-Key": "انقل المفتاح إلى مستودع أسرار ثم ولّد مفتاحاً جديداً (إلغاء القديم إلزامي).",
}


def _pick_provider() -> Tuple[str, str]:
    if config.has("GEMINI_API_KEY"):
        return "gemini", config.get("GEMINI_API_KEY")
    if config.has("GROQ_API_KEY"):
        return "groq", config.get("GROQ_API_KEY")
    if config.has("OPENROUTER_API_KEY"):
        return "openrouter", config.get("OPENROUTER_API_KEY")
    if config.has("OLLAMA_URL"):
        return "ollama", config.get("OLLAMA_URL")
    return "off", ""


def _post(url: str, payload: Dict, headers: Dict[str, str], timeout: int = 60) -> str:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _call_gemini(key: str, user_prompt: str) -> str:
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"gemini-1.5-flash:generateContent?key={key}")
    return _post(url, {
        "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + user_prompt}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 4096},
    }, {})


def _call_groq(key: str, user_prompt: str) -> str:
    return _post("https://api.groq.com/openai/v1/chat/completions",
                 {"model": "llama-3.3-70b-versatile",
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": user_prompt}],
                  "temperature": 0.1, "response_format": {"type": "json_object"}},
                 {"Authorization": f"Bearer {key}"})


def _call_openrouter(key: str, user_prompt: str) -> str:
    return _post("https://openrouter.ai/api/v1/chat/completions",
                 {"model": "meta-llama/llama-3.3-70b-instruct:free",
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": user_prompt}]},
                 {"Authorization": f"Bearer {key}"})


def _call_ollama(base: str, user_prompt: str) -> str:
    return _post(base.rstrip("/") + "/api/chat",
                 {"model": config.get("OLLAMA_MODEL", "llama3.1"),
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": user_prompt}],
                  "stream": False, "format": "json"},
                 {})


def _extract_json(raw: str) -> List[Dict]:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or [data]
    return [d for d in data if isinstance(d, dict)]


def _local_triage(report: ScanReport) -> Tuple[str, List[Dict]]:
    """Offline fallback — still gives severity, CVSS band and a patch."""
    out = []
    for f in report.findings:
        patch = FIXBOOK.get(f.rule_id, "")
        if not patch and f.category == "secrets":
            patch = FIXBOOK.get("SECRET-" + f.rule_id.split("-", 1)[-1],
                                "انقل القيمة إلى متغيّر بيئة وغيّرها فوراً.")
        cvss = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}.get(f.severity, 5.0)
        out.append({"key": f.key(), "severity": f.severity, "cvss": cvss,
                    "title_ar": f.title,
                    "ai_fix": (f"{f.remediation}\n```fix\n{patch}\n```" if patch else f.remediation)})
    return "local-rulebook", out


def enrich(report: ScanReport, max_items: int = 40) -> ScanReport:
    """Attach severity/CVSS/AI patch to findings. Never raises."""
    report.sort()
    provider, key = _pick_provider()
    report.ai_provider = provider
    report.ai_enabled = provider != "off"

    if not report.findings:
        return report

    if provider == "off":
        _, triaged = _local_triage(report)
        _apply(report, triaged)
        return report

    subset = report.findings[:max_items]
    payload = [{"key": f.key(), "rule_id": f.rule_id, "title": f.title,
                "severity": f.severity, "category": f.category,
                "location": f.location, "evidence": f.evidence, "owasp": f.owasp}
               for f in subset]
    clean, _ = redact(json.dumps(payload, ensure_ascii=False))
    prompt = ("Findings:\n" + clean +
              "\n\nReturn the JSON array only. Length must equal the findings length.")

    try:
        if provider == "gemini":
            raw = _call_gemini(key, prompt)
            try:
                body = json.loads(raw)
                raw = body["candidates"][0]["content"]["parts"][0]["text"]
            except (ValueError, KeyError, IndexError):
                pass
        elif provider == "groq":
            raw = _call_groq(key, prompt)
            try:
                raw = json.loads(raw)["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError):
                pass
        elif provider == "openrouter":
            raw = _call_openrouter(key, prompt)
            try:
                raw = json.loads(raw)["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError):
                pass
        else:
            raw = _call_ollama(key, prompt)
            try:
                raw = json.loads(raw)["message"]["content"]
            except (ValueError, KeyError, IndexError):
                pass
        triaged = _extract_json(raw)
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TimeoutError) as exc:
        report.errors.append(f"AI ({provider}) failed, using rulebook: {exc}")
        _, triaged = _local_triage(report)

    if not triaged:
        _, triaged = _local_triage(report)
    _apply(report, triaged)
    report.sort()
    return report


def _apply(report: ScanReport, triaged: List[Dict]) -> None:
    by_key = {d.get("key"): d for d in triaged if d.get("key")}
    for f in report.findings:
        d = by_key.get(f.key())
        if not d:
            continue
        sev = str(d.get("severity", "")).lower()
        if sev in ("critical", "high", "medium", "low", "info"):
            f.severity = sev
        try:
            f.cvss = float(d.get("cvss") or 0)
        except (TypeError, ValueError):
            f.cvss = 0.0
        fix = str(d.get("ai_fix") or "").strip()
        if fix:
            clean, _ = redact(fix[:1200])
            f.ai_fix = clean
        title_ar = str(d.get("title_ar") or "").strip()
        if title_ar:
            clean, _ = redact(title_ar[:200])
            f.title = clean
