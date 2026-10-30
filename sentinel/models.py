"""Finding / Report data model shared by every layer."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str  # sast | secrets | ports | web | ai
    location: str = ""
    evidence: str = ""  # always redacted before it leaves the process
    owasp: str = ""
    remediation: str = ""
    ai_fix: str = ""
    cvss: float = 0.0
    confidence: str = "high"

    def key(self) -> str:
        blob = f"{self.rule_id}|{self.location}|{self.title}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["key"] = self.key()
        return d


@dataclass
class ScanReport:
    target: str
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    mode: str = "local"
    engine_versions: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    ai_enabled: bool = False
    ai_provider: str = "off"

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def sort(self) -> None:
        self.findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.rule_id))

    def counts(self) -> Dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def score(self) -> int:
        """0 (fortified) .. 100 (critical exposure) — weighted exposure index."""
        weights = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(100, total)

    def grade(self) -> str:
        s = self.score()
        if s == 0:
            return "A+"
        if s < 15:
            return "A"
        if s < 30:
            return "B"
        if s < 55:
            return "C"
        if s < 80:
            return "D"
        return "F"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": round(self.finished_at - self.started_at, 2)
            if self.finished_at
            else 0,
            "engine_versions": self.engine_versions,
            "ai_enabled": self.ai_enabled,
            "ai_provider": self.ai_provider,
            "counts": self.counts(),
            "score": self.score(),
            "grade": self.grade(),
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ScanReport":
        r = ScanReport(target=d.get("target", ""), scan_id=d.get("scan_id", uuid.uuid4().hex))
        r.started_at = d.get("started_at", 0.0)
        r.finished_at = d.get("finished_at", 0.0)
        r.mode = d.get("mode", "local")
        r.engine_versions = d.get("engine_versions", {})
        r.ai_enabled = d.get("ai_enabled", False)
        r.ai_provider = d.get("ai_provider", "off")
        r.errors = d.get("errors", [])
        for fd in d.get("findings", []):
            fd.pop("key", None)
            known = {k: v for k, v in fd.items() if k in Finding.__dataclass_fields__}
            r.findings.append(Finding(**known))
        return r
