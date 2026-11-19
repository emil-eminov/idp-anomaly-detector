"""Core data types: authentication events and detection findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

EVENT_TYPES = {
    "login_success",
    "login_failure",
    "mfa_push_denied",
    "mfa_push_timeout",
    "mfa_success",
}


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    user: str
    event_type: str
    ip: str
    country: str = ""
    city: str = ""
    lat: float | None = None
    lon: float | None = None

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {self.event_type!r}")


@dataclass
class Finding:
    rule: str
    severity: str  # "medium" | "high" | "critical"
    technique_id: str  # MITRE ATT&CK technique ID
    technique_name: str
    subject: str  # user or IP the finding is about
    first_seen: datetime
    last_seen: datetime
    summary: str
    evidence: list[Event] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "subject": self.subject,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "summary": self.summary,
            "evidence_count": len(self.evidence),
        }
