"""Detection rules for identity-provider account takeover patterns.

Each rule takes a time-sorted list of events and returns a list of Findings.
Thresholds are keyword arguments so they can be tuned per environment.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Iterable

from .models import Event, Finding

EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _by_key(events: Iterable[Event], key: Callable[[Event], str]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        groups[key(e)].append(e)
    return groups


def impossible_travel(
    events: list[Event],
    max_speed_kmh: float = 900.0,
    min_distance_km: float = 500.0,
) -> list[Finding]:
    """Two successful logins for one user too far apart to travel between.

    900 km/h is roughly commercial jet cruising speed. The minimum distance
    filter avoids noise from IP geolocation error between nearby cities.
    """
    findings = []
    successes = [e for e in events if e.event_type == "login_success" and e.lat is not None]
    for user, evs in _by_key(successes, lambda e: e.user).items():
        for prev, cur in zip(evs, evs[1:]):
            dist = haversine_km(prev.lat, prev.lon, cur.lat, cur.lon)
            if dist < min_distance_km:
                continue
            hours = (cur.timestamp - prev.timestamp).total_seconds() / 3600
            speed = dist / hours if hours > 0 else math.inf
            if speed > max_speed_kmh:
                findings.append(
                    Finding(
                        rule="impossible_travel",
                        severity="high",
                        technique_id="T1078",
                        technique_name="Valid Accounts",
                        subject=user,
                        first_seen=prev.timestamp,
                        last_seen=cur.timestamp,
                        summary=(
                            f"{prev.city or prev.country} -> {cur.city or cur.country}: "
                            f"{dist:,.0f} km in {hours * 60:,.0f} min "
                            f"(~{min(speed, 99999):,.0f} km/h)"
                        ),
                        evidence=[prev, cur],
                    )
                )
    return findings


def _sliding_bursts(evs: list[Event], window: timedelta, threshold: int) -> list[list[Event]]:
    """Return non-overlapping bursts of >= threshold events inside `window`."""
    bursts, start = [], 0
    i = 0
    while i < len(evs):
        while evs[i].timestamp - evs[start].timestamp > window:
            start += 1
        if i - start + 1 >= threshold:
            # extend the burst as far as the window allows, then skip past it
            end = i
            while end + 1 < len(evs) and evs[end + 1].timestamp - evs[start].timestamp <= window:
                end += 1
            bursts.append(evs[start : end + 1])
            start = i = end + 1
            continue
        i += 1
    return bursts


def mfa_fatigue(
    events: list[Event],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
    accept_window: timedelta = timedelta(minutes=15),
) -> list[Finding]:
    """A flood of rejected or ignored MFA pushes, i.e. push bombing.

    Escalates to critical if the user approves a push shortly after the
    flood, which usually means the attacker wore the user down.
    """
    findings = []
    for user, evs in _by_key(events, lambda e: e.user).items():
        pushes = [e for e in evs if e.event_type in ("mfa_push_denied", "mfa_push_timeout")]
        accepts = [e for e in evs if e.event_type == "mfa_success"]
        for burst in _sliding_bursts(pushes, window, threshold):
            last = burst[-1].timestamp
            accepted = next(
                (a for a in accepts if last <= a.timestamp <= last + accept_window), None
            )
            summary = f"{len(burst)} rejected/ignored MFA pushes in {window.seconds // 60} min"
            evidence = list(burst)
            if accepted:
                summary += f", then approved at {accepted.timestamp:%H:%M} from {accepted.ip}"
                evidence.append(accepted)
            findings.append(
                Finding(
                    rule="mfa_fatigue",
                    severity="critical" if accepted else "high",
                    technique_id="T1621",
                    technique_name="Multi-Factor Authentication Request Generation",
                    subject=user,
                    first_seen=burst[0].timestamp,
                    last_seen=evidence[-1].timestamp,
                    summary=summary,
                    evidence=evidence,
                )
            )
    return findings


def password_spray(
    events: list[Event],
    min_users: int = 10,
    window: timedelta = timedelta(minutes=30),
) -> list[Finding]:
    """One source IP failing logins across many different accounts."""
    findings = []
    failures = [e for e in events if e.event_type == "login_failure"]
    for ip, evs in _by_key(failures, lambda e: e.ip).items():
        start = i = 0
        while i < len(evs):
            while evs[i].timestamp - evs[start].timestamp > window:
                start += 1
            if len({e.user for e in evs[start : i + 1]}) >= min_users:
                # grow to the full window, report once, then skip past it
                end = i
                while end + 1 < len(evs) and evs[end + 1].timestamp - evs[start].timestamp <= window:
                    end += 1
                chunk = evs[start : end + 1]
                users = {e.user for e in chunk}
                findings.append(
                    Finding(
                        rule="password_spray",
                        severity="high",
                        technique_id="T1110.003",
                        technique_name="Brute Force: Password Spraying",
                        subject=ip,
                        first_seen=chunk[0].timestamp,
                        last_seen=chunk[-1].timestamp,
                        summary=f"{len(chunk)} failed logins across {len(users)} accounts from one IP",
                        evidence=chunk,
                    )
                )
                start = i = end + 1
                continue
            i += 1
    return findings


def brute_force(
    events: list[Event],
    threshold: int = 10,
    window: timedelta = timedelta(minutes=15),
    success_window: timedelta = timedelta(minutes=10),
) -> list[Finding]:
    """Many failed logins against one account. Critical if a success follows."""
    findings = []
    for user, evs in _by_key(events, lambda e: e.user).items():
        fails = [e for e in evs if e.event_type == "login_failure"]
        wins = [e for e in evs if e.event_type == "login_success"]
        for burst in _sliding_bursts(fails, window, threshold):
            last = burst[-1].timestamp
            win = next((w for w in wins if last <= w.timestamp <= last + success_window), None)
            summary = f"{len(burst)} failed logins in {window.seconds // 60} min"
            evidence = list(burst)
            if win:
                summary += f", then a successful login from {win.ip}"
                evidence.append(win)
            findings.append(
                Finding(
                    rule="brute_force",
                    severity="critical" if win else "medium",
                    technique_id="T1110.001",
                    technique_name="Brute Force: Password Guessing",
                    subject=user,
                    first_seen=burst[0].timestamp,
                    last_seen=evidence[-1].timestamp,
                    summary=summary,
                    evidence=evidence,
                )
            )
    return findings


ALL_RULES: dict[str, Callable[[list[Event]], list[Finding]]] = {
    "impossible_travel": impossible_travel,
    "mfa_fatigue": mfa_fatigue,
    "password_spray": password_spray,
    "brute_force": brute_force,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


def run_all(events: list[Event], rules: Iterable[str] | None = None) -> list[Finding]:
    selected = rules or ALL_RULES.keys()
    findings: list[Finding] = []
    for name in selected:
        findings.extend(ALL_RULES[name](events))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
