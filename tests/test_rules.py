import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from detector import load_csv, run_all
from detector.models import Event
from detector.rules import brute_force, haversine_km, impossible_travel, mfa_fatigue, password_spray

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 11, 1, 12, 0, 0)
TULSA = (36.154, -95.993)
LAGOS = (6.524, 3.379)
OKC = (35.468, -97.516)


def ev(minutes, user="a@x.com", kind="login_success", ip="1.1.1.1", loc=TULSA):
    return Event(T0 + timedelta(minutes=minutes), user, kind, ip, lat=loc[0], lon=loc[1])


def test_haversine_known_distance():
    # Tulsa to Oklahoma City is about 160 km
    assert haversine_km(*TULSA, *OKC) == pytest.approx(160, abs=10)


def test_impossible_travel_flags_fast_jump():
    findings = impossible_travel([ev(0), ev(30, loc=LAGOS)])
    assert len(findings) == 1 and findings[0].technique_id == "T1078"


def test_impossible_travel_ignores_real_flight_and_nearby_city():
    assert impossible_travel([ev(0), ev(14 * 60, loc=LAGOS)]) == []
    assert impossible_travel([ev(0), ev(5, loc=OKC)]) == []  # under min distance


def test_mfa_fatigue_critical_when_user_gives_in():
    evs = [ev(i, kind="mfa_push_denied") for i in range(6)] + [ev(9, kind="mfa_success")]
    [f] = mfa_fatigue(evs)
    assert f.severity == "critical" and f.technique_id == "T1621"


def test_mfa_fatigue_high_without_approval_and_quiet_below_threshold():
    [f] = mfa_fatigue([ev(i, kind="mfa_push_timeout") for i in range(6)])
    assert f.severity == "high"
    assert mfa_fatigue([ev(i, kind="mfa_push_denied") for i in range(3)]) == []


def test_password_spray_needs_many_distinct_users():
    spray = [ev(i, user=f"u{i}@x.com", kind="login_failure", ip="9.9.9.9") for i in range(12)]
    [f] = password_spray(spray)
    assert f.subject == "9.9.9.9" and f.technique_id == "T1110.003"
    same_user = [ev(i, kind="login_failure", ip="9.9.9.9") for i in range(12)]
    assert password_spray(same_user) == []


def test_brute_force_reports_once_per_burst():
    evs = [ev(i * 0.5, kind="login_failure") for i in range(20)] + [ev(12)]
    [f] = brute_force(evs)
    assert f.severity == "critical" and len(f.evidence) == 21


def test_unknown_event_type_rejected():
    with pytest.raises(ValueError):
        ev(0, kind="logout")


def test_sample_log_finds_exactly_the_injected_attacks(tmp_path):
    out = tmp_path / "sample.csv"
    subprocess.run([sys.executable, str(ROOT / "generate_sample.py"), "--out", str(out)], check=True)
    findings = run_all(load_csv(out))
    got = {(f.rule, f.subject, f.severity) for f in findings}
    assert got == {
        ("impossible_travel", "alice@example.com", "high"),
        ("mfa_fatigue", "bob@example.com", "critical"),
        ("password_spray", "45.155.205.99", "high"),
        ("brute_force", "carol@example.com", "critical"),
    }
