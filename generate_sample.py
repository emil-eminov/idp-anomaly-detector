"""Generate a synthetic identity-provider login log with injected attacks.

Usage: python generate_sample.py [--out sample_logs.csv] [--seed 7]

Produces one week of normal activity for 40 users, plus four labelled
attack scenarios, so the detector can be demonstrated and tested without
real (sensitive) log data.
"""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta

CITIES = {
    "Tulsa": ("US", 36.154, -95.993),
    "Chicago": ("US", 41.878, -87.630),
    "Austin": ("US", 30.267, -97.743),
    "Denver": ("US", 39.739, -104.990),
    "Seattle": ("US", 47.606, -122.332),
    "Munich": ("DE", 48.135, 11.582),
    "Lagos": ("NG", 6.524, 3.379),
    "Bucharest": ("RO", 44.427, 26.103),
}
HOME_CITIES = ["Tulsa", "Chicago", "Austin", "Denver", "Seattle"]
FIELDS = ["timestamp", "user", "event_type", "ip", "country", "city", "lat", "lon"]
START = datetime(2026, 11, 9, 0, 0, 0)


def row(ts, user, event_type, ip, city):
    country, lat, lon = CITIES[city]
    return {
        "timestamp": ts.isoformat(timespec="seconds"),
        "user": user,
        "event_type": event_type,
        "ip": ip,
        "country": country,
        "city": city,
        "lat": lat,
        "lon": lon,
    }


def normal_activity(rng: random.Random, n_users: int = 40) -> list[dict]:
    rows = []
    for u in range(n_users):
        user = f"user{u:02d}@example.com"
        home = rng.choice(HOME_CITIES)
        ip = f"10.{u}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        for day in range(7):
            for _ in range(rng.randint(1, 3)):
                ts = START + timedelta(days=day, hours=rng.uniform(7, 19))
                if rng.random() < 0.15:  # a mistyped password now and then
                    rows.append(row(ts, user, "login_failure", ip, home))
                    ts += timedelta(seconds=rng.randint(10, 60))
                rows.append(row(ts, user, "login_success", ip, home))
                if rng.random() < 0.05:  # an occasional accidental MFA deny
                    rows.append(row(ts + timedelta(seconds=5), user, "mfa_push_denied", ip, home))
                rows.append(row(ts + timedelta(seconds=20), user, "mfa_success", ip, home))
    # benign: a real business trip, Tulsa -> Munich with 11 hours in between
    t = START + timedelta(days=3, hours=8)
    rows.append(row(t, "traveler@example.com", "login_success", "10.99.0.5", "Tulsa"))
    rows.append(row(t + timedelta(hours=11), "traveler@example.com", "login_success", "85.214.3.9", "Munich"))
    return rows


def attacks() -> list[dict]:
    rows = []

    # 1. Impossible travel: Tulsa login, then Lagos 35 minutes later
    t = START + timedelta(days=1, hours=9)
    rows.append(row(t, "alice@example.com", "login_success", "10.1.1.20", "Tulsa"))
    rows.append(row(t + timedelta(minutes=35), "alice@example.com", "login_success", "102.89.4.17", "Lagos"))

    # 2. MFA fatigue: attacker has the password, floods pushes until the user gives in
    t = START + timedelta(days=2, hours=23, minutes=40)
    for i in range(8):
        kind = "mfa_push_denied" if i % 2 else "mfa_push_timeout"
        rows.append(row(t + timedelta(seconds=45 * i), "bob@example.com", kind, "185.220.101.4", "Bucharest"))
    rows.append(row(t + timedelta(minutes=7), "bob@example.com", "mfa_success", "185.220.101.4", "Bucharest"))

    # 3. Password spray: one IP, one password guess each against 15 accounts
    t = START + timedelta(days=4, hours=3)
    for i in range(15):
        rows.append(
            row(t + timedelta(minutes=i), f"user{i:02d}@example.com", "login_failure", "45.155.205.99", "Bucharest")
        )

    # 4. Brute force on one account, ending in a successful login
    t = START + timedelta(days=5, hours=2)
    for i in range(14):
        rows.append(row(t + timedelta(seconds=30 * i), "carol@example.com", "login_failure", "102.89.9.200", "Lagos"))
    rows.append(row(t + timedelta(minutes=8), "carol@example.com", "login_success", "102.89.9.200", "Lagos"))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="sample_logs.csv")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    rows = normal_activity(random.Random(args.seed)) + attacks()
    rows.sort(key=lambda r: r["timestamp"])
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows):,} events to {args.out}")


if __name__ == "__main__":
    main()
