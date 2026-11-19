"""Load authentication events from CSV."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .models import Event

REQUIRED_COLUMNS = {"timestamp", "user", "event_type", "ip"}


def _float_or_none(value: str | None) -> float | None:
    if value is None or value.strip() == "":
        return None
    return float(value)


def load_csv(path: str | Path) -> list[Event]:
    """Read a CSV of auth events and return them sorted by time."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"missing required columns: {sorted(missing)}")
        events = [
            Event(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                user=row["user"].strip().lower(),
                event_type=row["event_type"].strip(),
                ip=row["ip"].strip(),
                country=row.get("country", "") or "",
                city=row.get("city", "") or "",
                lat=_float_or_none(row.get("lat")),
                lon=_float_or_none(row.get("lon")),
            )
            for row in reader
        ]
    return sorted(events, key=lambda e: e.timestamp)
