"""Command-line entry point: python -m detector <log.csv>"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from .loader import load_csv
from .rules import ALL_RULES, run_all

COLORS = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="detector",
        description="Detect account takeover patterns in identity-provider login logs.",
    )
    parser.add_argument("logfile", help="CSV of auth events")
    parser.add_argument("--rules", nargs="+", choices=sorted(ALL_RULES), help="run only these rules")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args(argv)

    events = load_csv(args.logfile)
    findings = run_all(events, args.rules)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 1 if findings else 0

    use_color = sys.stdout.isatty() and not args.no_color
    print(f"Scanned {len(events):,} events. {len(findings)} finding(s).\n")
    for f in findings:
        sev = f.severity.upper()
        if use_color:
            sev = f"{COLORS[f.severity]}{sev}{RESET}"
        print(f"[{sev}] {f.rule}  {f.technique_id} {f.technique_name}")
        print(f"    subject: {f.subject}")
        print(f"    window:  {f.first_seen:%Y-%m-%d %H:%M} to {f.last_seen:%H:%M}")
        print(f"    detail:  {f.summary}\n")

    if findings:
        counts = Counter(f.severity for f in findings)
        print("Summary: " + ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium") if counts[s]))
    # non-zero exit when something is found, so it can gate a CI job or cron alert
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
