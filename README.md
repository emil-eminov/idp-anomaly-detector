# idp-anomaly-detector

Detects account takeover patterns in identity-provider (IdP) login logs and maps every finding to a MITRE ATT&CK technique.

Most identity providers (Okta, Entra ID, Ping) log every login attempt and MFA prompt, but the attacks that matter show up as patterns *across* events, not in any single line. This tool reads a login log, applies four rule-based detectors, and prints a prioritized report an analyst can act on.

```
$ python -m detector sample_logs.csv
Scanned 1,261 events. 4 finding(s).

[CRITICAL] mfa_fatigue  T1621 Multi-Factor Authentication Request Generation
    subject: bob@example.com
    window:  2026-11-11 23:40 to 23:47
    detail:  8 rejected/ignored MFA pushes in 10 min, then approved at 23:47 from 185.220.101.4

[CRITICAL] brute_force  T1110.001 Brute Force: Password Guessing
    subject: carol@example.com
    window:  2026-11-14 02:00 to 02:08
    detail:  14 failed logins in 15 min, then a successful login from 102.89.9.200

[HIGH] impossible_travel  T1078 Valid Accounts
    subject: alice@example.com
    window:  2026-11-10 09:00 to 09:35
    detail:  Tulsa -> Lagos: 10,413 km in 35 min (~17,851 km/h)

[HIGH] password_spray  T1110.003 Brute Force: Password Spraying
    subject: 45.155.205.99
    window:  2026-11-13 03:00 to 03:14
    detail:  15 failed logins across 15 accounts from one IP

Summary: 2 critical, 2 high
```

## Detections

| Rule | ATT&CK | Fires when | Escalates to critical when |
|---|---|---|---|
| `mfa_fatigue` | [T1621](https://attack.mitre.org/techniques/T1621/) | 5+ denied or ignored MFA pushes for one user within 10 min | the user approves a push within 15 min of the flood |
| `brute_force` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | 10+ failed logins on one account within 15 min | a successful login follows within 10 min |
| `password_spray` | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | one IP fails logins against 10+ distinct accounts within 30 min | |
| `impossible_travel` | [T1078](https://attack.mitre.org/techniques/T1078/) | two successful logins 500+ km apart imply travel faster than 900 km/h | |

Design choices:

- **Severity follows outcome.** Failed attacks are noise; failed attacks followed by a success are an incident. Both MFA fatigue and brute force escalate only when the attacker appears to have gotten in.
- **Bursts are reported once.** A 14-attempt brute force is one finding, not five overlapping ones, so the report stays readable.
- **Distance floor on impossible travel.** IP geolocation is often off by a few hundred kilometres, so short jumps between nearby cities are ignored.
- **Every threshold is a keyword argument** in `detector/rules.py`, so it can be tuned to an environment's baseline.
- **Exit code 1 when anything is found**, so the tool can gate a CI job or a cron alert.

## Quick start

Requires Python 3.10+. No third-party dependencies.

```bash
git clone https://github.com/emil-eminov/idp-anomaly-detector.git
cd idp-anomaly-detector
python generate_sample.py            # writes sample_logs.csv
python -m detector sample_logs.csv   # human-readable report
python -m detector sample_logs.csv --json
python -m detector sample_logs.csv --rules mfa_fatigue impossible_travel
```

## Log format

CSV with one row per authentication event:

| column | required | example |
|---|---|---|
| `timestamp` | yes | `2026-11-11T23:40:00` (ISO 8601) |
| `user` | yes | `bob@example.com` |
| `event_type` | yes | `login_success`, `login_failure`, `mfa_push_denied`, `mfa_push_timeout`, `mfa_success` |
| `ip` | yes | `185.220.101.4` |
| `country`, `city`, `lat`, `lon` | no | needed only for `impossible_travel` |

Exporting from a real IdP means mapping its event names onto these five types (for Okta, `user.session.start` and `user.authentication.auth_via_mfa` outcomes).

## Sample data

`generate_sample.py` builds one week of synthetic activity for 40 users, with realistic noise (mistyped passwords, the occasional accidental MFA deny, and a legitimate Tulsa to Munich business trip) plus four injected attacks. The test suite checks that the detector finds exactly those four attacks and nothing else. No real log data is used anywhere in this repository.

## Tests

```bash
pip install pytest
python -m pytest
```

## Roadmap

- Okta System Log and Entra ID sign-in log importers
- New-device and new-ASN detection for privileged accounts
- Per-user baselines (statistical anomaly scoring) to complement the fixed rules

## Credits

Detection design and direction by [Emil Eminov](https://github.com/emil-eminov), drawing on identity and access management audit work and fraud and anomaly detection research. Implementation written with an AI pair-programmer.

## License

MIT
