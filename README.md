# Failed Login Detector

A working defensive-security tool that finds repeated authentication failures
within a sliding time window. It supports Linux SSH logs, exported Windows
Security Event 4625 XML, live Windows Security logs, and generic JSON Lines.

This project is intended for systems and logs you own or are authorized to
monitor. It does not generate login attempts or modify accounts.

## Security Notice

This repository is an educational defensive-security lab. It is not a
production monitoring system, and its detections must be validated before they
are used for operational decisions. Analyze only logs and systems you own or
are explicitly authorized to investigate. Included events and addresses are
synthetic or reserved for documentation; no real credentials are included.

Do not deploy this project in production.

## What it detects

- Repeated failures from one source, including password spraying across users
- Repeated failures against one username from multiple sources
- Repeated failures for a specific source-and-username pair
- Threshold crossings within a configurable sliding time window
- Password-spray, brute-force, and distributed-account classifications
- Windows failure reasons derived from common Event 4625 SubStatus codes
- Legacy syslog and modern ISO-8601/journalctl timestamps
- UTF-8 and common UTF-16 Windows XML exports
- SSH password, public-key, invalid-user, maximum-attempt, and PAM failures

## Quick proof that it works

Run the built-in deterministic demonstration:

```powershell
python failed_login_detector.py --format demo
```

It analyzes ten simulated records. Seven rapid failures from the documentation
address `203.0.113.42` trigger one alert, while three failures spaced twenty
minutes apart do not.

Analyze the included Linux SSH fixture:

```powershell
python failed_login_detector.py sample-data/auth.log --format linux --year 2026
```

## Analyze real logs

Linux SSH/authentication log:

```powershell
python failed_login_detector.py /var/log/auth.log --format linux --threshold 5 --window 10
```

Exported Windows Event 4625 XML:

```powershell
python failed_login_detector.py failed-logins.xml --format windows-xml
```

The included synthetic Windows fixture can be used for an immediate end-to-end
check of that input path:

```powershell
python failed_login_detector.py sample-data/windows-4625.xml --format windows-xml
```

Live Windows Security log (run from a terminal that has permission to read it):

```powershell
python failed_login_detector.py --format windows-live --max-events 1000
```

Generic JSON Lines records must contain `timestamp` and `username`. They may
also include `source` or `source_ip`, `platform`, and `event_id`:

```json
{"timestamp":"2026-09-11T10:00:00Z","username":"admin","source_ip":"192.0.2.15"}
```

```powershell
python failed_login_detector.py events.jsonl --format jsonl --json
```

## Correlation modes

- `--group-by source` is the default and detects one source trying many users.
- `--group-by username` detects attacks on one account from multiple sources.
- `--group-by source-user` detects repeated attempts against an exact pair.

Alerts preserve the incident's original start time and cumulative failure count
while the activity remains above the threshold. They also report distinct user
and source counts so analysts can distinguish spraying from brute force.

## Exclusions

Suppress a known scanner subnet or service account with repeatable options:

```powershell
python failed_login_detector.py events.jsonl --format jsonl `
  --exclude-ip 10.20.30.0/24 --exclude-user monitoring-service
```

`--exclude-ip` accepts individual IPv4/IPv6 addresses, CIDRs, or an exact source
label. `--exclude-user` uses a case-insensitive exact match. The report shows how
many events were excluded so filtering remains visible to the analyst.

Use `--fail-on-alert` for automation that should return exit code 1 when an
alert is found. Processing and input errors return exit code 2.

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The project uses only the Python standard library. Tests and demonstrations use
only synthetic documentation addresses and local files; they perform no login
attempts and contact no network hosts. GitHub Actions runs the suite on Python
3.10 and 3.13 for every push and pull request.

## Limitations

- Legacy Linux syslog timestamps omit the year and timezone. `--year` means the
  newest year in the file; chronological December-to-January rollover is handled
  automatically. Legacy timestamps are interpreted as UTC, so confirm the host
  timezone before using them in a formal incident timeline.
- Live Windows collection depends on the current user's permission to read the
  Security log.
- This tool identifies threshold-based patterns. Production detection should
  also account for allowlists, asset criticality, identity context, and known
  administrative activity.
