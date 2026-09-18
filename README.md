# Security log analyzer

A local command-line tool for reviewing authentication events. It groups repeated failures, possible password spraying and successful logins following repeated failures, with the input line numbers behind each finding. Python 3.12+, standard library only.

[Try the sample](#try-the-sample) · [Input format](#input-format) · [Rules](#rules) · [Output](#output) · [Tests](#tests) · [Limits](#limits)

## Try the sample

Run from this repository's directory:

```bash
python analyzer.py samples/authentication.jsonl
python analyzer.py samples/authentication.jsonl --format json
```

The supplied file is entirely synthetic: fictional accounts, a fictional lab host and reserved documentation IP addresses. Its 12 events exercise all three rules. No real authentication records are included.

To analyze your own normalized file, pass its path explicitly:

```bash
python analyzer.py /path/to/events.jsonl --format json
```

The program reads that file and prints a report. It makes no network requests, changes no accounts and takes no automatic action.

## Input format

One JSON object per line, encoded as UTF-8. A UTF-8 BOM and blank lines are accepted. Each event needs these six fields:

```json
{"timestamp":"2026-09-14T09:01:00Z","event":"authentication","host":"lab-server","user":"sample-student","source_ip":"192.0.2.10","outcome":"failure"}
```

| Field | Accepted values |
|---|---|
| `timestamp` | ISO 8601 date/time with `T` and an explicit timezone, such as `Z` or `+01:00` |
| `event` | `authentication` |
| `host` | Nonempty printable text identifying the system |
| `user` | Nonempty printable text identifying the account |
| `source_ip` | IPv4 or IPv6 address; scoped IPv6 addresses are not supported |
| `outcome` | `success` or `failure` |

Text fields are limited to 256 characters. Host and account names are compared exactly, including case. IP addresses are normalized; timestamps are converted to UTC. Extra fields are ignored, but duplicate JSON fields and non-finite numbers are rejected.

Records are sorted by timestamp before detection. Equal timestamps retain their input line order. Evidence refers to physical lines in the original file, including any blank lines. Invalid input stops the analysis with a line-numbered error and exit status 2; no partial report is printed.

## Rules

Every rule uses an inclusive sliding window, 300 seconds by default. An event exactly 300 seconds old still counts.

| Rule | Pattern | Severity |
|---|---|---|
| `repeated_failures` | At least 5 failures for one host, source IP and account | Medium |
| `possible_password_spray` | Failures against at least 5 distinct accounts from one source IP on the same host | Medium |
| `success_after_failures` | A success preceded by at least 5 failures for the same host, source IP and account | High |

Overlapping qualifying windows for the same rule and group merge into one finding. A later window that starts after the previous finding ends creates another finding. Evidence counts include all distinct contributing input lines; the success rule includes the successful event. A success does not erase preceding failures from the window, so later successes can join the same incident.

Adjust thresholds when the environment calls for it:

```bash
python analyzer.py samples/authentication.jsonl --threshold 8 --window-seconds 600 --spray-users 6
```

All threshold values must be positive integers. Severity is a fixed label for the rule, not a calculated probability or confirmation of an attack.

## Output

Text output lists each rule, group, time range and evidence lines. `--format json` emits strict JSON containing event/finding counts, the effective settings and findings. Every finding includes:

- `rule`, `severity`, `host`, `source_ip` and `user` (`null` for a multi-account spray).
- Sorted `users`, UTC `first_seen`/`last_seen`, `event_count` and `evidence_lines`.

Exit status 0 means the file was analyzed successfully, whether findings exist or not. Exit status 2 means invalid arguments, invalid input or a file-reading error. Reports contain account names and IP addresses, so review them before sharing.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests cover window boundaries, threshold counts, overlapping/separate incidents, host/IP/account grouping, timezones, out-of-order records, malformed input, evidence lines and the text/JSON CLI. GitHub Actions runs the same suite on Python 3.12 for pushes, pull requests and manual runs.

The workflow pins [checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2) and [setup-python v5.6.0](https://github.com/actions/setup-python/releases/tag/v5.6.0) to their release commits.

## Limits

A finding is a pattern to investigate, not proof of compromise. Shared IPs, scripted lab exercises and users correcting a forgotten password can produce similar records. Correlate findings with the system's own context.

This tool accepts the documented normalized schema; it does not parse raw Windows Event Logs, Linux journal entries or cloud-provider exports. Missing or misleading source records cannot be repaired by these rules. Repeated copies of the same event count as separate input lines because there is no event ID in the schema.

Records are held in memory for sorting, and qualifying windows are examined to merge evidence. Very dense failure streams can make that work expensive. This implementation is intended for small local investigations, not continuous high-volume ingestion. No rate, detection-accuracy or production-scale claim is made.
