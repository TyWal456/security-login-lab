# Distribution Defense: Python Security Login Lab

An independent beginner security-operations portfolio project. All bundled events are fictional; this project is not affiliated with ABARTA Coca-Cola or any employer.

## What this project does

Reads authentication events from CSV, detects repeated failed logins followed by success, and exports an HTML investigation report plus CSV/JSON evidence. It does not connect to production systems or disable accounts.

**Requirements:** Python 3.10 or later. No additional packages or installation commands are required. Built and tested in Python; intended to run on Windows, macOS, and Linux.

## Start here — Windows




## python login_checker.py
```

5. Open `reports`, then double-click `report.html` to see the results in your browser.

Expected console result with the unchanged sample dataset:

```text
Reviewed 10 events. Found 1 alert(s).
AUTH-001: alice / warehouse-pc-01 — 3 failures followed by success.
```

The command also prints the report's location. If `python` is unavailable on a different machine, try `python3`. Do not type the code-block label or the command prompt's folder path.

## Files

| File | Purpose |
|---|---|
| `login_checker.py` | Main program; open this in Notepad++ to study or edit it |
| `data/login_events.csv` | Ten fictional events covering three scenarios |
| `test_login_checker.py` | Automated checks for detection and validation behavior |
| `reports/report.html` | Generated visual report, opens locally without a server |
| `reports/alerts.csv` | One row per alert |
| `reports/results.json` | Full alert evidence and rule settings |
| `TEST_RESULTS.md` | Recorded verification and sample outcomes |
| `INVESTIGATION_TEMPLATE.md` | Prompts for your own analysis |

## Read the Python in this order

1. Imports: standard-library tools for CSV, timestamps, reports, and command-line options.
2. `load_events`: checks the columns, timestamps, IP addresses, and status values.
3. `detect_alerts`: groups records and applies the rule.
4. `write_reports`: turns real calculation results into report files.
5. `main`: connects the steps and displays friendly error messages.

Unlike the earlier counting-only exercise, this version requires a successful login after the failures. Three failures alone will not alert.

## Exact rule

For each exact `(username, device, source_ip)` group:

- Require at least **3 failures within 5 minutes**, measured backward from the latest failure.
- Require a subsequent **success within 2 minutes of that latest failure**.
- Time boundaries are inclusive. Every success resets that group's pending failures.
- Input is sorted by timestamp. Tied timestamps retain CSV order.
- Username and device matching is case-sensitive. IP addresses are normalized.

An alert means **investigate**, not **confirmed compromise**. Legitimate password mistakes can match this rule.

## Input format

Required CSV columns: `timestamp,username,device,source_ip,status`.

Timestamps must include a timezone, such as `2026-09-06T09:00:00Z`. The program normalizes time to UTC. Status is `failed` or `success`. Use fictional accounts and documentation IP addresses for portfolio data.

Invalid input stops analysis with an error and a nonzero exit code. If reports from a previous run already exist, they remain unchanged; do not mistake them for new results after an error. Empty input with valid headers yields zero events and alerts.

## Change the rule or input

```text
python login_checker.py --threshold 5 --window-minutes 4 --success-minutes 2
python login_checker.py --input data/my_events.csv --output reports/my_test
python login_checker.py --help
```

With threshold 5, the bundled dataset produces no alerts. To reproduce the screenshot's illustrative five-failure scenario, add two distinct failure events within four minutes, followed by success within two minutes. This project implements login analysis, not the screenshot's asset inventory or vulnerability management panels.

Default input/output locations are relative to the script. Explicit relative paths are relative to the command prompt's current folder. Successful runs replace output files in the selected output folder. Use a different `--output` folder to preserve separate experiments.

## Test and record evidence

Run from the project folder:

```text
python -m unittest -v
python -m unittest -v > test-output.txt 2>&1
```

Change one condition at a time and record exact input, expected result, observed result, and your explanation. A passing test suite covers these examples, not all possible environments.

## Limitations and investigation

This offline educational rule is not a SIEM, EDR tool, or proof of production experience. It does not detect distributed attempts across IPs/devices, failure-only attacks, or behavior outside the time windows. It counts duplicate records independently. It loads the CSV into memory and is designed for small lab datasets.

The HTML is a static report generated directly from Python's findings, not a live dashboard. Rerun Python and refresh/reopen the HTML to update it. All styling is local; no internet connection is needed.

Use the investigation template to explain what you know, what you still need to verify, and why your recommended response is appropriate. Coordinate any proposed disruption to distribution/manufacturing systems with their owners. This program takes no containment actions.

## Publish on GitHub

Create a repository such as `security-login-lab`. Upload the extracted project files, not just the ZIP. Keep only synthetic/sanitized data and inspect all output before publishing. Include your own test notes and investigation conclusions. Clearly distinguish this lab from employment experience, and acknowledge any assistance used to build it.

Suggested next improvements: correlate asset criticality, add evidence-driven triage notes, and implement the same rule in KQL with documented schema differences.
