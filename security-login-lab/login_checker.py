"""Security portfolio lab: detect failed logins followed by success.

Uses synthetic CSV events. No third-party packages, network access, or
account changes. Run: python login_checker.py
"""

import argparse
import csv
import html
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REQUIRED_FIELDS = {"timestamp", "username", "device", "source_ip", "status"}


def load_events(path):
    """Validate CSV input and return events sorted in UTC chronological order."""
    events = []
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not REQUIRED_FIELDS.issubset(reader.fieldnames or []):
            raise ValueError("CSV must contain: " + ", ".join(sorted(REQUIRED_FIELDS)))
        for line_number, row in enumerate(reader, start=2):
            event = {name: (row.get(name) or "").strip() for name in REQUIRED_FIELDS}
            if not all(event.values()):
                raise ValueError(f"Row {line_number}: a required value is empty.")
            try:
                timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("Timestamp must include a timezone, such as Z or +00:00")
                ipaddress.ip_address(event["source_ip"])
            except ValueError as error:
                raise ValueError(f"Row {line_number}: {error}") from error
            if event["status"] not in {"failed", "success"}:
                raise ValueError(f"Row {line_number}: status must be failed or success.")
            event["timestamp"] = timestamp.astimezone(timezone.utc)
            event["source_ip"] = str(ipaddress.ip_address(event["source_ip"]))
            event["csv_row"] = line_number
            events.append(event)
    return sorted(events, key=lambda event: event["timestamp"])


def detect_alerts(events, threshold=3, window_minutes=5, success_minutes=2):
    """Find failure bursts followed by success for the same user/device/IP.

    The failure window ends at the most recent failure preceding a success.
    Boundaries are inclusive. Every success resets that group's pending failures.
    """
    if min(threshold, window_minutes, success_minutes) < 1:
        raise ValueError("Threshold and time windows must be positive integers.")
    pending = defaultdict(list)
    alerts = []
    failure_window = timedelta(minutes=window_minutes)
    success_window = timedelta(minutes=success_minutes)

    for event in sorted(events, key=lambda item: item["timestamp"]):
        key = (event["username"], event["device"], event["source_ip"])
        failures = pending[key]
        if event["status"] == "failed":
            cutoff = event["timestamp"] - failure_window
            failures[:] = [item for item in failures if item["timestamp"] >= cutoff]
            failures.append(event)
            continue

        if failures:
            delay = event["timestamp"] - failures[-1]["timestamp"]
            if len(failures) >= threshold and timedelta(0) <= delay <= success_window:
                evidence = failures + [event]
                alerts.append({
                    "alert_id": f"AUTH-{len(alerts) + 1:03d}",
                    "username": key[0],
                    "device": key[1],
                    "source_ip": key[2],
                    "failed_count": len(failures),
                    "first_failure": failures[0]["timestamp"].isoformat(),
                    "last_failure": failures[-1]["timestamp"].isoformat(),
                    "successful_login": event["timestamp"].isoformat(),
                    "verdict": "Needs investigation; compromise is not confirmed",
                    "evidence": [
                        {**item, "timestamp": item["timestamp"].isoformat()}
                        for item in evidence
                    ],
                })
        pending[key] = []
    return alerts


def write_reports(alerts, events, output_dir, settings):
    """Export reproducible evidence and a self-contained HTML report."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat()
    summary = {
        "generated_at": generated,
        "event_count": len(events),
        "alert_count": len(alerts),
        "settings": settings,
        "alerts": alerts,
    }
    (output_dir / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    fields = ["alert_id", "username", "device", "source_ip", "failed_count",
              "first_failure", "last_failure", "successful_login", "verdict"]
    with (output_dir / "alerts.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for alert in alerts:
            # Prevent spreadsheet formula interpretation when reviewing untrusted CSV values.
            safe = {k: ("'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v)
                    for k, v in alert.items()}
            writer.writerow(safe)

    escape = lambda value: html.escape(str(value), quote=True)
    cards = []
    for alert in alerts:
        rows = "".join(
            "<tr>" + "".join(f"<td>{escape(event[field])}</td>"
                            for field in ["csv_row", "timestamp", "status"]) + "</tr>"
            for event in alert["evidence"]
        )
        cards.append(f"""<section><span class="badge">REVIEW REQUIRED</span>
        <h2>{escape(alert['alert_id'])} · {escape(alert['username'])}</h2>
        <p>{escape(alert['device'])} · {escape(alert['source_ip'])}</p>
        <p><strong>{alert['failed_count']} failures followed by a successful login.</strong>
        {escape(alert['verdict'])}.</p>
        <div class="scroll"><table><thead><tr><th>CSV row</th><th>Time (UTC)</th><th>Status</th>
        </tr></thead><tbody>{rows}</tbody></table></div></section>""")
    rule = (f"At least {settings['threshold']} failed logins within {settings['window_minutes']} "
            f"minutes, followed by success within {settings['success_minutes']} minutes of the "
            "last failure, for the same username, device, and source IP.")
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Distribution Defense — Login Analysis</title><style>
    :root{color-scheme:dark}body{margin:0;background:#101722;color:#e6edf7;
    font:16px/1.6 system-ui,sans-serif}main{max-width:1000px;margin:auto;padding:36px 22px}
    h1{font-size:clamp(28px,5vw,44px);line-height:1.15}h2{font-size:22px}
    .eyebrow{color:#a9bfff;letter-spacing:2px;font-size:13px}.muted{color:#b6c2d6}
    section,.metric{background:#1b2636;border:1px solid #35445b;border-radius:12px;padding:22px;margin:18px 0}
    .metrics{display:flex;gap:18px;flex-wrap:wrap}.metric{flex:1;min-width:150px}
    .metric strong{display:block;font-size:30px;color:#b7c8ff}.badge{color:#ffd88b;font-size:12px;letter-spacing:1px}
    table{border-collapse:collapse;width:100%;text-align:left}th,td{padding:10px;border-bottom:1px solid #35445b}
    .scroll{overflow-x:auto}li{margin:8px 0}code{color:#b7c8ff}footer{font-size:13px;color:#b6c2d6}
    @media print{body{background:white;color:black}section,.metric{background:white;color:black}footer,.muted{color:#333}}
    </style></head><body><main><p class="eyebrow">DISTRIBUTION DEFENSE / SECURITY PORTFOLIO LAB</p>
    <h1>From login events to investigation.</h1>
    <p class="muted">Offline analysis · Bundled dataset is fictional · No automated containment</p>
    """
    page += f"<div class='metrics'><div class='metric'>Events reviewed<strong>{len(events)}</strong></div>"
    page += f"<div class='metric'>Alerts to investigate<strong>{len(alerts)}</strong></div></div>"
    page += f"<section><h2>Detection rule</h2><p>{escape(rule)}</p><p>Window boundaries are inclusive. A successful login resets the group's failure history.</p></section>"
    page += "".join(cards) or "<section><h2>No matching alerts</h2><p>No events matched this rule. This does not establish that the environment is secure.</p></section>"
    page += """<section><h2>Suggested analyst next steps</h2><ol>
    <li>Verify whether the user recognizes the activity and check approved administrative work.</li>
    <li>Correlate identity, MFA, endpoint, and network records around the listed timestamps.</li>
    <li>Assess account privileges and device importance; document evidence and uncertainty.</li>
    <li>Escalate confirmed concerns using the organization's response process. Coordinate any
    disruption to distribution or production systems with their owners.</li></ol>
    <p>These are recommendations, not actions taken by this program.</p></section>
    <section><h2>Limitations</h2><p>This small rule does not detect all password attacks.
    It misses distributed attempts across different IPs or devices, failure-only attacks,
    and activity outside its windows. Legitimate password mistakes may also match.
    Input duplicates are counted separately; remove collection duplicates before analysis.</p></section>"""
    page += f"<footer>Generated {escape(generated)} · Evidence: alerts.csv and results.json · Independent educational project; no company affiliation.</footer></main></body></html>"
    (output_dir / "report.html").write_text(page, encoding="utf-8")
    return output_dir / "report.html"


def positive_integer(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Use an integer greater than zero.")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=BASE_DIR / "data" / "login_events.csv")
    parser.add_argument("--output", type=Path, default=BASE_DIR / "reports")
    parser.add_argument("--threshold", type=positive_integer, default=3)
    parser.add_argument("--window-minutes", type=positive_integer, default=5)
    parser.add_argument("--success-minutes", type=positive_integer, default=2)
    args = parser.parse_args()
    settings = {"threshold": args.threshold, "window_minutes": args.window_minutes,
                "success_minutes": args.success_minutes}
    try:
        events = load_events(args.input)
        alerts = detect_alerts(events, **settings)
        report = write_reports(alerts, events, args.output, settings)
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"Reviewed {len(events)} events. Found {len(alerts)} alert(s).")
    for alert in alerts:
        print(f"{alert['alert_id']}: {alert['username']} / {alert['device']} — "
              f"{alert['failed_count']} failures followed by success.")
    print(f"Open this file in your browser: {report.resolve()}")
    print("CSV and JSON evidence saved alongside the HTML report.")


if __name__ == "__main__":
    main()
