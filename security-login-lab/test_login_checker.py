"""Run with: python -m unittest -v"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from login_checker import detect_alerts, load_events, write_reports


def event(minute, status="failed", username="alice", device="pc-01", ip="192.0.2.1"):
    return {"timestamp": datetime(2026, 9, 6, tzinfo=timezone.utc) + timedelta(minutes=minute),
            "status": status, "username": username, "device": device,
            "source_ip": ip, "csv_row": minute + 2}


class DetectionTests(unittest.TestCase):
    def test_threshold_and_success(self):
        self.assertEqual(len(detect_alerts([event(0), event(1), event(2), event(3, "success")])), 1)

    def test_below_threshold(self):
        self.assertEqual(detect_alerts([event(0), event(1), event(2, "success")]), [])

    def test_failures_without_success(self):
        self.assertEqual(detect_alerts([event(0), event(1), event(2)]), [])

    def test_separated_failures(self):
        self.assertEqual(detect_alerts([event(0), event(10), event(20), event(21, "success")]), [])

    def test_late_success(self):
        self.assertEqual(detect_alerts([event(0), event(1), event(2), event(5, "success")]), [])

    def test_inclusive_boundaries(self):
        self.assertEqual(len(detect_alerts([event(0), event(1), event(5), event(7, "success")])), 1)

    def test_no_cross_group_combining(self):
        for field, value in [("username", "bob"), ("device", "pc-02"), ("source_ip", "192.0.2.2")]:
            with self.subTest(field=field):
                other = event(1)
                other[field] = value
                self.assertEqual(detect_alerts([event(0), other, event(2), event(3, "success")]), [])

    def test_success_resets_history(self):
        data = [event(0), event(1), event(2, "success"), event(3), event(4, "success")]
        self.assertEqual(detect_alerts(data), [])

    def test_no_duplicate_alert_on_second_success(self):
        data = [event(0), event(1), event(2), event(3, "success"), event(4, "success")]
        self.assertEqual(len(detect_alerts(data)), 1)

    def test_unsorted_events(self):
        data = [event(3, "success"), event(2), event(0), event(1)]
        self.assertEqual(len(detect_alerts(data)), 1)

    def test_input_validation(self):
        for row in ["bad,a,pc,192.0.2.1,failed", "2026-09-06T00:00:00,a,pc,192.0.2.1,failed",
                    "2026-09-06T00:00:00Z,a,pc,bad,failed", "2026-09-06T00:00:00Z,a,pc,192.0.2.1,unknown"]:
            with self.subTest(row=row), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "input.csv"
                path.write_text("timestamp,username,device,source_ip,status\n" + row, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_events(path)

    def test_report_escapes_html(self):
        data = [event(0), event(1), event(2), event(3, "success")]
        for item in data:
            item["username"] = "<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as folder:
            report = write_reports(detect_alerts(data), data, folder,
                                   {"threshold": 3, "window_minutes": 5, "success_minutes": 2})
            content = report.read_text(encoding="utf-8")
            self.assertNotIn("<script>", content)
            self.assertIn("&lt;script&gt;", content)

    def test_sample_dataset(self):
        data = load_events(Path(__file__).parent / "data" / "login_events.csv")
        alerts = detect_alerts(data)
        self.assertEqual(len(data), 10)
        self.assertEqual([a["username"] for a in alerts], ["alice"])


if __name__ == "__main__":
    unittest.main()
