
import csv
import os
import tempfile
import unittest

from analyzer import analyze_logs, create_report


class TestSecurityLogAnalyzer(unittest.TestCase):

    # Test 1: Check login counts from the original sample CSV
    def test_login_counts(self):
        results = analyze_logs("sample_logs.csv")

        total_success, total_failed, failed_by_ip, invalid_rows = results

        self.assertEqual(total_success, 3)
        self.assertEqual(total_failed, 4)
        self.assertEqual(failed_by_ip["203.0.113.5"], 3)
        self.assertEqual(failed_by_ip["198.51.100.8"], 1)
        self.assertEqual(invalid_rows, 0)

    # Test 2: Check alerts at threshold 3
    def test_alert_threshold(self):
        results = (
            3, 4,
            {"203.0.113.5": 3, "198.51.100.8": 1},
            0
        )

        report = create_report(results, 3)

        self.assertIn(
            "WARNING: 203.0.113.5 has 3 failed attempts.",
            report
        )
        self.assertNotIn(
            "WARNING: 198.51.100.8 has 1 failed attempts.",
            report
        )

    # Test 3: Check alerts at threshold 1
    def test_lower_threshold(self):
        results = (
            3, 4,
            {"203.0.113.5": 3, "198.51.100.8": 1},
            0
        )

        report = create_report(results, 1)

        self.assertIn(
            "WARNING: 203.0.113.5 has 3 failed attempts.",
            report
        )
        self.assertIn(
            "WARNING: 198.51.100.8 has 1 failed attempts.",
            report
        )

    # Test 4: Check that invalid statuses are skipped
    def test_invalid_status_is_skipped(self):
        filename = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                newline="",
                encoding="utf-8",
                suffix=".csv",
                delete=False
            ) as file:
                filename = file.name
                writer = csv.writer(file)

                writer.writerow(
                    ["timestamp", "ip_address", "status"]
                )
                writer.writerow(
                    ["2026-10-13 09:00:00", "192.0.2.10", "UNKNOWN"]
                )
                writer.writerow(
                    ["2026-10-13 09:01:00", "192.0.2.11", "SUCCESS"]
                )

            results = analyze_logs(filename)

            self.assertEqual(results[0], 1)
            self.assertEqual(results[1], 0)
            self.assertEqual(results[3], 1)

        finally:
            if filename and os.path.exists(filename):
                os.remove(filename)

    # Test 5: Check that missing required columns raise an error
    def test_missing_columns_raises_error(self):
        filename = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                newline="",
                encoding="utf-8",
                suffix=".csv",
                delete=False
            ) as file:
                filename = file.name
                writer = csv.writer(file)

                writer.writerow(["timestamp", "status"])
                writer.writerow(
                    ["2026-10-13 09:00:00", "SUCCESS"]
                )

            with self.assertRaises(ValueError):
                analyze_logs(filename)

        finally:
            if filename and os.path.exists(filename):
                os.remove(filename)


if __name__ == "__main__":
    unittest.main()
