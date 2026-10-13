
import csv
import os
import unittest
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app import count_recent_failures


class TestTimeWindowDetection(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            delete=False
        )
        self.temp_file.close()

        self.now = datetime.now(timezone.utc)

        with open(
            self.temp_file.name,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp", "ip_address", "status"
            ])

            # Recent failed attempt: should count.
            writer.writerow([
                (self.now - timedelta(minutes=2)).isoformat(),
                "127.0.0.1",
                "FAILED"
            ])

            # Old failed attempt: should not count.
            writer.writerow([
                (self.now - timedelta(minutes=10)).isoformat(),
                "127.0.0.1",
                "FAILED"
            ])

            # Recent successful login: should not count.
            writer.writerow([
                (self.now - timedelta(minutes=1)).isoformat(),
                "127.0.0.1",
                "SUCCESS"
            ])

            # Failure from a different IP: should not count.
            writer.writerow([
                (self.now - timedelta(minutes=1)).isoformat(),
                "192.168.1.10",
                "FAILED"
            ])

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_only_recent_failures_are_counted(self):
        with patch("app.LOG_FILE", self.temp_file.name):
            count = count_recent_failures("127.0.0.1")

        self.assertEqual(count, 1)

    def test_unknown_ip_has_zero_failures(self):
        with patch("app.LOG_FILE", self.temp_file.name):
            count = count_recent_failures("10.0.0.5")

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
