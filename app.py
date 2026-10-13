
from flask import Flask, request, render_template_string
from datetime import datetime, timezone, timedelta
import csv
import os

from analyzer import analyze_logs, create_report

app = Flask(__name__)

LOG_FILE = "login_events.csv"
REPORT_FILE = "security_report.txt"

ALERT_THRESHOLD = 2
TIME_WINDOW_MINUTES = 5

DEMO_USERNAME = "student"
DEMO_PASSWORD = "demo123"

PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Security Monitor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 520px;
            margin: 60px auto;
            padding: 20px;
            background: #f3f5f8;
        }

        .card {
            background: white;
            padding: 28px;
            border-radius: 12px;
            box-shadow: 0 3px 14px #0001;
        }

        input, button {
            box-sizing: border-box;
            width: 100%;
            padding: 12px;
            margin-top: 12px;
        }

        button {
            background: #24476b;
            color: white;
            border: 0;
            cursor: pointer;
        }

        .message {
            margin-top: 16px;
            padding: 12px;
            background: #eef3f8;
            border-radius: 6px;
        }

        .alert {
            background: #ffe5e5;
            color: #8b0000;
        }
    </style>
</head>

<body>
    <div class="card">
        <h2>Login Security Monitor</h2>
        <p>Local security monitoring demonstration</p>

        <form method="POST">
            <input name="username"
                   placeholder="Username" required>

            <input name="password" type="password"
                   placeholder="Password" required>

            <button type="submit">Log in</button>
        </form>

        {% if message %}
            <div class="message">{{ message }}</div>
        {% endif %}

        {% if alert %}
            <div class="message alert">
                <strong>Security alert:</strong>
                {{ alert }}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""


def record_event(status, ip_address):
    needs_header = (
        not os.path.exists(LOG_FILE)
        or os.path.getsize(LOG_FILE) == 0
    )

    with open(
        LOG_FILE, "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        if needs_header:
            writer.writerow([
                "timestamp", "ip_address", "status"
            ])

        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            ip_address,
            status
        ])


def count_recent_failures(ip_address):
    """Count failed logins from this IP in the last 5 minutes."""
    if not os.path.exists(LOG_FILE):
        return 0

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=TIME_WINDOW_MINUTES)
    count = 0

    with open(
        LOG_FILE, "r", newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            if (
                (row.get("ip_address") or "").strip()
                != ip_address
                or (row.get("status") or "").strip().upper()
                != "FAILED"
            ):
                continue

            try:
                timestamp = datetime.fromisoformat(
                    row["timestamp"].strip()
                )

                # Handle timestamps that have no timezone.
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(
                        tzinfo=timezone.utc
                    )

                if cutoff <= timestamp <= now:
                    count += 1

            except (ValueError, AttributeError):
                # Ignore rows with invalid timestamps.
                continue

    return count


def update_security_report():
    results = analyze_logs(LOG_FILE)
    report = create_report(results, ALERT_THRESHOLD)

    with open(
        REPORT_FILE, "w", encoding="utf-8"
    ) as file:
        file.write(report)


@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    alert = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip_address = request.remote_addr or "unknown"

        if (
            username == DEMO_USERNAME
            and password == DEMO_PASSWORD
        ):
            record_event("SUCCESS", ip_address)
            message = "Demo login successful."
        else:
            record_event("FAILED", ip_address)
            message = "Login failed. Check your credentials."

            recent_failures = count_recent_failures(ip_address)

            if recent_failures >= ALERT_THRESHOLD:
                alert = (
                    f"{recent_failures} failed attempts from "
                    f"{ip_address} within the last "
                    f"{TIME_WINDOW_MINUTES} minutes. "
                    "Review this activity."
                )

        try:
            update_security_report()
        except (OSError, ValueError, csv.Error) as error:
            app.logger.error(
                "Report generation failed: %s", error
            )
            if not alert:
                alert = (
                    "The event was recorded, but "
                    "report generation failed."
                )

    return render_template_string(
        PAGE, message=message, alert=alert
    )


if __name__ == "__main__":
    # Local development only. Do not expose this demo online.
    app.run(debug=True)
