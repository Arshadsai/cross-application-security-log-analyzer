# Cross-Application Security Log Analyzer

A Python security-monitoring project that analyzes login events, identifies repeated failed login attempts, and generates security reports. It includes a local Flask login application to demonstrate event collection and alerting.

## Features

- Records successful and failed login attempts in a CSV file.
- Analyzes login events by IP address.
- Counts failed attempts and flags counts that meet a configurable threshold.
- Detects repeated failed logins within a configurable five-minute time window in the local Flask demo.
- Generates a text-based security report.
- Includes automated tests for log analysis and time-window detection.
- Handles invalid log rows and missing CSV columns.

## Technologies

- Python
- Flask
- CSV-based event logging
- HTML and CSS
- `unittest`

## Project Files

- `analyzer.py` — analyzes CSV logs and generates reports.
- `app.py` — local demonstration login application and recent-failure detection.
- `sample_logs.csv` — sample input events.
- `login_events.csv` — events recorded by the local app.
- `security_report.txt` — generated analysis report.
- `test_analyzer.py` — tests for the original log analyzer.
- `test_time_window.py` — tests for recent-failure detection.
- `requirements.txt` — Python dependency list.

## Setup

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the local demonstration:

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

Demo credentials:

- Username: `student`
- Password: `demo123`

These credentials are for local testing only. Do not expose this demo to the public internet or use real credentials.

## Analyze a CSV File

Run the analyzer against the sample file:

```bash
python analyzer.py --file sample_logs.csv --threshold 3
```

Analyze the events recorded by the local app:

```bash
python analyzer.py --file login_events.csv --threshold 2
```

## Run Tests

Run all automated tests:

```bash
python -m unittest -v
```

## Limitations

- This is an educational demonstration, not a production authentication system.
- The local demo normally records `127.0.0.1` as the client IP address.
- CSV files are used instead of a database or centralized logging platform.
- The time-window alert checks recent failed attempts from the same IP address. It does not identify individual people or prove malicious intent.
- The generated report summarizes the full log, while the web alert uses the recent time window.
- The demo does not implement account lockout, production-grade authentication, or deployment security.

## Future Improvements

- Add a dashboard with event summaries.
- Support additional log formats.
- Add configurable detection windows and thresholds.
- Improve report filtering and visualization.
- Add more automated tests for malformed timestamps and edge cases.

## Learning Outcomes

This project demonstrates Python file handling, CSV parsing, log analysis, exception handling, automated testing, basic Flask development, and a simple defensive security-monitoring workflow.