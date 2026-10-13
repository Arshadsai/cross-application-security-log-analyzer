
import csv
import argparse

REPORT_FILE = "security_report.txt"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze login security logs from a CSV file."
    )

    parser.add_argument(
        "--file",
        default="sample_logs.csv",
        help="Path to the CSV log file."
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed attempts required to trigger an alert."
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    return args


def analyze_logs(filename):
    total_success = 0
    total_failed = 0
    failed_by_ip = {}
    invalid_rows = 0

    with open(filename, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        required_columns = {"timestamp", "ip_address", "status"}

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or has no header.")

        reader.fieldnames = [
            (name or "").strip().lower()
            for name in reader.fieldnames
        ]

        if not required_columns.issubset(reader.fieldnames):
            raise ValueError(
                "CSV must contain timestamp, ip_address, and status columns."
            )

        for row in reader:
            timestamp = (row.get("timestamp") or "").strip()
            ip = (row.get("ip_address") or "").strip()
            status = (row.get("status") or "").strip().upper()

            if not timestamp or not ip or status not in {"SUCCESS", "FAILED"}:
                invalid_rows += 1
                continue

            if status == "SUCCESS":
                total_success += 1
            else:
                total_failed += 1
                failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

    return total_success, total_failed, failed_by_ip, invalid_rows


def create_report(results, threshold):
    total_success, total_failed, failed_by_ip, invalid_rows = results

    lines = [
        "CROSS-APPLICATION SECURITY LOG ANALYZER",
        "=" * 42,
        "",
        "ANALYSIS SUMMARY",
        "-" * 42,
        f"Successful logins: {total_success}",
        f"Failed logins: {total_failed}",
        f"Total valid events: {total_success + total_failed}",
        f"Invalid rows skipped: {invalid_rows}",
        "",
        "FAILED ATTEMPTS BY IP",
        "-" * 42,
    ]

    if failed_by_ip:
        for ip, count in sorted(failed_by_ip.items()):
            lines.append(f"{ip}: {count} failed attempts")
    else:
        lines.append("No failed login attempts recorded.")

    lines.extend(["", "SECURITY ALERTS", "-" * 42])

    alerts = [
        (ip, count)
        for ip, count in failed_by_ip.items()
        if count >= threshold
    ]

    if alerts:
        for ip, count in sorted(alerts):
            lines.append(
                f"WARNING: {ip} has {count} failed attempts."
            )
            lines.append("Action: Review this activity.")
    else:
        lines.append("No IP addresses reached the alert threshold.")

    lines.append(f"\nAlert threshold: {threshold}")

    return "\n".join(lines) + "\n"


def main():
    print("CROSS-APPLICATION SECURITY LOG ANALYZER")
    print("=" * 42)

    try:
        args = parse_arguments()

        results = analyze_logs(args.file)
        report = create_report(results, args.threshold)

        print("\n" + report)

        with open(REPORT_FILE, "w", encoding="utf-8") as file:
            file.write(report)

        print(f"Report saved to {REPORT_FILE}")

    except (OSError, ValueError, csv.Error) as error:
        print(f"ERROR: Could not analyze the log file: {error}")


if __name__ == "__main__":
    main()
