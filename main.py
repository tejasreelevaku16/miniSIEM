"""
Mini-SIEM Main Runner.

Entry point for the Mini-SIEM application. Loads authentication logs from
a CSV file, executes detection rules, and displays alerts in a clear,
analyst-friendly format in the terminal.
"""

from datetime import datetime
from pathlib import Path
import sys

from app.services.csv_parser import load_logs
from app.services.detection_engine import Alert, detect_brute_force
from app.database import count_incidents, init_db, save_alerts, DEFAULT_DB_PATH

def format_timestamp(dt: datetime) -> str:
    """Formats datetime for clean terminal presentation."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def print_banner() -> None:
    """Displays the Mini-SIEM startup banner."""
    print("=" * 64)
    print("            MINI-SIEM :: SECURITY EVENT MONITOR")
    print("           Authentication Brute-Force Detector")
    print("=" * 64)


def print_alert(alert: Alert, index: int) -> None:
    """
    Renders an alert card in the terminal with key SIEM metadata.

    Args:
        alert: The Alert instance to display.
        index: The alert sequence number (1-based).
    """
    duration = int((alert.window_end - alert.window_start).total_seconds())
    user_list = ", ".join(alert.targeted_usernames) if alert.targeted_usernames else "unknown"

    print(f"\n[ALERT #{index}] ----------------------------------------------")
    print(f"  Severity:          [{alert.severity}]")
    print(f"  Source IP:         {alert.source_ip}")
    print(f"  Failed Attempts:   {alert.failure_count}")
    print(f"  Time Window:       {format_timestamp(alert.window_start)} -> {format_timestamp(alert.window_end)} ({duration}s)")
    print(f"  Targeted User(s):  {user_list}")
    print(f"  Summary:           {alert.description}")
    print("  Recommended Action: Consider blocking/throttling IP at the firewall")
    print("-" * 55)


def run_siem(file_path: Path) -> int:
    """
    Coordinates the log ingestion, rule detection, and alert output.

    Args:
        file_path: Path to the CSV log file.

    Returns:
        Exit code (0 for normal execution, 1 for fatal error).
    """
    print_banner()
    print(f"[*] Analyzing log file: {file_path.resolve()}")

    # 1. Ingest and parse logs
    events, warnings = load_logs(file_path)

    # 2. Display parser warnings (e.g. malformed rows, missing fields)
    if warnings:
        print(f"\n[!] Log Parser Warnings ({len(warnings)}):")
        for warn in warnings:
            print(f"    - {warn}")

    if not events:
        print("\n[!] No valid log events available for analysis.")
        return 1

    print(f"[*] Successfully ingested {len(events)} valid log event(s).")
    print("[*] Running detection rule: 'Brute-Force Login (>=3 failures in 5m)'...")

    # 3. Execute detection engine
    alerts = detect_brute_force(events, threshold=3, window_minutes=5)

    # 4. Display results
    print("\n" + "=" * 64)
    print("                         DETECTION REPORT")
    print("=" * 64)

    if not alerts:
        print("\n[+] Clean run: No suspicious brute-force activity detected.")
    else:
        print(f"\n[!] Discovered {len(alerts)} suspicious incident(s):")
        for idx, alert in enumerate(alerts, start=1):
            print_alert(alert, idx)

    # 5. Persist alerts to SQLite database with deduplication
    db_file = DEFAULT_DB_PATH
    init_db(db_file)
    if alerts:
        saved_count, dup_count = save_alerts(alerts, db_file)
        total_stored = count_incidents(db_file)
        print(f"\n[*] Incident Storage ({db_file.name}):")
        print(f"    - {saved_count} incident(s) newly saved to database")
        print(f"    - {dup_count} duplicate incident(s) skipped")
        print(f"    - Total stored incidents in database: {total_stored}")
    else:
        total_stored = count_incidents(db_file)
        print(f"\n[*] Incident Storage ({db_file.name}): {total_stored} incident(s) currently on file.")

    print("\n" + "=" * 64)
    print(f"[*] Analysis complete at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 64)
    return 0


def main() -> None:
    """Main CLI handler."""
    # Allow specifying a custom log file or default to sample_logs.csv in the script's directory
    default_log_file = Path(__file__).parent / "sample_logs" / "sample_logs.csv"
    if len(sys.argv) > 1:
        target_file = Path(sys.argv[1])
    else:
        target_file = default_log_file

    exit_code = run_siem(target_file)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
