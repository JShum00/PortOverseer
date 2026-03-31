"""Port Overseer command-line entrypoint."""

from __future__ import annotations

import ctypes
import os
import platform
import sqlite3
import sys

try:
    import colors
    import cve_lookup
    import reporter
    import scanner
    import updater
except ImportError:  # pragma: no cover - package-style import fallback
    from . import colors, cve_lookup, reporter, scanner, updater


TITLE_ART = r"""
                       _______    ______     _______  ___________
                      |   __ "\  /    " \   /"      \("     _   ")
                      (. |__) :)// ____  \ |:        |)__/  \\__/
                      |:  ____//  /    ) :)|_____/   )   \\_ /
                      (|  /   (: (____/ //  //      /    |.  |
                     /|__/ \   \        /  |:  __   \    \:  |
                    (_______)   \"_____/   |__|  \___)    \__|

    ______  ___      ___  _______   _______    ________  _______   _______   _______
   /    " \|"  \    /"  |/"     "| /"      \  /"       )/"     "| /"     "| /"      \
  // ____  \\   \  //  /(: ______)|:        |(:   \___/(: ______)(: ______)|:        |
 /  /    ) :)\\  \/. ./  \/    |  |_____/   ) \___  \   \/    |   \/    |  |_____/   )
(: (____/ //  \.    //   // ___)_  //      /   __/  \\  // ___)_  // ___)_  //      /
 \        /    \\   /   (:      "||:  __   \  /" \   :)(:      "|(:      "||:  __   \
  \"_____/      \__/     \_______)|__|  \___)(_______/  \_______) \_______)|__|  \___)
"""

TAGLINE = "Vulnerability Hunt & Scan // v1.0"
REPORTS_DIR = reporter.REPORTS_DIR


def has_required_privileges() -> bool:
    """Return True when the current process has elevated privileges."""
    system_name = platform.system()

    if system_name == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin()) # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False

    if system_name == "Linux":
        return os.geteuid() == 0

    return False


def enforce_privileges() -> None:
    """Exit early when the process is not running with sufficient privileges."""
    if has_required_privileges():
        return

    system_name = platform.system()
    if system_name == "Windows":
        print("Error: Port Overseer must be run from an Administrator command prompt.")
    elif system_name == "Linux":
        print("Error: Port Overseer must be run as root (for example, with sudo).")
    else:
        print(
            "Error: Port Overseer requires elevated privileges on this platform, "
            "but automatic verification is only implemented for Windows and Linux."
        )
    sys.exit(1)


def clear_screen() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")


def print_title_screen() -> None:
    clear_screen()
    print(TITLE_ART)
    print(TAGLINE)
    print()


def _database_is_empty() -> bool:
    with sqlite3.connect(cve_lookup.DB_PATH) as connection:
        row = connection.execute("SELECT COUNT(*) FROM cves").fetchone()
    return row is None or int(row[0]) == 0


def _run_scan(scan_func, scan_type: str) -> None:
    print(f"\nScanning with {scan_type}...")

    try:
        scan_results = scan_func()
    except (scanner.ScannerError, ValueError) as exc:
        print(f"\nScan failed: {exc}")
        return

    if not scan_results:
        print("\nNo open ports were found.")
    cve_matches: dict[int, list[dict]] = {}
    for result in scan_results:
        port = int(result["port"])
        matches = cve_lookup.lookup_cves(result["service"], result["version"])
        cve_matches[port] = matches
        colors.print_finding(port, result["service"], result["version"], matches)

    txt_path, json_path = reporter.generate_report(scan_results, cve_matches, scan_type)
    print(f"\nReport saved: {txt_path}")
    print(f"Report saved: {json_path}")


def quick_scan() -> None:
    _run_scan(scanner.quick_scan, "Quick Scan")


def full_scan() -> None:
    print("\nFull scan may take several minutes...")
    _run_scan(scanner.full_scan, "Full Scan")


def custom_range() -> None:
    try:
        start_port = int(input("\nStart port: ").strip())
        end_port = int(input("End port: ").strip())
    except ValueError:
        print("\nInvalid input. Ports must be integers.")
        return

    if not 1 <= start_port <= 65535 or not 1 <= end_port <= 65535:
        print("\nInvalid port range. Ports must be between 1 and 65535.")
        return
    if start_port > end_port:
        print("\nInvalid port range. Start port must be less than or equal to end port.")
        return

    _run_scan(lambda: scanner.custom_scan(start_port, end_port), "Custom Range")


def update_database() -> None:
    print(
        "\nThis will download the full NVD dataset and may take several minutes. "
        "An internet connection is required."
    )
    confirm = input("Proceed with database update? (y/n): ").strip().lower()
    if confirm != "y":
        print("\nUpdate cancelled.")
        return

    try:
        updater.update_database()
    except RuntimeError as exc:
        print(f"\nDatabase update failed: {exc}")


def show_help() -> None:
    clear_screen()
    print(
        "\nHelp\n"
        "1. Quick Scan: Scan the top 1,000 common localhost ports, look up matching CVEs, "
        "and generate text and JSON reports.\n"
        "2. Full Scan: Scan all 65,535 localhost ports, look up matching CVEs, and generate "
        "reports. This may take several minutes.\n"
        "3. Custom Range: Scan a user-provided localhost port range, look up matching CVEs, "
        "and generate reports.\n"
        "4. Update Database: Download the NVD CVE dataset from the internet and refresh the "
        "local SQLite CVE database.\n"
        "5. Help: Show this help screen.\n"
        "6. Exit: Close Port Overseer.\n\n"
        "Privilege requirements:\n"
        "- Windows: Run from an Administrator command prompt or terminal.\n"
        "- Linux: Run as root, typically with sudo.\n"
        "- Elevated privileges are required before any scan or database action will run.\n\n"
        f"Output report files are saved in: {REPORTS_DIR}\n"
    )


def print_menu() -> None:
    print("1. Quick Scan")
    print("2. Full Scan")
    print("3. Custom Range")
    print("4. Update Database")
    print("5. Help")
    print("6. Exit")


def handle_selection(choice: str) -> bool:
    actions = {
        "1": quick_scan,
        "2": full_scan,
        "3": custom_range,
        "4": update_database,
        "5": show_help,
    }

    if choice == "6":
        print("\nExiting Port Overseer.")
        return False

    action = actions.get(choice)
    if action is None:
        print("\nInvalid selection. Enter a number from 1 to 6.")
        return True

    action()
    input("\nPress Enter to return to the main menu...")
    return True


def main() -> None:
    enforce_privileges()
    cve_lookup.initialize_db()
    if _database_is_empty():
        print(
            colors.colorize(
                "Warning: CVE database is empty. Select option 4 to download CVE data before scanning.",
                colors.HIGH,
            )
        )
        input("\nPress Enter to continue...")

    running = True
    while running:
        print_title_screen()
        print_menu()
        choice = input("\nSelect an option: ").strip()
        running = handle_selection(choice)


if __name__ == "__main__":
    main()
