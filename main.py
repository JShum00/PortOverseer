"""Port Overseer command-line entrypoint."""

from __future__ import annotations

import ctypes
import os
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path

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


def ensure_environment() -> None:
    """Relaunch with the project venv and elevated privileges when needed."""
    script_dir = Path(__file__).resolve().parent
    system_name = platform.system()

    if system_name == "Windows":
        venv_python = script_dir / "venv" / "Scripts" / "python.exe"
    else:
        venv_python = script_dir / "venv" / "bin" / "python3"

    current_python = Path(sys.executable).resolve()
    if venv_python.exists():
        if current_python != venv_python.resolve():
            os.execv(str(venv_python), [str(venv_python), *sys.argv])
    else:
        print(f"Warning: Virtual environment not found at {venv_python}. Continuing anyway.")

    if has_required_privileges():
        return

    if system_name == "Linux":
        os.execvp("sudo", ["sudo", sys.executable, *sys.argv])

    if system_name == "Windows":
        params = subprocess.list2cmdline(sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None,
            "runas",
            sys.executable,
            params,
            None,
            1,
        )
        if result > 32:
            sys.exit(0)


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


def _print_audit_section(label: str, results: list[dict], match_map: dict[int, list[dict]]) -> None:
    print(f"\n{label}")
    if not results:
        print("No open ports were found.")
        return

    for result in results:
        port = int(result["port"])
        colors.print_finding(
            port,
            result["service"],
            result["version"],
            match_map.get(port, []),
        )


def full_local_audit() -> None:
    depth = input("\nSelect scan depth: 1 for Quick, 2 for Full: ").strip()
    if depth == "1":
        port_range = None
    elif depth == "2":
        port_range = "1-65535"
    else:
        print("\nInvalid selection. Enter 1 or 2.")
        return

    print("\nStarting Full Local Audit...")
    try:
        audit_results = scanner.local_audit_scan(port_range)
    except scanner.ScannerError as exc:
        print(f"\nScan failed: {exc}")
        return

    cve_matches: dict[str, dict[int, list[dict]]] = {"loopback": {}, "lan": {}}
    for target in ("loopback", "lan"):
        for result in audit_results.get(target, []):
            port = int(result["port"])
            cve_matches[target][port] = cve_lookup.lookup_cves(
                result["service"], result["version"]
            )

    _print_audit_section("Loopback Findings (127.0.0.1)", audit_results.get("loopback", []), cve_matches["loopback"]) # type: ignore[attr-defined]
    lan_ip = scanner.get_lan_ip()
    lan_label = f"LAN Findings ({lan_ip})" if lan_ip else "LAN Findings"
    _print_audit_section(lan_label, audit_results.get("lan", []), cve_matches["lan"]) # type: ignore[attr-defined]

    txt_path, json_path = reporter.generate_audit_report(
        audit_results, cve_matches, "Full Local Audit"
    )
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
        "6. Full Local Audit: Scan both 127.0.0.1 and the host LAN IP with quick or full depth, "
        "look up CVEs, and generate separated audit reports.\n"
        "7. Exit: Close Port Overseer.\n\n"
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
    print("6. Full Local Audit")
    print("7. Exit")


def handle_selection(choice: str) -> bool:
    actions = {
        "1": quick_scan,
        "2": full_scan,
        "3": custom_range,
        "4": update_database,
        "5": show_help,
        "6": full_local_audit,
    }

    if choice == "7":
        print("\nExiting Port Overseer.")
        return False

    action = actions.get(choice)
    if action is None:
        print("\nInvalid selection. Enter a number from 1 to 7.")
        return True

    action()
    input("\nPress Enter to return to the main menu...")
    return True


def main() -> None:
    ensure_environment()
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
