"""Port Overseer command-line entrypoint."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import os
import platform
import sqlite3
import sys
from pathlib import Path

TITLE_ART = r"""
                       _______    ______     _______  ___________
                      |   __ "\  /    " \   /"      \("     _   ")
                      (. |__) :)// ____  \ |:        |)__/  \__/
                      |:  ____//  /    ) :)|_____/   )   \_ /
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
VERSION = "1.0"
PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"

#: Set this environment variable to any non-empty value to skip the bundled
#: virtualenv check (useful for containers, CI, and non-interactive runs).
ENV_CHECK_OVERRIDE = "PORTOVERSEER_SKIP_ENV_CHECK"

colors = None
cve_lookup = None
reporter = None
scanner = None
updater = None


def ensure_environment() -> None:
    """Check environment and guide user if setup is incorrect."""
    script_dir = PROJECT_ROOT
    system_name = platform.system()

    if system_name == "Windows":
        venv_python = script_dir / "venv" / "Scripts" / "python.exe"
    else:
        venv_python = script_dir / "venv" / "bin" / "python3"

    if not venv_python.exists():
        print(
            "Error: Project virtual environment not found. "
            f"Create it at {venv_python.parent} and install dependencies first."
        )
        sys.exit(1)

    active_prefix = Path(sys.prefix).resolve()
    venv_dir = (script_dir / "venv").resolve()

    if active_prefix != venv_dir:
        print(
            "Error: Port Overseer must be run using the project virtual environment.\n"
            f"Run it with: sudo {venv_python} main.py"
        )
        sys.exit(1)


def bootstrap_modules() -> None:
    """Import local modules after the interpreter environment has been normalized."""
    global colors, cve_lookup, reporter, scanner, updater

    if all(module is not None for module in (colors, cve_lookup, reporter, scanner, updater)):
        return

    try:
        import colors as colors_module
        import cve_lookup as cve_lookup_module
        import reporter as reporter_module
        import scanner as scanner_module
        import updater as updater_module
    except ImportError:  # pragma: no cover - package-style import fallback
        from . import colors as colors_module
        from . import cve_lookup as cve_lookup_module
        from . import reporter as reporter_module
        from . import scanner as scanner_module
        from . import updater as updater_module

    colors = colors_module
    cve_lookup = cve_lookup_module
    reporter = reporter_module
    scanner = scanner_module
    updater = updater_module


def has_required_privileges() -> bool:
    """Return True when the current process has elevated privileges."""
    system_name = platform.system()

    if system_name == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
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


def _collect_cve_matches(scan_results: list) -> dict[int, list[dict]]:
    """Look up CVEs for each scanned port, keyed by port number."""
    cve_matches: dict[int, list[dict]] = {}
    for result in scan_results:
        port = int(result["port"])
        cve_matches[port] = cve_lookup.lookup_cves(result["service"], result["version"])
    return cve_matches


def _print_findings(scan_results: list, cve_matches: dict[int, list[dict]]) -> None:
    for result in scan_results:
        port = int(result["port"])
        colors.print_finding(
            port,
            result["service"],
            result["version"],
            cve_matches.get(port, []),
            correlation_verified=cve_lookup.can_correlate_cves(
                str(result.get("service", "")),
                str(result.get("version", "")),
            ),
        )


def _emit(message: str, *, to_stderr: bool = False) -> None:
    """Print a human-facing message, routed to stderr for ``--json`` runs."""
    print(message, file=sys.stderr if to_stderr else sys.stdout)


@contextlib.contextmanager
def _stdout_to_stderr(enabled: bool):
    """Send anything written to stdout to stderr instead (``--json`` runs)."""
    if not enabled:
        yield
        return

    with contextlib.redirect_stdout(sys.stderr):
        yield


def _finding_dict(
    result: dict, matches: list[dict]
) -> dict:
    service = str(result.get("service", ""))
    version = str(result.get("version", ""))
    can_correlate = cve_lookup.can_correlate_cves(service, version)
    return {
        "port": int(result.get("port", 0)),
        "protocol": str(result.get("protocol", "")),
        "service": service,
        "version": version,
        "state": str(result.get("state", "")),
        "cve_analysis_status": "confirmed" if can_correlate else "unverified",
        "cve_ids": [str(cve.get("id", "")) for cve in matches],
        "highest_severity": reporter.get_highest_severity({0: matches}),
    }


def _json_scan_payload(
    scan_type: str,
    scanned_ports: int,
    scan_results: list,
    cve_matches: dict[int, list[dict]],
    txt_path: Path,
    json_path: Path,
) -> dict:
    return {
        "scan_type": scan_type,
        "target": reporter.TARGET,
        "scanned_ports": scanned_ports,
        "open_port_count": len(scan_results),
        "total_cves_found": sum(len(matches) for matches in cve_matches.values()),
        "highest_severity": reporter.get_highest_severity(cve_matches),
        "findings": [
            _finding_dict(result, cve_matches.get(int(result["port"]), []))
            for result in scan_results
        ],
        "report": {"txt": str(txt_path), "json": str(json_path)},
    }


def execute_scan(
    scan_func,
    scan_type: str,
    scanned_ports: int,
    *,
    emit_json: bool = False,
) -> int:
    """Run one scan end to end. Returns a process exit code."""
    _emit(f"\nScanning with {scan_type}...", to_stderr=emit_json)

    try:
        scan_results = scan_func()
    except (scanner.ScannerError, ValueError) as exc:
        _emit(f"\nScan failed: {exc}", to_stderr=emit_json)
        return 1

    cve_matches = _collect_cve_matches(scan_results)

    if not scan_results:
        _emit("\nNo open ports were found.", to_stderr=emit_json)
    elif not emit_json:
        _print_findings(scan_results, cve_matches)

    with _stdout_to_stderr(emit_json):
        txt_path, json_path = reporter.generate_report(
            scan_results, cve_matches, scan_type, scanned_ports
        )

    if emit_json:
        payload = _json_scan_payload(
            scan_type, scanned_ports, scan_results, cve_matches, txt_path, json_path
        )
        print(json.dumps(payload, indent=2))
    else:
        print(f"\nReport saved: {txt_path}")
        print(f"Report saved: {json_path}")

    return 0


def _print_audit_section(label: str, results: list, match_map: dict[int, list[dict]]) -> None:
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
            correlation_verified=cve_lookup.can_correlate_cves(
                str(result.get("service", "")),
                str(result.get("version", "")),
            ),
        )


def execute_audit(port_range: str | None, *, emit_json: bool = False) -> int:
    """Run a dual-target (loopback + LAN) audit. Returns a process exit code."""
    _emit("\nStarting Full Local Audit...", to_stderr=emit_json)

    try:
        audit_results = scanner.local_audit_scan(port_range)
    except scanner.ScannerError as exc:
        _emit(f"\nScan failed: {exc}", to_stderr=emit_json)
        return 1

    cve_matches: dict[str, dict[int, list[dict]]] = {"loopback": {}, "lan": {}}
    for target in ("loopback", "lan"):
        for result in audit_results.get(target, []):
            cve_matches[target][int(result["port"])] = cve_lookup.lookup_cves(
                result["service"], result["version"]
            )

    lan_ip = scanner.get_lan_ip()

    if not emit_json:
        _print_audit_section(
            "Loopback Findings (127.0.0.1)", audit_results.get("loopback", []), cve_matches["loopback"]
        )
        lan_label = f"LAN Findings ({lan_ip})" if lan_ip else "LAN Findings"
        _print_audit_section(lan_label, audit_results.get("lan", []), cve_matches["lan"])

    # Both targets are scanned with the same range; when no LAN address could be
    # determined only the loopback sweep actually ran.
    targets_scanned = 2 if lan_ip else 1
    scanned_ports = scanner.scanned_port_count(port_range) * targets_scanned

    with _stdout_to_stderr(emit_json):
        txt_path, json_path = reporter.generate_audit_report(
            audit_results, cve_matches, "Full Local Audit", scanned_ports
        )
    _emit(f"\nReport saved: {txt_path}", to_stderr=emit_json)
    _emit(f"Report saved: {json_path}", to_stderr=emit_json)
    return 0


def full_local_audit() -> None:
    depth = input("\nSelect scan depth: 1 for Quick, 2 for Full: ").strip()
    if depth == "1":
        port_range = None
    elif depth == "2":
        port_range = scanner.FULL_PORT_RANGE
    else:
        print("\nInvalid selection. Enter 1 or 2.")
        return

    execute_audit(port_range)


def quick_scan() -> None:
    execute_scan(scanner.quick_scan, "Quick Scan", scanner.scanned_port_count())


def full_scan() -> None:
    print("\nFull scan may take several minutes...")
    execute_scan(
        scanner.full_scan, "Full Scan", scanner.scanned_port_count(scanner.FULL_PORT_RANGE)
    )


def custom_range() -> None:
    try:
        start_port = int(input("\nStart port: ").strip())
        end_port = int(input("\nEnd port: ").strip())
    except ValueError:
        print("\nInvalid input. Ports must be integers.")
        return

    error = _validate_port_range(start_port, end_port)
    if error:
        print(f"\n{error}")
        return

    execute_scan(
        lambda: scanner.custom_scan(start_port, end_port),
        "Custom Range",
        scanner.scanned_port_count(f"{start_port}-{end_port}"),
    )


def _validate_port_range(start_port: int, end_port: int) -> str | None:
    """Return a human-readable validation error, or ``None`` when valid."""
    if not 1 <= start_port <= 65535 or not 1 <= end_port <= 65535:
        return "Invalid port range. Ports must be between 1 and 65535."
    if start_port > end_port:
        return "Invalid port range. Start port must be less than or equal to end port."
    return None


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
        "Non-interactive usage:\n"
        "  python main.py scan --mode quick|full|custom [--start N --end M] [--json]\n"
        "  python main.py audit --depth quick|full [--json]\n"
        "  python main.py update --yes\n\n"
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


def run_menu() -> None:
    """Run the interactive menu until the user chooses to exit."""
    running = True
    while running:
        print_title_screen()
        print_menu()
        choice = input("\nSelect an option: ").strip()
        running = handle_selection(choice)


def _env_check_disabled() -> bool:
    return bool(os.environ.get(ENV_CHECK_OVERRIDE, "").strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-overseer",
        description="Scan localhost ports, correlate them against a local CVE database, and "
        "write text/JSON reports.",
    )
    parser.add_argument("--version", action="version", version=f"Port Overseer {VERSION}")
    parser.add_argument(
        "--skip-env-check",
        action="store_true",
        help=f"skip the bundled virtualenv check (or set {ENV_CHECK_OVERRIDE})",
    )
    parser.add_argument("--no-spinner", action="store_true", help="disable the scanning spinner")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="run a scan without the interactive menu")
    scan.add_argument("--mode", choices=("quick", "full", "custom"), default="quick")
    scan.add_argument("--start", type=int, help="first port for --mode custom")
    scan.add_argument("--end", type=int, help="last port for --mode custom")
    scan.add_argument("--json", action="store_true", help="print a JSON summary to stdout")

    audit = subparsers.add_parser("audit", help="audit loopback and the LAN IP")
    audit.add_argument("--depth", choices=("quick", "full"), default="quick")
    audit.add_argument("--json", action="store_true", help="print a JSON summary to stdout")

    update = subparsers.add_parser("update", help="download the NVD CVE dataset")
    update.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    subparsers.add_parser("menu", help="open the interactive menu (default)")
    subparsers.add_parser("version", help="print the version and exit")
    return parser


def _cli_scan(args) -> int:
    if args.mode == "custom":
        if args.start is None or args.end is None:
            print("Error: --start and --end are required with --mode custom.", file=sys.stderr)
            return 2
        error = _validate_port_range(args.start, args.end)
        if error:
            print(f"Error: {error}", file=sys.stderr)
            return 2
        port_range: str | None = f"{args.start}-{args.end}"
        scan_func = lambda: scanner.custom_scan(args.start, args.end)  # noqa: E731
        scan_type = "Custom Range"
    elif args.mode == "full":
        port_range = scanner.FULL_PORT_RANGE
        scan_func = scanner.full_scan
        scan_type = "Full Scan"
    else:
        port_range = None
        scan_func = scanner.quick_scan
        scan_type = "Quick Scan"

    return execute_scan(
        scan_func, scan_type, scanner.scanned_port_count(port_range), emit_json=args.json
    )


def _cli_audit(args) -> int:
    port_range = scanner.FULL_PORT_RANGE if args.depth == "full" else None
    return execute_audit(port_range, emit_json=args.json)


def _cli_update(args) -> int:
    if not args.yes:
        confirm = input("Proceed with database update? (y/n): ").strip().lower()
        if confirm != "y":
            print("\nUpdate cancelled.")
            return 0
    try:
        updater.update_database()
    except RuntimeError as exc:
        print(f"\nDatabase update failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _warn_if_database_empty(*, interactive: bool, to_stderr: bool = False) -> None:
    cve_lookup.initialize_db()
    if not _database_is_empty():
        return

    warning = (
        "Warning: CVE database is empty. Select option 4 to download CVE data before scanning."
    )
    print(
        colors.colorize(warning, colors.HIGH),
        file=sys.stderr if to_stderr else sys.stdout,
    )
    if interactive:
        input("\nPress Enter to continue...")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if getattr(args, "no_spinner", False):
        scanner.SPINNER_ENABLED = False

    if not (getattr(args, "skip_env_check", False) or _env_check_disabled()):
        ensure_environment()

    bootstrap_modules()
    enforce_privileges()

    command = getattr(args, "command", None)
    if command in (None, "menu"):
        _warn_if_database_empty(interactive=True)
        run_menu()
        return 0
    if command == "version":
        print(f"Port Overseer {VERSION}")
        return 0
    if command == "scan":
        _warn_if_database_empty(interactive=False, to_stderr=bool(args.json))
        return _cli_scan(args)
    if command == "audit":
        _warn_if_database_empty(interactive=False, to_stderr=bool(args.json))
        return _cli_audit(args)
    if command == "update":
        cve_lookup.initialize_db()
        return _cli_update(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
