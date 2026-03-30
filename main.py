"""Port Overseer command-line entrypoint."""

from __future__ import annotations

import ctypes
import os
import platform
import sys


TITLE_ART = r"""
==============================================================
 ____   ___  ____ _____    _____     _______ ____  ____  _____
|  _ \ / _ \|  _ \_   _|  / _ \ \   / / ____|  _ \/ ___|| ____|
| |_) | | | | |_) || |   | | | \ \ / /|  _| | |_) \___ \|  _|
|  __/| |_| |  _ < | |   | |_| |\ V / | |___|  _ < ___) | |___
|_|    \___/|_| \_\|_|    \___/  \_/  |_____|_| \_\____/|_____|

==============================================================
"""

TAGLINE = "Vulnerability Hunt & Scan // v1.0"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def has_required_privileges() -> bool:
    """Return True when the current process has elevated privileges."""
    system_name = platform.system()

    if system_name == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
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


def quick_scan() -> None:
    print("\nQuick Scan: Coming soon...")


def full_scan() -> None:
    print("\nFull Scan: Coming soon...")


def custom_range() -> None:
    print("\nCustom Range: Coming soon...")


def update_database() -> None:
    print("\nUpdate Database: Coming soon...")


def show_help() -> None:
    clear_screen()
    print(
        "\nHelp\n"
        "1. Quick Scan: Run a faster, minimal scan against common targets.\n"
        "2. Full Scan: Run a broader and more thorough scan.\n"
        "3. Custom Range: Scan a user-defined host or IP range.\n"
        "4. Update Database: Refresh vulnerability or signature data before scanning.\n"
        "5. Help: Show this help screen.\n"
        "6. Exit: Close Port Overseer.\n\n"
        "Privilege requirements:\n"
        "- Windows: Run from an Administrator command prompt or terminal.\n"
        "- Linux: Run as root, typically with sudo.\n\n"
        f"Output files are saved in: {OUTPUT_DIR}\n"
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

    running = True
    while running:
        print_title_screen()
        print_menu()
        choice = input("\nSelect an option: ").strip()
        running = handle_selection(choice)


if __name__ == "__main__":
    main()
