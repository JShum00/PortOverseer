"""Terminal color helpers for Port Overseer."""

from __future__ import annotations

from colorama import Fore, Style, init


init(autoreset=True)


CRITICAL = Fore.RED + Style.BRIGHT
HIGH = Fore.YELLOW
MEDIUM = Fore.CYAN
LOW = Fore.WHITE
CLEAN = Fore.GREEN + Style.BRIGHT
CLOSED = Fore.WHITE + Style.DIM
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

_SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_SEVERITY_COLORS = {
    "None": LOW,
    "Low": LOW,
    "Medium": MEDIUM,
    "High": HIGH,
    "Critical": CRITICAL,
}


def colorize(text: str, color: str) -> str:
    """Wrap text with a color/style prefix and reset sequence."""
    return f"{color}{text}{RESET}"


def _highest_severity(cve_list: list[dict]) -> str:
    highest = "None"
    for cve in cve_list:
        label = str(cve.get("severity_label", "None"))
        if _SEVERITY_ORDER.get(label, -1) > _SEVERITY_ORDER[highest]:
            highest = label
    return highest


def print_finding(port: int, service: str, version: str, cve_list: list[dict]) -> None:
    """Print a color-coded summary for one open port and its CVEs."""
    service_text = service or "unknown"
    version_text = version or "unknown"

    if not cve_list:
        summary = (
            f"Port {port} | Service: {service_text} | Version: {version_text} | "
            "No known CVEs"
        )
        print(colorize(summary, CLEAN))
        return

    highest = _highest_severity(cve_list)
    summary = (
        f"Port {port} | Service: {service_text} | Version: {version_text} | "
        f"{len(cve_list)} CVEs found - highest: {highest}"
    )
    print(colorize(summary, _SEVERITY_COLORS.get(highest, LOW)))

    for cve in cve_list:
        cve_id = str(cve.get("id", "Unknown CVE"))
        severity = str(cve.get("severity_label", "None"))
        line = f"  {cve_id} | Severity: {severity}"
        print(colorize(line, _SEVERITY_COLORS.get(severity, LOW)))
