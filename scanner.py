"""Nmap-backed scanning helpers for Port Overseer."""

from __future__ import annotations

from typing import TypedDict

try:
    import nmap
except ImportError:  # pragma: no cover - depends on runtime environment
    nmap = None


TARGET_HOST = "127.0.0.1"
VERSION_ARGS = "-sV"


class ScanResult(TypedDict):
    port: int
    protocol: str
    service: str
    version: str
    state: str


class ScannerError(RuntimeError):
    """Raised when the local scan environment is unavailable or a scan fails."""


def _build_version_string(port_data: dict) -> str:
    parts = [
        str(port_data.get("product", "")).strip(),
        str(port_data.get("version", "")).strip(),
        str(port_data.get("extrainfo", "")).strip(),
    ]
    return " ".join(part for part in parts if part)


def _get_scanner() -> "nmap.PortScanner":
    if nmap is None:
        raise ScannerError(
            "python-nmap is not installed. Install dependencies from requirements.txt first."
        )

    try:
        return nmap.PortScanner()
    except nmap.PortScannerError as exc:
        raise ScannerError(
            "Nmap is not installed or is not available on PATH. Install the Nmap binary first."
        ) from exc


def _extract_open_ports(scanner: "nmap.PortScanner") -> list[ScanResult]:
    results: list[ScanResult] = []

    if TARGET_HOST not in scanner.all_hosts():
        return results

    host_data = scanner[TARGET_HOST]
    for protocol in host_data.all_protocols():
        for port, port_data in sorted(host_data[protocol].items()):
            state = str(port_data.get("state", ""))
            if state != "open":
                continue

            results.append(
                {
                    "port": int(port),
                    "protocol": protocol,
                    "service": str(port_data.get("name", "")),
                    "version": _build_version_string(port_data),
                    "state": state,
                }
            )

    return results


def _run_scan(port_range: str | None = None) -> list[ScanResult]:
    scanner = _get_scanner()

    try:
        scan_result = scanner.scan(hosts=TARGET_HOST, ports=port_range, arguments=VERSION_ARGS)
    except nmap.PortScannerError as exc:
        raise ScannerError(f"Nmap scan failed: {exc}") from exc
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        raise ScannerError(f"Unexpected scan failure: {exc}") from exc

    if not scan_result or "scan" not in scan_result:
        raise ScannerError("Nmap returned an empty or invalid scan result.")

    return _extract_open_ports(scanner)


def quick_scan() -> list[ScanResult]:
    """Scan the top 1,000 common ports on localhost with service detection."""
    return _run_scan()


def full_scan() -> list[ScanResult]:
    """Scan all TCP ports on localhost with service detection."""
    return _run_scan("1-65535")


def custom_scan(start_port: int, end_port: int) -> list[ScanResult]:
    """Scan a user-specified localhost port range with service detection."""
    if not 1 <= start_port <= 65535:
        raise ValueError("start_port must be between 1 and 65535.")
    if not 1 <= end_port <= 65535:
        raise ValueError("end_port must be between 1 and 65535.")
    if start_port > end_port:
        raise ValueError("start_port must be less than or equal to end_port.")

    return _run_scan(f"{start_port}-{end_port}")
