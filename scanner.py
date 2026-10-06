"""Nmap-backed scanning helpers for Port Overseer."""

from __future__ import annotations

import itertools
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, TypedDict

try:
    import nmap
except ImportError:  # pragma: no cover - depends on runtime environment
    nmap = None

if TYPE_CHECKING:  # pragma: no cover - typing-only import
    import nmap as nmap_types


TARGET_HOST = "127.0.0.1"
VERSION_ARGS = "-sV"

#: nmap scans its own top-1000 TCP ports when no ``-p`` argument is supplied.
QUICK_SCAN_PORT_COUNT = 1000
FULL_PORT_RANGE = "1-65535"

#: Toggle for the console spinner. Disabled in tests and non-interactive runs.
SPINNER_ENABLED = True


class ScanResult(TypedDict):
    port: int
    protocol: str
    service: str
    version: str
    state: str


class ScannerError(RuntimeError):
    """Raised when the local scan environment is unavailable or a scan fails."""


def scanned_port_count(port_range: str | None = None) -> int:
    """Return how many ports a scan covers, for report metadata.

    ``None`` means the ``nmap`` default sweep (its top-1000 ports). A range such
    as ``"1-65535"`` or a comma-separated list of ranges/singles is counted
    exactly. Unparseable fragments are ignored rather than raising, so a report
    is still produced when the scanner is handed something unexpected.
    """
    if port_range is None:
        return QUICK_SCAN_PORT_COUNT

    total = 0
    for chunk in str(port_range).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError:
                continue
            if end >= start:
                total += end - start + 1
        else:
            try:
                int(chunk)
            except ValueError:
                continue
            total += 1
    return total


def _spinner_worker(stop_event: threading.Event, label: str = "Scanning...") -> None:
    """Render an in-place spinner while Nmap is running."""
    for frame in itertools.cycle("|/-\\"):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\r{label} {frame}")
        sys.stdout.flush()
        time.sleep(0.1)

    # Always clear the spinner line; never claim completion here, the caller
    # knows whether the scan actually succeeded.
    sys.stdout.write("\r" + " " * (len(label) + 2) + "\r")
    sys.stdout.flush()


def _build_version_string(port_data: dict) -> str:
    """Join nmap's product/version/extra-info fields into one display string."""
    parts = [
        str(port_data.get("product", "")).strip(),
        str(port_data.get("version", "")).strip(),
        str(port_data.get("extrainfo", "")).strip(),
    ]
    return " ".join(part for part in parts if part)


def _get_scanner() -> "nmap_types.PortScanner":
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


def _extract_open_ports(scanner: "nmap_types.PortScanner", host: str) -> list[ScanResult]:
    """Return every open port nmap reported for ``host``, sorted by port number."""
    results: list[ScanResult] = []

    if host not in scanner.all_hosts():
        return results

    host_data = scanner[host]
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


def _run_scan(host: str = TARGET_HOST, port_range: str | None = None) -> list[ScanResult]:
    scanner = _get_scanner()
    stop_event = threading.Event()
    spinner_thread: threading.Thread | None = None

    if SPINNER_ENABLED:
        spinner_thread = threading.Thread(
            target=_spinner_worker, args=(stop_event,), daemon=True
        )
        spinner_thread.start()

    try:
        scan_result = scanner.scan(hosts=host, ports=port_range, arguments=VERSION_ARGS)
    except nmap.PortScannerError as exc:
        raise ScannerError(f"Nmap scan failed: {exc}") from exc
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        raise ScannerError(f"Unexpected scan failure: {exc}") from exc
    finally:
        stop_event.set()
        if spinner_thread is not None:
            spinner_thread.join(timeout=2)

    if not scan_result or "scan" not in scan_result:
        raise ScannerError("Nmap returned an empty or invalid scan result.")

    return _extract_open_ports(scanner, host)


def get_lan_ip() -> str | None:
    """Return the detected LAN-facing IP address, excluding loopback.

    Uses a UDP socket "connect" which performs no I/O; it only asks the kernel
    which local address would be used to reach a public host, so this works
    offline and behind NAT.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()

    if not address or address.startswith("127."):
        return None
    return address


def quick_scan() -> list[ScanResult]:
    """Scan the top 1,000 common ports on localhost with service detection."""
    return _run_scan()


def full_scan() -> list[ScanResult]:
    """Scan all TCP ports on localhost with service detection."""
    return _run_scan(port_range=FULL_PORT_RANGE)


def custom_scan(start_port: int, end_port: int) -> list[ScanResult]:
    """Scan a user-specified localhost port range with service detection."""
    if not 1 <= start_port <= 65535:
        raise ValueError("start_port must be between 1 and 65535.")
    if not 1 <= end_port <= 65535:
        raise ValueError("end_port must be between 1 and 65535.")
    if start_port > end_port:
        raise ValueError("start_port must be less than or equal to end_port.")

    return _run_scan(port_range=f"{start_port}-{end_port}")


def local_audit_scan(port_range: str | None = None) -> dict[str, list[ScanResult]]:
    """Scan loopback and the detected LAN IP, if available."""
    results: dict[str, list[ScanResult]] = {"loopback": _run_scan(TARGET_HOST, port_range), "lan": []}
    lan_ip = get_lan_ip()

    if lan_ip is None:
        print("Warning: Could not determine LAN IP. Proceeding with loopback only.")
        return results

    results["lan"] = _run_scan(lan_ip, port_range)
    return results
