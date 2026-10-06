"""Tests for scanner: port accounting, nmap wrapping, and LAN detection."""

from __future__ import annotations

import types

import pytest
from conftest import FakeHost, FakePortScanner, FakePortScannerError

import scanner


# --------------------------------------------------------------------------- #
# scanned_port_count
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("port_range", "expected"),
    [
        (None, 1000),
        ("1-65535", 65535),
        ("80", 1),
        ("1-3,7,10-12", 7),
        (" 5 - 9 ", 5),
        ("", 0),
        ("   ", 0),
        ("abc", 0),
        ("10-5", 0),
        ("80,abc,443", 2),
    ],
)
def test_scanned_port_count(port_range, expected):
    assert scanner.scanned_port_count(port_range) == expected


# --------------------------------------------------------------------------- #
# _build_version_string
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("port_data", "expected"),
    [
        ({}, ""),
        ({"product": "Apache httpd"}, "Apache httpd"),
        ({"product": "Apache httpd", "version": "2.4.49"}, "Apache httpd 2.4.49"),
        (
            {"product": "Apache httpd", "version": "2.4.49", "extrainfo": "(Ubuntu)"},
            "Apache httpd 2.4.49 (Ubuntu)",
        ),
        ({"product": "  nginx  ", "version": " ", "extrainfo": "1.18"}, "nginx 1.18"),
        ({"version": "8.2"}, "8.2"),
    ],
)
def test_build_version_string(port_data, expected):
    assert scanner._build_version_string(port_data) == expected


# --------------------------------------------------------------------------- #
# _get_scanner
# --------------------------------------------------------------------------- #


def test_get_scanner_without_python_nmap(monkeypatch):
    monkeypatch.setattr(scanner, "nmap", None)

    with pytest.raises(scanner.ScannerError) as excinfo:
        scanner._get_scanner()

    assert "python-nmap is not installed" in str(excinfo.value)


def test_get_scanner_wraps_portscanner_error(monkeypatch):
    def boom():
        raise FakePortScannerError("nmap is not installed")

    monkeypatch.setattr(
        scanner,
        "nmap",
        types.SimpleNamespace(PortScanner=boom, PortScannerError=FakePortScannerError),
    )

    with pytest.raises(scanner.ScannerError) as excinfo:
        scanner._get_scanner()

    assert "Nmap is not installed" in str(excinfo.value)


def test_get_scanner_returns_instance(fake_nmap):
    instance = FakePortScanner()
    fake_nmap(instance)

    assert scanner._get_scanner() is instance


# --------------------------------------------------------------------------- #
# _extract_open_ports
# --------------------------------------------------------------------------- #


def _hosts(*, tcp=None, udp=None):
    protocols = {}
    if tcp is not None:
        protocols["tcp"] = tcp
    if udp is not None:
        protocols["udp"] = udp
    return {"127.0.0.1": FakeHost(protocols)}


def test_extract_open_ports_missing_host():
    assert scanner._extract_open_ports(FakePortScanner(), "127.0.0.1") == []


def test_extract_open_ports_filters_non_open_and_sorts():
    hosts = _hosts(
        tcp={
            "443": {"state": "open", "name": "https", "product": "nginx", "version": "1.18"},
            "22": {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.2"},
            "80": {"state": "closed", "name": "http"},
            "8080": {"state": "filtered", "name": "http-proxy"},
        }
    )

    results = scanner._extract_open_ports(FakePortScanner(hosts=hosts), "127.0.0.1")

    assert [row["port"] for row in results] == [22, 443]
    assert results[0]["service"] == "ssh"
    assert results[0]["version"] == "OpenSSH 8.2"
    assert results[0]["protocol"] == "tcp"
    assert results[0]["state"] == "open"


def test_extract_open_ports_handles_multiple_protocols():
    hosts = _hosts(
        tcp={"80": {"state": "open", "name": "http"}},
        udp={"53": {"state": "open", "name": "domain"}},
    )

    results = scanner._extract_open_ports(FakePortScanner(hosts=hosts), "127.0.0.1")

    assert {(row["port"], row["protocol"]) for row in results} == {(80, "tcp"), (53, "udp")}


def test_extract_open_ports_defaults_missing_fields():
    hosts = _hosts(tcp={"631": {"state": "open"}})

    results = scanner._extract_open_ports(FakePortScanner(hosts=hosts), "127.0.0.1")

    assert results == [
        {"port": 631, "protocol": "tcp", "service": "", "version": "", "state": "open"}
    ]


# --------------------------------------------------------------------------- #
# _run_scan and the public scan helpers
# --------------------------------------------------------------------------- #


def test_run_scan_returns_results_and_passes_arguments(fake_nmap):
    hosts = _hosts(tcp={"22": {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.2"}})
    instance = FakePortScanner(hosts=hosts)
    fake_nmap(instance)

    results = scanner._run_scan("127.0.0.1", "1-100")

    assert [row["port"] for row in results] == [22]
    assert instance.calls == [
        {"hosts": "127.0.0.1", "ports": "1-100", "arguments": scanner.VERSION_ARGS}
    ]


class ReturningScanner(FakePortScanner):
    """A scanner whose ``scan()`` returns a fixed payload."""

    def __init__(self, value):
        super().__init__()
        self._value = value

    def scan(self, hosts=None, ports=None, arguments=None):
        return self._value


@pytest.mark.parametrize("scan_result", [{}, None, {"notscan": 1}])
def test_run_scan_rejects_empty_results(fake_nmap, scan_result):
    fake_nmap(ReturningScanner(scan_result))

    with pytest.raises(scanner.ScannerError) as excinfo:
        scanner._run_scan()

    assert "empty or invalid scan result" in str(excinfo.value)


def test_run_scan_accepts_valid_result_with_no_open_ports(fake_nmap):
    fake_nmap(FakePortScanner(result={"scan": {"127.0.0.1": {}}}))

    assert scanner._run_scan() == []


def test_run_scan_wraps_portscanner_error(fake_nmap):
    class ExplodingScanner(FakePortScanner):
        def scan(self, hosts=None, ports=None, arguments=None):
            raise FakePortScannerError("nmap exploded")

    fake_nmap(ExplodingScanner())

    with pytest.raises(scanner.ScannerError) as excinfo:
        scanner._run_scan()

    assert "Nmap scan failed" in str(excinfo.value)


def test_run_scan_wraps_unexpected_error(fake_nmap):
    class ExplodingScanner(FakePortScanner):
        def scan(self, hosts=None, ports=None, arguments=None):
            raise RuntimeError("kaboom")

    fake_nmap(ExplodingScanner())

    with pytest.raises(scanner.ScannerError) as excinfo:
        scanner._run_scan()

    assert "Unexpected scan failure" in str(excinfo.value)


def test_quick_scan_uses_default_port_range(fake_nmap):
    instance = FakePortScanner()
    fake_nmap(instance)

    scanner.quick_scan()

    assert instance.calls[0]["ports"] is None
    assert instance.calls[0]["hosts"] == "127.0.0.1"


def test_full_scan_covers_all_ports(fake_nmap):
    instance = FakePortScanner()
    fake_nmap(instance)

    scanner.full_scan()

    assert instance.calls[0]["ports"] == "1-65535"


def test_custom_scan_builds_range(fake_nmap):
    instance = FakePortScanner()
    fake_nmap(instance)

    scanner.custom_scan(20, 25)

    assert instance.calls[0]["ports"] == "20-25"


@pytest.mark.parametrize(
    ("start", "end", "message"),
    [
        (0, 10, "start_port must be between 1 and 65535."),
        (10, 0, "end_port must be between 1 and 65535."),
        (70000, 70001, "start_port must be between 1 and 65535."),
        (100, 99, "start_port must be less than or equal to end_port."),
    ],
)
def test_custom_scan_validates_bounds(start, end, message):
    with pytest.raises(ValueError) as excinfo:
        scanner.custom_scan(start, end)

    assert str(excinfo.value) == message


# --------------------------------------------------------------------------- #
# get_lan_ip
# --------------------------------------------------------------------------- #


class FakeSocket:
    def __init__(self, address=("192.168.1.50", 51000), fail=False):
        self.address = address
        self.fail = fail
        self.closed = False

    def connect(self, target):
        if self.fail:
            raise OSError("network is unreachable")

    def getsockname(self):
        return self.address

    def close(self):
        self.closed = True


def test_get_lan_ip_returns_address(monkeypatch):
    sock = FakeSocket()
    monkeypatch.setattr(scanner.socket, "socket", lambda *args, **kwargs: sock)

    assert scanner.get_lan_ip() == "192.168.1.50"
    assert sock.closed is True


def test_get_lan_ip_rejects_loopback(monkeypatch):
    monkeypatch.setattr(
        scanner.socket, "socket", lambda *args, **kwargs: FakeSocket(("127.0.0.1", 5))
    )

    assert scanner.get_lan_ip() is None


def test_get_lan_ip_handles_oserror(monkeypatch):
    sock = FakeSocket(fail=True)
    monkeypatch.setattr(scanner.socket, "socket", lambda *args, **kwargs: sock)

    assert scanner.get_lan_ip() is None
    assert sock.closed is True


# --------------------------------------------------------------------------- #
# local_audit_scan
# --------------------------------------------------------------------------- #


def test_local_audit_scan_scans_both_targets(fake_nmap, monkeypatch):
    hosts = _hosts(tcp={"22": {"state": "open", "name": "ssh"}})
    hosts["192.168.1.50"] = FakeHost({"tcp": {"80": {"state": "open", "name": "http"}}})
    instance = FakePortScanner(hosts=hosts)
    fake_nmap(instance)
    monkeypatch.setattr(scanner, "get_lan_ip", lambda: "192.168.1.50")

    results = scanner.local_audit_scan("1-100")

    assert [row["port"] for row in results["loopback"]] == [22]
    assert [row["port"] for row in results["lan"]] == [80]


def test_local_audit_scan_without_lan(fake_nmap, monkeypatch, capsys):
    fake_nmap(FakePortScanner(hosts=_hosts(tcp={"22": {"state": "open", "name": "ssh"}})))
    monkeypatch.setattr(scanner, "get_lan_ip", lambda: None)

    results = scanner.local_audit_scan()

    assert results["lan"] == []
    assert [row["port"] for row in results["loopback"]] == [22]
    assert "Could not determine LAN IP" in capsys.readouterr().out


def test_fake_nmap_installer_returns_module(fake_nmap):
    instance = FakePortScanner()

    module = fake_nmap(instance)

    assert module.PortScanner() is instance
    assert module.PortScannerError is FakePortScannerError
