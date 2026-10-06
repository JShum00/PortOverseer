"""Shared fixtures for the Port Overseer test suite.

Every test runs fully offline: nmap is replaced by a fake module, HTTP is never
touched, and the CVE database / report directories are redirected into a tmp
directory so nothing leaks into the repository checkout.
"""

from __future__ import annotations

import types

import pytest

import cve_lookup
import main
import reporter
import scanner
import updater


# --------------------------------------------------------------------------- #
# Fake nmap
# --------------------------------------------------------------------------- #


class FakePortScannerError(Exception):
    """Stand-in for ``nmap.PortScannerError``."""


class FakeHost:
    """Mimics ``nmap.PortScanner``'s per-host mapping."""

    def __init__(self, protocols: dict[str, dict]):
        self._protocols = protocols

    def all_protocols(self) -> list[str]:
        return list(self._protocols)

    def __getitem__(self, protocol: str) -> dict:
        return self._protocols[protocol]


class FakePortScanner:
    """Records ``scan()`` calls and returns canned data."""

    def __init__(self, hosts: dict | None = None, result: dict | None = None):
        self._hosts = hosts if hosts is not None else {}
        self._result = result if result is not None else {"scan": {}}
        self.calls: list[dict] = []

    def all_hosts(self) -> list[str]:
        return list(self._hosts)

    def __getitem__(self, host: str) -> FakeHost:
        return self._hosts[host]

    def scan(self, hosts=None, ports=None, arguments=None):
        self.calls.append({"hosts": hosts, "ports": ports, "arguments": arguments})
        return self._result


def make_fake_nmap():
    """Build a module-like object usable as ``scanner.nmap``."""
    return types.SimpleNamespace(PortScanner=None, PortScannerError=FakePortScannerError)


def install_fake_nmap(monkeypatch, port_scanner):
    """Point ``scanner.nmap`` at a fake module returning ``port_scanner``."""
    module = make_fake_nmap()
    module.PortScanner = lambda: port_scanner
    monkeypatch.setattr(scanner, "nmap", module)
    return module


@pytest.fixture()
def fake_nmap(monkeypatch):
    """Return an installer so tests control the (fake) nmap module."""

    def _install(port_scanner):
        return install_fake_nmap(monkeypatch, port_scanner)

    return _install


# --------------------------------------------------------------------------- #
# Isolated data / report directories
# --------------------------------------------------------------------------- #


class DataDirs:
    def __init__(self, root):
        self.root = root
        self.data = root / "data"
        self.reports = root / "reports"
        self.db = self.data / "cve_db.sqlite"
        self.last_updated = self.data / "last_updated.txt"
        self.backup_1 = self.data / "cve_db_backup_1.sqlite"
        self.backup_2 = self.data / "cve_db_backup_2.sqlite"
        self.backup_3 = self.data / "cve_db_backup_3.sqlite"


@pytest.fixture(autouse=True)
def _no_spinner(monkeypatch):
    """Never start the console spinner thread during tests."""
    monkeypatch.setattr(scanner, "SPINNER_ENABLED", False)


@pytest.fixture(autouse=True)
def _wired_modules():
    """Populate main's module handles the way bootstrap_modules() does."""
    main.bootstrap_modules()


@pytest.fixture()
def data_dirs(tmp_path, monkeypatch):
    """Redirect the CVE database and report output into a tmp directory."""
    dirs = DataDirs(tmp_path)
    dirs.data.mkdir(parents=True, exist_ok=True)
    dirs.reports.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(cve_lookup, "DATA_DIR", dirs.data)
    monkeypatch.setattr(cve_lookup, "DB_PATH", dirs.db)
    monkeypatch.setattr(updater, "DATA_DIR", dirs.data)
    monkeypatch.setattr(updater, "DB_PATH", dirs.db)
    monkeypatch.setattr(updater, "LAST_UPDATED_PATH", dirs.last_updated)
    monkeypatch.setattr(updater, "BACKUP_PATH", dirs.backup_1)
    monkeypatch.setattr(reporter, "REPORTS_DIR", dirs.reports)

    return dirs


SAMPLE_CVES = [
    {
        "id": "CVE-2021-41773",
        "service": "http_server",
        "version": "2.4.49",
        "cvss_score": 9.8,
        "severity_label": "Critical",
        "description": "Apache httpd 2.4.49 path traversal allows remote attackers to read files.",
        "remediation": "Upgrade to 2.4.51.",
        "reference_url": "https://example.test/CVE-2021-41773",
    },
    {
        "id": "CVE-2021-42013",
        "service": "http_server",
        "version": "2.4.50",
        "cvss_score": 9.8,
        "severity_label": "Critical",
        "description": "Apache httpd 2.4.50 incomplete fix for the httpd 2.4.49 traversal flaw.",
        "remediation": "Upgrade to 2.4.51.",
        "reference_url": "https://example.test/CVE-2021-42013",
    },
    {
        "id": "CVE-2020-15778",
        "service": "ssh",
        "version": "8.2",
        "cvss_score": 7.8,
        "severity_label": "High",
        "description": "OpenSSH 8.2 scp allows command injection via crafted filenames.",
        "remediation": "Upgrade OpenSSH.",
        "reference_url": "https://example.test/CVE-2020-15778",
    },
    {
        "id": "CVE-2021-20316",
        "service": "smbd",
        "version": "4.13",
        "cvss_score": 7.5,
        "severity_label": "High",
        "description": "Samba 4.13 smbd symlink metadata handling allows access bypass.",
        "remediation": "Upgrade Samba.",
        "reference_url": "https://example.test/CVE-2021-20316",
    },
    {
        "id": "CVE-2019-11043",
        "service": "nginx",
        "version": "1.18",
        "cvss_score": 9.8,
        "severity_label": "Critical",
        "description": "nginx 1.18 with php-fpm allows remote code execution via a crafted request.",
        "remediation": "Upgrade nginx and php-fpm.",
        "reference_url": "https://example.test/CVE-2019-11043",
    },
    {
        "id": "CVE-2020-1234",
        "service": "nodejs",
        "version": "12.0",
        "cvss_score": 5.3,
        "severity_label": "Medium",
        "description": "nodejs 12.0 http server mishandles chunked transfers.",
        "remediation": "Upgrade Node.js.",
        "reference_url": "https://example.test/CVE-2020-1234",
    },
    {
        "id": "CVE-2022-0001",
        "service": "cups",
        "version": "2.4",
        "cvss_score": 3.1,
        "severity_label": "Low",
        "description": "CUPS ipp server 2.4 reflects crafted values in the web interface.",
        "remediation": "Upgrade CUPS.",
        "reference_url": "https://example.test/CVE-2022-0001",
    },
    {
        "id": "CVE-2023-0002",
        "service": "informational",
        "version": "1.0",
        "cvss_score": 0.0,
        "severity_label": "None",
        "description": "An informational http 1.0 advisory with no measurable impact.",
        "remediation": "None required.",
        "reference_url": "https://example.test/CVE-2023-0002",
    },
]


@pytest.fixture()
def seeded_db(data_dirs):
    """Create the schema and insert SAMPLE_CVES."""
    cve_lookup.initialize_db()
    for cve in SAMPLE_CVES:
        cve_lookup.insert_cve(cve)
    return data_dirs


@pytest.fixture()
def open_port():
    """A single open-port payload as produced by the scanner."""
    return {
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "version": "Apache httpd 2.4.49",
        "state": "open",
    }
