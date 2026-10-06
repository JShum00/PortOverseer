"""Tests for colors: severity colouring and finding output."""

from __future__ import annotations

import colors


def test_colorize_wraps_text_with_reset():
    colored = colors.colorize("hello", colors.HIGH)

    assert "hello" in colored
    assert colored.startswith(colors.HIGH)
    assert colored.endswith(colors.RESET)


def test_highest_severity_picks_strongest():
    assert colors._highest_severity([{"severity_label": "Low"}, {"severity_label": "High"}]) == "High"
    assert colors._highest_severity([]) == "None"
    assert colors._highest_severity([{"severity_label": "bogus"}]) == "None"


def test_print_finding_without_cves_is_clean(capsys):
    colors.print_finding(22, "ssh", "OpenSSH 8.2", [])

    out = capsys.readouterr().out
    assert "Port 22 | Service: ssh | Version: OpenSSH 8.2 | No known CVEs" in out


def test_print_finding_without_cves_and_unverified(capsys):
    colors.print_finding(631, "", "", [], correlation_verified=False)

    out = capsys.readouterr().out
    assert "Service: unknown | Version: unknown" in out
    assert "CVE analysis unavailable - product/version not identified" in out


def test_print_finding_lists_cve_ids(capsys):
    cves = [
        {"id": "CVE-1", "severity_label": "Critical"},
        {"id": "CVE-2", "severity_label": "Low"},
    ]

    colors.print_finding(80, "http", "Apache httpd 2.4.49", cves)

    out = capsys.readouterr().out
    assert "2 CVEs found - highest: Critical" in out
    assert "CVE-1 | Severity: Critical" in out
    assert "CVE-2 | Severity: Low" in out
