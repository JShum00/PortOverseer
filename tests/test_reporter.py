"""Tests for reporter: finding assembly, severity roll-up, and report output."""

from __future__ import annotations

import json

import reporter


def _cve(cve_id, score, label):
    return {
        "id": cve_id,
        "severity_label": label,
        "cvss_score": score,
        "description": f"description for {cve_id}",
        "remediation": "patch it",
        "reference_url": f"https://example.test/{cve_id}",
    }


# --------------------------------------------------------------------------- #
# get_highest_severity
# --------------------------------------------------------------------------- #


def test_get_highest_severity_with_no_matches():
    assert reporter.get_highest_severity({}) == "None"
    assert reporter.get_highest_severity({80: []}) == "None"


def test_get_highest_severity_rolls_up_across_ports():
    matches = {
        22: [_cve("CVE-1", 7.5, "High")],
        80: [_cve("CVE-2", 9.8, "Critical"), _cve("CVE-3", 3.1, "Low")],
    }

    assert reporter.get_highest_severity(matches) == "Critical"


def test_get_highest_severity_ignores_unknown_labels():
    matches = {80: [{"severity_label": "Bogus"}]}

    assert reporter.get_highest_severity(matches) == "None"


# --------------------------------------------------------------------------- #
# _build_findings / _finding_lines
# --------------------------------------------------------------------------- #


def test_build_findings_marks_confirmed_and_unverified():
    scan_results = [
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2", "state": "open"},
        {"port": 631, "protocol": "tcp", "service": "", "version": "", "state": "open"},
    ]
    cve_matches = {22: [_cve("CVE-1", 7.8, "High")], 631: []}

    findings = reporter._build_findings(scan_results, cve_matches)

    assert findings[0]["cve_analysis_status"] == "confirmed"
    assert findings[0]["cve_analysis_note"] == ""
    assert findings[0]["cves"][0]["id"] == "CVE-1"
    assert findings[1]["cve_analysis_status"] == "unverified"
    assert findings[1]["cve_analysis_note"] == reporter._UNVERIFIED_NOTE


def test_finding_lines_without_cves_and_confirmed():
    finding = {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "version": "OpenSSH 8.2",
        "cve_analysis_status": "confirmed",
        "cves": [],
    }

    lines = reporter._finding_lines(finding)

    assert lines == [
        "Port: 22 | Protocol: tcp | Service: ssh | Version: OpenSSH 8.2",
        "  No associated CVEs found.",
    ]


def test_finding_lines_without_cves_and_unverified():
    finding = {
        "port": 631,
        "protocol": "tcp",
        "service": "",
        "version": "",
        "cve_analysis_status": "unverified",
        "cves": [],
    }

    lines = reporter._finding_lines(finding)

    assert lines[0] == "Port: 631 | Protocol: tcp | Service: unknown | Version: unknown"
    assert lines[1] == f"  {reporter._UNVERIFIED_NOTE}"


def test_finding_lines_with_cves():
    finding = {
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "version": "Apache httpd 2.4.49",
        "cve_analysis_status": "confirmed",
        "cves": [_cve("CVE-2021-41773", 9.8, "Critical")],
    }

    lines = reporter._finding_lines(finding)

    assert lines[0].startswith("Port: 80 | Protocol: tcp | Service: http")
    assert "  CVE ID: CVE-2021-41773" in lines
    assert "    Severity: Critical" in lines
    assert "    Reference URL: https://example.test/CVE-2021-41773" in lines


# --------------------------------------------------------------------------- #
# generate_report
# --------------------------------------------------------------------------- #


def test_generate_report_separates_scanned_and_open_port_counts(data_dirs):
    scan_results = [
        {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache httpd 2.4.49", "state": "open"}
    ]
    cve_matches = {80: [_cve("CVE-2021-41773", 9.8, "Critical")]}

    txt_path, json_path = reporter.generate_report(
        scan_results, cve_matches, "Quick Scan", scanned_ports=1000
    )

    text = txt_path.read_text(encoding="utf-8")
    assert "Total Ports Scanned: 1000" in text
    assert "Total Open Ports: 1" in text
    assert "Total CVEs Found: 1" in text
    assert "Highest Severity: Critical" in text
    assert "Port: 80 | Protocol: tcp | Service: http" in text
    assert "This report is intended for authorized use only. Scan target: localhost (127.0.0.1)" in text

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["scan_type"] == "Quick Scan"
    assert payload["metadata"]["total_ports_scanned"] == 1000
    assert payload["metadata"]["total_cves_found"] == 1
    assert payload["metadata"]["target"] == "localhost (127.0.0.1)"
    assert payload["findings"][0]["port"] == 80
    assert payload["findings"][0]["cves"][0]["id"] == "CVE-2021-41773"


def test_generate_report_defaults_scanned_to_open_ports(data_dirs):
    scan_results = [
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2", "state": "open"}
    ]

    txt_path, _ = reporter.generate_report(scan_results, {22: []}, "Custom Range")

    assert "Total Ports Scanned: 1" in txt_path.read_text(encoding="utf-8")


def test_generate_report_with_no_open_ports(data_dirs):
    txt_path, json_path = reporter.generate_report([], {}, "Quick Scan", scanned_ports=1000)

    text = txt_path.read_text(encoding="utf-8")
    assert "Total Open Ports: 0" in text
    assert "Highest Severity: None" in text
    assert json.loads(json_path.read_text(encoding="utf-8"))["findings"] == []


# --------------------------------------------------------------------------- #
# generate_audit_report
# --------------------------------------------------------------------------- #


def test_generate_audit_report_writes_both_sections(data_dirs):
    audit_results = {
        "loopback": [
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2", "state": "open"}
        ],
        "lan": [
            {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache httpd 2.4.49", "state": "open"}
        ],
    }
    cve_matches = {
        "loopback": {22: [_cve("CVE-1", 7.8, "High")]},
        "lan": {80: [_cve("CVE-2", 9.8, "Critical")]},
    }

    txt_path, json_path = reporter.generate_audit_report(
        audit_results, cve_matches, "Full Local Audit", scanned_ports=2000
    )

    text = txt_path.read_text(encoding="utf-8")
    assert "Loopback Findings (127.0.0.1)" in text
    assert "LAN Findings" in text
    assert "Total Ports Scanned: 2000" in text
    assert "Total Open Ports: 2" in text
    assert "Highest Severity: Critical" in text
    assert "Scan target: loopback (127.0.0.1) and LAN" in text

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["target"] == "loopback (127.0.0.1) and LAN"
    assert set(payload["findings"]) == {"loopback", "lan"}
    assert payload["findings"]["lan"][0]["cves"][0]["id"] == "CVE-2"


def test_generate_audit_report_without_lan_results(data_dirs):
    audit_results = {"loopback": [], "lan": []}

    _, json_path = reporter.generate_audit_report(audit_results, {}, "Full Local Audit")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["total_cves_found"] == 0
    assert payload["findings"] == {"loopback": [], "lan": []}


def test_build_audit_findings_handles_missing_keys():
    findings = reporter._build_audit_findings({}, {})

    assert findings == {"loopback": [], "lan": []}
