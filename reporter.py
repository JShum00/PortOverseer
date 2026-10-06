"""Report generation helpers for Port Overseer."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import cve_lookup


PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"
TOOL_NAME = "PORT OVERSEER"
TOOL_VERSION = "1.0"
TARGET = "localhost (127.0.0.1)"
AUDIT_TARGET = "loopback (127.0.0.1) and LAN"

_SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

_UNVERIFIED_NOTE = "CVE analysis unavailable - product/version not identified."
_NO_CVES_NOTE = "No associated CVEs found."


def get_highest_severity(cve_matches: dict[int, list[dict]]) -> str:
    """Return the highest severity label across all matched CVEs."""
    highest = "None"

    for matches in cve_matches.values():
        for cve in matches:
            label = str(cve.get("severity_label", "None"))
            if _SEVERITY_ORDER.get(label, -1) > _SEVERITY_ORDER[highest]:
                highest = label

    return highest


def _build_findings(scan_results: list[dict], cve_matches: dict[int, list[dict]]) -> list[dict]:
    findings: list[dict] = []

    for result in scan_results:
        port = int(result.get("port", 0))
        matches = cve_matches.get(port, [])
        service = str(result.get("service", ""))
        version = str(result.get("version", ""))
        can_correlate = cve_lookup.can_correlate_cves(service, version)
        findings.append(
            {
                "port": port,
                "protocol": str(result.get("protocol", "")),
                "service": service,
                "version": version,
                "state": str(result.get("state", "")),
                "cve_analysis_status": "confirmed" if can_correlate else "unverified",
                "cve_analysis_note": "" if can_correlate else _UNVERIFIED_NOTE,
                "cves": [
                    {
                        "id": str(cve.get("id", "")),
                        "severity_label": str(cve.get("severity_label", "")),
                        "cvss_score": cve.get("cvss_score", 0.0),
                        "description": str(cve.get("description", "")),
                        "remediation": str(cve.get("remediation", "")),
                        "reference_url": str(cve.get("reference_url", "")),
                    }
                    for cve in matches
                ],
            }
        )

    return findings


def _flatten_cve_matches(cve_matches: dict[int, list[dict]]) -> list[dict]:
    flattened: list[dict] = []
    for matches in cve_matches.values():
        flattened.extend(matches)
    return flattened


def _build_audit_findings(
    audit_results: dict[str, list[dict]], cve_matches: dict[str, dict[int, list[dict]]]
) -> dict[str, list[dict]]:
    return {
        "loopback": _build_findings(audit_results.get("loopback", []), cve_matches.get("loopback", {})),
        "lan": _build_findings(audit_results.get("lan", []), cve_matches.get("lan", {})),
    }


def _finding_lines(finding: dict) -> list[str]:
    """Render one finding (port header plus its CVEs) as plain text lines."""
    lines = [
        f"Port: {finding['port']} | Protocol: {finding['protocol']} | "
        f"Service: {finding['service'] or 'unknown'} | "
        f"Version: {finding['version'] or 'unknown'}"
    ]

    if not finding["cves"]:
        if finding.get("cve_analysis_status") == "unverified":
            lines.append(f"  {_UNVERIFIED_NOTE}")
        else:
            lines.append(f"  {_NO_CVES_NOTE}")
        return lines

    for cve in finding["cves"]:
        lines.extend(
            [
                f"  CVE ID: {cve['id']}",
                f"    Severity: {cve['severity_label']}",
                f"    CVSS Score: {cve['cvss_score']}",
                f"    Description: {cve['description']}",
                f"    Remediation: {cve['remediation']}",
                f"    Reference URL: {cve['reference_url']}",
            ]
        )

    return lines


def _findings_lines(findings: list[dict]) -> list[str]:
    """Render a list of findings into a flat list of report lines."""
    lines: list[str] = []
    for finding in findings:
        lines.extend(_finding_lines(finding))
    return lines


def _summary_lines(
    scan_type: str, timestamp: str, scanned_ports: int, open_ports: int, total_cves: int,
    highest_severity: str,
) -> list[str]:
    return [
        TOOL_NAME,
        f"Scan Type: {scan_type}",
        f"Timestamp: {timestamp}",
        f"Total Ports Scanned: {scanned_ports}",
        f"Total Open Ports: {open_ports}",
        "",
        "Summary",
        f"Total CVEs Found: {total_cves}",
        f"Highest Severity: {highest_severity}",
    ]


def _metadata(scan_type: str, timestamp: str, target: str, scanned_ports: int, total_cves: int) -> dict:
    return {
        "tool_name": TOOL_NAME,
        "version": TOOL_VERSION,
        "scan_type": scan_type,
        "timestamp": timestamp,
        "target": target,
        "total_ports_scanned": scanned_ports,
        "total_cves_found": total_cves,
    }


def _disclaimer(target: str) -> str:
    return f"This report is intended for authorized use only. Scan target: {target}"


def _write_text(path: Path, lines: list[str], target: str) -> None:
    lines = [*lines, "", _disclaimer(target)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _report_paths() -> tuple[Path, Path, str]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return (
        REPORTS_DIR / f"scan_{timestamp}.txt",
        REPORTS_DIR / f"scan_{timestamp}.json",
        timestamp,
    )


def generate_report(
    scan_results: list[dict],
    cve_matches: dict[int, list[dict]],
    scan_type: str,
    scanned_ports: int | None = None,
) -> tuple[Path, Path]:
    """Generate text and JSON reports for a completed scan.

    ``scanned_ports`` is how many ports the scan covered; when omitted it falls
    back to the number of open ports so the field is never blank.
    """
    print("Generating reports...")
    txt_path, json_path, timestamp = _report_paths()

    findings = _build_findings(scan_results, cve_matches)
    open_ports = len(scan_results)
    if scanned_ports is None:
        scanned_ports = open_ports
    total_cves = sum(len(matches) for matches in cve_matches.values())
    highest_severity = get_highest_severity(cve_matches)

    _write_text(
        txt_path,
        [
            *_summary_lines(
                scan_type, timestamp, scanned_ports, open_ports, total_cves, highest_severity
            ),
            "",
            "Findings",
            *_findings_lines(findings),
        ],
        TARGET,
    )
    _write_json(
        json_path,
        {
            "metadata": _metadata(scan_type, timestamp, TARGET, scanned_ports, total_cves),
            "findings": findings,
        },
    )

    print("Reports saved.")
    return txt_path, json_path


def generate_audit_report(
    audit_results: dict,
    cve_matches: dict,
    scan_type: str,
    scanned_ports: int | None = None,
) -> tuple[Path, Path]:
    """Generate text and JSON reports for a dual-target local audit."""
    print("Generating reports...")
    txt_path, json_path, timestamp = _report_paths()

    findings = _build_audit_findings(audit_results, cve_matches)
    loopback_matches = cve_matches.get("loopback", {})
    lan_matches = cve_matches.get("lan", {})
    open_ports = len(audit_results.get("loopback", [])) + len(audit_results.get("lan", []))
    if scanned_ports is None:
        scanned_ports = open_ports
    total_cves = sum(len(matches) for matches in loopback_matches.values()) + sum(
        len(matches) for matches in lan_matches.values()
    )
    highest_severity = get_highest_severity(
        {
            0: _flatten_cve_matches(loopback_matches),
            1: _flatten_cve_matches(lan_matches),
        }
    )

    _write_text(
        txt_path,
        [
            *_summary_lines(
                scan_type, timestamp, scanned_ports, open_ports, total_cves, highest_severity
            ),
            "",
            "Loopback Findings (127.0.0.1)",
            *_findings_lines(findings["loopback"]),
            "",
            "LAN Findings",
            *_findings_lines(findings["lan"]),
        ],
        AUDIT_TARGET,
    )
    _write_json(
        json_path,
        {
            "metadata": _metadata(scan_type, timestamp, AUDIT_TARGET, scanned_ports, total_cves),
            "findings": {
                "loopback": findings["loopback"],
                "lan": findings["lan"],
            },
        },
    )

    print("Reports saved.")
    return txt_path, json_path
