"""Report generation helpers for Port Overseer."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"
TOOL_NAME = "PORT OVERSEER"
TOOL_VERSION = "1.0"
TARGET = "localhost (127.0.0.1)"
DISCLAIMER = (
    "This report is intended for authorized use only. "
    "Scan target: localhost (127.0.0.1)"
)

_SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


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
        findings.append(
            {
                "port": port,
                "protocol": str(result.get("protocol", "")),
                "service": str(result.get("service", "")),
                "version": str(result.get("version", "")),
                "state": str(result.get("state", "")),
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


def _write_text_report(
    path: Path,
    scan_type: str,
    timestamp: str,
    scan_results: list[dict],
    findings: list[dict],
    total_cves: int,
    highest_severity: str,
) -> None:
    lines = [
        TOOL_NAME,
        f"Scan Type: {scan_type}",
        f"Timestamp: {timestamp}",
        f"Total Ports Scanned: {len(scan_results)}",
        "",
        "Summary",
        f"Total Open Ports: {len(scan_results)}",
        f"Total CVEs Found: {total_cves}",
        f"Highest Severity: {highest_severity}",
        "",
        "Findings",
    ]

    for finding in findings:
        lines.extend(
            [
                (
                    f"Port: {finding['port']} | Protocol: {finding['protocol']} | "
                    f"Service: {finding['service'] or 'unknown'} | "
                    f"Version: {finding['version'] or 'unknown'}"
                )
            ]
        )

        if not finding["cves"]:
            lines.append("  No associated CVEs found.")
            continue

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

    lines.extend(["", DISCLAIMER])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_json_report(
    path: Path,
    scan_type: str,
    timestamp: str,
    scan_results: list[dict],
    findings: list[dict],
    total_cves: int,
) -> None:
    payload = {
        "metadata": {
            "tool_name": TOOL_NAME,
            "version": TOOL_VERSION,
            "scan_type": scan_type,
            "timestamp": timestamp,
            "target": TARGET,
            "total_ports_scanned": len(scan_results),
            "total_cves_found": total_cves,
        },
        "findings": findings,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def generate_report(
    scan_results: list[dict], cve_matches: dict[int, list[dict]], scan_type: str
) -> tuple[Path, Path]:
    """Generate text and JSON reports for a completed scan."""
    print("Generating reports...")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = REPORTS_DIR / f"scan_{timestamp}.txt"
    json_path = REPORTS_DIR / f"scan_{timestamp}.json"

    findings = _build_findings(scan_results, cve_matches)
    total_cves = sum(len(matches) for matches in cve_matches.values())
    highest_severity = get_highest_severity(cve_matches)

    _write_text_report(
        txt_path,
        scan_type,
        timestamp,
        scan_results,
        findings,
        total_cves,
        highest_severity,
    )
    _write_json_report(
        json_path,
        scan_type,
        timestamp,
        scan_results,
        findings,
        total_cves,
    )

    print("Reports saved.")
    return txt_path, json_path
