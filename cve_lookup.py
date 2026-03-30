"""Local SQLite-backed CVE storage and lookup helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "cve_db.sqlite"


def initialize_db() -> None:
    """Create the local CVE database and schema if they do not exist yet."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                service TEXT,
                version TEXT,
                cvss_score REAL,
                severity_label TEXT,
                description TEXT,
                remediation TEXT,
                reference_url TEXT
            )
            """
        )
        connection.commit()


def get_severity_label(cvss_score: float) -> str:
    """Return a human-readable severity label for a CVSS score."""
    if cvss_score == 0.0:
        return "None"
    if cvss_score >= 9.0:
        return "Critical"
    if cvss_score >= 7.0:
        return "High"
    if cvss_score >= 4.0:
        return "Medium"
    return "Low"


def lookup_cves(service: str, version: str) -> list[dict]:
    """Return CVEs whose service and version fields partially match the inputs."""
    if not DB_PATH.exists():
        return []

    service_term = f"%{service.strip()}%"
    version_term = f"%{version.strip()}%"

    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                id,
                service,
                version,
                cvss_score,
                severity_label,
                description,
                remediation,
                reference_url
            FROM cves
            WHERE LOWER(service) LIKE LOWER(?)
              AND LOWER(version) LIKE LOWER(?)
            ORDER BY cvss_score DESC, id ASC
            """,
            (service_term, version_term),
        ).fetchall()

    return [dict(row) for row in rows]


def insert_cve(cve: dict) -> None:
    """Insert or replace a CVE record in the local SQLite database."""
    initialize_db()

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO cves (
                id,
                service,
                version,
                cvss_score,
                severity_label,
                description,
                remediation,
                reference_url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve["id"],
                cve["service"],
                cve["version"],
                cve["cvss_score"],
                cve["severity_label"],
                cve["description"],
                cve["remediation"],
                cve["reference_url"],
            ),
        )
        connection.commit()
