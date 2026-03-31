"""Download and ingest CVE data from the NVD API."""

from __future__ import annotations

import gc
import sqlite3
import sys
import time
from datetime import datetime, timezone

import requests

try:
    from cve_lookup import DB_PATH, DATA_DIR, get_severity_label, initialize_db
except ImportError:  # pragma: no cover - package-style import fallback
    from .cve_lookup import DB_PATH, DATA_DIR, get_severity_label, initialize_db


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
DEFAULT_REMEDIATION = (
    "Refer to vendor advisory and apply available patches or mitigations."
)
PROGRESS_BAR_WIDTH = 40
INSERT_BATCH_SIZE = 1000
LAST_UPDATED_PATH = DATA_DIR / "last_updated.txt"


def rotate_backups() -> None:
    """Rotate SQLite database backups, retaining at most three files."""
    gc.collect()
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    current_db = DB_PATH
    backup_1 = DATA_DIR / "cve_db_backup_1.sqlite"
    backup_2 = DATA_DIR / "cve_db_backup_2.sqlite"
    backup_3 = DATA_DIR / "cve_db_backup_3.sqlite"

    if backup_3.exists():
        backup_3.unlink()
    if backup_2.exists():
        backup_2.replace(backup_3)
    if backup_1.exists():
        backup_1.replace(backup_2)
    if current_db.exists():
        current_db.replace(backup_1)


def _render_progress(label: str, current: int, total: int) -> None:
    """Render an in-place ASCII progress bar."""
    display_total = total
    if total <= 0:
        percent = 100
        filled = PROGRESS_BAR_WIDTH
    else:
        percent = int((current / total) * 100)
        filled = int((current / total) * PROGRESS_BAR_WIDTH)
    bar = "=" * filled + " " * (PROGRESS_BAR_WIDTH - filled)
    sys.stdout.write(f"\r{label} [{bar}] {current}/{display_total} ({percent}%)")
    sys.stdout.flush()


def download_nvd_data(
    last_mod_start_date: str | None = None, last_mod_end_date: str | None = None
) -> list[dict]:
    """Fetch all CVE items from the paginated NVD 2.0 API."""
    raw_items: list[dict] = []
    start_index = 0
    total_results: int | None = None
    request_params: dict[str, str | int] = {"resultsPerPage": PAGE_SIZE}

    if last_mod_start_date and last_mod_end_date:
        request_params["lastModStartDate"] = last_mod_start_date
        request_params["lastModEndDate"] = last_mod_end_date

    while total_results is None or start_index < total_results:
        try:
            request_params["startIndex"] = start_index
            response = requests.get(
                NVD_API_URL,
                params=request_params,
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"Failed to download NVD data: {exc}") from exc
        except ValueError as exc:
            raise RuntimeError(f"Received malformed JSON from NVD: {exc}") from exc

        vulnerabilities = payload.get("vulnerabilities")
        total_results = payload.get("totalResults")

        if not isinstance(vulnerabilities, list) or not isinstance(total_results, int):
            raise RuntimeError("Malformed NVD response: missing vulnerabilities or totalResults.")

        for item in vulnerabilities:
            if isinstance(item, dict):
                raw_items.append(item)

        _render_progress("Downloading CVEs...", len(raw_items), total_results)

        if not vulnerabilities:
            break

        time.sleep(6)
        start_index += PAGE_SIZE

    if total_results is not None:
        _render_progress("Downloading CVEs...", len(raw_items), total_results)
        sys.stdout.write("\n")
        sys.stdout.flush()

    return raw_items


def _current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_last_updated_timestamp() -> str | None:
    if not LAST_UPDATED_PATH.exists():
        return None

    timestamp = LAST_UPDATED_PATH.read_text(encoding="utf-8").strip()
    return timestamp or None


def _write_last_updated_timestamp(timestamp: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LAST_UPDATED_PATH.write_text(timestamp, encoding="utf-8")


def _insert_cves_batch(records: list[tuple]) -> None:
    """Insert parsed CVEs in one transaction using chunked executemany calls."""
    if not records:
        _render_progress("Inserting CVEs...", 0, 0)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return

    with sqlite3.connect(DB_PATH) as connection:
        for start in range(0, len(records), INSERT_BATCH_SIZE):
            batch = records[start : start + INSERT_BATCH_SIZE]
            connection.executemany(
                "INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?,?)",
                batch,
            )
            _render_progress(
                "Inserting CVEs...",
                min(start + len(batch), len(records)),
                len(records),
            )
        connection.commit()

    sys.stdout.write("\n")
    sys.stdout.flush()


def _get_english_description(cve_data: dict) -> str:
    descriptions = cve_data.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""

    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            return str(description.get("value", "")).strip()
    return ""


def _get_score(metrics: dict) -> float | None:
    metric_keys = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for key in metric_keys:
        metric_list = metrics.get(key, [])
        if not isinstance(metric_list, list):
            continue

        for metric in metric_list:
            if not isinstance(metric, dict):
                continue
            cvss_data = metric.get("cvssData", {})
            if not isinstance(cvss_data, dict):
                continue
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _get_reference_url(cve_data: dict) -> str:
    references = cve_data.get("references", [])
    if not isinstance(references, list):
        return ""

    for reference in references:
        if isinstance(reference, dict):
            url = str(reference.get("url", "")).strip()
            if url:
                return url
    return ""


def _extract_service_and_version(raw: dict) -> tuple[str, str]:
    configurations = raw.get("configurations", [])
    if not isinstance(configurations, list):
        return "", ""

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes", [])
        if not isinstance(nodes, list):
            continue

        for node in nodes:
            if not isinstance(node, dict):
                continue
            cpe_matches = node.get("cpeMatch", [])
            if not isinstance(cpe_matches, list):
                continue

            for match in cpe_matches:
                if not isinstance(match, dict):
                    continue
                criteria = str(match.get("criteria", "")).strip()
                if not criteria.startswith("cpe:2.3:"):
                    continue

                parts = criteria.split(":")
                if len(parts) < 6:
                    continue

                service = "" if parts[4] == "*" else parts[4]
                version = "" if parts[5] == "*" else parts[5]
                if service or version:
                    return service, version

    return "", ""


def parse_cve(raw: dict) -> dict | None:
    """Convert a raw NVD item into the internal CVE record format."""
    cve_data = raw.get("cve")
    if not isinstance(cve_data, dict):
        return None

    metrics = cve_data.get("metrics", {})
    if not isinstance(metrics, dict):
        return None

    score = _get_score(metrics)
    if score is None:
        return None

    cve_id = str(cve_data.get("id", "")).strip()
    if not cve_id:
        return None

    service, version = _extract_service_and_version(raw)

    return {
        "id": cve_id,
        "service": service,
        "version": version,
        "cvss_score": score,
        "severity_label": get_severity_label(score),
        "description": _get_english_description(cve_data),
        "remediation": DEFAULT_REMEDIATION,
        "reference_url": _get_reference_url(cve_data),
    }


def update_database() -> None:
    """Download, parse, and store CVEs in the local SQLite database."""
    last_updated = _load_last_updated_timestamp()
    current_timestamp = _current_timestamp()

    if last_updated:
        print(f"Performing incremental update from {last_updated} to {current_timestamp}.")
    else:
        print("Performing full update.")

    rotate_backups()
    initialize_db()

    raw_cves = download_nvd_data(last_updated, current_timestamp) if last_updated else download_nvd_data()
    records: list[tuple] = []
    skipped = 0

    for raw_cve in raw_cves:
        parsed = parse_cve(raw_cve)
        if parsed is None:
            skipped += 1
            continue

        records.append(
            (
                parsed["id"],
                parsed["service"],
                parsed["version"],
                parsed["cvss_score"],
                parsed["severity_label"],
                parsed["description"],
                parsed["remediation"],
                parsed["reference_url"],
            )
        )

    _insert_cves_batch(records)
    _write_last_updated_timestamp(current_timestamp)

    print(
        f"Update complete. Total fetched: {len(raw_cves)}, "
        f"total inserted: {len(records)}, total skipped: {skipped}"
    )
