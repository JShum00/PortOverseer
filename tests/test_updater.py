"""Tests for updater: NVD parsing, pagination, and safe database rotation."""

from __future__ import annotations

import sqlite3
import types

import pytest

import cve_lookup
import updater


# --------------------------------------------------------------------------- #
# Fake HTTP layer
# --------------------------------------------------------------------------- #


class FakeRequestException(Exception):
    """Stands in for ``requests.RequestException``."""


class FakeResponse:
    def __init__(self, payload=None, json_error: str | None = None):
        self._payload = payload
        self._json_error = json_error

    def raise_for_status(self):
        return None

    def json(self):
        if self._json_error:
            raise ValueError(self._json_error)
        return self._payload


def install_fake_requests(monkeypatch, responses):
    """Replace ``updater.requests`` with a fake and record every call."""
    calls: list[dict] = []
    queue = list(responses)

    def get(url, params=None, timeout=None):
        calls.append({"url": url, "params": dict(params or {}), "timeout": timeout})
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    module = types.SimpleNamespace(get=get, RequestException=FakeRequestException)
    monkeypatch.setattr(updater, "requests", module)
    return calls


def nvd_item(cve_id, score, description, criteria=None, metric_key="cvssMetricV31"):
    item = {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {metric_key: [{"cvssData": {"baseScore": score}}]},
            "references": [{"url": f"https://nvd.test/{cve_id}"}],
        }
    }
    if criteria is not None:
        item["configurations"] = [{"nodes": [{"cpeMatch": [{"criteria": criteria}]}]}]
    return item


# --------------------------------------------------------------------------- #
# Score / description / reference extraction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        ({"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]}, 9.1),
        ({"cvssMetricV30": [{"cvssData": {"baseScore": 7.2}}]}, 7.2),
        ({"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}, 5.0),
        (
            {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.9}}],
                "cvssMetricV2": [{"cvssData": {"baseScore": 1.0}}],
            },
            9.9,
        ),
        ({"cvssMetricV31": [{"cvssData": {}}]}, None),
        ({"cvssMetricV31": [{"cvssData": {"baseScore": "high"}}]}, None),
        ({"cvssMetricV31": [{"cvssData": {"baseScore": True}}]}, None),
        ({}, None),
        ({"cvssMetricV31": "not-a-list"}, None),
        ({"cvssMetricV31": ["not-a-dict"]}, None),
    ],
)
def test_get_score(metrics, expected):
    assert updater._get_score(metrics) == expected


def test_get_english_description_picks_english():
    cve_data = {
        "descriptions": [
            {"lang": "es", "value": "descripcion"},
            {"lang": "en", "value": "  english text  "},
        ]
    }

    assert updater._get_english_description(cve_data) == "english text"


@pytest.mark.parametrize(
    "cve_data",
    [{}, {"descriptions": "nope"}, {"descriptions": [{"lang": "es", "value": "x"}]}],
)
def test_get_english_description_missing(cve_data):
    assert updater._get_english_description(cve_data) == ""


def test_get_reference_url_takes_first_url():
    cve_data = {"references": [{"url": " https://a.test "}, {"url": "https://b.test"}]}

    assert updater._get_reference_url(cve_data) == "https://a.test"


@pytest.mark.parametrize("cve_data", [{}, {"references": "x"}, {"references": [{}]}])
def test_get_reference_url_missing(cve_data):
    assert updater._get_reference_url(cve_data) == ""


# --------------------------------------------------------------------------- #
# CPE parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", ("http_server", "2.4.49")),
        ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", ("http_server", "")),
        ("cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*", ("http_server", "")),
        ("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", ("linux_kernel", "")),
    ],
)
def test_extract_service_and_version(criteria, expected):
    raw = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": criteria}]}]}]}

    assert updater._extract_service_and_version(raw) == expected


def test_extract_service_and_version_skips_non_cpe_and_short_entries():
    raw = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "not-a-cpe"},
                            {"criteria": "cpe:2.3:a:x"},
                        ]
                    }
                ]
            }
        ]
    }

    assert updater._extract_service_and_version(raw) == ("", "")


@pytest.mark.parametrize("raw", [{}, {"configurations": "x"}, {"configurations": [{}]}])
def test_extract_service_and_version_missing(raw):
    assert updater._extract_service_and_version(raw) == ("", "")


# --------------------------------------------------------------------------- #
# parse_cve / _to_records
# --------------------------------------------------------------------------- #


def test_parse_cve_happy_path():
    raw = nvd_item(
        "CVE-2021-41773",
        9.8,
        "Apache httpd 2.4.49 path traversal",
        criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    )

    parsed = updater.parse_cve(raw)

    assert parsed == {
        "id": "CVE-2021-41773",
        "service": "http_server",
        "version": "2.4.49",
        "cvss_score": 9.8,
        "severity_label": "Critical",
        "description": "Apache httpd 2.4.49 path traversal",
        "remediation": updater.DEFAULT_REMEDIATION,
        "reference_url": "https://nvd.test/CVE-2021-41773",
    }


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"cve": "not-a-dict"},
        {"cve": {"id": "CVE-1", "metrics": {"cvssMetricV31": []}}},  # no score
        {"cve": {"id": "  ", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]}}},
        {"cve": {"id": "CVE-1", "metrics": "x"}},
    ],
)
def test_parse_cve_returns_none_for_unusable_entries(raw):
    assert updater.parse_cve(raw) is None


def test_to_records_counts_skips():
    raw = [
        nvd_item("CVE-1", 5.0, "one"),
        {"cve": {"id": "CVE-2", "metrics": {}}},
        "not-a-dict",
    ]

    records, skipped = updater._to_records(raw)

    assert len(records) == 1
    assert skipped == 2
    assert records[0][0] == "CVE-1"


# --------------------------------------------------------------------------- #
# Backups
# --------------------------------------------------------------------------- #


def test_rotate_backups_keeps_three_generations(data_dirs):
    data_dirs.db.write_text("live")
    data_dirs.backup_1.write_text("one")
    data_dirs.backup_2.write_text("two")

    updater.rotate_backups()

    assert not data_dirs.db.exists()
    assert data_dirs.backup_1.read_text() == "live"
    assert data_dirs.backup_2.read_text() == "one"
    assert data_dirs.backup_3.read_text() == "two"


def test_rotate_backups_drops_oldest(data_dirs):
    data_dirs.db.write_text("live")
    data_dirs.backup_1.write_text("one")
    data_dirs.backup_2.write_text("two")
    data_dirs.backup_3.write_text("three")

    updater.rotate_backups()

    assert data_dirs.backup_3.read_text() == "two"
    assert data_dirs.backup_2.read_text() == "one"
    assert data_dirs.backup_1.read_text() == "live"


def test_rotate_backups_without_existing_database(data_dirs):
    updater.rotate_backups()

    assert not data_dirs.backup_1.exists()


def test_restore_from_backup_returns_false_without_backup(data_dirs):
    assert updater._restore_from_backup() is False


def test_restore_from_backup_replaces_live_database(data_dirs):
    data_dirs.db.write_text("empty")
    data_dirs.backup_1.write_text("previous")

    assert updater._restore_from_backup() is True
    assert data_dirs.db.read_text() == "previous"
    assert not data_dirs.backup_1.exists()


# --------------------------------------------------------------------------- #
# download_nvd_data
# --------------------------------------------------------------------------- #


def test_download_single_page_does_not_sleep(monkeypatch):
    monkeypatch.setattr(updater.time, "sleep", _fail_if_called())
    payload = {
        "totalResults": 2,
        "vulnerabilities": [nvd_item("CVE-1", 5.0, "a"), nvd_item("CVE-2", 6.0, "b")],
    }
    calls = install_fake_requests(monkeypatch, [FakeResponse(payload)])

    items = updater.download_nvd_data()

    assert len(items) == 2
    assert len(calls) == 1
    assert calls[0]["params"]["startIndex"] == 0


def test_download_paginates_and_sleeps_only_between_pages(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(updater.time, "sleep", lambda seconds: slept.append(seconds))
    monkeypatch.setattr(updater, "PAGE_SIZE", 2)

    page_one = {
        "totalResults": 3,
        "vulnerabilities": [nvd_item("CVE-1", 5.0, "a"), nvd_item("CVE-2", 6.0, "b")],
    }
    page_two = {"totalResults": 3, "vulnerabilities": [nvd_item("CVE-3", 7.0, "c")]}
    calls = install_fake_requests(monkeypatch, [FakeResponse(page_one), FakeResponse(page_two)])

    items = updater.download_nvd_data()

    assert [item["cve"]["id"] for item in items] == ["CVE-1", "CVE-2", "CVE-3"]
    assert [call["params"]["startIndex"] for call in calls] == [0, 2]
    # One pause, between page one and page two, never after the last page.
    assert slept == [updater.REQUEST_DELAY_SECONDS]


def test_download_breaks_on_empty_page(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(updater.time, "sleep", lambda seconds: slept.append(seconds))
    payload = {"totalResults": 5000, "vulnerabilities": []}
    install_fake_requests(monkeypatch, [FakeResponse(payload)])

    assert updater.download_nvd_data() == []
    assert slept == []


def test_download_filters_non_dict_items(monkeypatch):
    payload = {"totalResults": 2, "vulnerabilities": [nvd_item("CVE-1", 5.0, "a"), "junk"]}
    install_fake_requests(monkeypatch, [FakeResponse(payload)])

    items = updater.download_nvd_data()

    assert len(items) == 1


def test_download_passes_last_modified_window(monkeypatch):
    payload = {"totalResults": 0, "vulnerabilities": []}
    calls = install_fake_requests(monkeypatch, [FakeResponse(payload)])

    updater.download_nvd_data("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")

    assert calls[0]["params"]["lastModStartDate"] == "2026-01-01T00:00:00Z"
    assert calls[0]["params"]["lastModEndDate"] == "2026-01-02T00:00:00Z"


def test_download_wraps_request_errors(monkeypatch):
    install_fake_requests(monkeypatch, [FakeRequestException("connection reset")])

    with pytest.raises(RuntimeError) as excinfo:
        updater.download_nvd_data()

    assert "Failed to download NVD data" in str(excinfo.value)


def test_download_wraps_malformed_json(monkeypatch):
    install_fake_requests(monkeypatch, [FakeResponse(json_error="bad json")])

    with pytest.raises(RuntimeError) as excinfo:
        updater.download_nvd_data()

    assert "malformed JSON" in str(excinfo.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"totalResults": 1},
        {"vulnerabilities": []},
        {"totalResults": "many", "vulnerabilities": []},
    ],
)
def test_download_rejects_malformed_payload(monkeypatch, payload):
    install_fake_requests(monkeypatch, [FakeResponse(payload)])

    with pytest.raises(RuntimeError) as excinfo:
        updater.download_nvd_data()

    assert "Malformed NVD response" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# _insert_cves_batch / _render_progress
# --------------------------------------------------------------------------- #


def test_render_progress_zero_total_is_full(capsys):
    updater._render_progress("Working", 0, 0)

    assert "(100%)" in capsys.readouterr().out


def test_render_progress_partial(capsys):
    updater._render_progress("Working", 1, 4)

    assert "1/4 (25%)" in capsys.readouterr().out


def test_insert_cves_batch_with_no_records_is_a_noop(data_dirs, capsys):
    cve_lookup.initialize_db()

    updater._insert_cves_batch([])

    assert "(100%)" in capsys.readouterr().out
    with sqlite3.connect(data_dirs.db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0


def test_insert_cves_batch_chunks_writes(data_dirs):
    cve_lookup.initialize_db()
    records = [
        (f"CVE-{index}", "svc", "1.0", 5.0, "Medium", "d", "r", "u") for index in range(3)
    ]

    updater._insert_cves_batch(records)

    with sqlite3.connect(data_dirs.db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 3


# --------------------------------------------------------------------------- #
# update_database
# --------------------------------------------------------------------------- #


def test_update_database_preserves_existing_data_when_download_fails(data_dirs, monkeypatch):
    """Regression: the live CVE table must survive a failed download.

    The original flow rotated the database and created a fresh empty one before
    downloading, so any network failure silently emptied the CVE store and every
    later scan reported "no known CVEs".
    """
    cve_lookup.initialize_db()
    cve_lookup.insert_cve(
        {
            "id": "CVE-EXISTING",
            "service": "ssh",
            "version": "8.2",
            "cvss_score": 7.8,
            "severity_label": "High",
            "description": "OpenSSH 8.2 pre-existing entry",
            "remediation": "patch",
            "reference_url": "https://example.test/existing",
        }
    )

    def failing_download(*args, **kwargs):
        raise RuntimeError("Failed to download NVD data: connection reset")

    monkeypatch.setattr(updater, "download_nvd_data", failing_download)

    with pytest.raises(RuntimeError):
        updater.update_database()

    assert [row["id"] for row in cve_lookup.lookup_cves("ssh", "8.2")] == ["CVE-EXISTING"]
    assert not data_dirs.backup_1.exists()  # nothing was rotated away


def test_update_database_restores_backup_when_insert_fails(data_dirs, monkeypatch):
    cve_lookup.initialize_db()
    cve_lookup.insert_cve(
        {
            "id": "CVE-EXISTING",
            "service": "ssh",
            "version": "8.2",
            "cvss_score": 7.8,
            "severity_label": "High",
            "description": "OpenSSH 8.2 pre-existing entry",
            "remediation": "patch",
            "reference_url": "https://example.test/existing",
        }
    )
    monkeypatch.setattr(
        updater, "download_nvd_data", lambda *a, **k: [nvd_item("CVE-NEW", 5.0, "new entry")]
    )

    def failing_insert(records):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(updater, "_insert_cves_batch", failing_insert)

    with pytest.raises(sqlite3.OperationalError):
        updater.update_database()

    assert [row["id"] for row in cve_lookup.lookup_cves("ssh", "8.2")] == ["CVE-EXISTING"]


def test_update_database_full_run(data_dirs, monkeypatch, capsys):
    monkeypatch.setattr(
        updater,
        "download_nvd_data",
        lambda *a, **k: [
            nvd_item(
                "CVE-2021-41773",
                9.8,
                "Apache httpd 2.4.49 path traversal",
                criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            ),
            {"cve": {"id": "CVE-NOSCORE", "metrics": {}}},
        ],
    )

    updater.update_database()

    out = capsys.readouterr().out
    assert "Performing full update." in out
    assert "total inserted: 1" in out
    assert "total skipped: 1" in out
    assert data_dirs.last_updated.exists()
    # Lookup matches on the description text, so query the product token that
    # appears there ("httpd" carries the "http" substring).
    assert [row["id"] for row in cve_lookup.lookup_cves("http", "2.4.49")] == [
        "CVE-2021-41773"
    ]


def test_update_database_incremental_run(data_dirs, monkeypatch, capsys):
    data_dirs.last_updated.write_text("2026-01-01T00:00:00Z", encoding="utf-8")
    captured: list[tuple] = []

    def fake_download(start=None, end=None):
        captured.append((start, end))
        return []

    monkeypatch.setattr(updater, "download_nvd_data", fake_download)

    updater.update_database()

    assert captured[0][0] == "2026-01-01T00:00:00Z"
    assert captured[0][1] is not None
    assert "Performing incremental update from 2026-01-01T00:00:00Z" in capsys.readouterr().out


def _fail_if_called():
    def _boom(*args, **kwargs):  # pragma: no cover - only runs on regression
        raise AssertionError("time.sleep() should not be called")

    return _boom
