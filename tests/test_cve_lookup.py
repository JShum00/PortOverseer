"""Tests for cve_lookup: severity labels, correlation gating, and SQLite lookup."""

from __future__ import annotations

import sqlite3

import pytest

import cve_lookup


# --------------------------------------------------------------------------- #
# get_severity_label
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "None"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_get_severity_label_boundaries(score, expected):
    assert cve_lookup.get_severity_label(score) == expected


# --------------------------------------------------------------------------- #
# can_correlate_cves
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("token", ["", "   ", "unknown", "Unknown", "UNKNOWN", "unidentified", "none", "N/A"])
def test_can_correlate_rejects_unknown_service(token):
    assert cve_lookup.can_correlate_cves(token, "1.0") is False


@pytest.mark.parametrize("token", ["", "unknown", "N/A", " none "])
def test_can_correlate_rejects_unknown_version(token):
    assert cve_lookup.can_correlate_cves("http", token) is False


def test_can_correlate_accepts_real_service_and_version():
    assert cve_lookup.can_correlate_cves("http", "2.4.49") is True
    assert cve_lookup.can_correlate_cves("Apache httpd", "2.4.49") is True


# --------------------------------------------------------------------------- #
# initialize_db / insert_cve
# --------------------------------------------------------------------------- #


def test_initialize_db_is_idempotent(data_dirs):
    cve_lookup.initialize_db()
    cve_lookup.initialize_db()

    with sqlite3.connect(data_dirs.db) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "cves" in tables


def test_insert_cve_roundtrip(data_dirs):
    cve_lookup.initialize_db()
    record = {
        "id": "CVE-0000-0001",
        "service": "svc",
        "version": "1.2.3",
        "cvss_score": 6.6,
        "severity_label": "Medium",
        "description": "svc 1.2.3 has a flaw",
        "remediation": "patch",
        "reference_url": "https://example.test/1",
    }
    cve_lookup.insert_cve(record)

    assert cve_lookup.lookup_cves("svc", "1.2.3") == [
        {
            "id": "CVE-0000-0001",
            "service": "svc",
            "version": "1.2.3",
            "cvss_score": 6.6,
            "severity_label": "Medium",
            "description": "svc 1.2.3 has a flaw",
            "remediation": "patch",
            "reference_url": "https://example.test/1",
        }
    ]


def test_insert_cve_replaces_existing_row(data_dirs):
    cve_lookup.initialize_db()
    base = {
        "id": "CVE-0000-0002",
        "service": "svc",
        "version": "1.0",
        "cvss_score": 1.0,
        "severity_label": "Low",
        "description": "svc 1.0 first revision",
        "remediation": "patch",
        "reference_url": "https://example.test/2",
    }
    cve_lookup.insert_cve(base)
    cve_lookup.insert_cve({**base, "cvss_score": 9.1, "severity_label": "Critical"})

    with sqlite3.connect(data_dirs.db) as connection:
        rows = connection.execute(
            "SELECT cvss_score, severity_label FROM cves WHERE id = ?", (base["id"],)
        ).fetchall()
    assert rows == [(9.1, "Critical")]


# --------------------------------------------------------------------------- #
# lookup_cves
# --------------------------------------------------------------------------- #


def test_lookup_without_database_returns_empty(data_dirs):
    assert cve_lookup.lookup_cves("http", "2.4.49") == []


def test_lookup_with_unknown_service_returns_empty(seeded_db):
    assert cve_lookup.lookup_cves("unknown", "1.0") == []


def test_lookup_matches_service_and_version(seeded_db):
    results = cve_lookup.lookup_cves("ssh", "8.2")

    assert [row["id"] for row in results] == ["CVE-2020-15778"]
    assert results[0]["severity_label"] == "High"


def test_lookup_expands_service_alias(seeded_db):
    # "www" is an nmap service name mapped to the "http" alias.
    assert cve_lookup.SERVICE_ALIASES["www"] == "http"

    results = cve_lookup.lookup_cves("www", "12.0")

    assert [row["id"] for row in results] == ["CVE-2020-1234"]
    # A term with no alias and no description match stays empty.
    assert cve_lookup.lookup_cves("zzz-not-a-service", "12.0") == []


def test_lookup_alias_is_applied(seeded_db, monkeypatch):
    monkeypatch.setitem(cve_lookup.SERVICE_ALIASES, "webby", "http")

    results = cve_lookup.lookup_cves("webby", "12.0")

    assert [row["id"] for row in results] == ["CVE-2020-1234"]


def test_lookup_orders_by_score_then_id(seeded_db):
    results = cve_lookup.lookup_cves("http", "2.4")

    assert [row["id"] for row in results] == ["CVE-2021-41773", "CVE-2021-42013"]
    scores = [row["cvss_score"] for row in results]
    assert scores == sorted(scores, reverse=True)


def test_lookup_does_not_duplicate_rows_seen_via_multiple_terms(seeded_db):
    cve_lookup.insert_cve(
        {
            "id": "CVE-9999-0001",
            "service": "combo",
            "version": "12.0",
            "cvss_score": 4.0,
            "severity_label": "Medium",
            "description": "www http 12.0 combined advisory",
            "remediation": "patch",
            "reference_url": "https://example.test/combo",
        }
    )

    ids = [row["id"] for row in cve_lookup.lookup_cves("www", "12.0")]

    assert sorted(ids) == ["CVE-2020-1234", "CVE-9999-0001"]
    assert len(ids) == len(set(ids))


def test_lookup_caps_results_at_twenty(seeded_db):
    cve_lookup.initialize_db()
    for index in range(25):
        cve_lookup.insert_cve(
            {
                "id": f"CVE-7000-{index:04d}",
                "service": "flood",
                "version": "9.9",
                "cvss_score": 1.0 + index / 100,
                "severity_label": "Low",
                "description": f"widget 9.9 advisory number {index}",
                "remediation": "patch",
                "reference_url": "https://example.test/flood",
            }
        )

    results = cve_lookup.lookup_cves("widget", "9.9")

    assert len(results) == 20
    assert [row["cvss_score"] for row in results] == sorted(
        (row["cvss_score"] for row in results), reverse=True
    )


def test_lookup_returns_rows_for_none_severity(seeded_db):
    results = cve_lookup.lookup_cves("informational", "1.0")

    assert [row["id"] for row in results] == ["CVE-2023-0002"]
    assert results[0]["severity_label"] == "None"
