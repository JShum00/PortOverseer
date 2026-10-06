"""Tests for the main entrypoint: CLI parsing, dispatch, and scan orchestration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import main
import scanner
import updater


PORT_22 = {
    "port": 22,
    "protocol": "tcp",
    "service": "ssh",
    "version": "OpenSSH 8.2",
    "state": "open",
}
PORT_631 = {
    "port": 631,
    "protocol": "tcp",
    "service": "",
    "version": "",
    "state": "open",
}


@pytest.fixture()
def no_system_checks(monkeypatch):
    """Neutralise the environment and privilege gates."""
    monkeypatch.setattr(main, "ensure_environment", lambda: None)
    monkeypatch.setattr(main, "enforce_privileges", lambda: None)


# --------------------------------------------------------------------------- #
# Port range validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (1, 65535, None),
        (80, 80, None),
        (0, 10, "Invalid port range. Ports must be between 1 and 65535."),
        (10, 70000, "Invalid port range. Ports must be between 1 and 65535."),
        (100, 99, "Invalid port range. Start port must be less than or equal to end port."),
    ],
)
def test_validate_port_range(start, end, expected):
    assert main._validate_port_range(start, end) == expected


# --------------------------------------------------------------------------- #
# Interactive helpers
# --------------------------------------------------------------------------- #


def test_handle_selection_dispatches_action(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(main, "quick_scan", lambda: calls.append("quick"))
    monkeypatch.setattr("builtins.input", lambda *args: "")

    assert main.handle_selection("1") is True
    assert calls == ["quick"]


def test_handle_selection_exit(capsys):
    assert main.handle_selection("7") is False
    assert "Exiting Port Overseer." in capsys.readouterr().out


def test_handle_selection_rejects_unknown(capsys):
    assert main.handle_selection("42") is True
    assert "Invalid selection. Enter a number from 1 to 7." in capsys.readouterr().out


def test_custom_range_runs_scan(monkeypatch):
    answers = iter(["20", "25"])
    monkeypatch.setattr("builtins.input", lambda *args: next(answers))
    recorded: dict = {}

    def fake_execute(scan_func, scan_type, scanned_ports, **kwargs):
        recorded.update(scan_type=scan_type, scanned=scanned_ports)
        return 0

    monkeypatch.setattr(main, "execute_scan", fake_execute)

    main.custom_range()

    assert recorded == {"scan_type": "Custom Range", "scanned": 6}


def test_custom_range_rejects_non_numeric(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *args: "abc")

    main.custom_range()

    assert "Invalid input. Ports must be integers." in capsys.readouterr().out


def test_custom_range_rejects_reversed_range(monkeypatch, capsys):
    answers = iter(["90", "10"])
    monkeypatch.setattr("builtins.input", lambda *args: next(answers))

    main.custom_range()

    assert "Start port must be less than or equal to end port." in capsys.readouterr().out


def test_full_local_audit_depth_quick(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *args: "1")
    recorded: list = []
    monkeypatch.setattr(main, "execute_audit", lambda port_range, **kw: recorded.append(port_range))

    main.full_local_audit()

    assert recorded == [None]


def test_full_local_audit_depth_full(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *args: "2")
    recorded: list = []
    monkeypatch.setattr(main, "execute_audit", lambda port_range, **kw: recorded.append(port_range))

    main.full_local_audit()

    assert recorded == ["1-65535"]


def test_full_local_audit_rejects_bad_depth(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *args: "9")

    main.full_local_audit()

    assert "Invalid selection. Enter 1 or 2." in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Privileges / environment
# --------------------------------------------------------------------------- #


def test_has_required_privileges_on_linux(monkeypatch):
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")
    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    assert main.has_required_privileges() is True

    monkeypatch.setattr(main.os, "geteuid", lambda: 1000)
    assert main.has_required_privileges() is False


def test_has_required_privileges_unknown_platform(monkeypatch):
    monkeypatch.setattr(main.platform, "system", lambda: "Darwin")

    assert main.has_required_privileges() is False


def test_enforce_privileges_exits_when_unprivileged(monkeypatch, capsys):
    monkeypatch.setattr(main, "has_required_privileges", lambda: False)
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")

    with pytest.raises(SystemExit) as excinfo:
        main.enforce_privileges()

    assert excinfo.value.code == 1
    assert "must be run as root" in capsys.readouterr().out


def test_ensure_environment_requires_bundled_venv(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(main, "PROJECT_ROOT", tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        main.ensure_environment()

    assert excinfo.value.code == 1
    assert "virtual environment not found" in capsys.readouterr().out


def test_ensure_environment_rejects_other_prefix(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(main, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(main.platform, "system", lambda: "Linux")
    python = tmp_path / "venv" / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_text("")

    with pytest.raises(SystemExit) as excinfo:
        main.ensure_environment()

    assert excinfo.value.code == 1
    assert "must be run using the project virtual environment" in capsys.readouterr().out


def test_env_check_override(monkeypatch):
    monkeypatch.delenv(main.ENV_CHECK_OVERRIDE, raising=False)
    assert main._env_check_disabled() is False

    monkeypatch.setenv(main.ENV_CHECK_OVERRIDE, "1")
    assert main._env_check_disabled() is True


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def test_parser_defaults_to_menu():
    args = main.build_parser().parse_args([])

    assert args.command is None
    assert args.skip_env_check is False
    assert args.no_spinner is False


def test_parser_scan_defaults():
    args = main.build_parser().parse_args(["scan"])

    assert args.command == "scan"
    assert args.mode == "quick"
    assert args.json is False


def test_parser_scan_custom_full():
    args = main.build_parser().parse_args(
        ["scan", "--mode", "custom", "--start", "1", "--end", "5", "--json"]
    )

    assert (args.mode, args.start, args.end, args.json) == ("custom", 1, 5, True)


def test_parser_audit_and_update():
    audit = main.build_parser().parse_args(["audit", "--depth", "full", "--json"])
    update = main.build_parser().parse_args(["update", "--yes"])

    assert (audit.command, audit.depth, audit.json) == ("audit", "full", True)
    assert (update.command, update.yes) == ("update", True)


def test_parser_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main.build_parser().parse_args(["--version"])

    assert excinfo.value.code == 0
    assert "Port Overseer" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# execute_scan
# --------------------------------------------------------------------------- #


def test_execute_scan_reports_scanner_error(capsys, data_dirs):
    def failing_scan():
        raise scanner.ScannerError("nmap is not installed")

    assert main.execute_scan(failing_scan, "Quick Scan", 1000) == 1
    assert "Scan failed: nmap is not installed" in capsys.readouterr().out


def test_execute_scan_reports_value_error(capsys, data_dirs):
    def failing_scan():
        raise ValueError("bad range")

    assert main.execute_scan(failing_scan, "Custom Range", 5) == 1
    assert "Scan failed: bad range" in capsys.readouterr().out


def test_execute_scan_writes_reports_and_prints_findings(capsys, data_dirs):
    code = main.execute_scan(lambda: [PORT_22], "Quick Scan", 1000)

    out = capsys.readouterr().out
    assert code == 0
    assert "Scanning with Quick Scan..." in out
    assert "Port 22 | Service: ssh | Version: OpenSSH 8.2 | No known CVEs" in out
    assert "Report saved:" in out
    assert sorted(path.name for path in data_dirs.reports.iterdir()) != []


def test_execute_scan_without_open_ports(capsys, data_dirs):
    code = main.execute_scan(lambda: [], "Quick Scan", 1000)

    assert code == 0
    assert "No open ports were found." in capsys.readouterr().out


def test_execute_scan_json_mode_keeps_stdout_machine_readable(capsys, data_dirs):
    code = main.execute_scan(lambda: [PORT_22, PORT_631], "Quick Scan", 1000, emit_json=True)

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["scan_type"] == "Quick Scan"
    assert payload["scanned_ports"] == 1000
    assert payload["open_port_count"] == 2
    assert payload["highest_severity"] == "None"
    assert [finding["port"] for finding in payload["findings"]] == [22, 631]
    assert payload["findings"][0]["cve_analysis_status"] == "confirmed"
    assert payload["findings"][1]["cve_analysis_status"] == "unverified"
    assert payload["report"]["txt"].endswith(".txt")
    # Human-facing chatter is routed to stderr so stdout stays pure JSON.
    assert "Scanning with Quick Scan" in captured.err


def test_execute_scan_json_mode_on_failure(capsys, data_dirs):
    def failing_scan():
        raise scanner.ScannerError("nope")

    assert main.execute_scan(failing_scan, "Quick Scan", 1000, emit_json=True) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Scan failed: nope" in captured.err


# --------------------------------------------------------------------------- #
# _finding_dict / _json_scan_payload
# --------------------------------------------------------------------------- #


def test_finding_dict_reports_cve_ids_and_severity():
    matches = [{"id": "CVE-1", "severity_label": "High"}, {"id": "CVE-2", "severity_label": "Low"}]

    finding = main._finding_dict(PORT_22, matches)

    assert finding["cve_ids"] == ["CVE-1", "CVE-2"]
    assert finding["highest_severity"] == "High"
    assert finding["cve_analysis_status"] == "confirmed"


def test_json_scan_payload_counts_cves():
    cve_matches = {22: [{"id": "CVE-1", "severity_label": "High"}]}

    payload = main._json_scan_payload(
        "Quick Scan", 1000, [PORT_22], cve_matches, Path("/tmp/a.txt"), Path("/tmp/a.json")
    )

    assert payload["total_cves_found"] == 1
    assert payload["highest_severity"] == "High"
    assert payload["report"] == {"txt": "/tmp/a.txt", "json": "/tmp/a.json"}


# --------------------------------------------------------------------------- #
# execute_audit
# --------------------------------------------------------------------------- #


def test_execute_audit_scans_both_targets(monkeypatch, capsys, data_dirs):
    audit_results = {"loopback": [PORT_22], "lan": [PORT_631]}
    monkeypatch.setattr(scanner, "local_audit_scan", lambda port_range: audit_results)
    monkeypatch.setattr(scanner, "get_lan_ip", lambda: "192.168.1.50")

    code = main.execute_audit("1-100")

    out = capsys.readouterr().out
    assert code == 0
    assert "Loopback Findings (127.0.0.1)" in out
    assert "LAN Findings (192.168.1.50)" in out


def test_execute_audit_counts_both_sweeps(monkeypatch, data_dirs):
    monkeypatch.setattr(scanner, "local_audit_scan", lambda port_range: {"loopback": [], "lan": []})
    monkeypatch.setattr(scanner, "get_lan_ip", lambda: "10.0.0.5")
    recorded: dict = {}

    def fake_report(audit_results, cve_matches, scan_type, scanned_ports):
        recorded["scanned"] = scanned_ports
        return ("/tmp/a.txt", "/tmp/a.json")

    monkeypatch.setattr(main.reporter, "generate_audit_report", fake_report)

    assert main.execute_audit("1-100") == 0
    assert recorded["scanned"] == 200


def test_execute_audit_counts_single_sweep_without_lan(monkeypatch, data_dirs):
    monkeypatch.setattr(scanner, "local_audit_scan", lambda port_range: {"loopback": [], "lan": []})
    monkeypatch.setattr(scanner, "get_lan_ip", lambda: None)
    recorded: dict = {}

    def fake_report(audit_results, cve_matches, scan_type, scanned_ports):
        recorded["scanned"] = scanned_ports
        return ("/tmp/a.txt", "/tmp/a.json")

    monkeypatch.setattr(main.reporter, "generate_audit_report", fake_report)

    main.execute_audit(None)

    assert recorded["scanned"] == 1000


def test_execute_audit_handles_scanner_error(monkeypatch, capsys, data_dirs):
    def failing(port_range):
        raise scanner.ScannerError("nmap is not installed")

    monkeypatch.setattr(scanner, "local_audit_scan", failing)

    assert main.execute_audit(None) == 1
    assert "Scan failed: nmap is not installed" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# CLI subcommand handlers
# --------------------------------------------------------------------------- #


def test_cli_scan_custom_requires_bounds(capsys):
    args = main.build_parser().parse_args(["scan", "--mode", "custom"])

    assert main._cli_scan(args) == 2
    assert "--start and --end are required" in capsys.readouterr().err


def test_cli_scan_custom_rejects_bad_range(capsys):
    args = main.build_parser().parse_args(["scan", "--mode", "custom", "--start", "90", "--end", "10"])

    assert main._cli_scan(args) == 2
    assert "Start port must be less than or equal to end port." in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "expected_type", "expected_scanned"),
    [
        (["scan"], "Quick Scan", 1000),
        (["scan", "--mode", "full"], "Full Scan", 65535),
        (["scan", "--mode", "custom", "--start", "100", "--end", "103"], "Custom Range", 4),
    ],
)
def test_cli_scan_routes_modes(monkeypatch, argv, expected_type, expected_scanned):
    recorded: dict = {}

    def fake_execute(scan_func, scan_type, scanned_ports, **kwargs):
        recorded.update(scan_type=scan_type, scanned=scanned_ports)
        return 0

    monkeypatch.setattr(main, "execute_scan", fake_execute)

    assert main._cli_scan(main.build_parser().parse_args(argv)) == 0
    assert recorded == {"scan_type": expected_type, "scanned": expected_scanned}


def test_cli_audit_depth(monkeypatch):
    recorded: list = []
    monkeypatch.setattr(main, "execute_audit", lambda port_range, **kw: recorded.append(port_range) or 0)

    main._cli_audit(main.build_parser().parse_args(["audit"]))
    main._cli_audit(main.build_parser().parse_args(["audit", "--depth", "full"]))

    assert recorded == [None, "1-65535"]


def test_cli_update_prompts(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *args: "n")
    called: list = []
    monkeypatch.setattr(updater, "update_database", lambda: called.append(True))

    assert main._cli_update(main.build_parser().parse_args(["update"])) == 0
    assert called == []
    assert "Update cancelled." in capsys.readouterr().out


def test_cli_update_runs_with_yes(monkeypatch):
    called: list = []
    monkeypatch.setattr(updater, "update_database", lambda: called.append(True))

    assert main._cli_update(main.build_parser().parse_args(["update", "--yes"])) == 0
    assert called == [True]


def test_cli_update_reports_failure(monkeypatch, capsys):
    def failing():
        raise RuntimeError("Failed to download NVD data: timeout")

    monkeypatch.setattr(updater, "update_database", failing)

    assert main._cli_update(main.build_parser().parse_args(["update", "--yes"])) == 1
    assert "Database update failed" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Empty-database warning + main() dispatch
# --------------------------------------------------------------------------- #


def test_warn_if_database_empty(data_dirs, capsys):
    main._warn_if_database_empty(interactive=False)

    assert "CVE database is empty" in capsys.readouterr().out


def test_warn_if_database_empty_can_target_stderr(data_dirs, capsys):
    main._warn_if_database_empty(interactive=False, to_stderr=True)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "CVE database is empty" in captured.err


def test_warn_if_database_empty_silent_when_populated(seeded_db, capsys):
    main._warn_if_database_empty(interactive=False)

    assert capsys.readouterr().out == ""


def test_main_version(no_system_checks, capsys, data_dirs):
    assert main.main(["version"]) == 0
    assert "Port Overseer 1.0" in capsys.readouterr().out


def test_main_no_args_opens_menu(no_system_checks, monkeypatch, data_dirs):
    opened: list = []
    monkeypatch.setattr(main, "run_menu", lambda: opened.append(True))
    monkeypatch.setattr("builtins.input", lambda *args: "")

    assert main.main([]) == 0
    assert opened == [True]


def test_main_scan_command(no_system_checks, monkeypatch, data_dirs):
    recorded: list = []
    monkeypatch.setattr(main, "_cli_scan", lambda args: recorded.append(args.mode) or 0)

    assert main.main(["scan", "--mode", "full"]) == 0
    assert recorded == ["full"]


def test_main_audit_command(no_system_checks, monkeypatch, data_dirs):
    recorded: list = []
    monkeypatch.setattr(main, "_cli_audit", lambda args: recorded.append(args.depth) or 0)

    assert main.main(["audit", "--depth", "full"]) == 0
    assert recorded == ["full"]


def test_main_update_command(no_system_checks, monkeypatch, data_dirs):
    recorded: list = []
    monkeypatch.setattr(main, "_cli_update", lambda args: recorded.append(args.yes) or 0)

    assert main.main(["update", "--yes"]) == 0
    assert recorded == [True]


def test_main_disables_spinner(no_system_checks, monkeypatch, data_dirs):
    monkeypatch.setattr(scanner, "SPINNER_ENABLED", True)
    monkeypatch.setattr(main, "run_menu", lambda: None)
    monkeypatch.setattr("builtins.input", lambda *args: "")

    main.main(["--no-spinner", "menu"])

    assert scanner.SPINNER_ENABLED is False
