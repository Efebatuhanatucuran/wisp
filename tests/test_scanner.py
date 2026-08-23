import json
from pathlib import Path

from wisp import scanner
from wisp.models import Finding, Severity


def test_scan_inline_files_only(monkeypatch):
    monkeypatch.setattr(scanner.discovery, "discover_config_files", lambda project_dir=None: [])
    payload = json.dumps({"mcpServers": {"shell": {"command": "bash", "args": ["-c", "x"]}}})

    result = scanner.scan(inline_files=[("dropped.json", payload)])

    assert result.servers_scanned == 1
    assert Path("dropped.json") in result.files_scanned
    assert any(f.rule_id == "R001" for f in result.findings)


def test_scan_combines_paths_and_inline_files(tmp_path):
    path_payload = {"mcpServers": {"clean": {"command": "npx", "args": ["-y", "clean@1.0.0"]}}}
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps(path_payload))

    inline_payload = json.dumps({"mcpServers": {"shell": {"command": "bash"}}})

    result = scanner.scan(paths=[config_path], inline_files=[("dropped.json", inline_payload)])

    assert result.servers_scanned == 2
    assert config_path in result.files_scanned
    assert Path("dropped.json") in result.files_scanned


def test_scan_with_no_args_auto_discovers(monkeypatch, tmp_path):
    fake_config = tmp_path / "auto.json"
    fake_config.write_text(json.dumps({"mcpServers": {}}))
    monkeypatch.setattr(scanner.discovery, "discover_config_files", lambda project_dir=None: [fake_config])

    result = scanner.scan()

    assert result.files_scanned == [fake_config]


def test_scan_check_cve_merges_findings(monkeypatch, tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps({"mcpServers": {"pkg": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}))

    def fake_check(entries):
        assert len(entries) == 1
        return [Finding(
            rule_id="R010", severity=Severity.CRITICAL, title="fake cve",
            description="d", server_name="pkg", source_file=config_path,
        )]

    monkeypatch.setattr(scanner.cve, "check_entries_for_cves", fake_check)

    result = scanner.scan(paths=[config_path], check_cve=True)

    assert any(f.rule_id == "R010" for f in result.findings)
    # CRITICAL from the fake CVE finding should sort to the front
    assert result.findings[0].rule_id == "R010"


def test_scan_without_check_cve_skips_lookup(monkeypatch, tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps({"mcpServers": {"pkg": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}))

    def fail_if_called(entries):
        raise AssertionError("check_entries_for_cves should not be called when check_cve=False")

    monkeypatch.setattr(scanner.cve, "check_entries_for_cves", fail_if_called)

    result = scanner.scan(paths=[config_path], check_cve=False)
    assert not any(f.rule_id == "R010" for f in result.findings)
