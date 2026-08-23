from pathlib import Path

from wisp import discovery, rules

FIXTURES = Path(__file__).parent / "fixtures"


def _findings_for(server_name: str, entries):
    entry = next(e for e in entries if e.name == server_name)
    return rules.run_all_rules(entry)


def test_safe_config_has_no_high_or_critical_findings():
    entries = discovery.parse_config_file(FIXTURES / "safe.mcp.json")
    all_findings = [f for e in entries for f in rules.run_all_rules(e)]
    severities = {f.severity.label for f in all_findings}
    assert "CRITICAL" not in severities
    assert "HIGH" not in severities


def test_shell_invocation_detected():
    entries = discovery.parse_config_file(FIXTURES / "risky.mcp.json")
    findings = _findings_for("shell-access", entries)
    assert any(f.rule_id == "R001" for f in findings)


def test_unpinned_package_and_broad_access_and_secret_and_injection_detected():
    entries = discovery.parse_config_file(FIXTURES / "risky.mcp.json")
    findings = _findings_for("unpinned-fetcher", entries)
    rule_ids = {f.rule_id for f in findings}
    assert "R002" in rule_ids  # unpinned package
    assert "R003" in rule_ids  # hardcoded secret
    assert "R005" in rule_ids  # broad access flags/path
    assert "R008" in rule_ids  # embedded injection text


def test_remote_http_endpoint_flagged_critical():
    entries = discovery.parse_config_file(FIXTURES / "risky.mcp.json")
    findings = _findings_for("remote-http", entries)
    assert any(f.rule_id == "R004" and f.severity.label == "CRITICAL" for f in findings)


def test_privileged_docker_flagged():
    entries = discovery.parse_config_file(FIXTURES / "risky.mcp.json")
    findings = _findings_for("privileged-docker", entries)
    rule_ids = {f.rule_id for f in findings}
    assert "R006" in rule_ids
    assert "R009" in rule_ids  # :latest tag


def test_risk_score_lower_for_risky_config():
    from wisp.models import ScanResult

    safe_entries = discovery.parse_config_file(FIXTURES / "safe.mcp.json")
    risky_entries = discovery.parse_config_file(FIXTURES / "risky.mcp.json")

    safe_result = ScanResult(files_scanned=[FIXTURES / "safe.mcp.json"])
    for e in safe_entries:
        safe_result.findings.extend(rules.run_all_rules(e))
        safe_result.servers_scanned += 1

    risky_result = ScanResult(files_scanned=[FIXTURES / "risky.mcp.json"])
    for e in risky_entries:
        risky_result.findings.extend(rules.run_all_rules(e))
        risky_result.servers_scanned += 1

    assert risky_result.score < safe_result.score
