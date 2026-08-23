import io
from pathlib import Path

from rich.console import Console

from wisp import report
from wisp.models import Finding, ScanResult, Severity


def test_mask_home_path_replaces_username():
    home = Path.home()
    masked = report.mask_home_path(home / "Library" / "foo.json")
    assert str(home) not in masked
    assert masked.endswith("Library/foo.json")
    assert "****" in masked


def test_mask_home_path_leaves_other_paths_untouched():
    assert report.mask_home_path("/tmp/somewhere/x.json") == "/tmp/somewhere/x.json"


def test_mask_home_path_handles_bare_home_dir():
    home = Path.home()
    masked = report.mask_home_path(home)
    assert masked.endswith("****")
    assert str(home) != masked


def _malicious_finding() -> Finding:
    return Finding(
        rule_id="R001",
        severity=Severity.CRITICAL,
        title="MCP server launches a shell interpreter directly",
        description="Server '<img src=x onerror=alert(1)>' runs 'bash'.",
        server_name="<img src=x onerror=alert(1)>",
        source_file=Path("evil.json"),
        evidence="<script>alert(document.cookie)</script>",
        remediation="Fix it.",
    )


def test_to_html_escapes_attacker_controlled_fields():
    result = ScanResult(findings=[_malicious_finding()], servers_scanned=1, files_scanned=[Path("evil.json")])
    html_out = report.to_html(result)
    assert "<img src=x onerror" not in html_out
    assert "<script>alert(document.cookie)</script>" not in html_out
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_out
    assert "&lt;script&gt;" in html_out


def test_terminal_report_does_not_interpret_attacker_markup():
    finding = Finding(
        rule_id="R001",
        severity=Severity.CRITICAL,
        title="MCP server launches a shell interpreter directly",
        description="Server name tries to spoof the report.",
        server_name="[green]ALL CLEAR[/green][black on black]hidden",
        source_file=Path("evil.json"),
        evidence="bash",
        remediation="Fix it.",
    )
    result = ScanResult(findings=[finding], servers_scanned=1, files_scanned=[Path("evil.json")])
    buf = io.StringIO()
    console = Console(file=buf, width=120, no_color=True)
    report.print_terminal_report(result, console=console)
    output = buf.getvalue()
    # the literal bracketed text should appear verbatim, not be parsed as Rich markup
    assert "[green]ALL CLEAR[/green][black on black]hidden" in output


def _sample_findings():
    return [
        Finding(
            rule_id="R001", severity=Severity.CRITICAL,
            title="MCP server launches a shell interpreter directly",
            description="Server 'shell-access' runs 'bash'.", server_name="shell-access",
            source_file=Path("mcp.json"), evidence="bash -c x", remediation="Don't.",
        ),
        Finding(
            rule_id="R009", severity=Severity.MEDIUM,
            title="MCP server container image is not pinned to a digest/version",
            description="Server 'docker-tool' runs 'img:latest'.", server_name="docker-tool",
            source_file=Path("mcp.json"), evidence="docker run img:latest", remediation="Pin it.",
        ),
    ]


def test_to_sarif_has_valid_top_level_shape():
    result = ScanResult(findings=_sample_findings(), servers_scanned=2, files_scanned=[Path("mcp.json")])
    sarif = report.to_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Wisp"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids == {"R001", "R009"}


def test_to_sarif_maps_severity_to_level():
    result = ScanResult(findings=_sample_findings(), servers_scanned=2, files_scanned=[Path("mcp.json")])
    sarif = report.to_sarif(result)
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["R001"] == "error"  # CRITICAL
    assert levels["R009"] == "warning"  # MEDIUM


def test_to_sarif_masks_home_path_in_location():
    home = Path.home()
    finding = Finding(
        rule_id="R001", severity=Severity.CRITICAL, title="t", description="d",
        server_name="s", source_file=home / "secret-dir" / "mcp.json", evidence="", remediation="",
    )
    result = ScanResult(findings=[finding], servers_scanned=1, files_scanned=[finding.source_file])
    sarif = report.to_sarif(result)
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert str(home) not in uri
    assert "****" in uri


def test_to_sarif_json_round_trips():
    import json as json_module
    result = ScanResult(findings=_sample_findings(), servers_scanned=2, files_scanned=[Path("mcp.json")])
    parsed = json_module.loads(report.to_sarif_json(result))
    assert parsed["version"] == "2.1.0"


def test_to_sarif_empty_findings_is_still_valid():
    result = ScanResult(findings=[], servers_scanned=0, files_scanned=[])
    sarif = report.to_sarif(result)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
