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
