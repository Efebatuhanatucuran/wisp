from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import ScanResult, Severity


def mask_home_path(path) -> str:
    """Replace the current user's home directory with a masked placeholder
    (e.g. /Users/****/...) so displayed/screenshotted paths don't reveal the
    local username. Paths outside the home directory are left untouched."""
    p = str(path)
    home = Path.home()
    home_str = str(home)
    if p == home_str or p.startswith(home_str + "/") or p.startswith(home_str + "\\"):
        masked_home = str(home.parent / "****")
        return masked_home + p[len(home_str):]
    return p


def _score_color(score: int) -> str:
    if score >= 85:
        return "green"
    if score >= 60:
        return "yellow"
    if score >= 35:
        return "dark_orange"
    return "bold red"


def print_terminal_report(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.files_scanned:
        console.print(Panel(
            "No MCP config files found. Pass a path explicitly with --config, or run "
            "from a project that has a .mcp.json.",
            title="Wisp", border_style="yellow",
        ))
        return

    console.print(Panel(
        f"[bold]{result.servers_scanned}[/bold] server(s) across "
        f"[bold]{len(result.files_scanned)}[/bold] config file(s)\n"
        + "\n".join(f"  • {rich_escape(mask_home_path(p))}" for p in result.files_scanned),
        title="Wisp scan", border_style="cyan",
    ))

    if result.findings:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Rule")
        table.add_column("Server")
        table.add_column("Finding")

        for f in result.findings:
            table.add_row(
                Text(f.severity.label, style=f.severity.color),
                Text(f.rule_id),
                Text(f.server_name),
                Text(f.title),
            )
        console.print(table)

        for f in result.findings:
            console.print(Panel(
                f"[bold]{rich_escape(f.description)}[/bold]\n\n"
                f"[dim]Evidence:[/dim] {rich_escape(f.evidence) if f.evidence else '—'}\n"
                f"[dim]Fix:[/dim] {rich_escape(f.remediation) if f.remediation else '—'}",
                title=f"[{f.severity.color}]{f.severity.label}[/] {rich_escape(f.rule_id)} · "
                      f"{rich_escape(f.server_name)} · {rich_escape(f.title)}",
                border_style=f.severity.color.replace("bold ", ""),
            ))
    else:
        console.print("[green]No findings. Configured servers look clean against current "
                       "rules.[/green]")

    score = result.score
    console.print(Panel(
        Text(f"Risk score: {score}/100", style=f"bold {_score_color(score)}"),
        border_style=_score_color(score),
    ))


def to_dict(result: ScanResult) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "servers_scanned": result.servers_scanned,
        "files_scanned": [str(p) for p in result.files_scanned],
        "score": result.score,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "title": f.title,
                "description": f.description,
                "server_name": f.server_name,
                "source_file": str(f.source_file),
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2)


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Wisp report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #888; margin-bottom: 1.5rem; }}
  .score {{ font-size: 2.5rem; font-weight: 700; }}
  .finding {{ border: 1px solid #3333; border-left-width: 6px; border-radius: 6px;
              padding: 0.9rem 1.1rem; margin: 0.8rem 0; }}
  .CRITICAL {{ border-left-color: #d32f2f; }}
  .HIGH {{ border-left-color: #ef6c00; }}
  .MEDIUM {{ border-left-color: #f9a825; }}
  .LOW {{ border-left-color: #388e3c; }}
  .INFO {{ border-left-color: #0288d1; }}
  .badge {{ display: inline-block; font-size: 0.75rem; font-weight: 700; padding: 0.15rem 0.5rem;
            border-radius: 4px; color: white; margin-right: 0.5rem; }}
  .badge.CRITICAL {{ background: #d32f2f; }}
  .badge.HIGH {{ background: #ef6c00; }}
  .badge.MEDIUM {{ background: #f9a825; color: #222; }}
  .badge.LOW {{ background: #388e3c; }}
  .badge.INFO {{ background: #0288d1; }}
  .evidence {{ font-family: ui-monospace, monospace; font-size: 0.85rem; background: #8881;
               padding: 0.4rem 0.6rem; border-radius: 4px; margin-top: 0.4rem; }}
  .clean {{ color: #388e3c; font-weight: 600; }}
</style>
</head>
<body>
<h1>Wisp report</h1>
<div class="meta">Generated {generated_at} &middot; {servers} server(s) across {files} config file(s)</div>
<div class="score">Risk score: {score}/100</div>
{body}
</body>
</html>
"""


def to_html(result: ScanResult) -> str:
    if result.findings:
        body_parts = []
        for f in result.findings:
            body_parts.append(
                f'<div class="finding {f.severity.label}">'
                f'<span class="badge {f.severity.label}">{f.severity.label}</span>'
                f'<strong>{html.escape(f.rule_id)} &middot; {html.escape(f.server_name)} &middot; '
                f'{html.escape(f.title)}</strong>'
                f'<p>{html.escape(f.description)}</p>'
                f'<div class="evidence">{html.escape(f.evidence) if f.evidence else "&mdash;"}</div>'
                f'<p><em>Fix:</em> {html.escape(f.remediation) if f.remediation else "&mdash;"}</p>'
                f'</div>'
            )
        body = "\n".join(body_parts)
    else:
        body = '<p class="clean">No findings. Configured servers look clean against current rules.</p>'

    return _HTML_TEMPLATE.format(
        generated_at=datetime.now(timezone.utc).isoformat(),
        servers=result.servers_scanned,
        files=len(result.files_scanned),
        score=result.score,
        body=body,
    )


def write_html(result: ScanResult, path: Path) -> None:
    path.write_text(to_html(result))


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0 output, for feeding into GitHub Code Scanning or any other
    SARIF-consuming pipeline. Rule metadata is derived from the findings
    themselves (title/severity), not a separately maintained catalog, so it
    can't drift out of sync with what rules.py actually reports."""
    rules_seen: dict[str, dict] = {}
    sarif_results = []

    for f in result.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            }

        location_uri = mask_home_path(f.source_file)
        fingerprint = hashlib.sha256(
            f"{f.rule_id}:{f.server_name}:{f.source_file}".encode()
        ).hexdigest()[:16]
        message = f.description
        if f.remediation:
            message += f"\n\nFix: {f.remediation}"

        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": location_uri}},
            }],
            "partialFingerprints": {"wispFindingId/v1": fingerprint},
            "properties": {
                "severity": f.severity.label,
                "server_name": f.server_name,
                "evidence": f.evidence,
            },
        })

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Wisp",
                    "informationUri": "https://github.com/Efebatuhanatucuran/wisp",
                    "version": __version__,
                    "rules": list(rules_seen.values()),
                },
            },
            "results": sarif_results,
        }],
    }


def to_sarif_json(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2)


def write_sarif(result: ScanResult, path: Path) -> None:
    path.write_text(to_sarif_json(result))
