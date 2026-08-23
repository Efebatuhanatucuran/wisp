from __future__ import annotations

from pathlib import Path

from . import cve, discovery, rules
from .models import ScanResult


def scan(
    paths: list[Path] | None = None,
    project_dir: Path | None = None,
    inline_files: list[tuple[str, str]] | None = None,
    check_cve: bool = False,
) -> ScanResult:
    """Scan explicit config file paths, plus optional in-memory (name, text)
    pairs (e.g. drag-and-dropped/uploaded files). Auto-discovers known MCP
    config locations if neither paths nor inline_files are given.

    check_cve additionally cross-references every server package against
    known vulnerabilities via osv.dev — the only part of a scan that makes
    a network call. It's off by default so `scan()` stays static/offline
    unless a caller explicitly opts in."""
    if paths or inline_files:
        files = paths or []
    else:
        files = discovery.discover_config_files(project_dir)

    result = ScanResult(files_scanned=list(files))
    entries = []
    for path in files:
        parsed = discovery.parse_config_file(path)
        entries.extend(parsed)
        result.servers_scanned += len(parsed)
        for entry in parsed:
            result.findings.extend(rules.run_all_rules(entry))

    for name, text in inline_files or []:
        parsed = discovery.parse_config_text(text, name)
        entries.extend(parsed)
        result.servers_scanned += len(parsed)
        result.files_scanned.append(Path(name))
        for entry in parsed:
            result.findings.extend(rules.run_all_rules(entry))

    if check_cve:
        result.findings.extend(cve.check_entries_for_cves(entries))

    result.findings.sort(key=lambda f: f.severity, reverse=True)
    return result
