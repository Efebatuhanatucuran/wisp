from __future__ import annotations

from pathlib import Path

from . import discovery, rules
from .models import ScanResult


def scan(paths: list[Path] | None = None, project_dir: Path | None = None) -> ScanResult:
    """Scan explicit config file paths, or auto-discover known MCP config
    locations if none are given."""
    files = paths if paths else discovery.discover_config_files(project_dir)

    result = ScanResult(files_scanned=files)
    for path in files:
        entries = discovery.parse_config_file(path)
        result.servers_scanned += len(entries)
        for entry in entries:
            result.findings.extend(rules.run_all_rules(entry))

    result.findings.sort(key=lambda f: f.severity, reverse=True)
    return result
