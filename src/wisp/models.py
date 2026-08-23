from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "cyan",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "dark_orange",
            Severity.CRITICAL: "bold red",
        }[self]


@dataclass
class ServerEntry:
    """A normalized representation of one MCP server definition, regardless
    of which client's config format it was read from."""

    name: str
    source_file: Path
    source_format: str  # e.g. "claude_desktop", "mcp_json", "cursor", "vscode"
    transport: str = "unknown"  # "stdio" | "sse" | "http" | "unknown"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def command_line(self) -> str:
        parts = [p for p in [self.command, *self.args] if p]
        return " ".join(parts)


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    server_name: str
    source_file: Path
    evidence: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    servers_scanned: int = 0
    files_scanned: list[Path] = field(default_factory=list)

    @property
    def score(self) -> int:
        """0-100 risk score, 100 = clean. Each finding deducts points
        weighted by severity, floored at 0."""
        weights = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        deduction = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - deduction)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity >= Severity.HIGH for f in self.findings)
