from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from . import __version__, report, scanner
from .models import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel",
        description="Static security scanner for Model Context Protocol (MCP) server configs.",
    )
    parser.add_argument("--version", action="version", version=f"mcp-sentinel {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Scan MCP config file(s) for risky configuration")
    scan_p.add_argument(
        "--config", "-c", action="append", type=Path, default=None,
        help="Explicit config file path to scan (repeatable). If omitted, known "
             "client config locations and the current project are auto-discovered.",
    )
    scan_p.add_argument(
        "--project-dir", type=Path, default=None,
        help="Directory to look for project-local configs in (default: cwd).",
    )
    scan_p.add_argument("--json", type=Path, default=None, help="Write JSON report to this path.")
    scan_p.add_argument("--html", type=Path, default=None, help="Write HTML report to this path.")
    scan_p.add_argument(
        "--fail-on", choices=[s.name for s in Severity], default=None,
        help="Exit non-zero if any finding meets or exceeds this severity "
             "(useful in CI, e.g. --fail-on HIGH).",
    )
    scan_p.add_argument("--quiet", "-q", action="store_true", help="Suppress terminal report output.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.cmd == "scan":
        try:
            result = scanner.scan(paths=args.config, project_dir=args.project_dir)
        except ValueError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            return 2

        if not args.quiet:
            report.print_terminal_report(result, console=console)

        if args.json:
            args.json.write_text(report.to_json(result))
            console.print(f"[dim]JSON report written to {args.json}[/dim]")

        if args.html:
            report.write_html(result, args.html)
            console.print(f"[dim]HTML report written to {args.html}[/dim]")

        if args.fail_on:
            threshold = Severity[args.fail_on]
            if any(f.severity >= threshold for f in result.findings):
                return 1
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
