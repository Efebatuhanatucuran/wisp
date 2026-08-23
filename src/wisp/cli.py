from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from . import __version__, report, scanner
from .models import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wisp",
        description="Wisp: a static security scanner for Model Context Protocol (MCP) server configs.",
    )
    parser.add_argument("--version", action="version", version=f"wisp {__version__}")

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
        "--sarif", type=Path, default=None,
        help="Write a SARIF 2.1.0 report to this path (for GitHub Code Scanning and similar).",
    )
    scan_p.add_argument(
        "--fail-on", choices=[s.name for s in Severity], default=None,
        help="Exit non-zero if any finding meets or exceeds this severity "
             "(useful in CI, e.g. --fail-on HIGH).",
    )
    scan_p.add_argument("--quiet", "-q", action="store_true", help="Suppress terminal report output.")
    scan_p.add_argument(
        "--check-cve", action="store_true",
        help="Cross-reference server packages against known vulnerabilities via osv.dev. "
             "The only flag that makes a network call; off by default.",
    )

    serve_p = sub.add_parser("serve", help="Launch a local web UI for scanning MCP configs")
    serve_p.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1). There is no authentication — "
             "binding beyond localhost exposes unauthenticated local file reads to the network.",
    )
    serve_p.add_argument("--port", type=int, default=8765, help="Port to bind to (default: 8765).")
    serve_p.add_argument(
        "--no-browser", action="store_true", help="Don't automatically open a browser tab.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.cmd == "scan":
        try:
            result = scanner.scan(
                paths=args.config, project_dir=args.project_dir, check_cve=args.check_cve,
            )
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

        if args.sarif:
            report.write_sarif(result, args.sarif)
            console.print(f"[dim]SARIF report written to {args.sarif}[/dim]")

        if args.fail_on:
            threshold = Severity[args.fail_on]
            if any(f.severity >= threshold for f in result.findings):
                return 1
        return 0

    if args.cmd == "serve":
        try:
            import uvicorn

            from .web import create_app
        except ImportError:
            console.print(
                "[bold red]Error:[/bold red] the web UI needs extra dependencies. "
                "Install with: [bold]pip install -e '.[web]'[/bold]"
            )
            return 2

        import threading
        import webbrowser

        if args.host not in ("127.0.0.1", "localhost", "::1"):
            console.print(
                f"[bold yellow]Warning:[/bold yellow] binding to {args.host} exposes Wisp to "
                "anyone who can reach this host on the network. There is no authentication: "
                "anyone with network access can read any file on this machine that /api/scan "
                "can be pointed at. Prefer an SSH tunnel or VPN over exposing this directly."
            )

        url = f"http://{args.host}:{args.port}"
        if not args.no_browser:
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()

        console.print(f"[cyan]Wisp web UI running at {url} (Ctrl+C to stop)[/cyan]")
        uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
