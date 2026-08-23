from __future__ import annotations

import json
import os
from pathlib import Path

from .models import ServerEntry

# Well-known locations where MCP client configs live, by platform.
KNOWN_CONFIG_PATHS: list[tuple[str, str]] = [
    ("claude_desktop", "Library/Application Support/Claude/claude_desktop_config.json"),
    ("claude_desktop_win", "AppData/Roaming/Claude/claude_desktop_config.json"),
    ("cursor", ".cursor/mcp.json"),
    ("vscode", ".vscode/mcp.json"),
    ("windsurf", ".codeium/windsurf/mcp_config.json"),
]

# Project-local filenames checked in the given/current directory.
PROJECT_LOCAL_FILENAMES: list[tuple[str, str]] = [
    ("mcp_json", ".mcp.json"),
    ("mcp_json", "mcp.json"),
    ("cursor", ".cursor/mcp.json"),
    ("vscode", ".vscode/mcp.json"),
]


def discover_config_files(project_dir: Path | None = None) -> list[Path]:
    """Find MCP config files on this machine: known client config
    locations under $HOME, plus any project-local configs under
    ``project_dir`` (defaults to the current working directory)."""
    found: list[Path] = []
    home = Path.home()

    for _fmt, rel in KNOWN_CONFIG_PATHS:
        candidate = home / rel
        if candidate.is_file():
            found.append(candidate)

    base = project_dir or Path.cwd()
    for _fmt, rel in PROJECT_LOCAL_FILENAMES:
        candidate = base / rel
        if candidate.is_file() and candidate not in found:
            found.append(candidate)

    return found


def _looks_like_env_passthrough_value(value: str) -> bool:
    return value.startswith("${") or value.startswith("$")


def parse_config_file(path: Path) -> list[ServerEntry]:
    """Parse a single MCP config file into normalized ServerEntry objects.
    Supports the two shapes in the wild: {"mcpServers": {...}} (Claude
    Desktop, Cursor, most clients) and {"servers": {...}} (VS Code)."""
    try:
        text = path.read_text()
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    return _parse_config_text(text, path)


def parse_config_text(text: str, source_name: str) -> list[ServerEntry]:
    """Parse MCP config JSON already in memory (e.g. an uploaded/dropped
    file) into normalized ServerEntry objects. ``source_name`` is used only
    for format inference and as a display label — it need not exist on disk."""
    return _parse_config_text(text, Path(source_name))


def _parse_config_text(text: str, path: Path) -> list[ServerEntry]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc

    servers_block = data.get("mcpServers") or data.get("servers") or {}
    source_format = _infer_format(path, data)

    entries: list[ServerEntry] = []
    for name, raw in servers_block.items():
        if not isinstance(raw, dict):
            continue
        entries.append(_normalize_entry(name, raw, path, source_format))
    return entries


def _infer_format(path: Path, data: dict) -> str:
    p = str(path)
    if "Claude" in p and "claude_desktop_config.json" in p:
        return "claude_desktop"
    if ".cursor" in p:
        return "cursor"
    if ".vscode" in p:
        return "vscode"
    if ".codeium" in p:
        return "windsurf"
    if "servers" in data:
        return "vscode"
    return "mcp_json"


def _normalize_entry(name: str, raw: dict, path: Path, source_format: str) -> ServerEntry:
    url = raw.get("url") or raw.get("serverUrl")
    command = raw.get("command")
    args = list(raw.get("args") or [])
    env = dict(raw.get("env") or {})

    transport = raw.get("type") or raw.get("transport")
    if not transport:
        transport = "stdio" if command else ("sse" if url else "unknown")

    return ServerEntry(
        name=name,
        source_file=path,
        source_format=source_format,
        transport=transport,
        command=command,
        args=args,
        env=env,
        url=url,
        raw=raw,
    )


def load_all(paths: list[Path]) -> list[ServerEntry]:
    entries: list[ServerEntry] = []
    for p in paths:
        entries.extend(parse_config_file(p))
    return entries
