<p align="center">
  <img src="assets/wisp.svg" width="90" alt="Wisp mascot">
</p>

<h1 align="center">Wisp</h1>

<p align="center"><em>Türkçe: <a href="README.tr.md">README.tr.md</a></em></p>

A static security scanner for [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
server configurations — the config files that tell Claude Desktop, Cursor, VS Code, and other
AI clients which tools an agent is allowed to call.

As agentic AI adoption accelerates, misconfigured or malicious MCP servers are becoming a real
attack surface: a config can hand an agent a raw shell, an unpinned package that can change
underneath you, a hardcoded API key, or a remote endpoint you've never audited. Wisp finds that
class of problem *before* you run the server, without ever connecting to it.

## What it checks for

| Rule | Checks for |
|------|------------|
| R001 | Server launches a raw shell (`bash`, `sh`, `powershell`, ...) instead of a scoped binary |
| R002 | MCP server package run via `npx`/`uvx`/etc. with no pinned version (supply-chain risk) |
| R003 | Hardcoded API keys / tokens / passwords sitting in plaintext in the config |
| R004 | Remote (non-localhost) endpoints, especially unencrypted HTTP |
| R005 | Permission-bypassing flags or whole-filesystem access (`/`, `~`, `--dangerously-skip-permissions`) |
| R006 | Privileged Docker containers or a mounted Docker socket |
| R007 | Malformed/ambiguous server entries |
| R008 | Prompt-injection-style text embedded directly in the config itself |
| R009 | Docker images not pinned to a version/digest (floating `:latest`) |
| R010 | Server package has a known published vulnerability (CVE/GHSA via osv.dev) — opt-in, see below |
| R011 | (INFO) Credential correctly externalized via an environment-variable passthrough |

Each finding gets a severity (INFO → CRITICAL) and the whole scan rolls up into a single
0–100 risk score.

## Install

```bash
pip install -e .
```

For the web UI too:

```bash
pip install -e ".[web]"
```

(PyPI package coming later — for now, clone and install from source.)

## Usage

```bash
# Auto-discover known client configs (Claude Desktop, Cursor, VS Code, Windsurf)
# plus any .mcp.json in the current project, and scan them all:
wisp scan

# Scan a specific file:
wisp scan --config path/to/mcp.json

# Write JSON/HTML reports (HTML is a shareable one-pager):
wisp scan --json report.json --html report.html

# Also cross-reference server packages against known CVEs via osv.dev
# (the only flag that makes a network call; off by default):
wisp scan --check-cve

# CI mode — exit non-zero if anything HIGH or above is found:
wisp scan --fail-on HIGH
```

## Example

```bash
wisp scan --config examples/risky-config.json
```

See [`examples/`](examples/) for a deliberately risky sample config and the report it produces.

## Web UI

```bash
wisp serve
```

Opens a local dashboard (default `http://127.0.0.1:8765`) for scanning interactively instead of
via the terminal: pick from auto-discovered configs, drag & drop a file, or load the bundled
risky/safe/all-severities examples; findings are grouped by server with severity filters, and
reports can be downloaded as JSON or HTML. Wisp — the little glowing mascot up top — sits next to
the header and changes color with your risk score once you scan. A few things the web UI does
that the CLI doesn't:

- **CVE matching** (on by default, toggleable): cross-references every server package against
  [osv.dev](https://osv.dev) and flags known vulnerabilities as R010 findings.
- **MCP CVE feed**: a panel tracking recently published CVEs that mention "Model Context
  Protocol" (via the [NVD](https://nvd.nist.gov) keyword search), refreshed automatically in the
  background every 6 hours while `serve` is running, plus a manual refresh button.
- **EN/TR language toggle**: switches all UI copy between English and Turkish. The CVE feed goes
  further — switching to TR machine-translates the currently fetched CVE summaries (via the free
  [MyMemory](https://mymemory.translated.net) API), so you can skim them in Turkish too.
- **Privacy-masked paths**: any file path under your home directory is shown as `/Users/****/...`
  (or the platform equivalent) everywhere a human looks at it — the file list, finding cards, and
  CLI terminal output — so screenshots don't leak your username. Raw JSON output is left unmasked
  since it's meant for programmatic use.

**Security note:** `wisp serve` has no authentication. It defaults to `127.0.0.1` (not reachable
from other machines), which is the safe setting — `/api/scan` will read and reflect back any file
on disk it's pointed at, by design, so it can scan a config anywhere on your machine. Don't pass
`--host 0.0.0.0` (or otherwise expose the port) without putting your own auth in front of it, e.g.
an SSH tunnel or VPN.

## Why config-only (no live connection) by default?

The core scanner is intentionally static: it parses the JSON your MCP client will hand a server,
with no network calls and no code execution. That keeps it safe to run against configs you don't
fully trust yet, and keeps the scope honest for what it actually checks. `--check-cve` (CLI) and
the web UI are the one deliberate exception — they query osv.dev/NVD to check for *known*,
already-published vulnerabilities, not to introspect anything about your machine. Live
introspection (fetching a running server's tool list and scanning *tool descriptions* for
prompt-injection payloads, similar to what [AgentDojo](https://github.com/ethz-spylab/agentdojo)
benchmarks) is the natural next step — see [Roadmap](#roadmap).

## Roadmap

- [ ] Live mode: connect to stdio/SSE servers and scan actual tool descriptions/schemas
- [ ] Allowlist/baseline file so CI only fails on *new* findings
- [ ] `pip`/`brew` distribution
- [ ] Vulnerability scanning for Docker images themselves (not just npm/PyPI packages)

## License

MIT — see [LICENSE](LICENSE).
