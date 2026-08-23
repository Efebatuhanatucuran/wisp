from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlparse

from .models import Finding, ServerEntry, Severity

RuleFunc = Callable[[ServerEntry], list[Finding]]
_REGISTRY: list[RuleFunc] = []


def rule(func: RuleFunc) -> RuleFunc:
    _REGISTRY.append(func)
    return func


def run_all_rules(entry: ServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    for fn in _REGISTRY:
        findings.extend(fn(entry))
    return findings


def _finding(entry: ServerEntry, rule_id: str, severity: Severity, title: str,
             description: str, evidence: str = "", remediation: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        server_name=entry.name,
        source_file=entry.source_file,
        evidence=evidence,
        remediation=remediation,
    )


# --- R001: direct shell invocation -----------------------------------------

_SHELL_BINARIES = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}


@rule
def r001_shell_invocation(entry: ServerEntry) -> list[Finding]:
    if not entry.command:
        return []
    cmd_name = entry.command.split("/")[-1].lower()
    if cmd_name in _SHELL_BINARIES:
        return [_finding(
            entry, "R001", Severity.CRITICAL,
            "MCP server launches a shell interpreter directly",
            f"Server '{entry.name}' runs '{entry.command}' as its command, handing an AI "
            "agent a general-purpose shell instead of a scoped tool interface. Any prompt "
            "injection reaching this server can execute arbitrary commands.",
            evidence=entry.command_line,
            remediation="Replace with a purpose-built MCP server binary/script that exposes "
                        "only the specific operations needed, not a raw shell.",
        )]
    return []


# --- R002: unpinned package execution (supply-chain risk) ------------------

_PACKAGE_RUNNERS = {"npx", "uvx", "pipx", "bunx", "dlx"}
_VERSION_PIN_RE = re.compile(r"@(\d+\.\d+\.\d+|latest|next|[\w.\-]+)$")


@rule
def r002_unpinned_package(entry: ServerEntry) -> list[Finding]:
    if not entry.command:
        return []
    cmd_name = entry.command.split("/")[-1].lower()
    if cmd_name not in _PACKAGE_RUNNERS:
        return []

    package_args = [a for a in entry.args if not a.startswith("-")]
    if not package_args:
        return []
    package = package_args[0]

    m = _VERSION_PIN_RE.search(package)
    if m is None:
        return [_finding(
            entry, "R002", Severity.HIGH,
            "MCP server package has no pinned version",
            f"Server '{entry.name}' runs '{package}' via {cmd_name} without a version pin. "
            "It will silently pull whatever the maintainer (or an attacker who compromises "
            "the package) publishes next time it runs.",
            evidence=entry.command_line,
            remediation=f"Pin an exact version, e.g. '{package}@1.2.3', and bump deliberately.",
        )]
    if m.group(1) in ("latest", "next"):
        return [_finding(
            entry, "R002", Severity.MEDIUM,
            "MCP server pinned to a floating tag",
            f"Server '{entry.name}' pins '{package}' to '{m.group(1)}', which still moves "
            "underneath you.",
            evidence=entry.command_line,
            remediation="Pin an exact semantic version instead of 'latest'/'next'.",
        )]
    return []


# --- R003: hardcoded secrets in env -----------------------------------------

_SECRET_KEY_RE = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE)
_SECRET_VALUE_PATTERNS = [
    re.compile(r"^sk-[A-Za-z0-9]{10,}$"),
    re.compile(r"^ghp_[A-Za-z0-9]{20,}$"),
    re.compile(r"^gh[oprsu]_[A-Za-z0-9]{20,}$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^AIza[0-9A-Za-z\-_]{35}$"),
    re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
]


def _is_placeholder(value: str) -> bool:
    if _looks_like_var_ref(value):
        return True
    if not value or len(value) < 8:
        return True
    lowered = value.lower()
    return any(tok in lowered for tok in ("your-", "changeme", "example", "placeholder", "<", ">"))


def _looks_like_var_ref(value: str) -> bool:
    return value.startswith("${") or value.startswith("$") or value.startswith("env:")


@rule
def r003_hardcoded_secret(entry: ServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in entry.env.items():
        if not isinstance(value, str):
            continue
        matches_known_pattern = any(p.match(value) for p in _SECRET_VALUE_PATTERNS)
        looks_like_secret_key = bool(_SECRET_KEY_RE.search(key)) and not _is_placeholder(value)
        if matches_known_pattern or looks_like_secret_key:
            findings.append(_finding(
                entry, "R003", Severity.HIGH,
                "Hardcoded credential in MCP server config",
                f"Server '{entry.name}' has env var '{key}' set to a literal value in the "
                "config file rather than a reference to a secret store. Config files are "
                "often committed to git, synced, or backed up in plaintext.",
                evidence=f"{key}=<redacted, {len(value)} chars>",
                remediation="Move the secret to your OS keychain / secret manager and "
                            "reference it (e.g. via an env-var passthrough), or at minimum "
                            "keep this config file out of version control.",
            ))
    return findings


# --- R004: remote / non-localhost endpoints ---------------------------------

@rule
def r004_remote_endpoint(entry: ServerEntry) -> list[Finding]:
    if not entry.url:
        return []
    parsed = urlparse(entry.url)
    host = parsed.hostname or ""
    is_local = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")

    if parsed.scheme == "http" and not is_local:
        return [_finding(
            entry, "R004", Severity.CRITICAL,
            "MCP server reachable over unencrypted remote HTTP",
            f"Server '{entry.name}' points at '{entry.url}': a plaintext, non-localhost "
            "endpoint. Traffic (including tool calls and results fed back into the model "
            "context) can be intercepted or tampered with in transit.",
            evidence=entry.url,
            remediation="Use HTTPS, and prefer a server you control over a third-party "
                        "remote endpoint for anything handling sensitive data.",
        )]
    if not is_local:
        return [_finding(
            entry, "R004", Severity.MEDIUM,
            "MCP server is a remote, non-localhost endpoint",
            f"Server '{entry.name}' connects to '{entry.url}'. Every tool call and its "
            "result crosses a trust boundary to a third party. Verify you trust the "
            "operator and that its responses can't be used to inject instructions.",
            evidence=entry.url,
            remediation="Confirm this endpoint is operated by a party you trust, and that "
                        "the client enforces least-privilege scopes for it.",
        )]
    return []


# --- R005: overly broad filesystem / permission flags -----------------------

_BROAD_ACCESS_MARKERS = [
    "--allow-all", "--dangerously-skip-permissions", "--no-sandbox",
    "--root", "--allow-root", "--full-access", "--unrestricted",
]
_BROAD_PATH_MARKERS = {"/", "~", "$HOME", "/etc", "/System", "C:\\"}


@rule
def r005_broad_access(entry: ServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    joined = " ".join(entry.args)
    for marker in _BROAD_ACCESS_MARKERS:
        if marker in joined:
            findings.append(_finding(
                entry, "R005", Severity.HIGH,
                "MCP server started with a permission-bypassing flag",
                f"Server '{entry.name}' is launched with '{marker}', which disables a "
                "safety boundary the tool would otherwise enforce.",
                evidence=entry.command_line,
                remediation="Drop the flag and grant only the specific access the server "
                            "actually needs.",
            ))
    for arg in entry.args:
        if arg.strip() in _BROAD_PATH_MARKERS:
            findings.append(_finding(
                entry, "R005", Severity.HIGH,
                "MCP server granted filesystem access to a broad root path",
                f"Server '{entry.name}' is passed '{arg}' as a path argument, which reads "
                "as whole-home or whole-filesystem access rather than a scoped directory.",
                evidence=entry.command_line,
                remediation="Scope the argument to the specific project/data directory the "
                            "server needs, not a home or root directory.",
            ))
    return findings


# --- R006: privileged / docker-socket container flags -----------------------

@rule
def r006_privileged_container(entry: ServerEntry) -> list[Finding]:
    if not entry.command or entry.command.split("/")[-1] != "docker":
        return []
    findings: list[Finding] = []
    joined = " ".join(entry.args)
    if "--privileged" in entry.args:
        findings.append(_finding(
            entry, "R006", Severity.CRITICAL,
            "MCP server container runs with --privileged",
            f"Server '{entry.name}' runs its container with '--privileged', which removes "
            "essentially all container isolation from the host.",
            evidence=entry.command_line,
            remediation="Remove --privileged; add only the specific capabilities required "
                        "via --cap-add.",
        ))
    if "/var/run/docker.sock" in joined:
        findings.append(_finding(
            entry, "R006", Severity.CRITICAL,
            "MCP server container is mounted with access to the Docker socket",
            f"Server '{entry.name}' mounts /var/run/docker.sock into its container, which "
            "is equivalent to root access on the host.",
            evidence=entry.command_line,
            remediation="Avoid mounting the Docker socket; use a scoped API/proxy if the "
                        "server genuinely needs to manage containers.",
        ))
    return findings


# --- R007: malformed / ambiguous entry --------------------------------------

@rule
def r007_ambiguous_entry(entry: ServerEntry) -> list[Finding]:
    if not entry.command and not entry.url:
        return [_finding(
            entry, "R007", Severity.LOW,
            "MCP server entry defines neither a command nor a url",
            f"Server '{entry.name}' has no launch command and no remote url, so its actual "
            "behavior can't be assessed from this config alone.",
            evidence=str(entry.raw),
            remediation="Confirm this entry is intentional; remove dead config.",
        )]
    return []


# --- R008: prompt-injection-style text embedded in the config itself -------

_INJECTION_PHRASES = [
    "ignore previous instructions", "ignore all previous instructions",
    "disregard prior instructions", "do not tell the user", "do not inform the user",
    "you must always", "system prompt", "reveal your instructions",
    "act as if", "this is not a test",
]


@rule
def r008_embedded_injection_text(entry: ServerEntry) -> list[Finding]:
    findings: list[Finding] = []
    haystacks: list[tuple[str, str]] = []
    for arg in entry.args:
        haystacks.append(("args", arg))
    for k, v in entry.env.items():
        if isinstance(v, str):
            haystacks.append((f"env.{k}", v))

    for field_name, text in haystacks:
        lowered = text.lower()
        for phrase in _INJECTION_PHRASES:
            if phrase in lowered:
                findings.append(_finding(
                    entry, "R008", Severity.CRITICAL,
                    "Prompt-injection-style text found inside server config",
                    f"Server '{entry.name}' has the phrase \"{phrase}\" embedded in "
                    f"'{field_name}'. Config fields like args/env can end up in the model's "
                    "context in some clients; this reads as an attempt to steer the agent "
                    "outside of normal conversation.",
                    evidence=f"{field_name}: {text[:120]}",
                    remediation="Treat this config as compromised or malicious until proven "
                                "otherwise. Do not run it; verify its source.",
                ))
    return findings


# --- R009: floating/latest docker image tag ---------------------------------

@rule
def r009_floating_docker_tag(entry: ServerEntry) -> list[Finding]:
    if not entry.command or entry.command.split("/")[-1] != "docker":
        return []
    run_idx = None
    for i, a in enumerate(entry.args):
        if a == "run":
            run_idx = i
            break
    if run_idx is None:
        return []
    image_candidates = [a for a in entry.args[run_idx + 1:] if not a.startswith("-")]
    if not image_candidates:
        return []
    image = image_candidates[-1]
    if ":" not in image.split("/")[-1]:
        tag_desc = "no tag (defaults to :latest)"
    elif image.endswith(":latest"):
        tag_desc = "':latest'"
    else:
        return []
    return [_finding(
        entry, "R009", Severity.MEDIUM,
        "MCP server container image is not pinned to a digest/version",
        f"Server '{entry.name}' runs image '{image}' with {tag_desc}. The image contents "
        "can change without any change to this config.",
        evidence=entry.command_line,
        remediation="Pin to a specific version tag or, better, an image digest (@sha256:...).",
    )]


# --- R011: credential correctly externalized (informational) ----------------

@rule
def r011_env_var_passthrough_info(entry: ServerEntry) -> list[Finding]:
    findings = []
    for key, value in entry.env.items():
        if not isinstance(value, str):
            continue
        if _SECRET_KEY_RE.search(key) and _looks_like_var_ref(value):
            findings.append(_finding(
                entry, "R011", Severity.INFO,
                "Credential correctly externalized via environment variable",
                f"Server '{entry.name}' references '{key}' via an environment-variable "
                f"passthrough ({value}) instead of a literal value — this is the right pattern.",
                evidence=f"{key}={value}",
                remediation="No action needed; keep secrets out of the config file like this.",
            ))
    return findings
