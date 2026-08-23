"""Live CVE/advisory lookups: matches MCP server packages against known
vulnerabilities (osv.dev) and tracks recently published MCP-related CVEs
(NVD keyword search). Unlike the rest of mcpsentinel, everything in this
module makes network calls and fails open (returns empty results) on any
network error so a lookup outage never breaks a scan."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import Finding, ServerEntry, Severity

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_TIMEOUT = 6.0

_OSV_CACHE_TTL = 6 * 3600
_NVD_CACHE_TTL = 6 * 3600

_osv_cache: dict[tuple[str, str, str | None], tuple[float, list[dict]]] = {}
_nvd_cache: dict[str, tuple[list[dict], float]] = {}

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_NPM_RUNNERS = {"npx", "bunx", "dlx"}
_PYPI_RUNNERS = {"uvx", "pipx"}


def _post_json(url: str, payload: dict) -> dict | None:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        return None


def _get_json(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        return None


# --- Package <-> CVE matching, run against the servers in a scanned config --

def extract_package_ref(entry: ServerEntry) -> tuple[str, str, str | None] | None:
    """Best-effort (ecosystem, package_name, version) for a server entry
    that runs a package via a known runner (npx/uvx/...). None if this
    entry isn't a package invocation we know how to look up."""
    if not entry.command:
        return None
    cmd_name = entry.command.split("/")[-1].lower()

    if cmd_name in _NPM_RUNNERS:
        ecosystem = "npm"
    elif cmd_name in _PYPI_RUNNERS:
        ecosystem = "PyPI"
    else:
        return None

    package_args = [a for a in entry.args if not a.startswith("-")]
    if not package_args:
        return None
    spec = package_args[0]

    name, version = _split_npm_spec(spec) if ecosystem == "npm" else _split_pypi_spec(spec)
    return ecosystem, name, version


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        rest = spec[1:]
        if "@" in rest:
            name, version = rest.rsplit("@", 1)
            return f"@{name}", version
        return spec, None
    if "@" in spec:
        name, version = spec.rsplit("@", 1)
        return name, version
    return spec, None


def _split_pypi_spec(spec: str) -> tuple[str, str | None]:
    for sep in ("==", "@"):
        if sep in spec:
            name, version = spec.split(sep, 1)
            return name, version
    return spec, None


def query_osv(ecosystem: str, package: str, version: str | None) -> list[dict]:
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    data = _post_json(_OSV_QUERY_URL, payload)
    return (data or {}).get("vulns", [])


def query_osv_cached(ecosystem: str, package: str, version: str | None) -> list[dict]:
    key = (ecosystem, package, version)
    now = time.time()
    cached = _osv_cache.get(key)
    if cached and now - cached[0] < _OSV_CACHE_TTL:
        return cached[1]
    result = query_osv(ecosystem, package, version)
    _osv_cache[key] = (now, result)
    return result


def _osv_severity(vuln: dict) -> Severity:
    label = (vuln.get("database_specific") or {}).get("severity")
    if label:
        return _SEVERITY_MAP.get(str(label).upper(), Severity.HIGH)
    return Severity.HIGH


def _osv_finding(entry: ServerEntry, ecosystem: str, package: str, version: str | None, vuln: dict) -> Finding:
    vuln_id = vuln.get("id", "UNKNOWN")
    cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    display_id = cve_ids[0] if cve_ids else vuln_id
    summary = vuln.get("summary") or (vuln.get("details") or "")[:200]
    scope = f"{package}@{version}" if version else f"{package} (unpinned — checked across all versions)"

    return Finding(
        rule_id="R010",
        severity=_osv_severity(vuln),
        title=f"Known vulnerability {display_id} in MCP server package",
        description=(
            f"Server '{entry.name}' runs '{scope}' ({ecosystem}), which has a published "
            f"security advisory: {summary}"
        ),
        server_name=entry.name,
        source_file=entry.source_file,
        evidence=f"{vuln_id}" + (f" / {', '.join(cve_ids)}" if cve_ids else "") + f" · {ecosystem}:{scope}",
        remediation=f"Review {display_id} and upgrade '{package}' to a patched version.",
    )


def check_entries_for_cves(entries: list[ServerEntry]) -> list[Finding]:
    """Cross-reference every package-based server entry against osv.dev.
    Never raises: network/parsing issues just yield fewer findings."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str | None]] = set()
    for entry in entries:
        try:
            ref = extract_package_ref(entry)
            if not ref:
                continue
            ecosystem, package, version = ref
            if (ecosystem, package, version) in seen:
                continue
            seen.add((ecosystem, package, version))
            for vuln in query_osv_cached(ecosystem, package, version):
                findings.append(_osv_finding(entry, ecosystem, package, version, vuln))
        except Exception:
            continue
    return findings


# --- General "MCP" CVE feed (NVD keyword search), independent of any scan --

def _nvd_severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseSeverity") or "UNKNOWN"
    return "UNKNOWN"


_NVD_FETCH_PAGE_SIZE = 2000  # NVD's max resultsPerPage; the "Model Context Protocol"
# keyword match set is far under this, so one request captures it all. Fetching a
# small page and sorting it would silently return the OLDEST matches instead of the
# newest, since NVD's default order is publish-date ascending, not descending.


def fetch_mcp_cve_feed(limit: int = 20) -> list[dict]:
    base_params = {
        "keywordSearch": "Model Context Protocol",
        "resultsPerPage": _NVD_FETCH_PAGE_SIZE,
    }
    data = _get_json(f"{_NVD_URL}?{urllib.parse.urlencode(base_params)}")
    if not data:
        return []

    total = data.get("totalResults", 0)
    if total > _NVD_FETCH_PAGE_SIZE:
        # Results come back oldest-first; once the corpus outgrows one page,
        # the newest entries live in the LAST page, not the first.
        start_index = max(0, total - _NVD_FETCH_PAGE_SIZE)
        data = _get_json(
            f"{_NVD_URL}?{urllib.parse.urlencode({**base_params, 'startIndex': start_index})}",
        ) or data

    items = []
    for entry in data.get("vulnerabilities", []):
        cve_data = entry.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue
        desc = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "",
        )
        items.append({
            "id": cve_id,
            "summary": desc,
            "published": cve_data.get("published"),
            "severity": _nvd_severity(cve_data),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    items.sort(key=lambda i: i.get("published") or "", reverse=True)
    return items[:limit]


def fetch_mcp_cve_feed_cached(limit: int = 20, force: bool = False) -> tuple[list[dict], float]:
    """Returns (items, fetched_at_epoch_seconds). Serves cached results within
    the TTL; on a failed refresh, falls back to serving stale cached data
    rather than going blank."""
    key = f"mcp_feed:{limit}"
    now = time.time()
    cached = _nvd_cache.get(key)
    if not force and cached and now - cached[1] < _NVD_CACHE_TTL:
        return cached

    items = fetch_mcp_cve_feed(limit)
    if items or not cached:
        _nvd_cache[key] = (items, now)
        return _nvd_cache[key]
    return cached
