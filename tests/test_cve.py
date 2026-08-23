from pathlib import Path

from wisp import cve
from wisp.models import ServerEntry, Severity


def _entry(command, args) -> ServerEntry:
    return ServerEntry(name="srv", source_file=Path("mcp.json"), source_format="mcp_json",
                        command=command, args=args)


def test_extract_package_ref_npm_pinned():
    entry = _entry("npx", ["-y", "some-tool@1.2.3"])
    assert cve.extract_package_ref(entry) == ("npm", "some-tool", "1.2.3")


def test_extract_package_ref_npm_unpinned():
    entry = _entry("npx", ["-y", "some-tool"])
    assert cve.extract_package_ref(entry) == ("npm", "some-tool", None)


def test_extract_package_ref_npm_scoped_pinned():
    entry = _entry("npx", ["-y", "@modelcontextprotocol/server-filesystem@1.4.2"])
    assert cve.extract_package_ref(entry) == ("npm", "@modelcontextprotocol/server-filesystem", "1.4.2")


def test_extract_package_ref_npm_scoped_unpinned():
    entry = _entry("npx", ["-y", "@scope/pkg"])
    assert cve.extract_package_ref(entry) == ("npm", "@scope/pkg", None)


def test_extract_package_ref_pypi_double_equals():
    entry = _entry("uvx", ["some-tool==2.0.0"])
    assert cve.extract_package_ref(entry) == ("PyPI", "some-tool", "2.0.0")


def test_extract_package_ref_unknown_runner_returns_none():
    entry = _entry("docker", ["run", "img:latest"])
    assert cve.extract_package_ref(entry) is None


def test_extract_package_ref_no_command_returns_none():
    entry = _entry(None, [])
    assert cve.extract_package_ref(entry) is None


def test_extract_package_ref_no_package_arg_returns_none():
    entry = _entry("npx", ["--yes"])
    assert cve.extract_package_ref(entry) is None


def test_osv_severity_maps_known_labels():
    assert cve._osv_severity({"database_specific": {"severity": "MODERATE"}}) == Severity.MEDIUM
    assert cve._osv_severity({"database_specific": {"severity": "CRITICAL"}}) == Severity.CRITICAL
    assert cve._osv_severity({}) == Severity.HIGH  # unknown -> default to HIGH, not silently LOW


def test_check_entries_for_cves_uses_cache_and_dedupes(monkeypatch):
    calls = []

    def fake_query(ecosystem, package, version):
        calls.append((ecosystem, package, version))
        return [{"id": "GHSA-xxxx", "aliases": ["CVE-2024-0001"], "summary": "bad stuff",
                  "database_specific": {"severity": "HIGH"}}]

    monkeypatch.setattr(cve, "query_osv_cached", fake_query)

    entry_a = _entry("npx", ["-y", "dup-pkg@1.0.0"])
    entry_b = _entry("npx", ["-y", "dup-pkg@1.0.0"])  # same ecosystem/package/version
    findings = cve.check_entries_for_cves([entry_a, entry_b])

    assert len(calls) == 1  # deduped, not queried twice
    assert len(findings) == 1
    assert findings[0].rule_id == "R010"
    assert "CVE-2024-0001" in findings[0].evidence


def test_check_entries_for_cves_skips_non_package_entries(monkeypatch):
    monkeypatch.setattr(cve, "query_osv_cached", lambda *a: (_ for _ in ()).throw(AssertionError("should not be called")))
    findings = cve.check_entries_for_cves([_entry("docker", ["run", "img"])])
    assert findings == []


def test_fetch_mcp_cve_feed_cached_serves_cache_within_ttl(monkeypatch):
    cve._nvd_cache.clear()
    calls = {"n": 0}

    def fake_fetch(limit=20):
        calls["n"] += 1
        return [{"id": "CVE-2099-0001"}]

    monkeypatch.setattr(cve, "fetch_mcp_cve_feed", fake_fetch)

    items1, ts1 = cve.fetch_mcp_cve_feed_cached()
    items2, ts2 = cve.fetch_mcp_cve_feed_cached()  # should hit cache, not re-fetch

    assert calls["n"] == 1
    assert items1 == items2 == [{"id": "CVE-2099-0001"}]
    assert ts1 == ts2


def test_fetch_mcp_cve_feed_cached_force_refetches(monkeypatch):
    cve._nvd_cache.clear()
    calls = {"n": 0}

    def fake_fetch(limit=20):
        calls["n"] += 1
        return [{"id": f"CVE-{calls['n']}"}]

    monkeypatch.setattr(cve, "fetch_mcp_cve_feed", fake_fetch)

    cve.fetch_mcp_cve_feed_cached()
    cve.fetch_mcp_cve_feed_cached(force=True)

    assert calls["n"] == 2


def test_fetch_mcp_cve_feed_cached_falls_back_to_stale_on_failed_refresh(monkeypatch):
    cve._nvd_cache.clear()
    responses = iter([[{"id": "CVE-1"}], []])  # second "fetch" fails/returns nothing

    monkeypatch.setattr(cve, "fetch_mcp_cve_feed", lambda limit=20: next(responses))

    items1, _ = cve.fetch_mcp_cve_feed_cached()
    items2, _ = cve.fetch_mcp_cve_feed_cached(force=True)

    assert items1 == [{"id": "CVE-1"}]
    assert items2 == [{"id": "CVE-1"}]  # stale data kept, not wiped by the empty refresh
