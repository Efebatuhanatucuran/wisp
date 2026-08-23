import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from mcpsentinel import cve as cve_module
from mcpsentinel import discovery
from mcpsentinel.models import Finding, Severity
from mcpsentinel.web import create_app


@pytest.fixture
def client(monkeypatch):
    # Never let a test hit the real network: the background CVE-feed
    # refresher fires on app startup.
    monkeypatch.setattr(cve_module, "fetch_mcp_cve_feed", lambda limit=20: [])
    monkeypatch.setattr(cve_module, "check_entries_for_cves", lambda entries: [])
    cve_module._nvd_cache.clear()
    with TestClient(create_app()) as c:
        yield c


def test_index_serves_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "Wisp" in res.text


def test_static_app_js_served(client):
    res = client.get("/static/app.js")
    assert res.status_code == 200


def test_discover_returns_files(client, monkeypatch):
    monkeypatch.setattr(discovery, "discover_config_files", lambda project_dir=None: [Path("/tmp/x.json")])
    res = client.get("/api/discover")
    assert res.status_code == 200
    assert res.json() == {"files": ["/tmp/x.json"]}


def test_example_risky_returns_content(client):
    res = client.get("/api/examples/risky")
    assert res.status_code == 200
    assert "mcpServers" in res.json()["content"]


def test_example_unknown_name_404s(client):
    res = client.get("/api/examples/nope")
    assert res.status_code == 404


def test_scan_via_inline_files(client):
    content = json.dumps({"mcpServers": {"shell": {"command": "bash"}}})
    res = client.post("/api/scan", json={
        "files": [{"name": "x.json", "content": content}], "check_cve": False,
    })
    assert res.status_code == 200
    body = res.json()
    assert body["servers_scanned"] == 1
    assert any(f["rule_id"] == "R001" for f in body["findings"])


def test_scan_bad_path_returns_400(client):
    res = client.post("/api/scan", json={"paths": ["/no/such/file.json"], "check_cve": False})
    assert res.status_code == 400
    assert "could not read" in res.json()["detail"]


def test_scan_check_cve_true_merges_findings(client, monkeypatch):
    def fake_check(entries):
        return [Finding(
            rule_id="R010", severity=Severity.CRITICAL, title="t", description="d",
            server_name="pkg", source_file=Path("x.json"),
        )]
    monkeypatch.setattr(cve_module, "check_entries_for_cves", fake_check)

    content = json.dumps({"mcpServers": {"pkg": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}})
    res = client.post("/api/scan", json={
        "files": [{"name": "x.json", "content": content}], "check_cve": True,
    })
    assert res.status_code == 200
    assert any(f["rule_id"] == "R010" for f in res.json()["findings"])


def test_scan_report_html_download(client):
    content = json.dumps({"mcpServers": {}})
    res = client.post("/api/scan/report.html", json={
        "files": [{"name": "x.json", "content": content}], "check_cve": False,
    })
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "attachment" in res.headers["content-disposition"]


def test_cve_feed_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        cve_module, "fetch_mcp_cve_feed_cached",
        lambda force=False: ([{"id": "CVE-2099-1"}], 1_700_000_000.0),
    )
    res = client.get("/api/cve-feed")
    assert res.status_code == 200
    body = res.json()
    assert body["items"] == [{"id": "CVE-2099-1"}]
    assert "source" in body and "fetched_at" in body
