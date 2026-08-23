import json

import pytest

from mcpsentinel import discovery


def test_parse_config_text_matches_parse_config_file(tmp_path):
    payload = {"mcpServers": {"foo": {"command": "npx", "args": ["-y", "foo@1.0.0"]}}}
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(payload))

    from_file = discovery.parse_config_file(path)
    from_text = discovery.parse_config_text(json.dumps(payload), "mcp.json")

    assert len(from_file) == len(from_text) == 1
    assert from_file[0].name == from_text[0].name == "foo"
    assert from_text[0].source_file == path.__class__("mcp.json")


def test_parse_config_text_supports_vscode_servers_key():
    payload = {"servers": {"bar": {"command": "docker", "args": ["run", "img:1.0"]}}}
    entries = discovery.parse_config_text(json.dumps(payload), ".vscode/mcp.json")
    assert len(entries) == 1
    assert entries[0].source_format == "vscode"


def test_parse_config_text_invalid_json_raises_value_error():
    with pytest.raises(ValueError, match="could not parse"):
        discovery.parse_config_text("{not valid json", "bad.json")


def test_parse_config_file_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="could not read"):
        discovery.parse_config_file(tmp_path / "does-not-exist.json")
