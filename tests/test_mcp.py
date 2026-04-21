import json
from pathlib import Path

from agent_cfi.mcp import (
    MCPSchemaFinding,
    check_schemas,
    hash_schema,
    load_pins,
    pin_schemas,
    save_pins,
)


def test_hash_schema_is_deterministic_across_key_order():
    a = {"type": "object", "properties": {"x": {"type": "string"}, "y": {"type": "integer"}}}
    b = {"properties": {"y": {"type": "integer"}, "x": {"type": "string"}}, "type": "object"}
    assert hash_schema(a) == hash_schema(b)


def test_hash_schema_changes_on_content_change():
    a = {"type": "object", "properties": {"x": {"type": "string"}}}
    b = {"type": "object", "properties": {"x": {"type": "number"}}}
    assert hash_schema(a) != hash_schema(b)


def test_check_schemas_identical_emits_nothing():
    schemas = {
        "fs": {
            "read_file": {"type": "object", "properties": {"path": {"type": "string"}}},
            "write_file": {"type": "object", "properties": {"path": {"type": "string"}}},
        }
    }
    pins = pin_schemas(schemas)
    findings = check_schemas(pins, schemas)
    assert findings == []


def test_check_schemas_flags_added_tool():
    baseline = {"fs": {"read_file": {"type": "object"}}}
    current = {
        "fs": {
            "read_file": {"type": "object"},
            "write_file": {"type": "object"},
        }
    }
    pins = pin_schemas(baseline)
    findings = check_schemas(pins, current)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, MCPSchemaFinding)
    assert f.kind == "mcp_schema_mismatch"
    assert f.server == "fs" and f.tool == "write_file"
    assert f.baseline_hash == ""
    assert f.current_hash != ""
    assert "added" in f.message


def test_check_schemas_flags_removed_tool():
    baseline = {
        "fs": {
            "read_file": {"type": "object"},
            "write_file": {"type": "object"},
        }
    }
    current = {"fs": {"read_file": {"type": "object"}}}
    pins = pin_schemas(baseline)
    findings = check_schemas(pins, current)
    assert len(findings) == 1
    f = findings[0]
    assert f.server == "fs" and f.tool == "write_file"
    assert f.current_hash == ""
    assert f.baseline_hash != ""
    assert "removed" in f.message


def test_check_schemas_flags_changed_schema():
    baseline = {"fs": {"read_file": {"type": "object", "properties": {"path": {"type": "string"}}}}}
    current = {"fs": {"read_file": {"type": "object", "properties": {"path": {"type": "string"}, "encoding": {"type": "string"}}}}}
    pins = pin_schemas(baseline)
    findings = check_schemas(pins, current)
    assert len(findings) == 1
    f = findings[0]
    assert f.server == "fs" and f.tool == "read_file"
    assert f.baseline_hash and f.current_hash
    assert f.baseline_hash != f.current_hash
    assert "changed" in f.message


def test_check_schemas_reports_entire_new_server():
    baseline = {"fs": {"read_file": {"type": "object"}}}
    current = {
        "fs": {"read_file": {"type": "object"}},
        "net": {"http_get": {"type": "object"}},
    }
    pins = pin_schemas(baseline)
    findings = check_schemas(pins, current)
    assert len(findings) == 1
    assert findings[0].server == "net" and findings[0].tool == "http_get"


def test_save_and_load_pins_roundtrip(tmp_path: Path):
    schemas = {
        "fs": {
            "read_file": {"type": "object", "properties": {"path": {"type": "string"}}},
            "write_file": {"type": "object", "properties": {"path": {"type": "string"}}},
        }
    }
    pins = pin_schemas(schemas)
    out = tmp_path / "nested" / "mcp-pins.json"
    save_pins(pins, out)
    assert out.exists()
    loaded = load_pins(out)
    assert loaded == pins
    # And the file must be valid JSON on disk
    assert json.loads(out.read_text()) == pins
