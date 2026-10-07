"""CORS_MISCONFIGURATION CLI validates its manifest without any secret material."""

import json
import pytest

from offensive.cors_misconfiguration_cli import (
    CorsMisconfigurationManifestError, main, parse_cors_misconfiguration_manifest,
    preflight_cors_misconfiguration_manifest, read_cors_misconfiguration_manifest,
)


def _manifest(**overrides):
    value = {
        "schema_version": 1, "experiment_id": "CORSMIS-CLI-001",
        "authorization_reference": "written-loopback-cors-misconfiguration-002",
        "authorized_by": "Lab Owner", "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080", "probe_path": "/unmatched-probe-path",
        "canary_origin": "http://canary.pancito-lab.invalid",
        "timeout_ms": 2000, "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode()


def test_preflight_is_zero_request():
    manifest = parse_cors_misconfiguration_manifest(_manifest())
    result = preflight_cors_misconfiguration_manifest(manifest)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 2
    assert result["active_probe_performed"] is False


def test_manifest_rejects_unknown_duplicate_float_and_invalid_canary():
    with pytest.raises(CorsMisconfigurationManifestError, match="unknown fields"):
        parse_cors_misconfiguration_manifest(_manifest(extra_field="nope"))
    with pytest.raises(CorsMisconfigurationManifestError, match="duplicate key"):
        parse_cors_misconfiguration_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(CorsMisconfigurationManifestError, match="floating-point"):
        parse_cors_misconfiguration_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5'))
    with pytest.raises(CorsMisconfigurationManifestError, match="bare http"):
        parse_cors_misconfiguration_manifest(_manifest(canary_origin="not-a-origin"))


def test_missing_field_and_symlink_fail_closed(tmp_path):
    raw = json.loads(_manifest())
    del raw["canary_origin"]
    with pytest.raises(CorsMisconfigurationManifestError, match="missing fields"):
        parse_cors_misconfiguration_manifest(json.dumps(raw).encode())
    real, linked = tmp_path / "real.json", tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(CorsMisconfigurationManifestError, match="symlink"):
        read_cors_misconfiguration_manifest(linked)


def test_cli_dry_run_validates_without_a_network_call(tmp_path, capsys):
    path = tmp_path / "cors_misconfiguration.json"
    path.write_bytes(_manifest())
    assert main(["--dry-run", str(path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "VALIDATED_NOT_EXECUTED"
    assert payload["canary_origin"] == "http://canary.pancito-lab.invalid"
