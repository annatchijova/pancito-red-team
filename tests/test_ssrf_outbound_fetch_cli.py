"""SSRF_OUTBOUND_FETCH CLI validates its manifest without any secret material."""

import json
import pytest

from offensive.ssrf_outbound_fetch_cli import (
    SsrfOutboundFetchManifestError, main, parse_ssrf_outbound_fetch_manifest,
    preflight_ssrf_outbound_fetch_manifest, read_ssrf_outbound_fetch_manifest,
)


def _manifest(**overrides):
    value = {
        "schema_version": 1, "experiment_id": "SSRF-CLI-001",
        "authorization_reference": "written-loopback-ssrf-outbound-fetch-002",
        "authorized_by": "Lab Owner", "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080", "probe_path": "/fetch",
        "url_parameter_name": "url", "timeout_ms": 2000, "canary_grace_ms": 300,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode()


def test_preflight_is_zero_request():
    manifest = parse_ssrf_outbound_fetch_manifest(_manifest())
    result = preflight_ssrf_outbound_fetch_manifest(manifest)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 2
    assert result["active_probe_performed"] is False


def test_manifest_rejects_unknown_duplicate_float_and_invalid_param():
    with pytest.raises(SsrfOutboundFetchManifestError, match="unknown fields"):
        parse_ssrf_outbound_fetch_manifest(_manifest(extra_field="nope"))
    with pytest.raises(SsrfOutboundFetchManifestError, match="duplicate key"):
        parse_ssrf_outbound_fetch_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(SsrfOutboundFetchManifestError, match="floating-point"):
        parse_ssrf_outbound_fetch_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5'))
    with pytest.raises(SsrfOutboundFetchManifestError, match="bare identifier"):
        parse_ssrf_outbound_fetch_manifest(_manifest(url_parameter_name="has spaces"))


def test_missing_field_and_symlink_fail_closed(tmp_path):
    raw = json.loads(_manifest())
    del raw["url_parameter_name"]
    with pytest.raises(SsrfOutboundFetchManifestError, match="missing fields"):
        parse_ssrf_outbound_fetch_manifest(json.dumps(raw).encode())
    real, linked = tmp_path / "real.json", tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(SsrfOutboundFetchManifestError, match="symlink"):
        read_ssrf_outbound_fetch_manifest(linked)


def test_cli_dry_run_validates_without_a_network_call(tmp_path, capsys):
    path = tmp_path / "ssrf_outbound_fetch.json"
    path.write_bytes(_manifest())
    assert main(["--dry-run", str(path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "VALIDATED_NOT_EXECUTED"
    assert payload["url_parameter_name"] == "url"
