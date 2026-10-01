"""Strict manifest and secret handling for export authorization CLI."""

from __future__ import annotations

import json

import pytest

from offensive.export_authz_cli import (
    ExportAuthorizationManifestError,
    parse_export_authorization_manifest,
    preflight_export_authorization_manifest,
    resolve_export_authorization_secrets,
)


def _data():
    return {
        "schema_version": 1, "experiment_id": "EXPORT-LOCAL-001",
        "authorization_reference": "written-scope-001", "authorized_by": "Lab Owner",
        "operator_acknowledged": True, "target_origin": "http://127.0.0.1:8080",
        "alpha_export_path": "/tenants/alpha/export.csv",
        "bravo_export_path": "/tenants/bravo/export.csv", "tenant_segment_index": 1,
        "alpha_principal_id": "alpha-member", "bravo_principal_id": "bravo-member",
        "alpha_token_env": "PANCITO_ALPHA_TOKEN", "bravo_token_env": "PANCITO_BRAVO_TOKEN",
        "alpha_canary_env": "PANCITO_ALPHA_CANARY", "bravo_canary_env": "PANCITO_BRAVO_CANARY",
        "timeout_ms": 2000, "max_response_bytes": 65536,
    }


def _env():
    return {"PANCITO_ALPHA_TOKEN": "token-alpha", "PANCITO_BRAVO_TOKEN": "token-bravo",
            "PANCITO_ALPHA_CANARY": "canary-alpha", "PANCITO_BRAVO_CANARY": "canary-bravo"}


def test_dry_run_validates_secrets_without_network_activity():
    manifest = parse_export_authorization_manifest(json.dumps(_data()).encode())
    secrets = resolve_export_authorization_secrets(manifest, _env())
    result = preflight_export_authorization_manifest(manifest, secrets)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["active_probe_performed"] is False


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(operator_acknowledged=False),
    lambda d: d.update(target_origin="http://example.com"),
    lambda d: d.update(bravo_export_path="/other/bravo/export.csv"),
    lambda d: d.update(tenant_segment_index=True),
    lambda d: d.update(alpha_token_env=d["bravo_token_env"]),
    lambda d: d.update(unexpected="field"),
])
def test_manifest_rejects_invalid_scope_and_shapes(mutation):
    data = _data()
    mutation(data)
    with pytest.raises((ExportAuthorizationManifestError, ValueError)):
        parse_export_authorization_manifest(json.dumps(data).encode())


def test_manifest_rejects_duplicate_keys_and_float_limits():
    with pytest.raises(ExportAuthorizationManifestError, match="duplicate"):
        parse_export_authorization_manifest(b'{"schema_version":1,"schema_version":1}')
    data = _data()
    data["timeout_ms"] = 2.5
    with pytest.raises(ExportAuthorizationManifestError, match="floating-point"):
        parse_export_authorization_manifest(json.dumps(data).encode())


def test_secrets_required_and_never_returned_in_preflight():
    manifest = parse_export_authorization_manifest(json.dumps(_data()).encode())
    with pytest.raises(ExportAuthorizationManifestError, match="missing"):
        resolve_export_authorization_secrets(manifest, {})
    secrets = resolve_export_authorization_secrets(manifest, _env())
    assert all(value not in repr(secrets) for value in _env().values())
