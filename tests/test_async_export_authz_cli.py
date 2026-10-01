"""Manifest parsing and no-network preflight for async export checks."""

from __future__ import annotations

import json

import pytest

from offensive.async_export_authz_cli import (
    AsyncExportAuthorizationManifestError,
    parse_async_export_authorization_manifest,
    preflight_async_export_authorization_manifest,
    resolve_async_export_authorization_secrets,
)


def _manifest():
    return {
        "schema_version": 1, "experiment_id": "ASYNC-EXPORT-LOCAL-001",
        "authorization_reference": "written-scope-001", "authorized_by": "Lab Owner",
        "operator_acknowledged": True, "target_origin": "http://127.0.0.1:8080",
        "alpha_create_path": "/tenants/alpha/exports",
        "bravo_create_path": "/tenants/bravo/exports",
        "alpha_jobs_path": "/tenants/alpha/exports",
        "bravo_jobs_path": "/tenants/bravo/exports",
        "alpha_principal_id": "alpha-member", "bravo_principal_id": "bravo-member",
        "alpha_token_env": "ASYNC_ALPHA_TOKEN", "bravo_token_env": "ASYNC_BRAVO_TOKEN",
        "alpha_canary_env": "ASYNC_ALPHA_CANARY", "bravo_canary_env": "ASYNC_BRAVO_CANARY",
        "timeout_ms": 2000, "max_response_bytes": 65536,
    }


def _environment():
    return {
        "ASYNC_ALPHA_TOKEN": "alpha-async-token",
        "ASYNC_BRAVO_TOKEN": "bravo-async-token",
        "ASYNC_ALPHA_CANARY": "alpha-async-canary",
        "ASYNC_BRAVO_CANARY": "bravo-async-canary",
    }


def test_preflight_resolves_secrets_but_performs_no_requests():
    manifest = parse_async_export_authorization_manifest(json.dumps(_manifest()).encode())
    secrets = resolve_async_export_authorization_secrets(manifest, _environment())
    result = preflight_async_export_authorization_manifest(manifest, secrets)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 12
    assert all(value not in repr(secrets) for value in _environment().values())


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(operator_acknowledged=False),
    lambda data: data.update(target_origin="http://198.51.100.2"),
    lambda data: data.update(bravo_jobs_path="/teams/bravo/exports"),
    lambda data: data.update(alpha_principal_id="bad/id"),
    lambda data: data.update(alpha_token_env=data["bravo_token_env"]),
    lambda data: data.update(unexpected="field"),
])
def test_manifest_rejects_unscoped_or_ambiguous_inputs(mutation):
    data = _manifest()
    mutation(data)
    with pytest.raises((AsyncExportAuthorizationManifestError, ValueError)):
        parse_async_export_authorization_manifest(json.dumps(data).encode())


def test_manifest_rejects_duplicate_keys_and_float_limits():
    with pytest.raises(AsyncExportAuthorizationManifestError, match="duplicate"):
        parse_async_export_authorization_manifest(b'{"schema_version":1,"schema_version":1}')
    data = _manifest()
    data["timeout_ms"] = 2.5
    with pytest.raises(AsyncExportAuthorizationManifestError, match="floating-point"):
        parse_async_export_authorization_manifest(json.dumps(data).encode())


def test_secrets_must_exist_and_be_distinct():
    manifest = parse_async_export_authorization_manifest(json.dumps(_manifest()).encode())
    with pytest.raises(AsyncExportAuthorizationManifestError, match="missing"):
        resolve_async_export_authorization_secrets(manifest, {})
    duplicate = _environment()
    duplicate["ASYNC_BRAVO_CANARY"] = duplicate["ASYNC_ALPHA_CANARY"]
    with pytest.raises(AsyncExportAuthorizationManifestError, match="differ"):
        resolve_async_export_authorization_secrets(manifest, duplicate)
