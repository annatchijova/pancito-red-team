"""SCOPE CLI resolves credentials and canaries atomically from the environment."""

import json
import pytest

from offensive.scope_authz_cli import (
    ScopeAuthorizationManifestError, main, parse_scope_authorization_manifest,
    preflight_scope_authorization_manifest, read_scope_authorization_manifest,
    resolve_scope_authorization_secrets,
)

SECRETS = {
    "PANCITO_SCOPE_BROAD_TOKEN": "cli-scope-broad-token",
    "PANCITO_SCOPE_NARROW_TOKEN": "cli-scope-narrow-token",
    "PANCITO_SCOPE_PRIVILEGED_CANARY": "CLI-SCOPE-PRIVILEGED-CANARY",
    "PANCITO_SCOPE_NARROW_CANARY": "CLI-SCOPE-NARROW-CANARY",
}


def _manifest(**overrides):
    value = {
        "schema_version": 1, "experiment_id": "SCOPE-CLI-001",
        "authorization_reference": "written-loopback-scope-scope-002",
        "authorized_by": "Lab Owner", "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080", "privileged_resource_path": "/scoped/privileged",
        "narrow_control_path": "/scoped/allowed", "broad_principal_id": "broad-token",
        "narrow_principal_id": "narrow-token", "broad_token_env": "PANCITO_SCOPE_BROAD_TOKEN",
        "narrow_token_env": "PANCITO_SCOPE_NARROW_TOKEN",
        "privileged_canary_env": "PANCITO_SCOPE_PRIVILEGED_CANARY",
        "narrow_canary_env": "PANCITO_SCOPE_NARROW_CANARY",
        "timeout_ms": 2000, "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode()


def test_preflight_is_zero_request_and_secret_free():
    manifest = parse_scope_authorization_manifest(_manifest())
    secrets = resolve_scope_authorization_secrets(manifest, SECRETS)
    result = preflight_scope_authorization_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 3
    assert all(value not in serialized for value in SECRETS.values())


def test_manifest_rejects_inline_secret_duplicate_float_and_alias():
    with pytest.raises(ScopeAuthorizationManifestError, match="unknown fields"):
        parse_scope_authorization_manifest(_manifest(broad_token="inline"))
    with pytest.raises(ScopeAuthorizationManifestError, match="duplicate key"):
        parse_scope_authorization_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ScopeAuthorizationManifestError, match="floating-point"):
        parse_scope_authorization_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5'))
    with pytest.raises(ScopeAuthorizationManifestError, match="distinct"):
        parse_scope_authorization_manifest(
            _manifest(narrow_token_env="PANCITO_SCOPE_BROAD_TOKEN"))


def test_missing_secrets_and_symlink_fail_closed(tmp_path):
    manifest = parse_scope_authorization_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_SCOPE_NARROW_TOKEN"]
    with pytest.raises(ScopeAuthorizationManifestError, match="PANCITO_SCOPE_NARROW_TOKEN"):
        resolve_scope_authorization_secrets(manifest, missing)
    real, linked = tmp_path / "real.json", tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(ScopeAuthorizationManifestError, match="symlink"):
        read_scope_authorization_manifest(linked)


def test_cli_dry_run_prints_no_secret(tmp_path, capsys):
    path = tmp_path / "scope.json"
    path.write_bytes(_manifest())
    assert main(["--dry-run", str(path)], environ=SECRETS) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert all(value not in captured.out for value in SECRETS.values())
