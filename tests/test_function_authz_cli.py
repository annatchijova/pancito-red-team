"""BFLA CLI resolves credentials and canaries atomically from the environment."""

import json
import pytest

from offensive.function_authz_cli import (
    FunctionAuthorizationManifestError, main, parse_function_authorization_manifest,
    preflight_function_authorization_manifest, read_function_authorization_manifest,
    resolve_function_authorization_secrets,
)

SECRETS = {
    "PANCITO_BFLA_ADMIN_TOKEN": "cli-bfla-admin-token",
    "PANCITO_BFLA_MEMBER_TOKEN": "cli-bfla-member-token",
    "PANCITO_BFLA_ADMIN_CANARY": "CLI-BFLA-ADMIN-CANARY",
    "PANCITO_BFLA_MEMBER_CANARY": "CLI-BFLA-MEMBER-CANARY",
}


def _manifest(**overrides):
    value = {
        "schema_version": 1, "experiment_id": "BFLA-CLI-001",
        "authorization_reference": "written-loopback-scope-bfla-002",
        "authorized_by": "Lab Owner", "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080", "admin_path": "/admin/report",
        "member_control_path": "/member/profile", "admin_principal_id": "admin",
        "member_principal_id": "member", "admin_token_env": "PANCITO_BFLA_ADMIN_TOKEN",
        "member_token_env": "PANCITO_BFLA_MEMBER_TOKEN",
        "admin_canary_env": "PANCITO_BFLA_ADMIN_CANARY",
        "member_canary_env": "PANCITO_BFLA_MEMBER_CANARY",
        "timeout_ms": 2000, "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode()


def test_preflight_is_zero_request_and_secret_free():
    manifest = parse_function_authorization_manifest(_manifest())
    secrets = resolve_function_authorization_secrets(manifest, SECRETS)
    result = preflight_function_authorization_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 3
    assert all(value not in serialized for value in SECRETS.values())


def test_manifest_rejects_inline_secret_duplicate_float_and_alias():
    with pytest.raises(FunctionAuthorizationManifestError, match="unknown fields"):
        parse_function_authorization_manifest(_manifest(admin_token="inline"))
    with pytest.raises(FunctionAuthorizationManifestError, match="duplicate key"):
        parse_function_authorization_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(FunctionAuthorizationManifestError, match="floating-point"):
        parse_function_authorization_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5'))
    with pytest.raises(FunctionAuthorizationManifestError, match="distinct"):
        parse_function_authorization_manifest(
            _manifest(member_token_env="PANCITO_BFLA_ADMIN_TOKEN"))


def test_missing_secrets_and_symlink_fail_closed(tmp_path):
    manifest = parse_function_authorization_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_BFLA_MEMBER_TOKEN"]
    with pytest.raises(FunctionAuthorizationManifestError, match="PANCITO_BFLA_MEMBER_TOKEN"):
        resolve_function_authorization_secrets(manifest, missing)
    real, linked = tmp_path / "real.json", tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(FunctionAuthorizationManifestError, match="symlink"):
        read_function_authorization_manifest(linked)


def test_cli_dry_run_prints_no_secret(tmp_path, capsys):
    path = tmp_path / "bfla.json"
    path.write_bytes(_manifest())
    assert main(["--dry-run", str(path)], environ=SECRETS) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert all(value not in captured.out for value in SECRETS.values())
