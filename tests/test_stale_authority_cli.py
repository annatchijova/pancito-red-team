"""Stale-authority manifests keep all credentials and markers in the environment."""

from __future__ import annotations

import json

import pytest

from offensive.stale_authority_cli import (
    StaleAuthorityManifestError,
    main,
    parse_stale_authority_manifest,
    preflight_stale_authority_manifest,
    read_stale_authority_manifest,
    resolve_stale_authority_secrets,
)


SECRETS = {
    "PANCITO_STALE_ACTOR_TOKEN": "cli-stale-actor-token",
    "PANCITO_STALE_ADMIN_TOKEN": "cli-stale-admin-token",
    "PANCITO_STALE_RESOURCE_CANARY": "CLI-STALE-CANARY",
    "PANCITO_STALE_ACTIVE": "CLI-STALE-ACTIVE",
    "PANCITO_STALE_REVOKED": "CLI-STALE-REVOKED",
}


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "STALE-CLI-001",
        "authorization_reference": "written-loopback-scope-stale-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "resource_path": "/protected/report",
        "membership_path": "/membership/actor",
        "membership_field": "role",
        "actor_principal_id": "stale-actor",
        "admin_principal_id": "stale-admin",
        "actor_token_env": "PANCITO_STALE_ACTOR_TOKEN",
        "admin_token_env": "PANCITO_STALE_ADMIN_TOKEN",
        "resource_canary_env": "PANCITO_STALE_RESOURCE_CANARY",
        "active_marker_env": "PANCITO_STALE_ACTIVE",
        "revoked_marker_env": "PANCITO_STALE_REVOKED",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_is_zero_request_bounded_and_secret_free():
    manifest = parse_stale_authority_manifest(_manifest())
    secrets = resolve_stale_authority_secrets(manifest, SECRETS)
    result = preflight_stale_authority_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 7
    assert result["active_probe_performed"] is False
    assert all(value not in serialized for value in SECRETS.values())


def test_manifest_rejects_inline_secrets_duplicates_floats_and_aliases():
    with pytest.raises(StaleAuthorityManifestError, match="unknown fields"):
        parse_stale_authority_manifest(_manifest(actor_token="inline"))
    with pytest.raises(StaleAuthorityManifestError, match="duplicate key"):
        parse_stale_authority_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(StaleAuthorityManifestError, match="floating-point"):
        parse_stale_authority_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )
    with pytest.raises(StaleAuthorityManifestError, match="distinct"):
        parse_stale_authority_manifest(
            _manifest(admin_token_env="PANCITO_STALE_ACTOR_TOKEN")
        )


def test_missing_and_equal_resolved_secrets_fail_atomically():
    manifest = parse_stale_authority_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_STALE_ACTIVE"]
    with pytest.raises(StaleAuthorityManifestError, match="PANCITO_STALE_ACTIVE"):
        resolve_stale_authority_secrets(manifest, missing)
    equal = dict(SECRETS)
    equal["PANCITO_STALE_REVOKED"] = equal["PANCITO_STALE_ACTIVE"]
    with pytest.raises(StaleAuthorityManifestError, match="distinct"):
        resolve_stale_authority_secrets(manifest, equal)


def test_reader_rejects_symlink_and_dry_run_prints_no_secret(tmp_path, capsys):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(StaleAuthorityManifestError, match="symlink"):
        read_stale_authority_manifest(linked)

    exit_code = main(["--dry-run", str(real)], environ=SECRETS)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert all(value not in captured.out for value in SECRETS.values())
