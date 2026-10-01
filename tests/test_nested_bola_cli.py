"""Nested-BOLA manifests contain references, never credentials or canaries."""

from __future__ import annotations

import json

import pytest

from offensive.nested_bola_cli import (
    NestedBolaManifestError,
    main,
    parse_nested_bola_manifest,
    preflight_nested_bola_manifest,
    read_nested_bola_manifest,
    resolve_nested_bola_secrets,
)


SECRETS = {
    "PANCITO_NESTED_OWNER_TOKEN": "cli-nested-owner-token",
    "PANCITO_NESTED_PEER_TOKEN": "cli-nested-peer-token",
    "PANCITO_NESTED_OWNER_CANARY": "CLI-NESTED-OWNER-CANARY",
    "PANCITO_NESTED_PEER_CANARY": "CLI-NESTED-PEER-CANARY",
}


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "NESTED-BOLA-CLI-001",
        "authorization_reference": "written-loopback-scope-nested-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "owner_control_path": "/orgs/a/docs/a-doc",
        "peer_control_path": "/orgs/b/docs/b-doc",
        "cross_child_path": "/orgs/a/docs/b-doc",
        "parent_segment_index": 1,
        "child_segment_index": 3,
        "owner_principal_id": "nested-owner",
        "peer_principal_id": "nested-peer",
        "owner_token_env": "PANCITO_NESTED_OWNER_TOKEN",
        "peer_token_env": "PANCITO_NESTED_PEER_TOKEN",
        "owner_canary_env": "PANCITO_NESTED_OWNER_CANARY",
        "peer_canary_env": "PANCITO_NESTED_PEER_CANARY",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_is_zero_request_and_secret_free():
    manifest = parse_nested_bola_manifest(_manifest())
    secrets = resolve_nested_bola_secrets(manifest, SECRETS)
    result = preflight_nested_bola_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 3
    assert result["active_probe_performed"] is False
    assert all(secret not in serialized for secret in SECRETS.values())


def test_manifest_rejects_inline_secrets_duplicates_floats_and_aliases():
    with pytest.raises(NestedBolaManifestError, match="unknown fields"):
        parse_nested_bola_manifest(_manifest(owner_token="inline"))
    with pytest.raises(NestedBolaManifestError, match="duplicate key"):
        parse_nested_bola_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(NestedBolaManifestError, match="floating-point"):
        parse_nested_bola_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )
    with pytest.raises(NestedBolaManifestError, match="distinct"):
        parse_nested_bola_manifest(
            _manifest(peer_token_env="PANCITO_NESTED_OWNER_TOKEN")
        )


def test_missing_and_equal_resolved_secrets_fail_atomically():
    manifest = parse_nested_bola_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_NESTED_PEER_TOKEN"]
    with pytest.raises(NestedBolaManifestError, match="PANCITO_NESTED_PEER_TOKEN"):
        resolve_nested_bola_secrets(manifest, missing)

    equal = dict(SECRETS)
    equal["PANCITO_NESTED_PEER_CANARY"] = equal["PANCITO_NESTED_OWNER_CANARY"]
    with pytest.raises(NestedBolaManifestError, match="distinct"):
        resolve_nested_bola_secrets(manifest, equal)


def test_manifest_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(NestedBolaManifestError, match="symlink"):
        read_nested_bola_manifest(linked)


def test_cli_dry_run_prints_no_secret(tmp_path, capsys):
    path = tmp_path / "nested-bola.json"
    path.write_bytes(_manifest())
    exit_code = main(["--dry-run", str(path)], environ=SECRETS)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert captured.err == ""
    assert all(secret not in captured.out for secret in SECRETS.values())
