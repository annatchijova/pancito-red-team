"""The BOLA CLI keeps secret material out of manifests and receipts."""

from __future__ import annotations

import json

import pytest

from offensive.bola_cli import (
    BolaManifestError,
    SecretValue,
    main,
    parse_bola_manifest,
    preflight_bola_manifest,
    read_bola_manifest,
    resolve_bola_secrets,
)


OWNER_TOKEN = "cli-owner-token-canary"
PEER_TOKEN = "cli-peer-token-canary"
OWNER_MARKER = "CLI-OWNER-MARKER-001"
PEER_MARKER = "CLI-PEER-MARKER-002"


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "BOLA-CLI-001",
        "authorization_reference": "written-lab-scope-004",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "owner_path": "/objects/a",
        "peer_control_path": "/objects/b",
        "owner_principal_id": "principal-a",
        "peer_principal_id": "principal-b",
        "owner_token_env": "PANCITO_OWNER_TOKEN",
        "peer_token_env": "PANCITO_PEER_TOKEN",
        "owner_canary_env": "PANCITO_OWNER_CANARY",
        "peer_canary_env": "PANCITO_PEER_CANARY",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _environment() -> dict[str, str]:
    return {
        "PANCITO_OWNER_TOKEN": OWNER_TOKEN,
        "PANCITO_PEER_TOKEN": PEER_TOKEN,
        "PANCITO_OWNER_CANARY": OWNER_MARKER,
        "PANCITO_PEER_CANARY": PEER_MARKER,
    }


def test_preflight_validates_secrets_and_plan_without_execution():
    manifest = parse_bola_manifest(_manifest())
    secrets = resolve_bola_secrets(manifest, _environment())

    result = preflight_bola_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["active_probe_performed"] is False
    assert result["target_origin"] == "http://127.0.0.1:8080"
    assert OWNER_TOKEN not in serialized
    assert PEER_TOKEN not in serialized
    assert OWNER_MARKER not in serialized
    assert PEER_MARKER not in serialized


def test_missing_secret_fails_before_a_partial_plan_is_returned():
    manifest = parse_bola_manifest(_manifest())
    environment = _environment()
    del environment["PANCITO_PEER_TOKEN"]

    with pytest.raises(BolaManifestError, match="PANCITO_PEER_TOKEN"):
        resolve_bola_secrets(manifest, environment)


def test_manifest_rejects_literal_secrets_unknown_fields_and_floats():
    with pytest.raises(BolaManifestError, match="unknown fields"):
        parse_bola_manifest(_manifest(owner_token="must-not-live-here"))
    with pytest.raises(BolaManifestError, match="duplicate key"):
        parse_bola_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(BolaManifestError, match="floating-point"):
        parse_bola_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )


def test_secret_environment_names_must_be_distinct():
    with pytest.raises(BolaManifestError, match="distinct"):
        parse_bola_manifest(
            _manifest(peer_token_env="PANCITO_OWNER_TOKEN")
        )


def test_resolved_secret_type_redacts_string_and_repr_and_refuses_json():
    secret = SecretValue(OWNER_TOKEN)

    assert OWNER_TOKEN not in str(secret)
    assert OWNER_TOKEN not in repr(secret)
    with pytest.raises(TypeError):
        json.dumps({"secret": secret})


def test_manifest_reader_rejects_symlinks(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(BolaManifestError, match="symlink"):
        read_bola_manifest(linked)


def test_cli_dry_run_outputs_only_nonsecret_preflight(tmp_path, capsys):
    path = tmp_path / "bola.json"
    path.write_bytes(_manifest())

    exit_code = main(["--dry-run", str(path)], environ=_environment())
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert captured.err == ""
    assert OWNER_TOKEN not in captured.out
    assert PEER_TOKEN not in captured.out


def test_cli_configuration_error_is_bounded_and_secret_free(tmp_path, capsys):
    path = tmp_path / "bola.json"
    path.write_bytes(_manifest())
    environment = _environment()
    environment["PANCITO_OWNER_TOKEN"] = ""

    exit_code = main(["--dry-run", str(path)], environ=environment)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "PANCITO_OWNER_TOKEN" in captured.err
    assert OWNER_TOKEN not in captured.err
