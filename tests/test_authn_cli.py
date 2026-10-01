"""The authentication CLI keeps every oracle and credential out of manifests."""

from __future__ import annotations

import json

import pytest

from offensive.authn_cli import (
    AuthnManifestError,
    main,
    parse_authn_manifest,
    preflight_authn_manifest,
    read_authn_manifest,
    resolve_authn_secrets,
)
from offensive.bola_cli import SecretValue as BolaSecretValue
from offensive.secrets import SecretValue


VALID_TOKEN = "cli-valid-authn-token"
PROTECTED_CANARY = "CLI-PROTECTED-AUTHN-CANARY"
INVALID_BEARER = "cli-invalid-authn-bearer"


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "AUTHN-CLI-001",
        "authorization_reference": "written-lab-scope-007",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "protected_path": "/protected",
        "valid_principal_id": "valid-principal",
        "valid_token_env": "PANCITO_AUTHN_VALID_TOKEN",
        "protected_canary_env": "PANCITO_AUTHN_PROTECTED_CANARY",
        "invalid_bearer_env": "PANCITO_AUTHN_INVALID_BEARER",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _environment() -> dict[str, str]:
    return {
        "PANCITO_AUTHN_VALID_TOKEN": VALID_TOKEN,
        "PANCITO_AUTHN_PROTECTED_CANARY": PROTECTED_CANARY,
        "PANCITO_AUTHN_INVALID_BEARER": INVALID_BEARER,
    }


def test_preflight_validates_all_secrets_and_plan_without_execution():
    manifest = parse_authn_manifest(_manifest())
    secrets = resolve_authn_secrets(manifest, _environment())

    result = preflight_authn_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["active_probe_performed"] is False
    assert result["target_origin"] == "http://127.0.0.1:8080"
    assert VALID_TOKEN not in serialized
    assert PROTECTED_CANARY not in serialized
    assert INVALID_BEARER not in serialized


def test_missing_secret_fails_atomically_and_names_only_the_source():
    manifest = parse_authn_manifest(_manifest())
    environment = _environment()
    del environment["PANCITO_AUTHN_PROTECTED_CANARY"]

    with pytest.raises(AuthnManifestError, match="PANCITO_AUTHN_PROTECTED_CANARY"):
        resolve_authn_secrets(manifest, environment)


def test_manifest_rejects_literal_secrets_unknown_fields_and_floats():
    with pytest.raises(AuthnManifestError, match="unknown fields"):
        parse_authn_manifest(_manifest(valid_token="must-not-live-here"))
    with pytest.raises(AuthnManifestError, match="duplicate key"):
        parse_authn_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(AuthnManifestError, match="floating-point"):
        parse_authn_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )


def test_secret_environment_names_must_be_distinct():
    with pytest.raises(AuthnManifestError, match="distinct"):
        parse_authn_manifest(
            _manifest(invalid_bearer_env="PANCITO_AUTHN_VALID_TOKEN")
        )


def test_bola_secret_import_remains_the_shared_redacting_type():
    assert BolaSecretValue is SecretValue
    secret = SecretValue(VALID_TOKEN)

    assert VALID_TOKEN not in str(secret)
    assert VALID_TOKEN not in repr(secret)
    with pytest.raises(TypeError):
        json.dumps({"secret": secret})


def test_manifest_reader_rejects_symlinks(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(AuthnManifestError, match="symlink"):
        read_authn_manifest(linked)


def test_cli_dry_run_outputs_only_nonsecret_preflight(tmp_path, capsys):
    path = tmp_path / "authn.json"
    path.write_bytes(_manifest())

    exit_code = main(["--dry-run", str(path)], environ=_environment())
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert captured.err == ""
    assert VALID_TOKEN not in captured.out
    assert PROTECTED_CANARY not in captured.out
    assert INVALID_BEARER not in captured.out


def test_cli_configuration_error_is_bounded_and_secret_free(tmp_path, capsys):
    path = tmp_path / "authn.json"
    path.write_bytes(_manifest())
    environment = _environment()
    environment["PANCITO_AUTHN_VALID_TOKEN"] = ""

    exit_code = main(["--dry-run", str(path)], environ=environment)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "PANCITO_AUTHN_VALID_TOKEN" in captured.err
    assert VALID_TOKEN not in captured.err
