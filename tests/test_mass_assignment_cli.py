"""The mass-assignment CLI keeps credentials and markers outside manifests."""

from __future__ import annotations

import json

import pytest

from offensive.mass_assignment_cli import (
    MassAssignmentManifestError,
    main,
    parse_mass_assignment_manifest,
    preflight_mass_assignment_manifest,
    read_mass_assignment_manifest,
    resolve_mass_assignment_secrets,
)


SECRETS = {
    "PANCITO_MASS_ACTOR_TOKEN": "cli-mass-actor-token",
    "PANCITO_MASS_OBSERVER_TOKEN": "cli-mass-observer-token",
    "PANCITO_MASS_BASE_ALLOWED": "CLI-BASE-ALLOWED",
    "PANCITO_MASS_BASE_PROTECTED": "CLI-BASE-PROTECTED",
    "PANCITO_MASS_CONTROL_ALLOWED": "CLI-CONTROL-ALLOWED",
    "PANCITO_MASS_NEGATIVE_ALLOWED": "CLI-NEGATIVE-ALLOWED",
    "PANCITO_MASS_NEGATIVE_PROTECTED": "CLI-NEGATIVE-PROTECTED",
}


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "MASS-CLI-001",
        "authorization_reference": "written-loopback-scope-mass-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "resource_path": "/profiles/mine",
        "readback_path": "/profiles/mine",
        "allowed_field": "display_name",
        "protected_field": "role",
        "actor_principal_id": "low-privilege-actor",
        "observer_principal_id": "privileged-observer",
        "actor_token_env": "PANCITO_MASS_ACTOR_TOKEN",
        "observer_token_env": "PANCITO_MASS_OBSERVER_TOKEN",
        "baseline_allowed_env": "PANCITO_MASS_BASE_ALLOWED",
        "baseline_protected_env": "PANCITO_MASS_BASE_PROTECTED",
        "control_allowed_env": "PANCITO_MASS_CONTROL_ALLOWED",
        "negative_allowed_env": "PANCITO_MASS_NEGATIVE_ALLOWED",
        "negative_protected_env": "PANCITO_MASS_NEGATIVE_PROTECTED",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_is_zero_request_bounded_and_secret_free():
    manifest = parse_mass_assignment_manifest(_manifest())
    secrets = resolve_mass_assignment_secrets(manifest, SECRETS)

    result = preflight_mass_assignment_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 9
    assert result["active_probe_performed"] is False
    assert all(secret not in serialized for secret in SECRETS.values())


def test_manifest_rejects_inline_secrets_duplicates_floats_and_env_aliases():
    with pytest.raises(MassAssignmentManifestError, match="unknown fields"):
        parse_mass_assignment_manifest(_manifest(actor_token="inline"))
    with pytest.raises(MassAssignmentManifestError, match="duplicate key"):
        parse_mass_assignment_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(MassAssignmentManifestError, match="floating-point"):
        parse_mass_assignment_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )
    with pytest.raises(MassAssignmentManifestError, match="distinct"):
        parse_mass_assignment_manifest(
            _manifest(observer_token_env="PANCITO_MASS_ACTOR_TOKEN")
        )


def test_missing_and_equal_resolved_secrets_fail_atomically():
    manifest = parse_mass_assignment_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_MASS_BASE_ALLOWED"]
    with pytest.raises(MassAssignmentManifestError, match="PANCITO_MASS_BASE_ALLOWED"):
        resolve_mass_assignment_secrets(manifest, missing)

    aliased = dict(SECRETS)
    aliased["PANCITO_MASS_NEGATIVE_PROTECTED"] = aliased[
        "PANCITO_MASS_NEGATIVE_ALLOWED"
    ]
    with pytest.raises(MassAssignmentManifestError, match="distinct"):
        resolve_mass_assignment_secrets(manifest, aliased)


def test_manifest_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(MassAssignmentManifestError, match="symlink"):
        read_mass_assignment_manifest(linked)


def test_cli_dry_run_emits_no_secret(tmp_path, capsys):
    path = tmp_path / "mass-assignment.json"
    path.write_bytes(_manifest())

    exit_code = main(["--dry-run", str(path)], environ=SECRETS)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert captured.err == ""
    assert all(secret not in captured.out for secret in SECRETS.values())
