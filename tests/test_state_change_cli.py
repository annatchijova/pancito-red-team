"""The state-change CLI keeps mutation markers and credentials out of plans."""

from __future__ import annotations

import json

import pytest

from offensive.state_change_cli import (
    StateChangeManifestError,
    main,
    parse_state_change_manifest,
    preflight_state_change_manifest,
    read_state_change_manifest,
    resolve_state_change_secrets,
)


SECRETS = {
    "PANCITO_STATE_OBSERVER_TOKEN": "cli-state-observer-token",
    "PANCITO_STATE_INVALID_BEARER": "cli-state-invalid-token",
    "PANCITO_STATE_BASELINE": "CLI-STATE-BASELINE",
    "PANCITO_STATE_CONTROL": "CLI-STATE-CONTROL",
    "PANCITO_STATE_ANONYMOUS": "CLI-STATE-ANONYMOUS",
    "PANCITO_STATE_INVALID": "CLI-STATE-INVALID",
}


def _handoff() -> dict[str, str]:
    return {
        "candidate_id": "CANDIDATE-0123456789abcdef",
        "source_label": "api/openapi.json@state1",
        "source_sha256": "a" * 64,
        "entry_point": "PATCH /settings/{tenant_id}",
        "json_pointer": "/paths/~1settings~1{tenant_id}/patch",
        "epistemic_level": "CANDIDATE",
        "integrity": "UNSEALED_TRIAGE_HANDOFF",
    }


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "STATE-CLI-001",
        "authorization_reference": "written-lab-scope-state-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "resource_path": "/settings/lab",
        "readback_path": "/settings/lab",
        "marker_field": "marker",
        "observer_principal_id": "state-observer",
        "observer_token_env": "PANCITO_STATE_OBSERVER_TOKEN",
        "invalid_bearer_env": "PANCITO_STATE_INVALID_BEARER",
        "baseline_marker_env": "PANCITO_STATE_BASELINE",
        "control_marker_env": "PANCITO_STATE_CONTROL",
        "anonymous_marker_env": "PANCITO_STATE_ANONYMOUS",
        "invalid_marker_env": "PANCITO_STATE_INVALID",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_is_zero_request_secret_free_and_bounded():
    manifest = parse_state_change_manifest(_manifest())
    secrets = resolve_state_change_secrets(manifest, SECRETS)

    result = preflight_state_change_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 13
    assert result["active_probe_performed"] is False
    assert result["method"] == "PATCH"
    assert all(secret not in serialized for secret in SECRETS.values())


def test_candidate_handoff_survives_without_promotion_and_rejects_drift():
    manifest = parse_state_change_manifest(
        _manifest(candidate_handoff=_handoff())
    )
    secrets = resolve_state_change_secrets(manifest, SECRETS)
    result = preflight_state_change_manifest(manifest, secrets)

    assert result["candidate_provenance"] == _handoff()
    assert result["candidate_provenance"]["epistemic_level"] == "CANDIDATE"

    with pytest.raises(StateChangeManifestError, match="candidate path"):
        parse_state_change_manifest(
            _manifest(resource_path="/admin/lab", candidate_handoff=_handoff())
        )


def test_manifest_rejects_inline_secrets_duplicates_floats_and_aliases():
    with pytest.raises(StateChangeManifestError, match="unknown fields"):
        parse_state_change_manifest(_manifest(observer_token="inline-secret"))
    with pytest.raises(StateChangeManifestError, match="duplicate key"):
        parse_state_change_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(StateChangeManifestError, match="floating-point"):
        parse_state_change_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )
    with pytest.raises(StateChangeManifestError, match="distinct"):
        parse_state_change_manifest(
            _manifest(invalid_bearer_env="PANCITO_STATE_OBSERVER_TOKEN")
        )


def test_missing_or_equal_resolved_secrets_fail_atomically():
    manifest = parse_state_change_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_STATE_BASELINE"]
    with pytest.raises(StateChangeManifestError, match="PANCITO_STATE_BASELINE"):
        resolve_state_change_secrets(manifest, missing)

    aliased = dict(SECRETS)
    aliased["PANCITO_STATE_INVALID"] = aliased["PANCITO_STATE_CONTROL"]
    with pytest.raises(StateChangeManifestError, match="distinct"):
        resolve_state_change_secrets(manifest, aliased)


def test_manifest_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(StateChangeManifestError, match="symlink"):
        read_state_change_manifest(linked)


def test_cli_dry_run_is_secret_free(tmp_path, capsys):
    path = tmp_path / "state-change.json"
    path.write_bytes(_manifest())

    exit_code = main(["--dry-run", str(path)], environ=SECRETS)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert captured.err == ""
    assert all(secret not in captured.out for secret in SECRETS.values())


def test_cli_error_names_source_but_not_secret(tmp_path, capsys):
    path = tmp_path / "state-change.json"
    path.write_bytes(_manifest())
    environment = dict(SECRETS)
    environment["PANCITO_STATE_OBSERVER_TOKEN"] = ""

    exit_code = main(["--dry-run", str(path)], environ=environment)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "PANCITO_STATE_OBSERVER_TOKEN" in captured.err
    assert SECRETS["PANCITO_STATE_OBSERVER_TOKEN"] not in captured.err
