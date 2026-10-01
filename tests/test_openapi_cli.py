"""The OpenAPI CLI preserves the triage and handoff contracts on disk."""

from __future__ import annotations

import hashlib
import json

import pytest

from offensive.openapi_cli import (
    OpenApiCliError,
    main,
    parse_triage_manifest,
    read_triage_manifest,
)


CANDIDATE_ID = "CANDIDATE-901da4b8d7484700"
AUTHN_CANDIDATE_ID = "CANDIDATE-" + hashlib.sha256(
    b"AUTHENTICATION_ENFORCEMENT_REVIEW\x00GET /objects/{id}"
).hexdigest()[:16]
STATE_CANDIDATE_ID = "CANDIDATE-" + hashlib.sha256(
    b"PUBLIC_STATE_CHANGE_REVIEW\x00PATCH /settings/{tenant_id}"
).hexdigest()[:16]
FILE_CANDIDATE_ID = "CANDIDATE-" + hashlib.sha256(
    b"FILE_INGRESS_REVIEW\x00POST /uploads"
).hexdigest()[:16]


def _spec() -> bytes:
    return json.dumps(
        {
            "openapi": "3.1.0",
            "info": {"title": "CLI API", "version": "1"},
            "security": [{"bearerAuth": []}],
            "paths": {
                "/objects/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True}
                        ],
                        "responses": {"200": {"description": "object"}},
                    }
                }
            },
        },
        sort_keys=True,
    ).encode("utf-8")


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "engagement_id": "OPENAPI-CLI-001",
        "authorization_reference": "written-lab-scope-005",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "source_label": "api/openapi.json@ghi789",
        "asset_annotations": [
            {
                "entry_point": "GET /objects/{id}",
                "value": 2,
                "basis": "Tenant-owned records",
            }
        ],
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _files(tmp_path):
    spec = tmp_path / "openapi.json"
    manifest = tmp_path / "triage.json"
    spec.write_bytes(_spec())
    manifest.write_bytes(_manifest())
    return spec, manifest


def test_cli_emits_full_passive_triage_receipt(tmp_path, capsys):
    spec, manifest = _files(tmp_path)

    exit_code = main([str(spec), str(manifest)])
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert result["mode"] == "PASSIVE_ARTIFACT_TRIAGE"
    assert result["candidate_queue"][0]["candidate_id"] == CANDIDATE_ID
    assert result["candidate_queue"][0]["epistemic_level"] == "CANDIDATE"
    assert result["active_probe_performed"] is False
    assert result["model_used"] is False


def test_cli_select_emits_only_loss_resistant_bola_handoff(tmp_path, capsys):
    spec, manifest = _files(tmp_path)

    exit_code = main(
        ["--select", CANDIDATE_ID, str(spec), str(manifest)]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert result == {
        "candidate_id": CANDIDATE_ID,
        "entry_point": "GET /objects/{id}",
        "epistemic_level": "CANDIDATE",
        "integrity": "UNSEALED_TRIAGE_HANDOFF",
        "json_pointer": "/paths/~1objects~1{id}/get",
        "source_label": "api/openapi.json@ghi789",
        "source_sha256": hashlib.sha256(_spec()).hexdigest(),
    }


def test_cli_select_authn_emits_only_loss_resistant_authn_handoff(tmp_path, capsys):
    spec, manifest = _files(tmp_path)

    exit_code = main(
        ["--select-authn", AUTHN_CANDIDATE_ID, str(spec), str(manifest)]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert result == {
        "candidate_id": AUTHN_CANDIDATE_ID,
        "entry_point": "GET /objects/{id}",
        "epistemic_level": "CANDIDATE",
        "integrity": "UNSEALED_TRIAGE_HANDOFF",
        "json_pointer": "/paths/~1objects~1{id}/get",
        "source_label": "api/openapi.json@ghi789",
        "source_sha256": hashlib.sha256(_spec()).hexdigest(),
    }


def test_cli_select_state_change_emits_only_public_patch_handoff(tmp_path, capsys):
    spec_document = {
        "openapi": "3.1.0",
        "info": {"title": "State API", "version": "1"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/settings/{tenant_id}": {
                "patch": {
                    "security": [],
                    "parameters": [
                        {"name": "tenant_id", "in": "path", "required": True}
                    ],
                    "responses": {"200": {"description": "updated"}},
                }
            }
        },
    }
    raw_spec = json.dumps(spec_document, sort_keys=True).encode("utf-8")
    spec = tmp_path / "state.openapi.json"
    manifest = tmp_path / "state.triage.json"
    spec.write_bytes(raw_spec)
    manifest.write_bytes(
        _manifest(
            asset_annotations=[{
                "entry_point": "PATCH /settings/{tenant_id}",
                "value": 3,
                "basis": "Tenant security settings",
            }]
        )
    )

    exit_code = main([
        "--select-state-change",
        STATE_CANDIDATE_ID,
        str(spec),
        str(manifest),
    ])
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert result == {
        "candidate_id": STATE_CANDIDATE_ID,
        "entry_point": "PATCH /settings/{tenant_id}",
        "epistemic_level": "CANDIDATE",
        "integrity": "UNSEALED_TRIAGE_HANDOFF",
        "json_pointer": "/paths/~1settings~1{tenant_id}/patch",
        "source_label": "api/openapi.json@ghi789",
        "source_sha256": hashlib.sha256(raw_spec).hexdigest(),
    }


def test_cli_select_file_ingress_requires_post_candidate(tmp_path, capsys):
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Upload API", "version": "1"},
        "security": [{"bearerAuth": []}],
        "paths": {"/uploads": {"post": {
            "requestBody": {"content": {"multipart/form-data": {}}},
            "responses": {"201": {"description": "stored"}},
        }}},
    }
    raw = json.dumps(document, sort_keys=True).encode()
    spec = tmp_path / "upload.openapi.json"
    plan = tmp_path / "upload.triage.json"
    spec.write_bytes(raw)
    plan.write_bytes(_manifest(asset_annotations=[{
        "entry_point": "POST /uploads", "value": 3, "basis": "Uploaded evidence",
    }]))

    code = main(["--select-file-ingress", FILE_CANDIDATE_ID, str(spec), str(plan)])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["entry_point"] == "POST /uploads"
    assert result["epistemic_level"] == "CANDIDATE"
    assert result["source_sha256"] == hashlib.sha256(raw).hexdigest()


def test_select_rejects_unknown_candidate_without_partial_stdout(tmp_path, capsys):
    spec, manifest = _files(tmp_path)

    exit_code = main(
        ["--select", "CANDIDATE-0000000000000000", str(spec), str(manifest)]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "not found" in captured.err


def test_manifest_parser_rejects_unknown_duplicate_and_float_fields():
    with pytest.raises(OpenApiCliError, match="unknown fields"):
        parse_triage_manifest(_manifest(severity="critical"))
    with pytest.raises(OpenApiCliError, match="duplicate key"):
        parse_triage_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(OpenApiCliError, match="floating-point"):
        parse_triage_manifest(
            _manifest().replace(b'"value": 2', b'"value": 2.5')
        )


def test_annotation_shape_and_drift_fail_at_the_cli_boundary(tmp_path, capsys):
    with pytest.raises(OpenApiCliError, match="unknown annotation fields"):
        parse_triage_manifest(
            _manifest(
                asset_annotations=[
                    {
                        "entry_point": "GET /objects/{id}",
                        "value": 2,
                        "basis": "Tenant-owned records",
                        "confidence": "high",
                    }
                ]
            )
        )

    spec, manifest = _files(tmp_path)
    manifest.write_bytes(
        _manifest(
            asset_annotations=[
                {
                    "entry_point": "GET /missing/{id}",
                    "value": 2,
                    "basis": "Stale annotation",
                }
            ]
        )
    )
    exit_code = main([str(spec), str(manifest)])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "not present" in captured.err


def test_manifest_and_spec_symlinks_are_rejected(tmp_path):
    spec, manifest = _files(tmp_path)
    spec_link = tmp_path / "spec-link.json"
    manifest_link = tmp_path / "manifest-link.json"
    spec_link.symlink_to(spec)
    manifest_link.symlink_to(manifest)

    with pytest.raises(OpenApiCliError, match="symlink"):
        read_triage_manifest(manifest_link)
    exit_code = main([str(spec_link), str(manifest)])
    assert exit_code == 2


def test_output_never_introduces_finding_or_severity_labels(tmp_path, capsys):
    spec, manifest = _files(tmp_path)

    assert main([str(spec), str(manifest)]) == 0
    serialized = capsys.readouterr().out

    assert '"severity"' not in serialized
    assert '"finding"' not in serialized
    assert '"CONFIRMED"' not in serialized
