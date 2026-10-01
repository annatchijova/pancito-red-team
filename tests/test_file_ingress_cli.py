"""File-ingress manifests reference one credential and never accept sample bytes."""

from __future__ import annotations

import json

import pytest

from offensive.file_ingress_cli import (
    FileIngressManifestError,
    main,
    parse_file_ingress_manifest,
    preflight_file_ingress_manifest,
    read_file_ingress_manifest,
    resolve_file_ingress_secrets,
)


TOKEN = "cli-file-observer-token"


def _manifest(**overrides):
    value = {
        "schema_version": 1,
        "experiment_id": "FILE-CLI-001",
        "authorization_reference": "written-file-scope-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "upload_path": "/uploads",
        "readback_path_template": "/uploads/{upload_id}",
        "upload_field": "file",
        "observer_principal_id": "file-observer",
        "observer_token_env": "PANCITO_FILE_OBSERVER_TOKEN",
        "expected_max_bytes": 1024,
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode()


def test_preflight_is_zero_request_and_has_no_sample_input_surface():
    manifest = parse_file_ingress_manifest(_manifest())
    secrets = resolve_file_ingress_secrets(
        manifest, {"PANCITO_FILE_OBSERVER_TOKEN": TOKEN}
    )
    result = preflight_file_ingress_manifest(manifest, secrets)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 12
    assert result["sample_source"] == "SYNTHETIC_INERT_GENERATED_IN_MEMORY"
    assert TOKEN not in json.dumps(result)


def test_manifest_rejects_inline_sample_secret_duplicates_and_float():
    with pytest.raises(FileIngressManifestError, match="unknown fields"):
        parse_file_ingress_manifest(_manifest(sample_path="malware.exe"))
    with pytest.raises(FileIngressManifestError, match="unknown fields"):
        parse_file_ingress_manifest(_manifest(observer_token="inline"))
    with pytest.raises(FileIngressManifestError, match="duplicate key"):
        parse_file_ingress_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(FileIngressManifestError, match="floating-point"):
        parse_file_ingress_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )


def test_missing_secret_names_only_environment_source():
    manifest = parse_file_ingress_manifest(_manifest())
    with pytest.raises(FileIngressManifestError, match="PANCITO_FILE_OBSERVER_TOKEN"):
        resolve_file_ingress_secrets(manifest, {})


def test_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(FileIngressManifestError, match="symlink"):
        read_file_ingress_manifest(linked)


def test_cli_dry_run_is_secret_free(tmp_path, capsys):
    path = tmp_path / "file.json"
    path.write_bytes(_manifest())
    code = main(
        ["--dry-run", str(path)],
        environ={"PANCITO_FILE_OBSERVER_TOKEN": TOKEN},
    )
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert TOKEN not in captured.out
