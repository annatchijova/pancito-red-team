"""One strict manifest coordinates both offline SIFT validation modules."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from offensive.windows_artifact_cli import (
    WindowsArtifactManifestError,
    main,
    parse_windows_artifact_manifest,
    preflight_windows_artifact_manifest,
    read_windows_artifact_manifest,
)


def _manifest(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "experiment_id": "WINDOWS-ARTIFACTS-001",
        "authorization_reference": "written-scope-windows-artifacts",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_is_closed_and_runs_neither_sensor():
    manifest = parse_windows_artifact_manifest(_manifest())
    result = preflight_windows_artifact_manifest(manifest)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["modules"] == ["PREFETCH_EVASION", "REGISTRY_EVASION"]
    assert result["sensor_run"] is False
    assert result["network_request_count"] == 0
    assert result["sample_source"] == "MODULE_OWNED_SYNTHETIC_FIXTURES"


def test_manifest_rejects_authority_expansion_duplicates_and_floats():
    for field in ("target", "hive_path", "prefetch_dir", "command", "sample"):
        with pytest.raises(WindowsArtifactManifestError, match="unknown fields"):
            parse_windows_artifact_manifest(_manifest(**{field: "forbidden"}))
    with pytest.raises(WindowsArtifactManifestError, match="duplicate key"):
        parse_windows_artifact_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(WindowsArtifactManifestError, match="floating-point"):
        parse_windows_artifact_manifest(
            _manifest().replace(b'"schema_version": 1', b'"schema_version": 1.0')
        )


def test_manifest_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(WindowsArtifactManifestError, match="symlink"):
        read_windows_artifact_manifest(linked)


def test_cli_runs_both_modules_and_is_hash_seed_stable(tmp_path, capsys):
    path = tmp_path / "windows-artifacts.json"
    path.write_bytes(_manifest())

    assert main(["--dry-run", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VALIDATED_NOT_EXECUTED"

    outputs = []
    for seed in ("23", "1201"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-m", "offensive.windows_artifact_cli", str(path)],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]
    receipt = json.loads(outputs[0])
    assert receipt["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert sorted(receipt["module_results"]) == ["PREFETCH_EVASION", "REGISTRY_EVASION"]
    assert receipt["part_of_forensic_verdict"] is False

