"""The forensic-evasion CLI accepts only authorization metadata."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from offensive.forensic_evasion_cli import (
    ForensicEvasionManifestError,
    main,
    parse_forensic_evasion_manifest,
    preflight_forensic_evasion_manifest,
    read_forensic_evasion_manifest,
)


def _manifest(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "experiment_id": "SIFT-EVASION-CLI-001",
        "authorization_reference": "written-lab-scope-sift-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_has_no_sensor_execution_or_sample_surface():
    manifest = parse_forensic_evasion_manifest(_manifest())
    result = preflight_forensic_evasion_manifest(manifest)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["sensor_run"] is False
    assert result["cells"] == ["CONTROL", "LOG_WIPE", "TIMESTOMP"]
    assert result["sample_source"] == "MODULE_OWNED_SYNTHETIC_FIXTURES"
    assert result["part_of_forensic_verdict"] is False


def test_manifest_rejects_samples_paths_duplicates_and_floats():
    for field in ("sample_path", "mft_bytes", "event_log_path", "target"):
        with pytest.raises(ForensicEvasionManifestError, match="unknown fields"):
            parse_forensic_evasion_manifest(_manifest(**{field: "forbidden"}))
    with pytest.raises(ForensicEvasionManifestError, match="duplicate key"):
        parse_forensic_evasion_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ForensicEvasionManifestError, match="floating-point"):
        parse_forensic_evasion_manifest(
            _manifest().replace(b'"schema_version": 1', b'"schema_version": 1.0')
        )


def test_manifest_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(ForensicEvasionManifestError, match="symlink"):
        read_forensic_evasion_manifest(linked)


def test_cli_dry_run_and_execution(tmp_path, capsys):
    path = tmp_path / "forensic-evasion.json"
    path.write_bytes(_manifest())

    assert main(["--dry-run", str(path)]) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["status"] == "VALIDATED_NOT_EXECUTED"

    assert main([str(path)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert receipt["part_of_forensic_verdict"] is False


def test_cli_receipt_is_identical_across_fresh_hash_seeds(tmp_path):
    path = tmp_path / "forensic-evasion.json"
    path.write_bytes(_manifest())
    outputs = []
    for seed in ("17", "991"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-m", "offensive.forensic_evasion_cli", str(path)],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(completed.stdout)

    assert outputs[0] == outputs[1]
