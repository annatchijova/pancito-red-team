"""The timeline composition audit has no operator-controlled evidence surface."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from offensive.timeline_evasion_cli import (
    TimelineEvasionManifestError,
    main,
    parse_timeline_evasion_manifest,
    preflight_timeline_evasion_manifest,
    read_timeline_evasion_manifest,
)


def _manifest(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "experiment_id": "TIMELINE-CLI-001",
        "authorization_reference": "written-scope-timeline-cli",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_runs_nothing_and_names_the_fixed_cells():
    manifest = parse_timeline_evasion_manifest(_manifest())
    result = preflight_timeline_evasion_manifest(manifest)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["cells"] == [
        "CONTROL_SHARED_ENTITY",
        "MISSING_MFT",
        "PRODUCTION_SHAPED_PAIR",
    ]
    assert result["sensor_run"] is False
    assert result["network_request_count"] == 0
    assert result["sample_source"] == "MODULE_OWNED_SYNTHETIC_FACTS"


def test_manifest_rejects_evidence_targets_duplicates_and_floats():
    for field in ("target", "memory_dump", "mft_path", "signals", "sample"):
        with pytest.raises(TimelineEvasionManifestError, match="unknown fields"):
            parse_timeline_evasion_manifest(_manifest(**{field: "forbidden"}))
    with pytest.raises(TimelineEvasionManifestError, match="duplicate key"):
        parse_timeline_evasion_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(TimelineEvasionManifestError, match="floating-point"):
        parse_timeline_evasion_manifest(
            _manifest().replace(b'"schema_version": 1', b'"schema_version": 1.0')
        )


def test_manifest_reader_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)

    with pytest.raises(TimelineEvasionManifestError, match="symlink"):
        read_timeline_evasion_manifest(linked)


def test_cli_is_hash_seed_stable_and_reports_falsification(tmp_path, capsys):
    path = tmp_path / "timeline.json"
    path.write_bytes(_manifest())

    assert main(["--dry-run", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VALIDATED_NOT_EXECUTED"

    outputs = []
    for seed in ("31", "1301"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-m", "offensive.timeline_evasion_cli", str(path)],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]
    receipt = json.loads(outputs[0])
    assert receipt["epistemic_level"] == "FALSIFIED"
    assert receipt["part_of_forensic_verdict"] is False

