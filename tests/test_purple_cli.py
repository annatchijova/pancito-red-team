"""The Purple CLI binds Blue assertions to the exact Red receipt evaluated."""

from __future__ import annotations

import hashlib
import json

import pytest

from offensive.purple import (
    authn_blue_objective,
    bola_blue_objective,
    file_ingress_blue_objective,
    state_change_blue_objective,
)
from offensive.purple_cli import (
    PurpleCliError,
    main,
    parse_blue_observation,
    read_blue_observation,
)


def _receipt(technique: str = "bola") -> bytes:
    if technique == "bola":
        experiment_id = "PURPLE-CLI-BOLA-001"
        capability = "http-bola-differential"
        objective = bola_blue_objective(experiment_id)
        extra = {}
    elif technique == "authn":
        experiment_id = "PURPLE-CLI-AUTHN-001"
        capability = "http-authentication-enforcement-differential"
        objective = authn_blue_objective(experiment_id)
        extra = {}
    elif technique == "state-change":
        experiment_id = "PURPLE-CLI-STATE-001"
        capability = "http-public-state-change-differential"
        steps = (
            "BASELINE_READ",
            "VALID_CREDENTIAL_CONTROL",
            "VALID_CONTROL_READBACK",
            "CONTROL_RESTORE",
            "CONTROL_RESTORE_VERIFY",
            "ANONYMOUS_TEST",
            "ANONYMOUS_READBACK",
            "INVALID_BEARER_TEST",
            "INVALID_BEARER_READBACK",
        )
        objective = state_change_blue_objective(experiment_id, steps)
        extra = {
            "request_count": len(steps),
            "maximum_request_count": 13,
            "method": "PATCH",
            "observations": [{"step": step} for step in steps],
            "confirmed_cells": ["ANONYMOUS"],
            "cell_outcomes": {
                "ANONYMOUS": "MUTATION_CONFIRMED",
                "INVALID_BEARER": "MUTATION_DENIED",
            },
            "cleanup_status": "RESTORED_TO_BASELINE",
            "final_state_verified": True,
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        }
    else:
        experiment_id = "PURPLE-CLI-FILE-001"
        capability = "http-file-ingress-differential"
        steps = (
            "CONTROL_UPLOAD", "CONTROL_READBACK", "CONTROL_CLEANUP",
            "CONTROL_CLEANUP_VERIFY", "TYPE_MISMATCH_UPLOAD",
            "TYPE_MISMATCH_READBACK", "TYPE_MISMATCH_CLEANUP",
            "TYPE_MISMATCH_CLEANUP_VERIFY", "OVERSIZE_UPLOAD",
        )
        objective = file_ingress_blue_objective(experiment_id, steps)
        marker = objective["exercise_marker"].encode("ascii")
        sample_bytes = {
            "CONTROL": b"PANCITO-INERT-TEXT-V1\n" + marker + b"\n",
            "TYPE_MISMATCH": b"PANCITO-NOT-A-PNG-V1\n" + marker + b"\n",
        }
        oversize = b"PANCITO-INERT-OVERSIZE-V1\n" + marker + b"\n"
        sample_bytes["OVERSIZE"] = oversize + b"X" * (1025 - len(oversize))
        sample_names = {
            "CONTROL": ("control.txt", "text/plain"),
            "TYPE_MISMATCH": ("mismatch.png", "image/png"),
            "OVERSIZE": ("oversize.bin", "application/octet-stream"),
        }
        extra = {
            "method": "POST",
            "confirmed_cells": ["TYPE_MISMATCH"],
            "cell_outcomes": {
                "CONTROL": "STORED_EXACTLY",
                "TYPE_MISMATCH": "STORED_EXACTLY",
                "OVERSIZE": "REJECTED",
            },
            "cleanup_status": "VERIFIED_ABSENT",
            "final_absence_verified": True,
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
            "request_count": len(steps),
            "maximum_request_count": 12,
            "expected_max_bytes": 1024,
            "samples": {
                cell: {
                    "filename": sample_names[cell][0],
                    "declared_media_type": sample_names[cell][1],
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "synthetic_inert": True,
                }
                for cell, content in sample_bytes.items()
            },
            "observations": [{"step": step} for step in steps],
        }
    return json.dumps(
        {
            "experiment_id": experiment_id,
            "capability": capability,
            "epistemic_level": "CONFIRMED_BY_INDUCTION",
            "blue_objective": objective,
            "model_used": False,
            "part_of_forensic_verdict": False,
            "receipt_integrity": "UNSEALED",
            **extra,
        },
        sort_keys=True,
    ).encode("utf-8")


def _observation(technique: str = "bola", **overrides) -> bytes:
    if technique == "bola":
        objective = bola_blue_objective("PURPLE-CLI-BOLA-001")
    elif technique == "authn":
        objective = authn_blue_objective("PURPLE-CLI-AUTHN-001")
    elif technique == "state-change":
        objective = state_change_blue_objective(
            "PURPLE-CLI-STATE-001",
            tuple(item["step"] for item in json.loads(_receipt(technique))["observations"]),
        )
    else:
        receipt = json.loads(_receipt(technique))
        objective = file_ingress_blue_objective(
            "PURPLE-CLI-FILE-001",
            tuple(item["step"] for item in receipt["observations"]),
        )
    value = {
        "schema_version": 1,
        "exercise_marker": objective["exercise_marker"],
        "collection_status": "COMPLETE",
        "observed_steps": objective["expected_steps"],
        "alert_status": "FIRED",
        "alert_reference": "SIEM-CLI-4001",
        "alert_depends_on_exercise_marker": False,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_parser_builds_strict_blue_observation():
    observation = parse_blue_observation(_observation())

    assert observation.collection_status == "COMPLETE"
    assert observation.alert_reference == "SIEM-CLI-4001"
    assert observation.observed_steps == (
        "OWNER_CONTROL",
        "PEER_CONTROL",
        "CROSS_PRINCIPAL_TEST",
    )


def test_parser_rejects_unknown_duplicate_float_and_ambiguous_shapes():
    with pytest.raises(PurpleCliError, match="unknown fields"):
        parse_blue_observation(_observation(confidence="high"))
    with pytest.raises(PurpleCliError, match="duplicate key"):
        parse_blue_observation(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(PurpleCliError, match="floating-point"):
        parse_blue_observation(
            _observation().replace(b'"schema_version": 1', b'"schema_version": 1.0')
        )
    with pytest.raises(PurpleCliError, match="observed_steps must be an array"):
        parse_blue_observation(_observation(observed_steps="OWNER_CONTROL"))
    oversized_integer = (
        b'{"schema_version":'
        + b"9" * 5_000
        + b',"exercise_marker":"PANCITO-0123456789abcdef"}'
    )
    with pytest.raises(PurpleCliError, match="invalid Blue observation JSON"):
        parse_blue_observation(oversized_integer)


@pytest.mark.parametrize(
    "technique", ["bola", "authn", "state-change", "file-ingress"]
)
def test_cli_evaluates_exact_inputs_and_records_source_hashes(
    technique, tmp_path, capsys
):
    receipt_raw = _receipt(technique)
    observation_raw = _observation(technique)
    receipt_path = tmp_path / "receipt.json"
    observation_path = tmp_path / "observation.json"
    receipt_path.write_bytes(receipt_raw)
    observation_path.write_bytes(observation_raw)

    exit_code = main([technique, str(receipt_path), str(observation_path)])
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert result["detection_outcome"] == "DETECTED"
    assert result["coverage_claim"] == "EARNED_FOR_THIS_EXERCISE"
    assert result["changes_offensive_result"] is False
    assert result["source_provenance"] == {
        "blue_observation_sha256": hashlib.sha256(observation_raw).hexdigest(),
        "red_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
    }
    assert result["evaluation_integrity"] == "UNSEALED_DETERMINISTIC_DERIVATION"
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False


def test_cli_marker_mismatch_fails_without_partial_stdout(tmp_path, capsys):
    receipt_path = tmp_path / "receipt.json"
    observation_path = tmp_path / "observation.json"
    receipt_path.write_bytes(_receipt())
    observation_path.write_bytes(
        _observation(exercise_marker="PANCITO-fedcba9876543210")
    )

    exit_code = main(["bola", str(receipt_path), str(observation_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "marker" in captured.err


def test_blue_observation_reader_rejects_symlinks(tmp_path):
    real = tmp_path / "observation.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_observation())
    linked.symlink_to(real)

    with pytest.raises(PurpleCliError, match="symlink"):
        read_blue_observation(linked)
