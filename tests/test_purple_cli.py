"""The Purple CLI binds Blue assertions to the exact Red receipt evaluated."""

from __future__ import annotations

import hashlib
import json

import pytest

from offensive.purple import (
    authn_blue_objective,
    bola_blue_objective,
    collection_authz_blue_objective,
    file_ingress_blue_objective,
    function_authz_blue_objective,
    mass_assignment_blue_objective,
    nested_bola_blue_objective,
    stale_authority_blue_objective,
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
    elif technique == "file-ingress":
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
    elif technique == "mass-assignment":
        experiment_id = "PURPLE-CLI-MASS-001"
        capability = "http-mass-assignment-differential"
        steps = (
            "BASELINE_READ",
            "ALLOWED_FIELD_CONTROL",
            "ALLOWED_CONTROL_READBACK",
            "CONTROL_RESTORE",
            "CONTROL_RESTORE_VERIFY",
            "PROTECTED_FIELD_TEST",
            "PROTECTED_TEST_READBACK",
            "NEGATIVE_RESTORE",
            "NEGATIVE_RESTORE_VERIFY",
        )
        objective = mass_assignment_blue_objective(experiment_id, steps)
        extra = {
            "request_count": 9,
            "maximum_request_count": 9,
            "method": "PATCH",
            "observations": [{"step": step} for step in steps],
            "control_outcome": "ALLOWED_FIELD_MUTATION_CONFIRMED",
            "negative_outcome": "PROTECTED_FIELD_MUTATION_CONFIRMED",
            "cleanup_status": "RESTORED_TO_BASELINE",
            "final_state_verified": True,
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        }
    elif technique == "nested-bola":
        experiment_id = "PURPLE-CLI-NESTED-001"
        capability = "http-nested-bola-differential"
        objective = nested_bola_blue_objective(experiment_id)
        extra = {
            "request_count": 3,
            "maximum_request_count": 3,
            "method": "GET",
            "controls": {
                "owner_control_passed": True,
                "peer_control_passed": True,
            },
            "reason_code": "FOREIGN_CHILD_CANARY_OBSERVED",
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        }
    elif technique == "stale-authority":
        experiment_id = "PURPLE-CLI-STALE-001"
        capability = "http-stale-authority-differential"
        steps = (
            "INITIAL_MEMBERSHIP_READ", "ACTOR_PRE_REVOKE_CONTROL",
            "ADMIN_REVOKE", "ADMIN_REVOKE_VERIFY", "STALE_CREDENTIAL_TEST",
            "ADMIN_RESTORE", "ADMIN_RESTORE_VERIFY",
        )
        objective = stale_authority_blue_objective(experiment_id, steps)
        extra = {
            "reason_code": "STALE_CREDENTIAL_ACCESS_CONFIRMED",
            "revoke_verified": True,
            "stale_access_observed": True,
            "cleanup_status": "RESTORED_TO_BASELINE",
            "final_state_verified": True,
            "request_count": 7,
            "maximum_request_count": 7,
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
            "observations": [{"step": step} for step in steps],
        }
    elif technique == "function-authz":
        experiment_id = "PURPLE-CLI-BFLA-001"
        capability = "http-function-authorization-differential"
        objective = function_authz_blue_objective(experiment_id)
        extra = {
            "reason_code": "MEMBER_OBSERVED_ADMIN_CANARY",
            "controls": {
                "admin_control_passed": True,
                "member_control_passed": True,
            },
            "request_count": 3,
            "maximum_request_count": 3,
            "method": "GET",
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        }
    else:
        experiment_id = "PURPLE-CLI-COLLECTION-001"
        capability = "http-collection-authorization-differential"
        objective = collection_authz_blue_objective(experiment_id)
        extra = {
            "reason_code": "ALPHA_OBSERVED_BRAVO_COLLECTION_CANARY",
            "controls": {
                "alpha_control_passed": True,
                "bravo_control_passed": True,
            },
            "request_count": 3,
            "maximum_request_count": 3,
            "method": "GET",
            "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
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
    elif technique == "file-ingress":
        receipt = json.loads(_receipt(technique))
        objective = file_ingress_blue_objective(
            "PURPLE-CLI-FILE-001",
            tuple(item["step"] for item in receipt["observations"]),
        )
    elif technique == "mass-assignment":
        receipt = json.loads(_receipt(technique))
        objective = mass_assignment_blue_objective(
            "PURPLE-CLI-MASS-001",
            tuple(item["step"] for item in receipt["observations"]),
        )
    elif technique == "nested-bola":
        objective = nested_bola_blue_objective("PURPLE-CLI-NESTED-001")
    elif technique == "stale-authority":
        receipt = json.loads(_receipt(technique))
        objective = stale_authority_blue_objective(
            "PURPLE-CLI-STALE-001",
            tuple(item["step"] for item in receipt["observations"]),
        )
    elif technique == "function-authz":
        objective = function_authz_blue_objective("PURPLE-CLI-BFLA-001")
    else:
        objective = collection_authz_blue_objective("PURPLE-CLI-COLLECTION-001")
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
    "technique",
    [
        "bola",
        "authn",
        "state-change",
        "file-ingress",
        "mass-assignment",
        "nested-bola",
        "stale-authority",
        "function-authz",
        "collection-authz",
    ],
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
