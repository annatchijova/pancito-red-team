"""Blue evaluation follows the exact synthetic upload and cleanup sequence."""

from __future__ import annotations

import hashlib

import pytest

from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_file_ingress_detection,
    file_ingress_blue_objective,
)


DENIED_STEPS = (
    "CONTROL_UPLOAD", "CONTROL_READBACK", "CONTROL_CLEANUP", "CONTROL_CLEANUP_VERIFY",
    "TYPE_MISMATCH_UPLOAD", "OVERSIZE_UPLOAD",
)


def _receipt(level="FALSIFIED", steps=DENIED_STEPS):
    confirmed = ["TYPE_MISMATCH"] if level == "CONFIRMED_BY_INDUCTION" else []
    outcomes = {
        "CONTROL": "STORED_EXACTLY",
        "TYPE_MISMATCH": "STORED_EXACTLY" if confirmed else "REJECTED",
        "OVERSIZE": "REJECTED",
    }
    marker = file_ingress_blue_objective("FILE-PURPLE-001", steps)[
        "exercise_marker"
    ].encode("ascii")
    control = b"PANCITO-INERT-TEXT-V1\n" + marker + b"\n"
    mismatch = b"PANCITO-NOT-A-PNG-V1\n" + marker + b"\n"
    oversize = b"PANCITO-INERT-OVERSIZE-V1\n" + marker + b"\n"
    oversize += b"X" * (1025 - len(oversize))
    samples = {
        "CONTROL": ("control.txt", "text/plain", control),
        "TYPE_MISMATCH": ("mismatch.png", "image/png", mismatch),
        "OVERSIZE": ("oversize.bin", "application/octet-stream", oversize),
    }
    return {
        "experiment_id": "FILE-PURPLE-001",
        "capability": "http-file-ingress-differential",
        "method": "POST",
        "epistemic_level": level,
        "confirmed_cells": confirmed,
        "cell_outcomes": outcomes,
        "cleanup_status": "VERIFIED_ABSENT",
        "final_absence_verified": True,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "request_count": len(steps),
        "maximum_request_count": 12,
        "expected_max_bytes": 1024,
        "samples": {
            cell: {
                "filename": filename,
                "declared_media_type": media_type,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "synthetic_inert": True,
            }
            for cell, (filename, media_type, content) in samples.items()
        },
        "observations": [{"step": step} for step in steps],
        "blue_objective": file_ingress_blue_objective("FILE-PURPLE-001", steps),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def _observation(receipt, steps=None, alert="NOT_FIRED"):
    objective = receipt["blue_objective"]
    return BlueObservation(
        exercise_marker=objective["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=tuple(objective["expected_steps"] if steps is None else steps),
        alert_status=alert,
        alert_reference="SIEM-FILE-6001" if alert == "FIRED" else None,
        alert_depends_on_exercise_marker=False,
    )


def test_rejections_are_prevented_but_visible_without_alert():
    receipt = _receipt()
    result = evaluate_file_ingress_detection(receipt, _observation(receipt))
    assert result["preventive_outcome"] == "PREVENTED"
    assert result["visibility_outcome"] == "VISIBLE"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_stored_mismatch_with_behavior_alert_earns_detection():
    steps = (
        *DENIED_STEPS[:4],
        "TYPE_MISMATCH_UPLOAD", "TYPE_MISMATCH_READBACK",
        "TYPE_MISMATCH_CLEANUP", "TYPE_MISMATCH_CLEANUP_VERIFY",
        "OVERSIZE_UPLOAD",
    )
    receipt = _receipt("CONFIRMED_BY_INDUCTION", steps)
    result = evaluate_file_ingress_detection(receipt, _observation(receipt, alert="FIRED"))
    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["detection_outcome"] == "DETECTED"


def test_receipt_cannot_reorder_steps_or_promote_impact():
    receipt = _receipt()
    receipt["observations"][0], receipt["observations"][1] = (
        receipt["observations"][1], receipt["observations"][0]
    )
    with pytest.raises(BlueObservationError, match="step order"):
        evaluate_file_ingress_detection(receipt, _observation(_receipt()))


def test_receipt_rejects_impossible_lifecycle_and_nonreproducible_sample():
    steps = (
        "CONTROL_UPLOAD", "CONTROL_READBACK", "CONTROL_CLEANUP",
        "CONTROL_CLEANUP_VERIFY", "TYPE_MISMATCH_UPLOAD",
        "TYPE_MISMATCH_READBACK", "OVERSIZE_UPLOAD",
    )
    receipt = _receipt("INCONCLUSIVE", steps)
    with pytest.raises(BlueObservationError, match="lifecycle"):
        evaluate_file_ingress_detection(receipt, _observation(receipt))

    receipt = _receipt()
    receipt["samples"]["TYPE_MISMATCH"]["sha256"] = "0" * 64
    with pytest.raises(BlueObservationError, match="does not reproduce"):
        evaluate_file_ingress_detection(receipt, _observation(receipt))

    receipt = _receipt()
    receipt["impact_assessment"] = "CRITICAL"
    with pytest.raises(BlueObservationError, match="overclaims"):
        evaluate_file_ingress_detection(receipt, _observation(_receipt()))


def test_blue_gap_does_not_invent_cleanup_for_rejected_cells():
    receipt = _receipt()
    observed = tuple(step for step in DENIED_STEPS if step != "OVERSIZE_UPLOAD")
    result = evaluate_file_ingress_detection(receipt, _observation(receipt, observed))
    assert result["detection_outcome"] == "TELEMETRY_GAP"
    assert result["missing_steps"] == ["OVERSIZE_UPLOAD"]
    assert "OVERSIZE_CLEANUP" not in result["missing_steps"]
