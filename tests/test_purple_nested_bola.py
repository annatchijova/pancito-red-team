"""Nested BOLA prevention and Blue detection remain independent claims."""

from __future__ import annotations

import pytest

from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_nested_bola_detection,
    nested_bola_blue_objective,
)


STEPS = ("OWNER_NESTED_CONTROL", "PEER_NESTED_CONTROL", "CROSS_CHILD_TEST")


def _receipt(level="FALSIFIED"):
    experiment_id = "NESTED-PURPLE-001"
    return {
        "experiment_id": experiment_id,
        "capability": "http-nested-bola-differential",
        "epistemic_level": level,
        "request_count": 3,
        "maximum_request_count": 3,
        "method": "GET",
        "controls": {"owner_control_passed": True, "peer_control_passed": True},
        "reason_code": (
            "FOREIGN_CHILD_CANARY_OBSERVED"
            if level == "CONFIRMED_BY_INDUCTION"
            else "CROSS_PARENT_CHILD_ACCESS_DENIED"
        ),
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": nested_bola_blue_objective(experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def _blue(receipt, alert="NOT_FIRED"):
    return BlueObservation(
        exercise_marker=receipt["blue_objective"]["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=STEPS,
        alert_status=alert,
        alert_reference="SIEM-NESTED-1" if alert == "FIRED" else None,
        alert_depends_on_exercise_marker=False,
    )


def test_denial_is_prevention_but_not_automatically_detection():
    receipt = _receipt()
    result = evaluate_nested_bola_detection(receipt, _blue(receipt))

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_foreign_child_with_behavior_alert_earns_this_exercise_only():
    receipt = _receipt("CONFIRMED_BY_INDUCTION")
    result = evaluate_nested_bola_detection(receipt, _blue(receipt, "FIRED"))

    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["coverage_claim"] == "EARNED_FOR_THIS_EXERCISE"


def test_receipt_cannot_promote_confirmation_with_denial_reason():
    receipt = _receipt("CONFIRMED_BY_INDUCTION")
    receipt["reason_code"] = "CROSS_PARENT_CHILD_ACCESS_DENIED"
    with pytest.raises(BlueObservationError, match="confirmed result"):
        evaluate_nested_bola_detection(receipt, _blue(_receipt()))


def test_inconclusive_failed_control_can_still_measure_blue_visibility():
    receipt = _receipt("INCONCLUSIVE")
    receipt["controls"] = {
        "owner_control_passed": True,
        "peer_control_passed": False,
    }
    receipt["reason_code"] = "PEER_CONTROL_FAILED"

    result = evaluate_nested_bola_detection(receipt, _blue(receipt))

    assert result["preventive_outcome"] == "UNRESOLVED"
    assert result["visibility_outcome"] == "VISIBLE"
