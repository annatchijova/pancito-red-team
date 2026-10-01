"""Purple evaluation binds Blue claims to the exact field-authz experiment."""

from __future__ import annotations

import pytest

from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_mass_assignment_detection,
    mass_assignment_blue_objective,
)


STEPS = (
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


def _receipt(level="FALSIFIED"):
    experiment_id = "MASS-PURPLE-001"
    return {
        "experiment_id": experiment_id,
        "capability": "http-mass-assignment-differential",
        "epistemic_level": level,
        "request_count": 9,
        "maximum_request_count": 9,
        "method": "PATCH",
        "observations": [{"step": step} for step in STEPS],
        "control_outcome": "ALLOWED_FIELD_MUTATION_CONFIRMED",
        "negative_outcome": (
            "PROTECTED_FIELD_MUTATION_CONFIRMED"
            if level == "CONFIRMED_BY_INDUCTION"
            else "PROTECTED_FIELD_UNCHANGED"
        ),
        "cleanup_status": "RESTORED_TO_BASELINE",
        "final_state_verified": True,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": mass_assignment_blue_objective(experiment_id, STEPS),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def _blue(receipt, alert="NOT_FIRED"):
    return BlueObservation(
        exercise_marker=receipt["blue_objective"]["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=STEPS,
        alert_status=alert,
        alert_reference="SIEM-MASS-1" if alert == "FIRED" else None,
        alert_depends_on_exercise_marker=False,
    )


def test_prevention_and_detection_are_independent():
    receipt = _receipt()
    result = evaluate_mass_assignment_detection(receipt, _blue(receipt))

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
    assert "protected property" in result["detection_requirement"]


def test_confirmed_property_change_can_earn_behavior_detection():
    receipt = _receipt("CONFIRMED_BY_INDUCTION")
    result = evaluate_mass_assignment_detection(receipt, _blue(receipt, "FIRED"))

    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["detection_outcome"] == "DETECTED"


def test_receipt_cannot_claim_confirmation_without_matching_oracle():
    receipt = _receipt("CONFIRMED_BY_INDUCTION")
    receipt["negative_outcome"] = "PROTECTED_FIELD_UNCHANGED"

    with pytest.raises(BlueObservationError, match="confirmed result"):
        evaluate_mass_assignment_detection(receipt, _blue(_receipt()))
