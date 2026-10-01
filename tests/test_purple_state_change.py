"""Purple evaluation follows the exact reversible mutation steps executed."""

from __future__ import annotations

import pytest

from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_state_change_detection,
    state_change_blue_objective,
)


DENIED_STEPS = (
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
CONFIRMED_ANONYMOUS_STEPS = (
    *DENIED_STEPS[:7],
    "ANONYMOUS_RESTORE",
    "ANONYMOUS_RESTORE_VERIFY",
    *DENIED_STEPS[7:],
)


def _receipt(
    steps: tuple[str, ...] = DENIED_STEPS,
    epistemic_level: str = "FALSIFIED",
) -> dict[str, object]:
    experiment_id = "STATE-PURPLE-001"
    confirmed = (
        ["ANONYMOUS"]
        if epistemic_level == "CONFIRMED_BY_INDUCTION"
        else []
    )
    outcomes = {
        "ANONYMOUS": (
            "MUTATION_CONFIRMED" if confirmed else "MUTATION_DENIED"
        ),
        "INVALID_BEARER": "MUTATION_DENIED",
    }
    return {
        "experiment_id": experiment_id,
        "capability": "http-public-state-change-differential",
        "epistemic_level": epistemic_level,
        "request_count": len(steps),
        "maximum_request_count": 13,
        "method": "PATCH",
        "observations": [{"step": step} for step in steps],
        "confirmed_cells": confirmed,
        "cell_outcomes": outcomes,
        "cleanup_status": "RESTORED_TO_BASELINE",
        "final_state_verified": True,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": state_change_blue_objective(experiment_id, steps),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def _observation(receipt, *, steps=None, alert_status="NOT_FIRED"):
    objective = receipt["blue_objective"]
    return BlueObservation(
        exercise_marker=objective["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=tuple(objective["expected_steps"] if steps is None else steps),
        alert_status=alert_status,
        alert_reference=("SIEM-STATE-5001" if alert_status == "FIRED" else None),
        alert_depends_on_exercise_marker=False,
    )


def test_denied_cells_keep_prevention_and_detection_as_independent_axes():
    receipt = _receipt()

    result = evaluate_state_change_detection(receipt, _observation(receipt))

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["visibility_outcome"] == "VISIBLE"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
    assert "changed field" in result["detection_requirement"]


def test_confirmed_mutation_with_behavior_alert_earns_detection():
    receipt = _receipt(
        CONFIRMED_ANONYMOUS_STEPS, "CONFIRMED_BY_INDUCTION"
    )

    result = evaluate_state_change_detection(
        receipt, _observation(receipt, alert_status="FIRED")
    )

    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["detection_outcome"] == "DETECTED"
    assert result["coverage_claim"] == "EARNED_FOR_THIS_EXERCISE"
    assert result["missing_steps"] == []


def test_blue_gap_is_measured_only_against_requests_that_actually_ran():
    receipt = _receipt(CONFIRMED_ANONYMOUS_STEPS, "CONFIRMED_BY_INDUCTION")
    observed = tuple(
        step for step in CONFIRMED_ANONYMOUS_STEPS
        if step != "ANONYMOUS_RESTORE_VERIFY"
    )

    result = evaluate_state_change_detection(
        receipt, _observation(receipt, steps=observed)
    )

    assert result["detection_outcome"] == "TELEMETRY_GAP"
    assert result["missing_steps"] == ["ANONYMOUS_RESTORE_VERIFY"]
    assert "INVALID_BEARER_RESTORE" not in result["missing_steps"]


def test_receipt_cannot_reorder_or_invent_executed_steps():
    receipt = _receipt()
    receipt["observations"][5], receipt["observations"][6] = (
        receipt["observations"][6],
        receipt["observations"][5],
    )
    with pytest.raises(BlueObservationError, match="step order"):
        evaluate_state_change_detection(receipt, _observation(_receipt()))

    receipt = _receipt()
    receipt["blue_objective"]["expected_steps"].append("ANONYMOUS_RESTORE")
    receipt["blue_objective"]["expected_event_count"] += 1
    with pytest.raises(BlueObservationError, match="does not match"):
        evaluate_state_change_detection(receipt, _observation(_receipt()))


def test_request_count_and_maximum_are_contract_fields():
    receipt = _receipt()
    receipt["request_count"] = 13
    with pytest.raises(BlueObservationError, match="request count"):
        evaluate_state_change_detection(receipt, _observation(_receipt()))

    receipt = _receipt()
    receipt["maximum_request_count"] = 99
    with pytest.raises(BlueObservationError, match="maximum request count"):
        evaluate_state_change_detection(receipt, _observation(_receipt()))


def test_red_receipt_cannot_promote_impact_or_confirmation_without_evidence():
    receipt = _receipt()
    receipt["impact_assessment"] = "CRITICAL_VULNERABILITY"
    with pytest.raises(BlueObservationError, match="overclaims"):
        evaluate_state_change_detection(receipt, _observation(_receipt()))

    receipt = _receipt(epistemic_level="CONFIRMED_BY_INDUCTION")
    receipt["confirmed_cells"] = []
    with pytest.raises(BlueObservationError, match="confirmed result"):
        evaluate_state_change_detection(receipt, _observation(_receipt()))
