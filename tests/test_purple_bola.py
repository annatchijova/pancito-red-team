"""BOLA exercises measure Blue visibility without changing the Red result."""

from __future__ import annotations

import pytest

from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    authn_blue_objective,
    evaluate_authn_detection,
    evaluate_bola_detection,
)


MARKER = "PANCITO-0123456789abcdef"
EXPECTED_STEPS = ("OWNER_CONTROL", "PEER_CONTROL", "CROSS_PRINCIPAL_TEST")


def _receipt(epistemic_level: str = "CONFIRMED_BY_INDUCTION") -> dict[str, object]:
    return {
        "experiment_id": "BOLA-PURPLE-001",
        "epistemic_level": epistemic_level,
        "reason_code": "PEER_OBSERVED_OWNER_CANARY",
        "blue_objective": {
            "exercise_marker": MARKER,
            "expected_steps": list(EXPECTED_STEPS),
            "expected_event_count": 3,
            "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
            "correlation_marker_is_detection": False,
        },
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def test_complete_behavior_alert_is_detected_with_traceable_artifact():
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS,
        alert_status="FIRED",
        alert_reference="SIEM-ALERT-8821",
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_bola_detection(_receipt(), observation)

    assert result["detection_outcome"] == "DETECTED"
    assert result["visibility_outcome"] == "VISIBLE"
    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["alert_reference"] == "SIEM-ALERT-8821"
    assert result["offensive_epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["changes_offensive_result"] is False
    assert result["part_of_forensic_verdict"] is False


def test_marker_only_alert_does_not_claim_behavior_coverage():
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS,
        alert_status="FIRED",
        alert_reference="SIEM-ALERT-MARKER",
        alert_depends_on_exercise_marker=True,
    )

    result = evaluate_bola_detection(_receipt(), observation)

    assert result["detection_outcome"] == "MARKER_ONLY"
    assert result["reason_code"] == "ALERT_DEPENDS_ON_EXERCISE_MARKER"
    assert result["coverage_claim"] == "NOT_EARNED"


def test_complete_telemetry_without_alert_is_logged_not_alerted():
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS,
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_bola_detection(_receipt(), observation)

    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
    assert result["reason_code"] == "TELEMETRY_PRESENT_ALERT_ABSENT"
    assert "subject" in result["detection_requirement"].lower()
    assert "object" in result["detection_requirement"].lower()


def test_complete_collection_distinguishes_invisible_from_partial_gap():
    invisible = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=(),
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )
    partial = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=("OWNER_CONTROL",),
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    assert evaluate_bola_detection(_receipt(), invisible)[
        "detection_outcome"
    ] == "INVISIBLE"
    partial_result = evaluate_bola_detection(_receipt(), partial)
    assert partial_result["detection_outcome"] == "TELEMETRY_GAP"
    assert partial_result["missing_steps"] == [
        "PEER_CONTROL",
        "CROSS_PRINCIPAL_TEST",
    ]


def test_incomplete_collection_is_inconclusive_not_a_visibility_gap():
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="PARTIAL",
        observed_steps=(),
        alert_status="NOT_CHECKED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_bola_detection(_receipt(), observation)

    assert result["detection_outcome"] == "INCONCLUSIVE"
    assert result["visibility_outcome"] == "INCONCLUSIVE"
    assert result["reason_code"] == "COLLECTION_NOT_COMPLETE"


def test_real_alert_artifact_remains_detected_when_log_review_is_partial():
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="PARTIAL",
        observed_steps=("CROSS_PRINCIPAL_TEST",),
        alert_status="FIRED",
        alert_reference="SIEM-ALERT-8822",
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_bola_detection(_receipt(), observation)

    assert result["detection_outcome"] == "DETECTED"
    assert result["visibility_outcome"] == "INCONCLUSIVE"
    assert result["alert_reference"] == "SIEM-ALERT-8822"


def test_prevention_and_detection_are_independent_axes():
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS,
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_bola_detection(_receipt("FALSIFIED"), observation)

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_alert_contract_rejects_inconsistent_artifacts():
    with pytest.raises(BlueObservationError, match="alert_reference"):
        BlueObservation(
            exercise_marker=MARKER,
            collection_status="COMPLETE",
            observed_steps=EXPECTED_STEPS,
            alert_status="FIRED",
            alert_reference=None,
            alert_depends_on_exercise_marker=False,
        )
    with pytest.raises(BlueObservationError, match="must be absent"):
        BlueObservation(
            exercise_marker=MARKER,
            collection_status="COMPLETE",
            observed_steps=EXPECTED_STEPS,
            alert_status="NOT_FIRED",
            alert_reference="SHOULD-NOT-EXIST",
            alert_depends_on_exercise_marker=False,
        )


def test_wrong_marker_or_unexpected_step_is_rejected():
    wrong_marker = BlueObservation(
        exercise_marker="PANCITO-fedcba9876543210",
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS,
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )
    extra_step = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS + ("UNDECLARED_STEP",),
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    with pytest.raises(BlueObservationError, match="marker"):
        evaluate_bola_detection(_receipt(), wrong_marker)
    with pytest.raises(BlueObservationError, match="unexpected steps"):
        evaluate_bola_detection(_receipt(), extra_step)


def test_receipt_cannot_expand_the_declared_three_step_exercise():
    receipt = _receipt()
    receipt["blue_objective"]["expected_steps"].append("UNDECLARED_STEP")
    receipt["blue_objective"]["expected_event_count"] = 4
    observation = BlueObservation(
        exercise_marker=MARKER,
        collection_status="COMPLETE",
        observed_steps=EXPECTED_STEPS,
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    with pytest.raises(BlueObservationError, match="does not match"):
        evaluate_bola_detection(receipt, observation)


def _authn_receipt(epistemic_level: str) -> dict[str, object]:
    return {
        "experiment_id": "AUTHN-PURPLE-001",
        "epistemic_level": epistemic_level,
        "blue_objective": authn_blue_objective("AUTHN-PURPLE-001"),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def test_authn_blue_evaluation_keeps_prevention_and_detection_independent():
    receipt = _authn_receipt("FALSIFIED")
    objective = receipt["blue_objective"]
    observation = BlueObservation(
        exercise_marker=objective["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=tuple(objective["expected_steps"]),
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_authn_detection(receipt, observation)

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["visibility_outcome"] == "VISIBLE"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
    assert "authentication outcome" in result["detection_requirement"]


def test_authn_behavior_alert_earns_detection_for_failed_prevention():
    receipt = _authn_receipt("CONFIRMED_BY_INDUCTION")
    objective = receipt["blue_objective"]
    observation = BlueObservation(
        exercise_marker=objective["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=tuple(objective["expected_steps"]),
        alert_status="FIRED",
        alert_reference="SIEM-AUTHN-4001",
        alert_depends_on_exercise_marker=False,
    )

    result = evaluate_authn_detection(receipt, observation)

    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["detection_outcome"] == "DETECTED"
    assert result["coverage_claim"] == "EARNED_FOR_THIS_EXERCISE"
