"""FORWARDED_REDIRECT prevention and detection are evaluated independently."""

from offensive.purple import (
    BlueObservation, evaluate_forwarded_redirect_detection, forwarded_redirect_blue_objective,
)

STEPS = ("BASELINE_REDIRECT_CONTROL", "FORWARDED_HEADER_REDIRECT_TEST")


def _receipt(experiment_id, *, epistemic_level, reason_code, baseline_control_passed):
    return {
        "experiment_id": experiment_id,
        "capability": "http-forwarded-redirect-authority-differential",
        "epistemic_level": epistemic_level, "reason_code": reason_code,
        "controls": {"baseline_control_passed": baseline_control_passed},
        "request_count": 2, "maximum_request_count": 2, "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": forwarded_redirect_blue_objective(experiment_id),
        "model_used": False, "part_of_forensic_verdict": False,
    }


def test_confirmed_leak_is_failed_to_prevent_without_claiming_alerting():
    experiment_id = "FWDREDIR-PURPLE-001"
    receipt = _receipt(experiment_id, epistemic_level="CONFIRMED_BY_INDUCTION",
                        reason_code="FORWARDED_HEADER_BECAME_REDIRECT_AUTHORITY",
                        baseline_control_passed=True)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_forwarded_redirect_detection(receipt, observation)
    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_falsified_rejection_is_prevented():
    experiment_id = "FWDREDIR-PURPLE-002"
    receipt = _receipt(experiment_id, epistemic_level="FALSIFIED",
                        reason_code="FORWARDED_HEADER_REJECTED_OR_IGNORED",
                        baseline_control_passed=True)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_forwarded_redirect_detection(receipt, observation)
    assert result["preventive_outcome"] == "PREVENTED"


def test_inconclusive_baseline_failure_is_unresolved():
    experiment_id = "FWDREDIR-PURPLE-003"
    receipt = _receipt(experiment_id, epistemic_level="INCONCLUSIVE",
                        reason_code="BASELINE_ALREADY_EXTERNAL",
                        baseline_control_passed=False)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_forwarded_redirect_detection(receipt, observation)
    assert result["preventive_outcome"] == "UNRESOLVED"


def test_confirmed_result_requires_a_passed_baseline_control():
    experiment_id = "FWDREDIR-PURPLE-004"
    receipt = _receipt(experiment_id, epistemic_level="CONFIRMED_BY_INDUCTION",
                        reason_code="FORWARDED_HEADER_BECAME_REDIRECT_AUTHORITY",
                        baseline_control_passed=False)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    try:
        evaluate_forwarded_redirect_detection(receipt, observation)
        assert False, "inconsistent confirmed receipt must be rejected"
    except Exception as exc:
        assert "inconsistent" in str(exc)
