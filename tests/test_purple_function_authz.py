"""BFLA prevention and detection are evaluated independently."""

from offensive.purple import (
    BlueObservation, evaluate_function_authz_detection, function_authz_blue_objective,
)

STEPS = ("ADMIN_FUNCTION_CONTROL", "MEMBER_FUNCTION_CONTROL", "MEMBER_ADMIN_FUNCTION_TEST")


def test_denial_is_prevention_without_claiming_alerting():
    experiment_id = "BFLA-PURPLE-001"
    receipt = {
        "experiment_id": experiment_id, "capability": "http-function-authorization-differential",
        "epistemic_level": "FALSIFIED", "reason_code": "MEMBER_ADMIN_FUNCTION_DENIED",
        "controls": {"admin_control_passed": True, "member_control_passed": True},
        "request_count": 3, "maximum_request_count": 3, "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": function_authz_blue_objective(experiment_id),
        "model_used": False, "part_of_forensic_verdict": False,
    }
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_function_authz_detection(receipt, observation)
    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_failed_control_remains_evaluable_as_inconclusive_blue_visibility():
    experiment_id = "BFLA-PURPLE-002"
    receipt = {
        "experiment_id": experiment_id,
        "capability": "http-function-authorization-differential",
        "epistemic_level": "INCONCLUSIVE",
        "reason_code": "MEMBER_CONTROL_FAILED",
        "controls": {
            "admin_control_passed": True,
            "member_control_passed": False,
        },
        "request_count": 3,
        "maximum_request_count": 3,
        "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": function_authz_blue_objective(experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"],
        "COMPLETE",
        STEPS,
        "NOT_FIRED",
        None,
        False,
    )

    result = evaluate_function_authz_detection(receipt, observation)

    assert result["preventive_outcome"] == "UNRESOLVED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
