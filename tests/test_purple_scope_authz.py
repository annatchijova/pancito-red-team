"""SCOPE prevention and detection are evaluated independently."""

from offensive.purple import (
    BlueObservation, evaluate_scope_authz_detection, scope_authz_blue_objective,
)

STEPS = ("BROAD_SCOPE_CONTROL", "NARROW_SCOPE_CONTROL", "NARROW_PRIVILEGED_SCOPE_TEST")


def test_denial_is_prevention_without_claiming_alerting():
    experiment_id = "SCOPE-PURPLE-001"
    receipt = {
        "experiment_id": experiment_id, "capability": "http-token-scope-authorization-differential",
        "epistemic_level": "FALSIFIED", "reason_code": "NARROW_PRIVILEGED_SCOPE_DENIED",
        "controls": {"broad_control_passed": True, "narrow_control_passed": True},
        "request_count": 3, "maximum_request_count": 3, "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": scope_authz_blue_objective(experiment_id),
        "model_used": False, "part_of_forensic_verdict": False,
    }
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_scope_authz_detection(receipt, observation)
    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_failed_control_remains_evaluable_as_inconclusive_blue_visibility():
    experiment_id = "SCOPE-PURPLE-002"
    receipt = {
        "experiment_id": experiment_id,
        "capability": "http-token-scope-authorization-differential",
        "epistemic_level": "INCONCLUSIVE",
        "reason_code": "NARROW_CONTROL_FAILED",
        "controls": {
            "broad_control_passed": True,
            "narrow_control_passed": False,
        },
        "request_count": 3,
        "maximum_request_count": 3,
        "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": scope_authz_blue_objective(experiment_id),
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

    result = evaluate_scope_authz_detection(receipt, observation)

    assert result["preventive_outcome"] == "UNRESOLVED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
