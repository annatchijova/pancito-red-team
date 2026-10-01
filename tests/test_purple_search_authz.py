"""Search prevention and Blue detection remain independent conclusions."""

from offensive.purple import (
    BlueObservation,
    evaluate_search_authz_detection,
    search_authz_blue_objective,
)


STEPS = (
    "ALPHA_SEARCH_CONTROL",
    "BRAVO_SEARCH_CONTROL",
    "CROSS_TENANT_SEARCH_TEST",
)


def _receipt(level, reason, controls):
    experiment_id = "SEARCH-PURPLE-001"
    return {
        "experiment_id": experiment_id,
        "capability": "http-search-authorization-differential",
        "epistemic_level": level,
        "reason_code": reason,
        "controls": controls,
        "request_count": 3,
        "maximum_request_count": 3,
        "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": search_authz_blue_objective(experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def _observation(receipt):
    return BlueObservation(
        receipt["blue_objective"]["exercise_marker"],
        "COMPLETE",
        STEPS,
        "NOT_FIRED",
        None,
        False,
    )


def test_denial_is_prevention_without_claiming_alerting():
    receipt = _receipt(
        "FALSIFIED",
        "ALPHA_BRAVO_SEARCH_DENIED",
        {"alpha_control_passed": True, "bravo_control_passed": True},
    )

    result = evaluate_search_authz_detection(receipt, _observation(receipt))

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_failed_control_remains_unresolved_and_blue_visibility_is_evaluated():
    receipt = _receipt(
        "INCONCLUSIVE",
        "BRAVO_CONTROL_FAILED",
        {"alpha_control_passed": True, "bravo_control_passed": False},
    )

    result = evaluate_search_authz_detection(receipt, _observation(receipt))

    assert result["preventive_outcome"] == "UNRESOLVED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
