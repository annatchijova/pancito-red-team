"""Collection prevention and Blue detection remain separate conclusions."""

from offensive.purple import (
    BlueObservation,
    collection_authz_blue_objective,
    evaluate_collection_authz_detection,
)


STEPS = (
    "ALPHA_COLLECTION_CONTROL",
    "BRAVO_COLLECTION_CONTROL",
    "CROSS_TENANT_LIST_TEST",
)


def _receipt(level, reason, controls):
    experiment_id = "COLLECTION-PURPLE-001"
    return {
        "experiment_id": experiment_id,
        "capability": "http-collection-authorization-differential",
        "epistemic_level": level,
        "reason_code": reason,
        "controls": controls,
        "request_count": 3,
        "maximum_request_count": 3,
        "method": "GET",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": collection_authz_blue_objective(experiment_id),
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
        "ALPHA_BRAVO_COLLECTION_DENIED",
        {"alpha_control_passed": True, "bravo_control_passed": True},
    )

    result = evaluate_collection_authz_detection(receipt, _observation(receipt))

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_failed_control_remains_evaluable_as_unresolved_blue_visibility():
    receipt = _receipt(
        "INCONCLUSIVE",
        "BRAVO_CONTROL_FAILED",
        {"alpha_control_passed": True, "bravo_control_passed": False},
    )

    result = evaluate_collection_authz_detection(receipt, _observation(receipt))

    assert result["preventive_outcome"] == "UNRESOLVED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"
