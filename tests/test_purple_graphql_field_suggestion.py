"""GRAPHQL_FIELD_SUGGESTION prevention and detection are evaluated independently."""

from offensive.purple import (
    BlueObservation, evaluate_graphql_field_suggestion_detection,
    graphql_field_suggestion_blue_objective,
)

STEPS = ("BASELINE_TYPENAME_QUERY_CONTROL", "TYPO_FIELD_SUGGESTION_TEST")


def _receipt(experiment_id, *, epistemic_level, reason_code, baseline_control_passed):
    return {
        "experiment_id": experiment_id,
        "capability": "http-graphql-field-suggestion-leakage-differential",
        "epistemic_level": epistemic_level, "reason_code": reason_code,
        "controls": {"baseline_control_passed": baseline_control_passed},
        "request_count": 2, "maximum_request_count": 2, "method": "POST",
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": graphql_field_suggestion_blue_objective(experiment_id),
        "model_used": False, "part_of_forensic_verdict": False,
    }


def test_confirmed_leak_is_failed_to_prevent_without_claiming_alerting():
    experiment_id = "GQLSUGGEST-PURPLE-001"
    receipt = _receipt(experiment_id, epistemic_level="CONFIRMED_BY_INDUCTION",
                        reason_code="FIELD_SUGGESTION_DISCLOSED_SCHEMA_NAME",
                        baseline_control_passed=True)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_graphql_field_suggestion_detection(receipt, observation)
    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_falsified_suppression_is_prevented():
    experiment_id = "GQLSUGGEST-PURPLE-002"
    receipt = _receipt(experiment_id, epistemic_level="FALSIFIED",
                        reason_code="FIELD_SUGGESTION_SUPPRESSED",
                        baseline_control_passed=True)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_graphql_field_suggestion_detection(receipt, observation)
    assert result["preventive_outcome"] == "PREVENTED"


def test_inconclusive_baseline_failure_is_unresolved():
    experiment_id = "GQLSUGGEST-PURPLE-003"
    receipt = _receipt(experiment_id, epistemic_level="INCONCLUSIVE",
                        reason_code="BASELINE_NOT_A_GRAPHQL_ENDPOINT",
                        baseline_control_passed=False)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    result = evaluate_graphql_field_suggestion_detection(receipt, observation)
    assert result["preventive_outcome"] == "UNRESOLVED"


def test_confirmed_result_requires_a_passed_baseline_control():
    experiment_id = "GQLSUGGEST-PURPLE-004"
    receipt = _receipt(experiment_id, epistemic_level="CONFIRMED_BY_INDUCTION",
                        reason_code="FIELD_SUGGESTION_DISCLOSED_SCHEMA_NAME",
                        baseline_control_passed=False)
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False,
    )
    try:
        evaluate_graphql_field_suggestion_detection(receipt, observation)
        assert False, "inconsistent confirmed receipt must be rejected"
    except Exception as exc:
        assert "inconsistent" in str(exc)
