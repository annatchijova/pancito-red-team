"""Purple evaluation accepts complete and honestly degraded authority transitions."""

from __future__ import annotations

import pytest

from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_stale_authority_detection,
    stale_authority_blue_objective,
)


STEPS = (
    "INITIAL_MEMBERSHIP_READ",
    "ACTOR_PRE_REVOKE_CONTROL",
    "ADMIN_REVOKE",
    "ADMIN_REVOKE_VERIFY",
    "STALE_CREDENTIAL_TEST",
    "ADMIN_RESTORE",
    "ADMIN_RESTORE_VERIFY",
)


def _receipt(level="FALSIFIED"):
    experiment_id = "STALE-PURPLE-001"
    return {
        "experiment_id": experiment_id,
        "capability": "http-stale-authority-differential",
        "epistemic_level": level,
        "reason_code": (
            "STALE_CREDENTIAL_ACCESS_CONFIRMED"
            if level == "CONFIRMED_BY_INDUCTION"
            else "REVOKED_CREDENTIAL_ACCESS_DENIED"
        ),
        "revoke_verified": True,
        "stale_access_observed": level == "CONFIRMED_BY_INDUCTION",
        "cleanup_status": "RESTORED_TO_BASELINE",
        "final_state_verified": True,
        "request_count": 7,
        "maximum_request_count": 7,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "observations": [{"step": step} for step in STEPS],
        "blue_objective": stale_authority_blue_objective(experiment_id, STEPS),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def _blue(receipt):
    return BlueObservation(
        exercise_marker=receipt["blue_objective"]["exercise_marker"],
        collection_status="COMPLETE",
        observed_steps=STEPS,
        alert_status="NOT_FIRED",
        alert_reference=None,
        alert_depends_on_exercise_marker=False,
    )


def test_denial_is_prevention_but_not_automatically_detection():
    receipt = _receipt()
    result = evaluate_stale_authority_detection(receipt, _blue(receipt))
    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_confirmation_requires_verified_restoration():
    receipt = _receipt("CONFIRMED_BY_INDUCTION")
    receipt["cleanup_status"] = "MANUAL_ACTION_REQUIRED"
    receipt["final_state_verified"] = False
    with pytest.raises(BlueObservationError, match="confirmed result"):
        evaluate_stale_authority_detection(receipt, _blue(_receipt()))
