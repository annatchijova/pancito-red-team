"""Blue-observation contract for the marked BOLA purple-team exercise."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass


_MARKER_RE = re.compile(r"^PANCITO-[0-9a-f]{16}$")
_STEP_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_COLLECTION_STATUSES = frozenset({"COMPLETE", "PARTIAL", "UNKNOWN"})
_ALERT_STATUSES = frozenset({"FIRED", "NOT_FIRED", "NOT_CHECKED"})
_BOLA_STEPS = ("OWNER_CONTROL", "PEER_CONTROL", "CROSS_PRINCIPAL_TEST")
_DETECTION_REQUIREMENT = (
    "Alert on an allowed object read where the authenticated subject is not "
    "authorized for the resolved object owner or tenant. Required data: subject, "
    "object identifier, owner or tenant, authorization decision, route, and status."
)


class BlueObservationError(ValueError):
    """Blue evidence is internally inconsistent or outside the exercise contract."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BlueObservationError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise BlueObservationError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise BlueObservationError(f"{name} contains control characters")
    return value


def exercise_marker(experiment_id: str) -> str:
    """Create a public correlation marker; this is deliberately not a secret."""
    identifier = _text(experiment_id, "experiment_id", 128)
    digest = hashlib.sha256(
        f"pancito-purple-v1\x00{identifier}".encode("utf-8")
    ).hexdigest()[:16]
    return f"PANCITO-{digest}"


def bola_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare expected telemetry as a hypothesis, not an observed control."""
    return {
        "technique": "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        "attack_mapping": "UNMAPPED_API_WEAKNESS",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(_BOLA_STEPS),
        "expected_event_count": len(_BOLA_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "application access log with authenticated subject, route, and status",
            "authorization decision log with subject, object, owner or tenant, and decision",
        ],
        "true_positive_step": "CROSS_PRINCIPAL_TEST",
        "benign_twin_step": "PEER_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _DETECTION_REQUIREMENT,
    }


@dataclass(frozen=True)
class BlueObservation:
    """Operator-supplied evidence about Blue telemetry and alerting."""

    exercise_marker: str
    collection_status: str
    observed_steps: tuple[str, ...]
    alert_status: str
    alert_reference: str | None
    alert_depends_on_exercise_marker: bool

    def __post_init__(self) -> None:
        if not isinstance(self.exercise_marker, str) or not _MARKER_RE.fullmatch(
            self.exercise_marker
        ):
            raise BlueObservationError("exercise marker is invalid")
        if self.collection_status not in _COLLECTION_STATUSES:
            raise BlueObservationError("collection_status is invalid")
        if not isinstance(self.observed_steps, tuple):
            raise BlueObservationError("observed_steps must be a tuple")
        if any(
            not isinstance(step, str) or not _STEP_RE.fullmatch(step)
            for step in self.observed_steps
        ):
            raise BlueObservationError("observed_steps contains an invalid step")
        if len(set(self.observed_steps)) != len(self.observed_steps):
            raise BlueObservationError("observed_steps must not contain duplicates")
        if self.alert_status not in _ALERT_STATUSES:
            raise BlueObservationError("alert_status is invalid")
        if not isinstance(self.alert_depends_on_exercise_marker, bool):
            raise BlueObservationError(
                "alert_depends_on_exercise_marker must be boolean"
            )
        if self.alert_status == "FIRED":
            _text(self.alert_reference, "alert_reference", 512)
        elif self.alert_reference is not None:
            raise BlueObservationError(
                "alert_reference must be absent unless alert_status is FIRED"
            )


def _receipt_contract(receipt: dict[str, object]) -> tuple[str, tuple[str, ...]]:
    if not isinstance(receipt, dict):
        raise BlueObservationError("BOLA receipt must be an object")
    if receipt.get("model_used") is not False:
        raise BlueObservationError("BOLA receipt model status is inconsistent")
    if receipt.get("part_of_forensic_verdict") is not False:
        raise BlueObservationError("BOLA receipt verdict status is inconsistent")
    objective = receipt.get("blue_objective")
    if not isinstance(objective, dict):
        raise BlueObservationError("BOLA receipt has no Blue objective")
    marker = objective.get("exercise_marker")
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise BlueObservationError("BOLA receipt exercise marker is invalid")
    raw_steps = objective.get("expected_steps")
    if not isinstance(raw_steps, list) or any(
        not isinstance(step, str) or not _STEP_RE.fullmatch(step)
        for step in raw_steps
    ):
        raise BlueObservationError("BOLA receipt expected steps are invalid")
    steps = tuple(raw_steps)
    if len(set(steps)) != len(steps):
        raise BlueObservationError("BOLA receipt expected steps contain duplicates")
    if steps != _BOLA_STEPS:
        raise BlueObservationError(
            "BOLA receipt expected steps does not match the declared exercise"
        )
    if objective.get("expected_event_count") != len(steps):
        raise BlueObservationError("BOLA receipt event count is inconsistent")
    if objective.get("correlation_marker_is_detection") is not False:
        raise BlueObservationError("BOLA receipt overclaims its correlation marker")
    if receipt.get("epistemic_level") not in {
        "CONFIRMED_BY_INDUCTION",
        "FALSIFIED",
        "INCONCLUSIVE",
    }:
        raise BlueObservationError("BOLA receipt epistemic level is invalid")
    return marker, steps


def _preventive_outcome(epistemic_level: object) -> str:
    if epistemic_level == "FALSIFIED":
        return "PREVENTED"
    if epistemic_level == "CONFIRMED_BY_INDUCTION":
        return "FAILED_TO_PREVENT"
    return "UNRESOLVED"


def evaluate_bola_detection(
    bola_receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Compare expected and observed Blue evidence without changing Red evidence."""
    if not isinstance(observation, BlueObservation):
        raise TypeError("observation must be a BlueObservation")
    marker, expected_steps = _receipt_contract(bola_receipt)
    if observation.exercise_marker != marker:
        raise BlueObservationError("observation marker does not match BOLA receipt")
    unexpected = sorted(set(observation.observed_steps) - set(expected_steps))
    if unexpected:
        raise BlueObservationError(
            "observation contains unexpected steps: " + ", ".join(unexpected)
        )
    observed = set(observation.observed_steps)
    missing = [step for step in expected_steps if step not in observed]

    if observation.collection_status != "COMPLETE":
        visibility_outcome = "INCONCLUSIVE"
    elif len(missing) == len(expected_steps):
        visibility_outcome = "INVISIBLE"
    elif missing:
        visibility_outcome = "TELEMETRY_GAP"
    else:
        visibility_outcome = "VISIBLE"

    if (
        observation.alert_status == "FIRED"
        and not observation.alert_depends_on_exercise_marker
    ):
        detection_outcome = "DETECTED"
        reason_code = "BEHAVIOR_ALERT_ARTIFACT_OBSERVED"
    elif observation.alert_status == "FIRED":
        detection_outcome = "MARKER_ONLY"
        reason_code = "ALERT_DEPENDS_ON_EXERCISE_MARKER"
    elif visibility_outcome == "INCONCLUSIVE":
        detection_outcome = "INCONCLUSIVE"
        reason_code = "COLLECTION_NOT_COMPLETE"
    elif observation.alert_status == "NOT_CHECKED":
        detection_outcome = "INCONCLUSIVE"
        reason_code = "ALERT_STATUS_NOT_CHECKED"
    elif visibility_outcome == "VISIBLE":
        detection_outcome = "LOGGED_NOT_ALERTED"
        reason_code = "TELEMETRY_PRESENT_ALERT_ABSENT"
    elif visibility_outcome == "INVISIBLE":
        detection_outcome = "INVISIBLE"
        reason_code = "EXPECTED_TELEMETRY_ABSENT"
    elif visibility_outcome == "TELEMETRY_GAP":
        detection_outcome = "TELEMETRY_GAP"
        reason_code = "EXPECTED_TELEMETRY_PARTIAL"
    else:
        raise AssertionError("unhandled Blue observation state")

    return {
        "exercise_marker": marker,
        "offensive_epistemic_level": bola_receipt.get("epistemic_level"),
        "preventive_outcome": _preventive_outcome(
            bola_receipt.get("epistemic_level")
        ),
        "visibility_outcome": visibility_outcome,
        "detection_outcome": detection_outcome,
        "reason_code": reason_code,
        "collection_status": observation.collection_status,
        "observed_steps": [
            step for step in expected_steps if step in observed
        ],
        "missing_steps": missing,
        "alert_status": observation.alert_status,
        "alert_reference": observation.alert_reference,
        "alert_depends_on_exercise_marker": (
            observation.alert_depends_on_exercise_marker
        ),
        "coverage_claim": (
            "EARNED_FOR_THIS_EXERCISE"
            if detection_outcome == "DETECTED"
            else "NOT_EARNED"
        ),
        "detection_requirement": _DETECTION_REQUIREMENT,
        "observation_integrity": "UNSEALED_OPERATOR_ASSERTION",
        "changes_offensive_result": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }
