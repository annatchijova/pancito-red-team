"""Blue-observation contracts for marked offensive validation exercises."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass


_MARKER_RE = re.compile(r"^PANCITO-[0-9a-f]{16}$")
_EXPERIMENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_STEP_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_COLLECTION_STATUSES = frozenset({"COMPLETE", "PARTIAL", "UNKNOWN"})
_ALERT_STATUSES = frozenset({"FIRED", "NOT_FIRED", "NOT_CHECKED"})
_BOLA_STEPS = ("OWNER_CONTROL", "PEER_CONTROL", "CROSS_PRINCIPAL_TEST")
_NESTED_BOLA_STEPS = (
    "OWNER_NESTED_CONTROL",
    "PEER_NESTED_CONTROL",
    "CROSS_CHILD_TEST",
)
_FUNCTION_AUTHZ_STEPS = (
    "ADMIN_FUNCTION_CONTROL",
    "MEMBER_FUNCTION_CONTROL",
    "MEMBER_ADMIN_FUNCTION_TEST",
)
_COLLECTION_AUTHZ_STEPS = (
    "ALPHA_COLLECTION_CONTROL",
    "BRAVO_COLLECTION_CONTROL",
    "CROSS_TENANT_LIST_TEST",
)
_SCOPE_AUTHZ_STEPS = (
    "BROAD_SCOPE_CONTROL",
    "NARROW_SCOPE_CONTROL",
    "NARROW_PRIVILEGED_SCOPE_TEST",
)
_SEARCH_AUTHZ_STEPS = (
    "ALPHA_SEARCH_CONTROL",
    "BRAVO_SEARCH_CONTROL",
    "CROSS_TENANT_SEARCH_TEST",
)
_EXPORT_AUTHZ_STEPS = (
    "ALPHA_EXPORT_CONTROL",
    "BRAVO_EXPORT_CONTROL",
    "CROSS_TENANT_EXPORT_TEST",
)
_ASYNC_EXPORT_AUTHZ_STEPS = (
    "ALPHA_JOB_CREATE",
    "BRAVO_JOB_CREATE",
    "ALPHA_JOB_STATUS_CONTROL",
    "ALPHA_JOB_DOWNLOAD_CONTROL",
    "BRAVO_JOB_STATUS_CONTROL",
    "BRAVO_JOB_DOWNLOAD_CONTROL",
    "CROSS_TENANT_JOB_DOWNLOAD_TEST",
    "BRAVO_JOB_POST_TEST_DOWNLOAD_CONTROL",
    "ALPHA_JOB_CLEANUP",
    "ALPHA_JOB_CLEANUP_VERIFY",
    "BRAVO_JOB_CLEANUP",
    "BRAVO_JOB_CLEANUP_VERIFY",
)
_AUTHN_STEPS = (
    "VALID_CREDENTIAL_CONTROL",
    "ANONYMOUS_TEST",
    "INVALID_BEARER_TEST",
)
_STATE_CHANGE_STEPS = (
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
_STATE_CHANGE_ALL_STEPS = (
    "BASELINE_READ",
    "VALID_CREDENTIAL_CONTROL",
    "VALID_CONTROL_READBACK",
    "CONTROL_RESTORE",
    "CONTROL_RESTORE_VERIFY",
    "ANONYMOUS_TEST",
    "ANONYMOUS_READBACK",
    "ANONYMOUS_RESTORE",
    "ANONYMOUS_RESTORE_VERIFY",
    "INVALID_BEARER_TEST",
    "INVALID_BEARER_READBACK",
    "INVALID_BEARER_RESTORE",
    "INVALID_BEARER_RESTORE_VERIFY",
)
_FILE_INGRESS_ALL_STEPS = tuple(
    f"{cell}_{suffix}"
    for cell in ("CONTROL", "TYPE_MISMATCH", "OVERSIZE")
    for suffix in ("UPLOAD", "READBACK", "CLEANUP", "CLEANUP_VERIFY")
)
_MASS_ASSIGNMENT_ALL_STEPS = (
    "BASELINE_READ",
    "ALLOWED_FIELD_CONTROL",
    "ALLOWED_CONTROL_READBACK",
    "CONTROL_RESTORE",
    "CONTROL_RESTORE_VERIFY",
    "PROTECTED_FIELD_TEST",
    "PROTECTED_TEST_READBACK",
    "NEGATIVE_RESTORE",
    "NEGATIVE_RESTORE_VERIFY",
)
_STALE_AUTHORITY_ALL_STEPS = (
    "INITIAL_MEMBERSHIP_READ",
    "ACTOR_PRE_REVOKE_CONTROL",
    "ADMIN_REVOKE",
    "ADMIN_REVOKE_VERIFY",
    "STALE_CREDENTIAL_TEST",
    "ADMIN_RESTORE",
    "ADMIN_RESTORE_VERIFY",
)
_STALE_AUTHORITY_ALLOWED_SEQUENCES = frozenset(
    {
        _STALE_AUTHORITY_ALL_STEPS[:1],
        _STALE_AUTHORITY_ALL_STEPS[:2],
        _STALE_AUTHORITY_ALL_STEPS[:4],
        _STALE_AUTHORITY_ALL_STEPS[:4] + _STALE_AUTHORITY_ALL_STEPS[-2:],
        _STALE_AUTHORITY_ALL_STEPS,
    }
)
_BOLA_DETECTION_REQUIREMENT = (
    "Alert on an allowed object read where the authenticated subject is not "
    "authorized for the resolved object owner or tenant. Required data: subject, "
    "object identifier, owner or tenant, authorization decision, route, and status."
)
_NESTED_BOLA_DETECTION_REQUIREMENT = (
    "Alert on an allowed child read whose resolved parent differs from the parent "
    "authorized in the route. Required data: subject, route parent, child identifier, "
    "resolved child parent, authorization decision, and status."
)
_FUNCTION_AUTHZ_DETECTION_REQUIREMENT = (
    "Alert when a non-administrative principal is granted an administrative function. "
    "Required data: subject, effective role, route, required role, decision, and status."
)
_COLLECTION_AUTHZ_DETECTION_REQUIREMENT = (
    "Alert when a principal is granted a collection belonging to another tenant. "
    "Required data: subject tenant, requested tenant, route, authorization decision, "
    "and status."
)
_SCOPE_AUTHZ_DETECTION_REQUIREMENT = (
    "Alert when a token is granted an action outside its effective scope. Required "
    "data: token identifier, effective scopes, route, required scope, decision, and status."
)
_SEARCH_AUTHZ_DETECTION_REQUIREMENT = (
    "Alert when search returns a result outside the authenticated tenant. Required "
    "data: subject tenant, search scope, result tenant, query route, decision, and status."
)
_EXPORT_AUTHZ_DETECTION_REQUIREMENT = (
    "Alert when an export contains records outside the authenticated tenant. "
    "Required data: subject tenant, export job or route, resolved data scope, "
    "authorization decision, and exported record ownership."
)
_ASYNC_EXPORT_AUTHZ_DETECTION_REQUIREMENT = (
    "Alert when a principal reads or downloads an asynchronous export job outside "
    "its tenant. Required data: subject tenant, job owner, job state, download route, "
    "authorization decision, and exported record ownership."
)
_AUTHN_DETECTION_REQUIREMENT = (
    "Alert when a protected route returns protected data after the authentication "
    "decision is anonymous or invalid. Required data: route, authentication outcome, "
    "principal if any, authorization decision, and status."
)
_STATE_CHANGE_DETECTION_REQUIREMENT = (
    "Alert on a successful state mutation by an anonymous or invalid identity. "
    "Required data: authentication outcome, principal if any, route, method, "
    "authorization decision, changed field, response status, and read-back audit."
)
_FILE_INGRESS_DETECTION_REQUIREMENT = (
    "Alert when stored upload bytes contradict the declared media type or exceed "
    "the authorized size policy. Required data: principal, route, filename, declared "
    "type, observed digest and size, validation decision, storage result, and status."
)
_MASS_ASSIGNMENT_DETECTION_REQUIREMENT = (
    "Alert when a low-privilege principal changes a protected property. Required "
    "data: subject, route, resource owner, submitted fields, authorized fields, "
    "authorization decision, changed-field audit, and status."
)
_STALE_AUTHORITY_DETECTION_REQUIREMENT = (
    "Alert when a credential accesses a protected resource after its principal's "
    "role or membership was revoked. Required data: principal, credential/session "
    "identifier, authority version, revocation event, route, decision, and status."
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
        "detection_requirement": _BOLA_DETECTION_REQUIREMENT,
    }


def nested_bola_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue telemetry for one nested-resource authorization differential."""
    return {
        "technique": "NESTED_RESOURCE_AUTHORIZATION",
        "attack_mapping": "OWASP_API1_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(_NESTED_BOLA_STEPS),
        "expected_event_count": len(_NESTED_BOLA_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "access log with subject, parent id, child id, route, and status",
            "authorization log binding the child owner or parent to the route parent",
        ],
        "true_positive_step": "CROSS_CHILD_TEST",
        "benign_twin_step": "OWNER_NESTED_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _NESTED_BOLA_DETECTION_REQUIREMENT,
    }


def function_authz_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue evidence for one function-level authorization differential."""
    return {
        "technique": "BROKEN_FUNCTION_LEVEL_AUTHORIZATION",
        "attack_mapping": "OWASP_API5_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise", "step_header": "X-Pancito-Step",
        "expected_steps": list(_FUNCTION_AUTHZ_STEPS),
        "expected_event_count": len(_FUNCTION_AUTHZ_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "access log with subject, effective role, route, and status",
            "authorization decision with required role and grant or denial",
        ],
        "true_positive_step": "MEMBER_ADMIN_FUNCTION_TEST",
        "benign_twin_step": "ADMIN_FUNCTION_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _FUNCTION_AUTHZ_DETECTION_REQUIREMENT,
    }


def collection_authz_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue evidence for one cross-tenant collection differential."""
    return {
        "technique": "CROSS_TENANT_COLLECTION_ACCESS",
        "attack_mapping": "OWASP_API1_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": None,
        "step_identification": "REQUEST_ORDER_SUBJECT_AND_PATH",
        "expected_steps": list(_COLLECTION_AUTHZ_STEPS),
        "expected_event_count": len(_COLLECTION_AUTHZ_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "access log with subject tenant, requested tenant, route, and status",
            "authorization decision with tenant binding and grant or denial",
        ],
        "true_positive_step": "CROSS_TENANT_LIST_TEST",
        "benign_twin_step": "BRAVO_COLLECTION_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _COLLECTION_AUTHZ_DETECTION_REQUIREMENT,
    }


def scope_authz_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue evidence for one token-scope enforcement differential."""
    return {
        "technique": "TOKEN_SCOPE_ENFORCEMENT",
        "attack_mapping": "OWASP_API2_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": None,
        "step_identification": "REQUEST_ORDER_TOKEN_AND_PATH",
        "expected_steps": list(_SCOPE_AUTHZ_STEPS),
        "expected_event_count": len(_SCOPE_AUTHZ_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "access log with token id, effective scopes, route, and status",
            "authorization decision with required scope and grant or denial",
        ],
        "true_positive_step": "NARROW_PRIVILEGED_SCOPE_TEST",
        "benign_twin_step": "BROAD_SCOPE_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _SCOPE_AUTHZ_DETECTION_REQUIREMENT,
    }


def search_authz_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue evidence for one cross-tenant search-result differential."""
    return {
        "technique": "CROSS_TENANT_SEARCH_RESULT_ACCESS",
        "attack_mapping": "OWASP_API1_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": None,
        "step_identification": "REQUEST_ORDER_SUBJECT_AND_QUERY_SCOPE",
        "expected_steps": list(_SEARCH_AUTHZ_STEPS),
        "expected_event_count": len(_SEARCH_AUTHZ_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "search access log with subject tenant, query scope, and status",
            "result authorization decision with the result tenant binding",
        ],
        "true_positive_step": "CROSS_TENANT_SEARCH_TEST",
        "benign_twin_step": "BRAVO_SEARCH_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _SEARCH_AUTHZ_DETECTION_REQUIREMENT,
    }


def export_authz_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue evidence for one cross-tenant export differential."""
    return {
        "technique": "CROSS_TENANT_EXPORT_ACCESS",
        "attack_mapping": "OWASP_API1_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": None,
        "step_identification": "REQUEST_ORDER_SUBJECT_AND_EXPORT_PATH",
        "expected_steps": list(_EXPORT_AUTHZ_STEPS),
        "expected_event_count": len(_EXPORT_AUTHZ_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "export access log with subject tenant, export route, and status",
            "authorization decision binding the exported records to their tenant",
        ],
        "true_positive_step": "CROSS_TENANT_EXPORT_TEST",
        "benign_twin_step": "BRAVO_EXPORT_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _EXPORT_AUTHZ_DETECTION_REQUIREMENT,
    }


def async_export_authz_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare Blue telemetry for asynchronous export creation and retrieval."""
    return {
        "technique": "CROSS_TENANT_ASYNC_EXPORT_JOB_ACCESS",
        "attack_mapping": "OWASP_API1_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": None,
        "step_identification": "REQUEST_ORDER_SUBJECT_ROUTE_AND_JOB_ID_DIGEST",
        "expected_steps": list(_ASYNC_EXPORT_AUTHZ_STEPS),
        "expected_event_count": len(_ASYNC_EXPORT_AUTHZ_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "export-job access log with authenticated subject, tenant, job, state, and status",
            "download authorization decision bound to the job owner and exported records",
            "post-test owner download control to distinguish denial from job expiry",
            "cleanup and read-back audit for both disposable lab jobs",
        ],
        "true_positive_step": "CROSS_TENANT_JOB_DOWNLOAD_TEST",
        "benign_twin_step": "BRAVO_JOB_DOWNLOAD_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _ASYNC_EXPORT_AUTHZ_DETECTION_REQUIREMENT,
    }


def authn_blue_objective(experiment_id: str) -> dict[str, object]:
    """Declare the Blue hypothesis for an authentication enforcement exercise."""
    return {
        "technique": "AUTHENTICATION_ENFORCEMENT_BYPASS",
        "attack_mapping": "UNMAPPED_API_WEAKNESS",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(_AUTHN_STEPS),
        "expected_event_count": len(_AUTHN_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "application access log with authentication outcome, route, and status",
            "authentication decision log distinguishing absent and invalid credentials",
        ],
        "true_positive_steps": ["ANONYMOUS_TEST", "INVALID_BEARER_TEST"],
        "benign_twin_step": "VALID_CREDENTIAL_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _AUTHN_DETECTION_REQUIREMENT,
    }


def state_change_blue_objective(
    experiment_id: str, executed_steps: tuple[str, ...] | None = None
) -> dict[str, object]:
    """Declare telemetry needed to distinguish mutation from an HTTP response."""
    steps = _STATE_CHANGE_STEPS if executed_steps is None else executed_steps
    if not isinstance(steps, tuple) or not steps:
        raise BlueObservationError("state-change executed_steps must be a non-empty tuple")
    if len(set(steps)) != len(steps) or any(
        step not in _STATE_CHANGE_ALL_STEPS for step in steps
    ):
        raise BlueObservationError("state-change executed_steps are invalid")
    return {
        "technique": "PUBLIC_STATE_CHANGE",
        "attack_mapping": "UNMAPPED_API_WEAKNESS",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(steps),
        "conditional_steps": [
            "ANONYMOUS_RESTORE",
            "ANONYMOUS_RESTORE_VERIFY",
            "INVALID_BEARER_RESTORE",
            "INVALID_BEARER_RESTORE_VERIFY",
        ],
        "expected_event_count": len(steps),
        "maximum_event_count": 13,
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "access log with identity outcome, route, method, and status",
            "authorization decision log for PATCH",
            "application audit record identifying the changed field and actor",
        ],
        "true_positive_steps": ["ANONYMOUS_TEST", "INVALID_BEARER_TEST"],
        "benign_twin_step": "VALID_CREDENTIAL_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _STATE_CHANGE_DETECTION_REQUIREMENT,
    }


def file_ingress_blue_objective(
    experiment_id: str, executed_steps: tuple[str, ...]
) -> dict[str, object]:
    """Declare Blue evidence for exactly the synthetic upload steps executed."""
    if not isinstance(executed_steps, tuple) or not executed_steps:
        raise BlueObservationError("file-ingress executed_steps must be non-empty")
    if len(set(executed_steps)) != len(executed_steps) or any(
        step not in _FILE_INGRESS_ALL_STEPS for step in executed_steps
    ):
        raise BlueObservationError("file-ingress executed_steps are invalid")
    selected = set(executed_steps)
    if executed_steps != tuple(
        step for step in _FILE_INGRESS_ALL_STEPS if step in selected
    ):
        raise BlueObservationError("file-ingress executed_steps are out of order")
    return {
        "technique": "FILE_INGRESS_VALIDATION",
        "attack_mapping": "UNMAPPED_API_WEAKNESS",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(executed_steps),
        "expected_event_count": len(executed_steps),
        "maximum_event_count": len(_FILE_INGRESS_ALL_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "upload access log with principal, filename, declared media type, and status",
            "validation decision with observed size and type evidence",
            "storage audit with digest plus deletion and absence verification",
        ],
        "true_positive_steps": ["TYPE_MISMATCH_UPLOAD", "OVERSIZE_UPLOAD"],
        "benign_twin_step": "CONTROL_UPLOAD",
        "correlation_marker_is_detection": False,
        "detection_requirement": _FILE_INGRESS_DETECTION_REQUIREMENT,
    }


def mass_assignment_blue_objective(
    experiment_id: str, executed_steps: tuple[str, ...]
) -> dict[str, object]:
    """Declare Blue evidence for one property-authorization differential."""
    if not isinstance(executed_steps, tuple) or not executed_steps:
        raise BlueObservationError("mass-assignment executed_steps must be non-empty")
    selected = set(executed_steps)
    if len(selected) != len(executed_steps) or executed_steps != tuple(
        step for step in _MASS_ASSIGNMENT_ALL_STEPS if step in selected
    ):
        raise BlueObservationError("mass-assignment executed_steps are invalid")
    return {
        "technique": "BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
        "attack_mapping": "OWASP_API3_2023",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(executed_steps),
        "expected_event_count": len(executed_steps),
        "maximum_event_count": len(_MASS_ASSIGNMENT_ALL_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "access log with subject, route, submitted fields, and status",
            "field-level authorization decision with the allowed property set",
            "application audit record identifying actor and changed properties",
        ],
        "true_positive_step": "PROTECTED_FIELD_TEST",
        "benign_twin_step": "ALLOWED_FIELD_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _MASS_ASSIGNMENT_DETECTION_REQUIREMENT,
    }


def stale_authority_blue_objective(
    experiment_id: str, executed_steps: tuple[str, ...]
) -> dict[str, object]:
    """Declare Blue evidence for the exact authority transition executed."""
    if not isinstance(executed_steps, tuple) or not executed_steps:
        raise BlueObservationError("stale-authority executed_steps must be non-empty")
    if executed_steps not in _STALE_AUTHORITY_ALLOWED_SEQUENCES:
        raise BlueObservationError("stale-authority executed_steps are invalid")
    return {
        "technique": "STALE_AUTHORITY_AFTER_REVOCATION",
        "attack_mapping": "UNMAPPED_AUTHORIZATION_TRANSITION",
        "exercise_marker": exercise_marker(experiment_id),
        "marker_header": "X-Pancito-Exercise",
        "step_header": "X-Pancito-Step",
        "expected_steps": list(executed_steps),
        "expected_event_count": len(executed_steps),
        "maximum_event_count": len(_STALE_AUTHORITY_ALL_STEPS),
        "expected_telemetry_status": "HYPOTHESIS_NOT_YET_OBSERVED",
        "expected_telemetry": [
            "membership audit with actor, old role, new role, and authority version",
            "resource access log with credential/session id and current authority version",
            "authorization decision showing revocation-aware denial or stale grant",
        ],
        "true_positive_step": "STALE_CREDENTIAL_TEST",
        "benign_twin_step": "ACTOR_PRE_REVOKE_CONTROL",
        "correlation_marker_is_detection": False,
        "detection_requirement": _STALE_AUTHORITY_DETECTION_REQUIREMENT,
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


def _receipt_contract(
    receipt: dict[str, object],
    *,
    receipt_name: str,
    capability: str,
    technique: str,
    declared_steps: tuple[str, ...],
) -> tuple[str, tuple[str, ...]]:
    if not isinstance(receipt, dict):
        raise BlueObservationError(f"{receipt_name} receipt must be an object")
    if receipt.get("model_used") is not False:
        raise BlueObservationError(f"{receipt_name} receipt model status is inconsistent")
    if receipt.get("part_of_forensic_verdict") is not False:
        raise BlueObservationError(
            f"{receipt_name} receipt verdict status is inconsistent"
        )
    experiment_id = _text(receipt.get("experiment_id"), "experiment_id", 128)
    if not _EXPERIMENT_ID_RE.fullmatch(experiment_id):
        raise BlueObservationError("experiment_id is invalid")
    observed_capability = receipt.get("capability")
    if observed_capability is not None and observed_capability != capability:
        raise BlueObservationError(
            f"{receipt_name} receipt capability is inconsistent"
        )
    objective = receipt.get("blue_objective")
    if not isinstance(objective, dict):
        raise BlueObservationError(f"{receipt_name} receipt has no Blue objective")
    observed_technique = objective.get("technique")
    if observed_technique is not None and observed_technique != technique:
        raise BlueObservationError(f"{receipt_name} receipt technique is inconsistent")
    marker = objective.get("exercise_marker")
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise BlueObservationError(f"{receipt_name} receipt exercise marker is invalid")
    if marker != exercise_marker(experiment_id):
        raise BlueObservationError(
            f"{receipt_name} receipt marker does not match experiment_id"
        )
    raw_steps = objective.get("expected_steps")
    if not isinstance(raw_steps, list) or any(
        not isinstance(step, str) or not _STEP_RE.fullmatch(step)
        for step in raw_steps
    ):
        raise BlueObservationError(f"{receipt_name} receipt expected steps are invalid")
    steps = tuple(raw_steps)
    if len(set(steps)) != len(steps):
        raise BlueObservationError(
            f"{receipt_name} receipt expected steps contain duplicates"
        )
    if steps != declared_steps:
        raise BlueObservationError(
            f"{receipt_name} receipt expected steps does not match the declared exercise"
        )
    if objective.get("expected_event_count") != len(steps):
        raise BlueObservationError(f"{receipt_name} receipt event count is inconsistent")
    if objective.get("correlation_marker_is_detection") is not False:
        raise BlueObservationError(
            f"{receipt_name} receipt overclaims its correlation marker"
        )
    if receipt.get("epistemic_level") not in {
        "CONFIRMED_BY_INDUCTION",
        "FALSIFIED",
        "INCONCLUSIVE",
    }:
        raise BlueObservationError(f"{receipt_name} receipt epistemic level is invalid")
    return marker, steps


def _preventive_outcome(epistemic_level: object) -> str:
    if epistemic_level == "FALSIFIED":
        return "PREVENTED"
    if epistemic_level == "CONFIRMED_BY_INDUCTION":
        return "FAILED_TO_PREVENT"
    return "UNRESOLVED"


def _evaluate_detection(
    receipt: dict[str, object],
    observation: BlueObservation,
    *,
    receipt_name: str,
    capability: str,
    technique: str,
    declared_steps: tuple[str, ...],
    detection_requirement: str,
) -> dict[str, object]:
    if not isinstance(observation, BlueObservation):
        raise TypeError("observation must be a BlueObservation")
    marker, expected_steps = _receipt_contract(
        receipt,
        receipt_name=receipt_name,
        capability=capability,
        technique=technique,
        declared_steps=declared_steps,
    )
    if observation.exercise_marker != marker:
        raise BlueObservationError(
            f"observation marker does not match {receipt_name} receipt"
        )
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
        "offensive_epistemic_level": receipt.get("epistemic_level"),
        "preventive_outcome": _preventive_outcome(
            receipt.get("epistemic_level")
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
        "detection_requirement": detection_requirement,
        "observation_integrity": "UNSEALED_OPERATOR_ASSERTION",
        "changes_offensive_result": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def evaluate_bola_detection(
    bola_receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Compare BOLA telemetry and alert evidence without changing Red evidence."""
    return _evaluate_detection(
        bola_receipt,
        observation,
        receipt_name="BOLA",
        capability="http-bola-differential",
        technique="BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        declared_steps=_BOLA_STEPS,
        detection_requirement=_BOLA_DETECTION_REQUIREMENT,
    )


def evaluate_nested_bola_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the exact child-only substitution exercise."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("NESTED_BOLA receipt must be an object")
    if receipt.get("request_count") != 3 or receipt.get("maximum_request_count") != 3:
        raise BlueObservationError("nested-BOLA request budget is inconsistent")
    if receipt.get("method") != "GET":
        raise BlueObservationError("nested-BOLA method is inconsistent")
    if receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("nested-BOLA receipt overclaims impact")
    controls = receipt.get("controls")
    if (
        not isinstance(controls, dict)
        or set(controls) != {"owner_control_passed", "peer_control_passed"}
        or any(not isinstance(value, bool) for value in controls.values())
    ):
        raise BlueObservationError("nested-BOLA controls are inconsistent")
    level = receipt.get("epistemic_level")
    reason = receipt.get("reason_code")
    if level == "CONFIRMED_BY_INDUCTION":
        if reason != "FOREIGN_CHILD_CANARY_OBSERVED" or not all(controls.values()):
            raise BlueObservationError("nested-BOLA confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if reason != "CROSS_PARENT_CHILD_ACCESS_DENIED" or not all(controls.values()):
            raise BlueObservationError("nested-BOLA falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if reason not in {
            "OWNER_CONTROL_FAILED",
            "PEER_CONTROL_FAILED",
            "TEST_REQUEST_FAILED",
            "TEST_RESPONSE_TRUNCATED",
            "TEST_REDIRECTED",
            "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError("nested-BOLA inconclusive result is inconsistent")
    else:
        raise BlueObservationError("nested-BOLA epistemic level is invalid")
    return _evaluate_detection(
        receipt,
        observation,
        receipt_name="NESTED_BOLA",
        capability="http-nested-bola-differential",
        technique="NESTED_RESOURCE_AUTHORIZATION",
        declared_steps=_NESTED_BOLA_STEPS,
        detection_requirement=_NESTED_BOLA_DETECTION_REQUIREMENT,
    )


def evaluate_function_authz_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the exact member-to-admin function replay."""
    if receipt.get("request_count") != 3 or receipt.get("maximum_request_count") != 3:
        raise BlueObservationError("BFLA request budget is inconsistent")
    if receipt.get("method") != "GET" or receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("BFLA receipt contract is inconsistent")
    controls = receipt.get("controls")
    if (
        not isinstance(controls, dict)
        or set(controls) != {"admin_control_passed", "member_control_passed"}
        or any(not isinstance(value, bool) for value in controls.values())
    ):
        raise BlueObservationError("BFLA controls are inconsistent")
    level, reason = receipt.get("epistemic_level"), receipt.get("reason_code")
    controls_passed = controls == {
        "admin_control_passed": True,
        "member_control_passed": True,
    }
    if level == "CONFIRMED_BY_INDUCTION":
        if not controls_passed or reason != "MEMBER_OBSERVED_ADMIN_CANARY":
            raise BlueObservationError("BFLA confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if not controls_passed or reason != "MEMBER_ADMIN_FUNCTION_DENIED":
            raise BlueObservationError("BFLA falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if reason not in {
            "ADMIN_CONTROL_FAILED",
            "MEMBER_CONTROL_FAILED",
            "TEST_REQUEST_FAILED",
            "TEST_RESPONSE_TRUNCATED",
            "TEST_REDIRECTED",
            "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError("BFLA inconclusive result is inconsistent")
    else:
        raise BlueObservationError("BFLA epistemic level is invalid")
    return _evaluate_detection(
        receipt, observation, receipt_name="BFLA",
        capability="http-function-authorization-differential",
        technique="BROKEN_FUNCTION_LEVEL_AUTHORIZATION",
        declared_steps=_FUNCTION_AUTHZ_STEPS,
        detection_requirement=_FUNCTION_AUTHZ_DETECTION_REQUIREMENT)


def evaluate_collection_authz_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the exact cross-tenant collection replay."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("COLLECTION_AUTHZ receipt must be an object")
    if receipt.get("request_count") != 3 or receipt.get("maximum_request_count") != 3:
        raise BlueObservationError("collection authorization request budget is inconsistent")
    if (
        receipt.get("method") != "GET"
        or receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT"
    ):
        raise BlueObservationError("collection authorization contract is inconsistent")
    controls = receipt.get("controls")
    if (
        not isinstance(controls, dict)
        or set(controls) != {"alpha_control_passed", "bravo_control_passed"}
        or any(not isinstance(value, bool) for value in controls.values())
    ):
        raise BlueObservationError("collection authorization controls are inconsistent")
    controls_passed = controls == {
        "alpha_control_passed": True,
        "bravo_control_passed": True,
    }
    level = receipt.get("epistemic_level")
    reason = receipt.get("reason_code")
    if level == "CONFIRMED_BY_INDUCTION":
        if (
            not controls_passed
            or reason != "ALPHA_OBSERVED_BRAVO_COLLECTION_CANARY"
        ):
            raise BlueObservationError(
                "collection authorization confirmed result is inconsistent"
            )
    elif level == "FALSIFIED":
        if not controls_passed or reason != "ALPHA_BRAVO_COLLECTION_DENIED":
            raise BlueObservationError(
                "collection authorization falsified result is inconsistent"
            )
    elif level == "INCONCLUSIVE":
        if reason not in {
            "ALPHA_CONTROL_FAILED",
            "BRAVO_CONTROL_FAILED",
            "TEST_REQUEST_FAILED",
            "TEST_RESPONSE_TRUNCATED",
            "TEST_REDIRECTED",
            "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError(
                "collection authorization inconclusive result is inconsistent"
            )
    else:
        raise BlueObservationError(
            "collection authorization epistemic level is invalid"
        )
    return _evaluate_detection(
        receipt,
        observation,
        receipt_name="COLLECTION_AUTHZ",
        capability="http-collection-authorization-differential",
        technique="CROSS_TENANT_COLLECTION_ACCESS",
        declared_steps=_COLLECTION_AUTHZ_STEPS,
        detection_requirement=_COLLECTION_AUTHZ_DETECTION_REQUIREMENT,
    )


def evaluate_scope_authz_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the narrow-token privileged-resource replay."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("SCOPE_AUTHZ receipt must be an object")
    if receipt.get("request_count") != 3 or receipt.get("maximum_request_count") != 3:
        raise BlueObservationError("scope authorization request budget is inconsistent")
    if receipt.get("method") != "GET" or receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("scope authorization contract is inconsistent")
    controls = receipt.get("controls")
    if (
        not isinstance(controls, dict)
        or set(controls) != {"broad_control_passed", "narrow_control_passed"}
        or any(not isinstance(value, bool) for value in controls.values())
    ):
        raise BlueObservationError("scope authorization controls are inconsistent")
    controls_passed = controls == {
        "broad_control_passed": True,
        "narrow_control_passed": True,
    }
    level, reason = receipt.get("epistemic_level"), receipt.get("reason_code")
    if level == "CONFIRMED_BY_INDUCTION":
        if not controls_passed or reason != "NARROW_OBSERVED_PRIVILEGED_CANARY":
            raise BlueObservationError("scope authorization confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if not controls_passed or reason != "NARROW_PRIVILEGED_SCOPE_DENIED":
            raise BlueObservationError("scope authorization falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if reason not in {
            "BROAD_CONTROL_FAILED", "NARROW_CONTROL_FAILED", "TEST_REQUEST_FAILED",
            "TEST_RESPONSE_TRUNCATED", "TEST_REDIRECTED", "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError("scope authorization inconclusive result is inconsistent")
    else:
        raise BlueObservationError("scope authorization epistemic level is invalid")
    return _evaluate_detection(
        receipt, observation, receipt_name="SCOPE_AUTHZ",
        capability="http-token-scope-authorization-differential",
        technique="TOKEN_SCOPE_ENFORCEMENT", declared_steps=_SCOPE_AUTHZ_STEPS,
        detection_requirement=_SCOPE_AUTHZ_DETECTION_REQUIREMENT,
    )


def evaluate_search_authz_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the cross-tenant search-result replay."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("SEARCH_AUTHZ receipt must be an object")
    if receipt.get("request_count") != 3 or receipt.get("maximum_request_count") != 3:
        raise BlueObservationError("search authorization request budget is inconsistent")
    if receipt.get("method") != "GET" or receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("search authorization contract is inconsistent")
    controls = receipt.get("controls")
    if (
        not isinstance(controls, dict)
        or set(controls) != {"alpha_control_passed", "bravo_control_passed"}
        or any(not isinstance(value, bool) for value in controls.values())
    ):
        raise BlueObservationError("search authorization controls are inconsistent")
    controls_passed = controls == {
        "alpha_control_passed": True,
        "bravo_control_passed": True,
    }
    level, reason = receipt.get("epistemic_level"), receipt.get("reason_code")
    if level == "CONFIRMED_BY_INDUCTION":
        if not controls_passed or reason != "ALPHA_OBSERVED_BRAVO_SEARCH_CANARY":
            raise BlueObservationError("search authorization confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if not controls_passed or reason != "ALPHA_BRAVO_SEARCH_DENIED":
            raise BlueObservationError("search authorization falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if reason not in {
            "ALPHA_CONTROL_FAILED", "BRAVO_CONTROL_FAILED", "TEST_REQUEST_FAILED",
            "TEST_RESPONSE_TRUNCATED", "TEST_REDIRECTED", "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError("search authorization inconclusive result is inconsistent")
    else:
        raise BlueObservationError("search authorization epistemic level is invalid")
    return _evaluate_detection(
        receipt, observation, receipt_name="SEARCH_AUTHZ",
        capability="http-search-authorization-differential",
        technique="CROSS_TENANT_SEARCH_RESULT_ACCESS",
        declared_steps=_SEARCH_AUTHZ_STEPS,
        detection_requirement=_SEARCH_AUTHZ_DETECTION_REQUIREMENT,
    )


def evaluate_export_authz_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the cross-tenant export replay."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("EXPORT_AUTHZ receipt must be an object")
    if receipt.get("request_count") != 3 or receipt.get("maximum_request_count") != 3:
        raise BlueObservationError("export authorization request budget is inconsistent")
    if receipt.get("method") != "GET" or receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("export authorization contract is inconsistent")
    controls = receipt.get("controls")
    if (
        not isinstance(controls, dict)
        or set(controls) != {"alpha_control_passed", "bravo_control_passed"}
        or any(not isinstance(value, bool) for value in controls.values())
    ):
        raise BlueObservationError("export authorization controls are inconsistent")
    passed = controls == {"alpha_control_passed": True, "bravo_control_passed": True}
    level, reason = receipt.get("epistemic_level"), receipt.get("reason_code")
    if level == "CONFIRMED_BY_INDUCTION":
        if not passed or reason != "ALPHA_OBSERVED_BRAVO_EXPORT_CANARY":
            raise BlueObservationError("export authorization confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if not passed or reason != "ALPHA_BRAVO_EXPORT_DENIED":
            raise BlueObservationError("export authorization falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if reason not in {
            "ALPHA_CONTROL_FAILED", "BRAVO_CONTROL_FAILED", "TEST_REQUEST_FAILED",
            "TEST_RESPONSE_TRUNCATED", "TEST_REDIRECTED", "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError("export authorization inconclusive result is inconsistent")
    else:
        raise BlueObservationError("export authorization epistemic level is invalid")
    return _evaluate_detection(
        receipt, observation, receipt_name="EXPORT_AUTHZ",
        capability="http-export-authorization-differential",
        technique="CROSS_TENANT_EXPORT_ACCESS", declared_steps=_EXPORT_AUTHZ_STEPS,
        detection_requirement=_EXPORT_AUTHZ_DETECTION_REQUIREMENT,
    )


def evaluate_async_export_authz_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Validate the lifecycle receipt before evaluating its Blue telemetry."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("ASYNC_EXPORT_AUTHZ receipt must be an object")
    events = receipt.get("events")
    count = receipt.get("request_count")
    if (
        not isinstance(events, list) or len(events) != count
        or isinstance(count, bool) or not isinstance(count, int)
        or not 0 <= count <= 12 or receipt.get("maximum_request_count") != 12
    ):
        raise BlueObservationError("async export request budget is inconsistent")
    expected_methods = {
        "ALPHA_JOB_CREATE": "POST", "BRAVO_JOB_CREATE": "POST",
        "ALPHA_JOB_STATUS_CONTROL": "GET", "ALPHA_JOB_DOWNLOAD_CONTROL": "GET",
        "BRAVO_JOB_STATUS_CONTROL": "GET", "BRAVO_JOB_DOWNLOAD_CONTROL": "GET",
        "CROSS_TENANT_JOB_DOWNLOAD_TEST": "GET",
        "BRAVO_JOB_POST_TEST_DOWNLOAD_CONTROL": "GET", "ALPHA_JOB_CLEANUP": "DELETE",
        "ALPHA_JOB_CLEANUP_VERIFY": "GET", "BRAVO_JOB_CLEANUP": "DELETE",
        "BRAVO_JOB_CLEANUP_VERIFY": "GET",
    }
    order = {step: index for index, step in enumerate(_ASYNC_EXPORT_AUTHZ_STEPS)}
    previous = -1
    event_by_step: dict[str, dict[str, object]] = {}
    for event in events:
        if not isinstance(event, dict) or set(event) != {
            "step", "method", "status", "request_succeeded", "truncated",
            "oracle_satisfied", "canary_observed", "other_tenant_canary_observed",
            "job_id_sha256", "response_capture_sha256",
        }:
            raise BlueObservationError("async export event shape is inconsistent")
        step = event.get("step")
        if step not in expected_methods or step in event_by_step:
            raise BlueObservationError("async export event step is invalid or duplicated")
        if order[step] <= previous or event.get("method") != expected_methods[step]:
            raise BlueObservationError("async export event order or method is inconsistent")
        if not isinstance(event.get("request_succeeded"), bool) or not isinstance(
            event.get("truncated"), bool
        ):
            raise BlueObservationError("async export event observation flags are invalid")
        status = event.get("status")
        if status is not None and (
            isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
        ):
            raise BlueObservationError("async export event status is invalid")
        if event["request_succeeded"] != (status is not None):
            raise BlueObservationError("async export request status is inconsistent")
        if event.get("oracle_satisfied") is not None and not isinstance(
            event.get("oracle_satisfied"), bool
        ):
            raise BlueObservationError("async export event oracle is invalid")
        for field in ("canary_observed", "other_tenant_canary_observed"):
            if event.get(field) is not None and not isinstance(event.get(field), bool):
                raise BlueObservationError("async export canary observation is invalid")
        is_download = step in {
            "ALPHA_JOB_DOWNLOAD_CONTROL", "BRAVO_JOB_DOWNLOAD_CONTROL",
            "CROSS_TENANT_JOB_DOWNLOAD_TEST",
            "BRAVO_JOB_POST_TEST_DOWNLOAD_CONTROL",
        }
        canary_flags_are_boolean = all(
            isinstance(event.get(field), bool)
            for field in ("canary_observed", "other_tenant_canary_observed")
        )
        canary_flags_are_absent = all(
            event.get(field) is None
            for field in ("canary_observed", "other_tenant_canary_observed")
        )
        if (is_download and not canary_flags_are_boolean) or (
            not is_download and not canary_flags_are_absent
        ):
            raise BlueObservationError("async export canary fields contradict event type")
        if is_download and event.get("oracle_satisfied") != event.get("canary_observed"):
            raise BlueObservationError("async export oracle contradicts canary observation")
        if event.get("oracle_satisfied") is True and (
            not event["request_succeeded"] or event["truncated"]
        ):
            raise BlueObservationError("async export oracle contradicts request integrity")
        digest = event.get("job_id_sha256")
        if digest is not None and (
            not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise BlueObservationError("async export job identifier digest is invalid")
        response_digest = event.get("response_capture_sha256")
        if not isinstance(response_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", response_digest):
            raise BlueObservationError("async export response capture digest is invalid")
        event_by_step[step] = event
        previous = order[step]
    if receipt.get("method") is not None and receipt.get("method") != "MIXED":
        raise BlueObservationError("async export method declaration is inconsistent")
    if receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("async export impact contract is inconsistent")
    cleanup_status = receipt.get("cleanup_status")
    cleanup_count = receipt.get("manual_cleanup_count")
    if (
        cleanup_status not in {"RESTORED_TO_BASELINE", "MANUAL_ACTION_REQUIRED"}
        or isinstance(cleanup_count, bool) or not isinstance(cleanup_count, int)
        or cleanup_count < 0
        or (cleanup_status == "RESTORED_TO_BASELINE") != (cleanup_count == 0)
    ):
        raise BlueObservationError("async export cleanup status is inconsistent")
    if cleanup_status == "RESTORED_TO_BASELINE" and any(
        step not in event_by_step or event_by_step[step].get("oracle_satisfied") is not True
        for step in ("ALPHA_JOB_CLEANUP_VERIFY", "BRAVO_JOB_CLEANUP_VERIFY")
    ):
        raise BlueObservationError("async export cleanup claim lacks both verified deletions")
    level, reason = receipt.get("epistemic_level"), receipt.get("reason_code")
    if level in {"CONFIRMED_BY_INDUCTION", "FALSIFIED"}:
        required = (
            "ALPHA_JOB_CREATE", "BRAVO_JOB_CREATE", "ALPHA_JOB_STATUS_CONTROL",
            "ALPHA_JOB_DOWNLOAD_CONTROL", "BRAVO_JOB_STATUS_CONTROL",
            "BRAVO_JOB_DOWNLOAD_CONTROL", "CROSS_TENANT_JOB_DOWNLOAD_TEST",
        )
        if any(step not in event_by_step for step in required):
            raise BlueObservationError("async export decisive result lacks controls")
        if any(event_by_step[step].get("oracle_satisfied") is not True for step in required[:-1]):
            raise BlueObservationError("async export decisive result has failed controls")
        test = event_by_step[required[-1]]
        if not test.get("request_succeeded") or test.get("truncated"):
            raise BlueObservationError("async export test request is not fully observed")
        if level == "CONFIRMED_BY_INDUCTION":
            if reason != "ALPHA_OBSERVED_BRAVO_ASYNC_EXPORT_CANARY" or test.get(
                "oracle_satisfied"
            ) is not True:
                raise BlueObservationError("async export confirmed result is inconsistent")
        elif reason != "ALPHA_BRAVO_ASYNC_EXPORT_DENIED" or test.get("status") not in {401, 403, 404}:
            raise BlueObservationError("async export falsified result is inconsistent")
        elif (
            "BRAVO_JOB_POST_TEST_DOWNLOAD_CONTROL" not in event_by_step
            or event_by_step["BRAVO_JOB_POST_TEST_DOWNLOAD_CONTROL"].get("oracle_satisfied") is not True
        ):
            raise BlueObservationError("async export denial lacks a successful post-test control")
    elif level == "INCONCLUSIVE":
        if reason not in {
            "ALPHA_JOB_CREATE_FAILED", "BRAVO_JOB_CREATE_FAILED",
            "ALPHA_JOB_CONTROL_FAILED", "ALPHA_DOWNLOAD_CONTROL_FAILED",
            "BRAVO_JOB_CONTROL_FAILED", "BRAVO_DOWNLOAD_CONTROL_FAILED",
            "BRAVO_POST_TEST_CONTROL_FAILED",
            "TEST_REQUEST_FAILED", "TEST_RESPONSE_TRUNCATED",
            "TEST_ORACLE_NOT_SATISFIED",
        }:
            raise BlueObservationError("async export inconclusive result is inconsistent")
    else:
        raise BlueObservationError("async export epistemic level is invalid")
    return _evaluate_detection(
        receipt, observation, receipt_name="ASYNC_EXPORT_AUTHZ",
        capability="http-async-export-authorization-lifecycle",
        technique="CROSS_TENANT_ASYNC_EXPORT_JOB_ACCESS",
        declared_steps=_ASYNC_EXPORT_AUTHZ_STEPS,
        detection_requirement=_ASYNC_EXPORT_AUTHZ_DETECTION_REQUIREMENT,
    )


def evaluate_authn_detection(
    authn_receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Compare authn telemetry and alert evidence without changing Red evidence."""
    return _evaluate_detection(
        authn_receipt,
        observation,
        receipt_name="AUTHN",
        capability="http-authentication-enforcement-differential",
        technique="AUTHENTICATION_ENFORCEMENT_BYPASS",
        declared_steps=_AUTHN_STEPS,
        detection_requirement=_AUTHN_DETECTION_REQUIREMENT,
    )


def _state_change_receipt_steps(receipt: dict[str, object]) -> tuple[str, ...]:
    observations = receipt.get("observations")
    if not isinstance(observations, list) or not observations:
        raise BlueObservationError(
            "state-change receipt observations must be a non-empty array"
        )
    raw_steps = [
        item.get("step") if isinstance(item, dict) else None
        for item in observations
    ]
    if any(not isinstance(step, str) for step in raw_steps):
        raise BlueObservationError("state-change receipt observation step is invalid")
    steps = tuple(raw_steps)
    if len(steps) > len(_STATE_CHANGE_ALL_STEPS) or len(set(steps)) != len(steps):
        raise BlueObservationError("state-change receipt steps are invalid")
    observed = set(steps)
    canonical = tuple(step for step in _STATE_CHANGE_ALL_STEPS if step in observed)
    if steps != canonical or steps[0] != "BASELINE_READ":
        raise BlueObservationError("state-change receipt step order is invalid")
    if len(steps) > 1 and steps[:5] != _STATE_CHANGE_ALL_STEPS[:5]:
        raise BlueObservationError("state-change receipt control sequence is incomplete")
    if "INVALID_BEARER_TEST" in observed and not {
        "ANONYMOUS_TEST",
        "ANONYMOUS_READBACK",
    }.issubset(observed):
        raise BlueObservationError(
            "state-change receipt skipped the anonymous differential"
        )
    request_count = receipt.get("request_count")
    if isinstance(request_count, bool) or request_count != len(steps):
        raise BlueObservationError("state-change receipt request count is inconsistent")
    if receipt.get("maximum_request_count") != len(_STATE_CHANGE_ALL_STEPS):
        raise BlueObservationError("state-change receipt maximum request count is invalid")
    if receipt.get("method") != "PATCH":
        raise BlueObservationError("state-change receipt method is invalid")
    if receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("state-change receipt overclaims security impact")
    level = receipt.get("epistemic_level")
    confirmed = receipt.get("confirmed_cells")
    outcomes = receipt.get("cell_outcomes")
    cleanup = receipt.get("cleanup_status")
    final_verified = receipt.get("final_state_verified")
    if not isinstance(confirmed, list) or any(
        cell not in {"ANONYMOUS", "INVALID_BEARER"} for cell in confirmed
    ) or len(set(confirmed)) != len(confirmed):
        raise BlueObservationError("state-change confirmed cells are invalid")
    if not isinstance(outcomes, dict) or any(
        cell not in {"ANONYMOUS", "INVALID_BEARER"}
        or outcome not in {
            "MUTATION_CONFIRMED",
            "MUTATION_DENIED",
            "INCONCLUSIVE",
        }
        for cell, outcome in outcomes.items()
    ):
        raise BlueObservationError("state-change cell outcomes are invalid")
    if any(outcomes.get(cell) != "MUTATION_CONFIRMED" for cell in confirmed):
        raise BlueObservationError("state-change confirmed cells are inconsistent")
    if level == "CONFIRMED_BY_INDUCTION":
        if not confirmed or cleanup != "RESTORED_TO_BASELINE" or final_verified is not True:
            raise BlueObservationError("state-change confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if (
            confirmed
            or outcomes != {
                "ANONYMOUS": "MUTATION_DENIED",
                "INVALID_BEARER": "MUTATION_DENIED",
            }
            or cleanup != "RESTORED_TO_BASELINE"
            or final_verified is not True
        ):
            raise BlueObservationError("state-change falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if cleanup == "MANUAL_ACTION_REQUIRED" and final_verified is not False:
            raise BlueObservationError("state-change cleanup state is inconsistent")
    else:
        raise BlueObservationError("state-change epistemic level is invalid")
    return steps


def evaluate_state_change_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for the exact state-change steps that executed."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("STATE_CHANGE receipt must be an object")
    steps = _state_change_receipt_steps(receipt)
    return _evaluate_detection(
        receipt,
        observation,
        receipt_name="STATE_CHANGE",
        capability="http-public-state-change-differential",
        technique="PUBLIC_STATE_CHANGE",
        declared_steps=steps,
        detection_requirement=_STATE_CHANGE_DETECTION_REQUIREMENT,
    )


def _mass_assignment_receipt_steps(receipt: dict[str, object]) -> tuple[str, ...]:
    observations = receipt.get("observations")
    if not isinstance(observations, list) or not observations:
        raise BlueObservationError("mass-assignment receipt observations are invalid")
    raw = [item.get("step") if isinstance(item, dict) else None for item in observations]
    if any(not isinstance(step, str) for step in raw):
        raise BlueObservationError("mass-assignment observation step is invalid")
    steps = tuple(raw)
    if steps not in {
        _MASS_ASSIGNMENT_ALL_STEPS[:1],
        _MASS_ASSIGNMENT_ALL_STEPS[:5],
        _MASS_ASSIGNMENT_ALL_STEPS,
    }:
        raise BlueObservationError("mass-assignment receipt step order is invalid")
    if receipt.get("request_count") != len(steps) or receipt.get(
        "maximum_request_count"
    ) != len(_MASS_ASSIGNMENT_ALL_STEPS):
        raise BlueObservationError("mass-assignment request budget is inconsistent")
    if receipt.get("method") != "PATCH":
        raise BlueObservationError("mass-assignment receipt method is invalid")
    if receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("mass-assignment receipt overclaims impact")
    level = receipt.get("epistemic_level")
    control = receipt.get("control_outcome")
    negative = receipt.get("negative_outcome")
    cleanup = receipt.get("cleanup_status")
    final_verified = receipt.get("final_state_verified")
    if level == "CONFIRMED_BY_INDUCTION":
        if (
            steps != _MASS_ASSIGNMENT_ALL_STEPS
            or control != "ALLOWED_FIELD_MUTATION_CONFIRMED"
            or negative != "PROTECTED_FIELD_MUTATION_CONFIRMED"
            or cleanup != "RESTORED_TO_BASELINE"
            or final_verified is not True
        ):
            raise BlueObservationError("mass-assignment confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if (
            steps != _MASS_ASSIGNMENT_ALL_STEPS
            or control != "ALLOWED_FIELD_MUTATION_CONFIRMED"
            or negative != "PROTECTED_FIELD_UNCHANGED"
            or cleanup != "RESTORED_TO_BASELINE"
            or final_verified is not True
        ):
            raise BlueObservationError("mass-assignment falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if cleanup == "MANUAL_ACTION_REQUIRED" and final_verified is not False:
            raise BlueObservationError("mass-assignment cleanup state is inconsistent")
    else:
        raise BlueObservationError("mass-assignment epistemic level is invalid")
    return steps


def evaluate_mass_assignment_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence without changing the property-authz result."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("MASS_ASSIGNMENT receipt must be an object")
    steps = _mass_assignment_receipt_steps(receipt)
    return _evaluate_detection(
        receipt,
        observation,
        receipt_name="MASS_ASSIGNMENT",
        capability="http-mass-assignment-differential",
        technique="BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
        declared_steps=steps,
        detection_requirement=_MASS_ASSIGNMENT_DETECTION_REQUIREMENT,
    )


def evaluate_stale_authority_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence without changing the revocation result."""
    observations = receipt.get("observations")
    if not isinstance(observations, list) or not observations:
        raise BlueObservationError("stale-authority observations are invalid")
    steps = tuple(item.get("step") if isinstance(item, dict) else None for item in observations)
    if steps not in _STALE_AUTHORITY_ALLOWED_SEQUENCES:
        raise BlueObservationError("stale-authority step order is invalid")
    if receipt.get("request_count") != len(steps) or receipt.get("maximum_request_count") != 7:
        raise BlueObservationError("stale-authority request budget is inconsistent")
    if receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("stale-authority receipt overclaims impact")
    level = receipt.get("epistemic_level")
    restored = receipt.get("cleanup_status") == "RESTORED_TO_BASELINE"
    verified = receipt.get("final_state_verified") is True
    if level == "CONFIRMED_BY_INDUCTION":
        if not (receipt.get("revoke_verified") is True and
                receipt.get("stale_access_observed") is True and restored and verified and
                receipt.get("reason_code") == "STALE_CREDENTIAL_ACCESS_CONFIRMED"):
            raise BlueObservationError("stale-authority confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if not (receipt.get("revoke_verified") is True and
                receipt.get("stale_access_observed") is False and restored and verified and
                receipt.get("reason_code") == "REVOKED_CREDENTIAL_ACCESS_DENIED"):
            raise BlueObservationError("stale-authority falsified result is inconsistent")
    elif level != "INCONCLUSIVE":
        raise BlueObservationError("stale-authority epistemic level is invalid")
    return _evaluate_detection(
        receipt, observation, receipt_name="STALE_AUTHORITY",
        capability="http-stale-authority-differential",
        technique="STALE_AUTHORITY_AFTER_REVOCATION", declared_steps=steps,
        detection_requirement=_STALE_AUTHORITY_DETECTION_REQUIREMENT,
    )


def _file_ingress_receipt_steps(receipt: dict[str, object]) -> tuple[str, ...]:
    observations = receipt.get("observations")
    if not isinstance(observations, list) or not observations:
        raise BlueObservationError("file-ingress receipt observations are invalid")
    raw = [item.get("step") if isinstance(item, dict) else None for item in observations]
    if any(not isinstance(step, str) for step in raw):
        raise BlueObservationError("file-ingress observation step is invalid")
    steps = tuple(raw)
    if len(set(steps)) != len(steps) or len(steps) > len(_FILE_INGRESS_ALL_STEPS):
        raise BlueObservationError("file-ingress receipt steps are invalid")
    selected = set(steps)
    if steps != tuple(step for step in _FILE_INGRESS_ALL_STEPS if step in selected):
        raise BlueObservationError("file-ingress receipt step order is invalid")
    if steps[0] != "CONTROL_UPLOAD":
        raise BlueObservationError("file-ingress receipt skipped its control")
    request_count = receipt.get("request_count")
    if (
        isinstance(request_count, bool)
        or request_count != len(steps)
        or receipt.get("maximum_request_count") != 12
    ):
        raise BlueObservationError("file-ingress request budget is inconsistent")
    if receipt.get("method") != "POST" or receipt.get("impact_assessment") != "REQUIRES_HUMAN_CONTEXT":
        raise BlueObservationError("file-ingress receipt overclaims or changes method")
    confirmed = receipt.get("confirmed_cells")
    outcomes = receipt.get("cell_outcomes")
    if not isinstance(confirmed, list) or any(
        cell not in {"TYPE_MISMATCH", "OVERSIZE"} for cell in confirmed
    ) or len(set(confirmed)) != len(confirmed):
        raise BlueObservationError("file-ingress confirmed cells are invalid")
    if not isinstance(outcomes, dict) or any(
        cell not in {"CONTROL", "TYPE_MISMATCH", "OVERSIZE"}
        or outcome not in {
            "STORED_EXACTLY",
            "REJECTED",
            "CONTROL_FAILED",
            "INCONCLUSIVE",
        }
        for cell, outcome in outcomes.items()
    ):
        raise BlueObservationError("file-ingress cell outcomes are invalid")
    processed_cells = tuple(
        cell
        for cell in ("CONTROL", "TYPE_MISMATCH", "OVERSIZE")
        if f"{cell}_UPLOAD" in selected
    )
    if set(outcomes) != set(processed_cells):
        raise BlueObservationError("file-ingress cell outcomes are incomplete")
    for cell in processed_cells:
        cell_steps = tuple(
            step for step in _FILE_INGRESS_ALL_STEPS if step.startswith(f"{cell}_")
            and step in selected
        )
        if cell_steps not in {
            (f"{cell}_UPLOAD",),
            tuple(
                f"{cell}_{suffix}"
                for suffix in ("UPLOAD", "READBACK", "CLEANUP", "CLEANUP_VERIFY")
            ),
        }:
            raise BlueObservationError(
                "file-ingress cell lifecycle is incomplete"
            )
        if outcomes[cell] == "REJECTED" and cell_steps != (f"{cell}_UPLOAD",):
            raise BlueObservationError("file-ingress rejected cell is inconsistent")
        if outcomes[cell] == "STORED_EXACTLY" and len(cell_steps) != 4:
            raise BlueObservationError("file-ingress stored cell is inconsistent")
    expected_confirmed = [
        cell
        for cell in ("TYPE_MISMATCH", "OVERSIZE")
        if outcomes.get(cell) == "STORED_EXACTLY"
    ]
    if confirmed != expected_confirmed:
        raise BlueObservationError("file-ingress confirmed cells are inconsistent")
    expected_max = receipt.get("expected_max_bytes")
    if (
        isinstance(expected_max, bool)
        or not isinstance(expected_max, int)
        or not 1_024 <= expected_max <= 65_536
    ):
        raise BlueObservationError("file-ingress size policy is invalid")
    samples = receipt.get("samples")
    if not isinstance(samples, dict) or set(samples) != {
        "CONTROL", "TYPE_MISMATCH", "OVERSIZE"
    }:
        raise BlueObservationError("file-ingress sample manifest is invalid")
    marker_bytes = exercise_marker(receipt.get("experiment_id")).encode("ascii")
    expected_samples = {
        "CONTROL": (
            "control.txt", "text/plain", b"PANCITO-INERT-TEXT-V1\n" + marker_bytes + b"\n"
        ),
        "TYPE_MISMATCH": (
            "mismatch.png", "image/png", b"PANCITO-NOT-A-PNG-V1\n" + marker_bytes + b"\n"
        ),
    }
    oversize = b"PANCITO-INERT-OVERSIZE-V1\n" + marker_bytes + b"\n"
    oversize += b"X" * (expected_max + 1 - len(oversize))
    expected_samples["OVERSIZE"] = (
        "oversize.bin", "application/octet-stream", oversize
    )
    for cell, (filename, media_type, content) in expected_samples.items():
        fact = samples[cell]
        if not isinstance(fact, dict) or fact != {
            "filename": filename,
            "declared_media_type": media_type,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "synthetic_inert": True,
        }:
            raise BlueObservationError(
                "file-ingress sample manifest does not reproduce"
            )
    level = receipt.get("epistemic_level")
    cleanup = receipt.get("cleanup_status")
    final_absent = receipt.get("final_absence_verified")
    if level == "CONFIRMED_BY_INDUCTION":
        if not confirmed or cleanup != "VERIFIED_ABSENT" or final_absent is not True:
            raise BlueObservationError("file-ingress confirmed result is inconsistent")
    elif level == "FALSIFIED":
        if confirmed or outcomes != {
            "CONTROL": "STORED_EXACTLY",
            "TYPE_MISMATCH": "REJECTED",
            "OVERSIZE": "REJECTED",
        } or cleanup != "VERIFIED_ABSENT" or final_absent is not True:
            raise BlueObservationError("file-ingress falsified result is inconsistent")
    elif level == "INCONCLUSIVE":
        if cleanup == "MANUAL_ACTION_REQUIRED" and final_absent is not False:
            raise BlueObservationError("file-ingress cleanup state is inconsistent")
    else:
        raise BlueObservationError("file-ingress epistemic level is invalid")
    return steps


def evaluate_file_ingress_detection(
    receipt: dict[str, object], observation: BlueObservation
) -> dict[str, object]:
    """Evaluate Blue evidence for exactly the synthetic upload traffic emitted."""
    if not isinstance(receipt, dict):
        raise BlueObservationError("FILE_INGRESS receipt must be an object")
    steps = _file_ingress_receipt_steps(receipt)
    return _evaluate_detection(
        receipt,
        observation,
        receipt_name="FILE_INGRESS",
        capability="http-file-ingress-differential",
        technique="FILE_INGRESS_VALIDATION",
        declared_steps=steps,
        detection_requirement=_FILE_INGRESS_DETECTION_REQUIREMENT,
    )
