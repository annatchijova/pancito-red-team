"""Bounded field-level authorization experiment for a loopback API lab.

The experiment proves behavior from authenticated read-back, never from an HTTP
status or response echo.  It mutates only two named top-level string fields and
restores the operator-supplied baseline with a separate observer credential.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import exercise_marker, mass_assignment_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


class MassAssignmentPlanError(ValueError):
    """The field-authorization experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise MassAssignmentPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise MassAssignmentPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise MassAssignmentPlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise MassAssignmentPlanError("target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise MassAssignmentPlanError("target_origin must use HTTP for this local lab")
    if parsed.username is not None or parsed.password is not None:
        raise MassAssignmentPlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise MassAssignmentPlanError("target_origin must be an exact origin")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise MassAssignmentPlanError("target_origin port is invalid")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise MassAssignmentPlanError("target_origin must use a literal loopback IP") from exc
    if not address.is_loopback:
        raise MassAssignmentPlanError("target_origin must use a loopback IP")
    return parsed


def _relative_path(value: object, name: str) -> str:
    path = _text(value, name, 2_048)
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise MassAssignmentPlanError(f"{name} must be a relative path without query")
    return path


@dataclass(frozen=True)
class MassAssignmentPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    resource_path: str
    readback_path: str
    allowed_field: str
    protected_field: str
    baseline_allowed: str = field(repr=False)
    baseline_protected: str = field(repr=False)
    control_allowed: str = field(repr=False)
    negative_allowed: str = field(repr=False)
    negative_protected: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise MassAssignmentPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise MassAssignmentPlanError("operator_acknowledged must be literal true")
        _loopback_origin(self.target_origin)
        _relative_path(self.resource_path, "resource_path")
        _relative_path(self.readback_path, "readback_path")
        allowed = _text(self.allowed_field, "allowed_field", 128)
        protected = _text(self.protected_field, "protected_field", 128)
        if not _FIELD_RE.fullmatch(allowed) or not _FIELD_RE.fullmatch(protected):
            raise MassAssignmentPlanError("field names are invalid")
        if allowed == protected:
            raise MassAssignmentPlanError("allowed_field and protected_field must differ")
        markers = (
            _text(self.baseline_allowed, "baseline_allowed", 256),
            _text(self.baseline_protected, "baseline_protected", 256),
            _text(self.control_allowed, "control_allowed", 256),
            _text(self.negative_allowed, "negative_allowed", 256),
            _text(self.negative_protected, "negative_protected", 256),
        )
        if len(set(markers)) != len(markers):
            raise MassAssignmentPlanError("all field markers must be distinct")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise MassAssignmentPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise MassAssignmentPlanError("timeout_ms must be between 100 and 10000")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes, int
        ):
            raise MassAssignmentPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise MassAssignmentPlanError("max_response_bytes is outside the safe range")


@dataclass(frozen=True)
class _Observation:
    step: str
    method: str
    status: int | None
    request_succeeded: bool
    redirected: bool
    truncated: bool
    allowed_state: str | None
    protected_state: str | None

    def public(self) -> dict[str, object]:
        return {
            "step": self.step,
            "method": self.method,
            "status": self.status,
            "request_succeeded": self.request_succeeded,
            "redirected": self.redirected,
            "truncated": self.truncated,
            "allowed_state": self.allowed_state,
            "protected_state": self.protected_state,
        }


def _classify(value: object, identities: dict[str, str]) -> str:
    if not isinstance(value, str):
        return "OTHER"
    return identities.get(value, "OTHER")


def _classify_body(plan: MassAssignmentPlan, body: bytes) -> tuple[str, str]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "UNREADABLE", "UNREADABLE"
    if not isinstance(value, dict):
        return "OTHER", "OTHER"
    allowed = _classify(
        value.get(plan.allowed_field),
        {
            plan.baseline_allowed: "BASELINE",
            plan.control_allowed: "CONTROL",
            plan.negative_allowed: "NEGATIVE",
        },
    )
    protected = _classify(
        value.get(plan.protected_field),
        {
            plan.baseline_protected: "BASELINE",
            plan.negative_protected: "NEGATIVE",
        },
    )
    return allowed, protected


def _request(
    plan: MassAssignmentPlan,
    origin: SplitResult,
    *,
    step: str,
    method: str,
    token: str,
    values: dict[str, str] | None = None,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname, origin.port or 80, timeout=plan.timeout_ms / 1_000
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "pancito-red-team/mass-assignment-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "X-Pancito-Step": step,
        }
        body = None
        path = plan.readback_path
        if method == "PATCH":
            path = plan.resource_path
            headers["Content-Type"] = "application/merge-patch+json"
            body = json.dumps(
                values, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            headers["Content-Length"] = str(len(body))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        allowed_state = protected_state = None
        if method == "GET" and not truncated:
            allowed_state, protected_state = _classify_body(
                plan, captured[: plan.max_response_bytes]
            )
        return _Observation(
            step,
            method,
            response.status,
            True,
            300 <= response.status <= 399,
            truncated,
            allowed_state,
            protected_state,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(step, method, None, False, False, False, None, None)
    finally:
        if connection is not None:
            connection.close()


def _usable(item: _Observation) -> bool:
    return bool(
        item.request_succeeded
        and not item.redirected
        and not item.truncated
        and item.status is not None
    )


def _read(
    plan: MassAssignmentPlan, origin: SplitResult, token: str, step: str
) -> _Observation:
    return _request(plan, origin, step=step, method="GET", token=token)


def _write(
    plan: MassAssignmentPlan,
    origin: SplitResult,
    token: str,
    step: str,
    values: dict[str, str],
) -> _Observation:
    return _request(
        plan, origin, step=step, method="PATCH", token=token, values=values
    )


def _is_baseline(item: _Observation) -> bool:
    return bool(
        _usable(item)
        and item.allowed_state == "BASELINE"
        and item.protected_state == "BASELINE"
    )


def _restore(
    plan: MassAssignmentPlan,
    origin: SplitResult,
    observer_token: str,
    label: str,
    observations: list[_Observation],
) -> bool:
    observations.append(
        _write(
            plan,
            origin,
            observer_token,
            f"{label}_RESTORE",
            {
                plan.allowed_field: plan.baseline_allowed,
                plan.protected_field: plan.baseline_protected,
            },
        )
    )
    observations.append(
        _read(plan, origin, observer_token, f"{label}_RESTORE_VERIFY")
    )
    return _is_baseline(observations[-1])


def run_mass_assignment_experiment(
    plan: MassAssignmentPlan,
    *,
    actor: BearerCredential,
    observer: BearerCredential,
) -> dict[str, object]:
    """Run one positive and one negative field-authorization cell."""
    if not isinstance(plan, MassAssignmentPlan):
        raise TypeError("plan must be a MassAssignmentPlan")
    if not isinstance(actor, BearerCredential) or not isinstance(
        observer, BearerCredential
    ):
        raise TypeError("actor and observer must be BearerCredential values")
    if actor.principal_id == observer.principal_id or actor.token == observer.token:
        raise MassAssignmentPlanError("actor and observer must be distinct")
    markers = {
        plan.baseline_allowed,
        plan.baseline_protected,
        plan.control_allowed,
        plan.negative_allowed,
        plan.negative_protected,
        actor.token,
        observer.token,
    }
    if len(markers) != 7:
        raise MassAssignmentPlanError("credentials and markers must all be distinct")

    origin = _loopback_origin(plan.target_origin)
    observations: list[_Observation] = []
    level = "INCONCLUSIVE"
    reason = "INITIAL_READBACK_FAILED"
    control_outcome = "NOT_RUN"
    negative_outcome = "NOT_RUN"
    cleanup = "NOT_REQUIRED"

    observations.append(_read(plan, origin, observer.token, "BASELINE_READ"))
    if _is_baseline(observations[-1]):
        observations.append(
            _write(
                plan,
                origin,
                actor.token,
                "ALLOWED_FIELD_CONTROL",
                {plan.allowed_field: plan.control_allowed},
            )
        )
        observations.append(
            _read(plan, origin, observer.token, "ALLOWED_CONTROL_READBACK")
        )
        control_read = observations[-1]
        control_ok = bool(
            _usable(observations[-2])
            and 200 <= int(observations[-2].status) <= 299
            and _usable(control_read)
            and control_read.allowed_state == "CONTROL"
            and control_read.protected_state == "BASELINE"
        )
        control_outcome = (
            "ALLOWED_FIELD_MUTATION_CONFIRMED" if control_ok else "CONTROL_FAILED"
        )
        if not _restore(plan, origin, observer.token, "CONTROL", observations):
            reason = "CONTROL_RESTORE_FAILED"
            cleanup = "MANUAL_ACTION_REQUIRED"
        elif not control_ok:
            reason = "ALLOWED_FIELD_CONTROL_FAILED"
            cleanup = "RESTORED_TO_BASELINE"
        else:
            cleanup = "RESTORED_TO_BASELINE"
            observations.append(
                _write(
                    plan,
                    origin,
                    actor.token,
                    "PROTECTED_FIELD_TEST",
                    {
                        plan.allowed_field: plan.negative_allowed,
                        plan.protected_field: plan.negative_protected,
                    },
                )
            )
            observations.append(
                _read(plan, origin, observer.token, "PROTECTED_TEST_READBACK")
            )
            negative_read = observations[-1]
            protected_changed = bool(
                _usable(negative_read)
                and negative_read.protected_state == "NEGATIVE"
            )
            protected_unchanged = bool(
                _usable(negative_read)
                and negative_read.protected_state == "BASELINE"
                and negative_read.allowed_state in {"BASELINE", "NEGATIVE"}
            )
            if protected_changed:
                negative_outcome = "PROTECTED_FIELD_MUTATION_CONFIRMED"
            elif protected_unchanged:
                negative_outcome = "PROTECTED_FIELD_UNCHANGED"
            else:
                negative_outcome = "INCONCLUSIVE"
            if not _restore(plan, origin, observer.token, "NEGATIVE", observations):
                reason = "NEGATIVE_RESTORE_FAILED"
                cleanup = "MANUAL_ACTION_REQUIRED"
            elif protected_changed:
                level = "CONFIRMED_BY_INDUCTION"
                reason = "PROTECTED_FIELD_MUTATION_CONFIRMED"
                cleanup = "RESTORED_TO_BASELINE"
            elif protected_unchanged:
                level = "FALSIFIED"
                reason = "PROTECTED_FIELD_MUTATION_PREVENTED"
                cleanup = "RESTORED_TO_BASELINE"
            else:
                reason = "PROTECTED_FIELD_ORACLE_NOT_SATISFIED"
                cleanup = "RESTORED_TO_BASELINE"
    elif _usable(observations[-1]):
        reason = "BASELINE_FIELD_MISMATCH"

    steps = tuple(item.step for item in observations)
    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-mass-assignment-differential",
        "target_origin": plan.target_origin,
        "resource_path": plan.resource_path,
        "readback_path": plan.readback_path,
        "method": "PATCH",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "authorization_surface": {
            "actor": "AUTHENTICATED_LOW_PRIVILEGE",
            "resource": "OPERATOR_PROVISIONED_OWN_RESOURCE",
            "positive_action": "UPDATE_ALLOWED_FIELD",
            "negative_action": "UPDATE_PROTECTED_FIELD",
        },
        "prediction": (
            "If property-level authorization is absent, observer read-back will "
            "show the low-privilege actor's protected-field marker."
        ),
        "falsifier": (
            "After the allowed-field control succeeds, observer read-back keeps "
            "the protected field at baseline during the negative cell."
        ),
        "epistemic_level": level,
        "reason_code": reason,
        "control_outcome": control_outcome,
        "negative_outcome": negative_outcome,
        "cleanup_status": cleanup,
        "final_state_verified": cleanup == "RESTORED_TO_BASELINE",
        "request_count": len(observations),
        "maximum_request_count": 9,
        "observations": [item.public() for item in observations],
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": mass_assignment_blue_objective(plan.experiment_id, steps),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
