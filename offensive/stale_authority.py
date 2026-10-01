"""Reversible stale-authority differential for an operator-owned loopback lab.

The same pre-issued actor credential is exercised before and after an
administrator changes one membership field to a revoked marker.  Membership
state is read back before the replay and restored before any conclusive result.
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
from offensive.purple import exercise_marker, stale_authority_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_DENIAL_STATUSES = frozenset({401, 403, 404})


class StaleAuthorityPlanError(ValueError):
    """The authority-transition experiment is ambiguous or unsafe."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise StaleAuthorityPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise StaleAuthorityPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise StaleAuthorityPlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise StaleAuthorityPlanError("target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise StaleAuthorityPlanError("target_origin must use HTTP for this local lab")
    if parsed.username is not None or parsed.password is not None:
        raise StaleAuthorityPlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise StaleAuthorityPlanError("target_origin must be an exact origin")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise StaleAuthorityPlanError("target_origin port is invalid")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise StaleAuthorityPlanError("target_origin must use a literal loopback IP") from exc
    if not address.is_loopback:
        raise StaleAuthorityPlanError("target_origin must use a loopback IP")
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
        raise StaleAuthorityPlanError(f"{name} must be a relative path without query")
    return path


@dataclass(frozen=True)
class StaleAuthorityPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    resource_path: str
    membership_path: str
    membership_field: str
    resource_canary: str = field(repr=False)
    active_marker: str = field(repr=False)
    revoked_marker: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise StaleAuthorityPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise StaleAuthorityPlanError("operator_acknowledged must be literal true")
        _loopback_origin(self.target_origin)
        resource_path = _relative_path(self.resource_path, "resource_path")
        membership_path = _relative_path(self.membership_path, "membership_path")
        if resource_path == membership_path:
            raise StaleAuthorityPlanError("resource and membership paths must differ")
        field_name = _text(self.membership_field, "membership_field", 128)
        if not _FIELD_RE.fullmatch(field_name):
            raise StaleAuthorityPlanError("membership_field is invalid")
        secrets = (
            _text(self.resource_canary, "resource_canary", 256),
            _text(self.active_marker, "active_marker", 256),
            _text(self.revoked_marker, "revoked_marker", 256),
        )
        if len(set(secrets)) != len(secrets):
            raise StaleAuthorityPlanError("canary and membership markers must be distinct")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise StaleAuthorityPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise StaleAuthorityPlanError("timeout_ms must be between 100 and 10000")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes, int
        ):
            raise StaleAuthorityPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise StaleAuthorityPlanError("max_response_bytes is outside the safe range")


@dataclass(frozen=True)
class _Observation:
    step: str
    method: str
    status: int | None
    request_succeeded: bool
    redirected: bool
    truncated: bool
    resource_canary_observed: bool
    membership_state: str | None

    def public(self) -> dict[str, object]:
        return {
            "step": self.step,
            "method": self.method,
            "status": self.status,
            "request_succeeded": self.request_succeeded,
            "redirected": self.redirected,
            "truncated": self.truncated,
            "resource_canary_observed": self.resource_canary_observed,
            "membership_state": self.membership_state,
        }


def _classify_membership(plan: StaleAuthorityPlan, body: bytes) -> str:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "UNREADABLE"
    if not isinstance(value, dict):
        return "OTHER"
    marker = value.get(plan.membership_field)
    if marker == plan.active_marker:
        return "ACTIVE"
    if marker == plan.revoked_marker:
        return "REVOKED"
    return "OTHER"


def _request(
    plan: StaleAuthorityPlan,
    origin: SplitResult,
    *,
    step: str,
    method: str,
    path: str,
    token: str,
    membership_marker: str | None = None,
    classify_membership: bool = False,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname, origin.port or 80, timeout=plan.timeout_ms / 1_000
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "pancito-red-team/stale-authority-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "X-Pancito-Step": step,
        }
        body = None
        if method == "PATCH":
            headers["Content-Type"] = "application/merge-patch+json"
            body = json.dumps(
                {plan.membership_field: membership_marker},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            headers["Content-Length"] = str(len(body))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        bounded = captured[: plan.max_response_bytes]
        membership_state = None
        if classify_membership and not truncated:
            membership_state = _classify_membership(plan, bounded)
        return _Observation(
            step=step,
            method=method,
            status=response.status,
            request_succeeded=True,
            redirected=300 <= response.status <= 399,
            truncated=truncated,
            resource_canary_observed=(
                method == "GET"
                and not classify_membership
                and not truncated
                and plan.resource_canary.encode("utf-8") in bounded
            ),
            membership_state=membership_state,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(step, method, None, False, False, False, False, None)
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


def _membership_read(
    plan: StaleAuthorityPlan,
    origin: SplitResult,
    admin_token: str,
    step: str,
) -> _Observation:
    return _request(
        plan,
        origin,
        step=step,
        method="GET",
        path=plan.membership_path,
        token=admin_token,
        classify_membership=True,
    )


def _membership_write(
    plan: StaleAuthorityPlan,
    origin: SplitResult,
    admin_token: str,
    step: str,
    marker: str,
) -> _Observation:
    return _request(
        plan,
        origin,
        step=step,
        method="PATCH",
        path=plan.membership_path,
        token=admin_token,
        membership_marker=marker,
    )


def _resource_read(
    plan: StaleAuthorityPlan,
    origin: SplitResult,
    actor_token: str,
    step: str,
) -> _Observation:
    return _request(
        plan,
        origin,
        step=step,
        method="GET",
        path=plan.resource_path,
        token=actor_token,
    )


def _resource_control_passes(item: _Observation) -> bool:
    return bool(
        _usable(item)
        and item.status is not None
        and 200 <= item.status <= 299
        and item.resource_canary_observed
    )


def _restore(
    plan: StaleAuthorityPlan,
    origin: SplitResult,
    admin_token: str,
    observations: list[_Observation],
) -> bool:
    observations.append(
        _membership_write(
            plan, origin, admin_token, "ADMIN_RESTORE", plan.active_marker
        )
    )
    observations.append(
        _membership_read(plan, origin, admin_token, "ADMIN_RESTORE_VERIFY")
    )
    return bool(
        _usable(observations[-1])
        and observations[-1].membership_state == "ACTIVE"
    )


def run_stale_authority_experiment(
    plan: StaleAuthorityPlan,
    *,
    actor: BearerCredential,
    admin: BearerCredential,
) -> dict[str, object]:
    """Revoke one membership, replay the same token, and restore the baseline."""
    if not isinstance(plan, StaleAuthorityPlan):
        raise TypeError("plan must be a StaleAuthorityPlan")
    if not isinstance(actor, BearerCredential) or not isinstance(admin, BearerCredential):
        raise TypeError("actor and admin must be BearerCredential values")
    if actor.principal_id == admin.principal_id or actor.token == admin.token:
        raise StaleAuthorityPlanError("actor and admin credentials must be distinct")
    if len(
        {
            actor.token,
            admin.token,
            plan.resource_canary,
            plan.active_marker,
            plan.revoked_marker,
        }
    ) != 5:
        raise StaleAuthorityPlanError("credentials, canary, and markers must be distinct")

    origin = _loopback_origin(plan.target_origin)
    observations: list[_Observation] = []
    level = "INCONCLUSIVE"
    reason = "INITIAL_MEMBERSHIP_READ_FAILED"
    revoke_verified = False
    stale_access_observed = False
    cleanup = "NOT_REQUIRED"

    observations.append(
        _membership_read(plan, origin, admin.token, "INITIAL_MEMBERSHIP_READ")
    )
    baseline = observations[-1]
    if _usable(baseline) and baseline.membership_state == "ACTIVE":
        observations.append(
            _resource_read(plan, origin, actor.token, "ACTOR_PRE_REVOKE_CONTROL")
        )
        if not _resource_control_passes(observations[-1]):
            reason = "PRE_REVOKE_CONTROL_FAILED"
            cleanup = "BASELINE_VERIFIED"
        else:
            observations.append(
                _membership_write(
                    plan, origin, admin.token, "ADMIN_REVOKE", plan.revoked_marker
                )
            )
            observations.append(
                _membership_read(plan, origin, admin.token, "ADMIN_REVOKE_VERIFY")
            )
            revoke_read = observations[-1]
            if _usable(revoke_read) and revoke_read.membership_state == "ACTIVE":
                reason = "REVOKE_CONTROL_FAILED"
                cleanup = "BASELINE_VERIFIED"
            elif _usable(revoke_read) and revoke_read.membership_state == "REVOKED":
                revoke_verified = True
                observations.append(
                    _resource_read(
                        plan, origin, actor.token, "STALE_CREDENTIAL_TEST"
                    )
                )
                stale_test = observations[-1]
                stale_access_observed = bool(
                    _usable(stale_test)
                    and stale_test.status is not None
                    and 200 <= stale_test.status <= 299
                    and stale_test.resource_canary_observed
                )
                denied = bool(
                    _usable(stale_test)
                    and stale_test.status in _DENIAL_STATUSES
                    and not stale_test.resource_canary_observed
                )
                restored = _restore(plan, origin, admin.token, observations)
                if not restored:
                    reason = "RESTORE_FAILED"
                    cleanup = "MANUAL_ACTION_REQUIRED"
                elif stale_access_observed:
                    level = "CONFIRMED_BY_INDUCTION"
                    reason = "STALE_CREDENTIAL_ACCESS_CONFIRMED"
                    cleanup = "RESTORED_TO_BASELINE"
                elif denied:
                    level = "FALSIFIED"
                    reason = "REVOKED_CREDENTIAL_ACCESS_DENIED"
                    cleanup = "RESTORED_TO_BASELINE"
                else:
                    reason = "STALE_ACCESS_ORACLE_NOT_SATISFIED"
                    cleanup = "RESTORED_TO_BASELINE"
            else:
                restored = _restore(plan, origin, admin.token, observations)
                reason = "REVOKE_STATE_UNVERIFIED" if restored else "RESTORE_FAILED"
                cleanup = (
                    "RESTORED_TO_BASELINE" if restored else "MANUAL_ACTION_REQUIRED"
                )
    elif _usable(baseline):
        reason = "BASELINE_MEMBERSHIP_MISMATCH"

    steps = tuple(item.step for item in observations)
    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-stale-authority-differential",
        "target_origin": plan.target_origin,
        "resource_path": plan.resource_path,
        "membership_path": plan.membership_path,
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "authorization_surface": {
            "actor": "AUTHENTICATED_PREISSUED_CREDENTIAL",
            "resource": "ROLE_PROTECTED_RESOURCE",
            "transition": "ACTIVE_TO_REVOKED",
            "action": "READ_AFTER_REVOCATION",
        },
        "invariant": "authority(credential, test_time) == current_authority(principal)",
        "prediction": (
            "If revocation is not enforced on an already-issued credential, the "
            "protected canary remains readable after verified membership revocation."
        ),
        "falsifier": (
            "After both pre-revoke and revoke controls succeed, the same credential "
            "is denied and no protected canary is returned."
        ),
        "epistemic_level": level,
        "reason_code": reason,
        "revoke_verified": revoke_verified,
        "stale_access_observed": stale_access_observed,
        "cleanup_status": cleanup,
        "final_state_verified": cleanup in {"RESTORED_TO_BASELINE", "BASELINE_VERIFIED"},
        "request_count": len(observations),
        "maximum_request_count": 7,
        "observations": [item.public() for item in observations],
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": stale_authority_blue_objective(plan.experiment_id, steps),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
