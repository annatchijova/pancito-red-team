"""Bounded token-scope authorization differential for a loopback lab."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import exercise_marker, scope_authz_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL = frozenset({401, 403, 404, 405})


class ScopeAuthorizationPlanError(ValueError):
    """The token-scope experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ScopeAuthorizationPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise ScopeAuthorizationPlanError(f"{name} is outside its text boundary")
    return value


def _origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed, port = urlsplit(raw), urlsplit(raw).port
    except ValueError as exc:
        raise ScopeAuthorizationPlanError("target_origin is invalid") from exc
    if (parsed.scheme != "http" or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        raise ScopeAuthorizationPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ScopeAuthorizationPlanError("target_origin must use literal loopback") from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise ScopeAuthorizationPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object, name: str) -> str:
    raw = _text(value, name, 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise ScopeAuthorizationPlanError(f"{name} must be a relative path without query")
    return raw


@dataclass(frozen=True)
class ScopeAuthorizationPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    privileged_resource_path: str
    narrow_control_path: str
    privileged_canary: str = field(repr=False)
    narrow_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise ScopeAuthorizationPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise ScopeAuthorizationPlanError("operator_acknowledged must be literal true")
        _origin(self.target_origin)
        privileged_resource_path = _path(self.privileged_resource_path, "privileged_resource_path")
        narrow_path = _path(self.narrow_control_path, "narrow_control_path")
        if privileged_resource_path == narrow_path:
            raise ScopeAuthorizationPlanError("broad and narrow paths must differ")
        privileged_canary = _text(self.privileged_canary, "privileged_canary", 256)
        narrow_canary = _text(self.narrow_canary, "narrow_canary", 256)
        if privileged_canary == narrow_canary:
            raise ScopeAuthorizationPlanError("broad and narrow canaries must differ")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int) or not 100 <= self.timeout_ms <= 10_000:
            raise ScopeAuthorizationPlanError("timeout_ms is invalid")
        if isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int) or not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise ScopeAuthorizationPlanError("max_response_bytes is invalid")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body_sha256: str
    captured_bytes: int
    truncated: bool
    request_succeeded: bool
    privileged_canary_observed: bool
    narrow_canary_observed: bool

    @property
    def redirected(self) -> bool:
        return self.status is not None and 300 <= self.status <= 399

    def public(self) -> dict[str, object]:
        return {"status": self.status, "body_sha256": self.body_sha256,
                "captured_bytes": self.captured_bytes, "truncated": self.truncated,
                "request_succeeded": self.request_succeeded, "redirected": self.redirected,
                "privileged_canary_observed": self.privileged_canary_observed,
                "narrow_canary_observed": self.narrow_canary_observed}


def _observe(plan, origin, path, credential) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port if origin.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        connection.request("GET", path, headers={
            "Authorization": f"Bearer {credential.token}", "Accept": "application/json",
            "User-Agent": "pancito-red-team/scope-authz-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
        })
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[:plan.max_response_bytes]
        return _Observation(response.status, "" if truncated else hashlib.sha256(body).hexdigest(),
            len(body), truncated, True, not truncated and plan.privileged_canary.encode() in body,
            not truncated and plan.narrow_canary.encode() in body)
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, "", 0, False, False, False, False)
    finally:
        if connection is not None:
            connection.close()


def _control(item, expected: str) -> bool:
    seen = item.privileged_canary_observed if expected == "broad" else item.narrow_canary_observed
    other = item.narrow_canary_observed if expected == "broad" else item.privileged_canary_observed
    return bool(item.request_succeeded and item.status is not None and 200 <= item.status <= 299
                and not item.truncated and seen and not other)


def run_scope_authorization_experiment(plan, *, broad, narrow) -> dict[str, object]:
    if not isinstance(plan, ScopeAuthorizationPlan):
        raise TypeError("plan must be a ScopeAuthorizationPlan")
    if not isinstance(broad, BearerCredential) or not isinstance(narrow, BearerCredential):
        raise TypeError("broad and narrow must be BearerCredential values")
    if broad.principal_id == narrow.principal_id or broad.token == narrow.token:
        raise ScopeAuthorizationPlanError("broad and narrow credentials must differ")
    if len({broad.token, narrow.token, plan.privileged_canary, plan.narrow_canary}) != 4:
        raise ScopeAuthorizationPlanError("credentials and canaries must all differ")
    origin = _origin(plan.target_origin)
    broad_control = _observe(plan, origin, plan.privileged_resource_path, broad)
    narrow_control = _observe(plan, origin, plan.narrow_control_path, narrow)
    test = _observe(plan, origin, plan.privileged_resource_path, narrow)
    if not _control(broad_control, "broad"):
        level, reason = "INCONCLUSIVE", "BROAD_CONTROL_FAILED"
    elif not _control(narrow_control, "narrow"):
        level, reason = "INCONCLUSIVE", "NARROW_CONTROL_FAILED"
    elif not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    elif test.redirected:
        level, reason = "INCONCLUSIVE", "TEST_REDIRECTED"
    elif test.status is not None and 200 <= test.status <= 299 and test.privileged_canary_observed and not test.narrow_canary_observed:
        level, reason = "CONFIRMED_BY_INDUCTION", "NARROW_OBSERVED_PRIVILEGED_CANARY"
    elif test.status in _DENIAL and not test.privileged_canary_observed:
        level, reason = "FALSIFIED", "NARROW_PRIVILEGED_SCOPE_DENIED"
    else:
        level, reason = "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"
    return {
        "experiment_id": plan.experiment_id, "capability": "http-token-scope-authorization-differential",
        "target_origin": plan.target_origin, "method": "GET",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "authorization_surface": {"actor": "NARROW_SCOPED_TOKEN",
            "resource": "PRIVILEGED_SCOPE_RESOURCE", "action": "READ"},
        "prediction": "If action-level scope enforcement is absent, the narrow token receives the privileged canary.",
        "falsifier": "Both scope controls succeed and the narrow token is denied on the privileged resource.",
        "epistemic_level": level, "reason_code": reason,
        "controls": {"broad_control_passed": _control(broad_control, "broad"),
                     "narrow_control_passed": _control(narrow_control, "narrow")},
        "broad_control": broad_control.public(), "narrow_control": narrow_control.public(),
        "test": test.public(), "request_count": 3, "maximum_request_count": 3,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": scope_authz_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
