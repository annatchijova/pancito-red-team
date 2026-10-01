"""Bounded cross-tenant export authorization differential for loopback labs."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import exercise_marker, export_authz_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL = frozenset({401, 403, 404, 405})


class ExportAuthorizationPlanError(ValueError):
    """The export authorization experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ExportAuthorizationPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise ExportAuthorizationPlanError(f"{name} is outside its text boundary")
    return value


def _origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ExportAuthorizationPlanError("target_origin is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ExportAuthorizationPlanError(
            "target_origin must be an exact HTTP origin without user information"
        )
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ExportAuthorizationPlanError(
            "target_origin must use a literal loopback IP"
        ) from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise ExportAuthorizationPlanError("target_origin must use valid loopback")
    return parsed


def _path_segments(value: object, name: str) -> tuple[str, ...]:
    path = _text(value, name, 2_048)
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or "%" in path
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise ExportAuthorizationPlanError(
            f"{name} must be an unencoded relative path without query"
        )
    segments = tuple(path.split("/")[1:])
    if not segments or any(
        not segment or segment in {".", ".."} for segment in segments
    ):
        raise ExportAuthorizationPlanError(f"{name} contains ambiguous path segments")
    return segments


@dataclass(frozen=True)
class ExportAuthorizationPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    alpha_export_path: str
    bravo_export_path: str
    tenant_segment_index: int
    alpha_canary: str = field(repr=False)
    bravo_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 65_536

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise ExportAuthorizationPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise ExportAuthorizationPlanError(
                "operator_acknowledged must be literal true"
            )
        _origin(self.target_origin)
        alpha_segments = _path_segments(self.alpha_export_path, "alpha_export_path")
        bravo_segments = _path_segments(self.bravo_export_path, "bravo_export_path")
        if isinstance(self.tenant_segment_index, bool) or not isinstance(
            self.tenant_segment_index, int
        ):
            raise ExportAuthorizationPlanError("tenant_segment_index must be an integer")
        if len(alpha_segments) != len(bravo_segments):
            raise ExportAuthorizationPlanError("export paths must have equal segment counts")
        if not 0 <= self.tenant_segment_index < len(alpha_segments):
            raise ExportAuthorizationPlanError("tenant_segment_index is out of range")
        if alpha_segments[self.tenant_segment_index] == bravo_segments[
            self.tenant_segment_index
        ]:
            raise ExportAuthorizationPlanError("tenant path segments must differ")
        for index, (alpha_segment, bravo_segment) in enumerate(
            zip(alpha_segments, bravo_segments, strict=True)
        ):
            if index != self.tenant_segment_index and alpha_segment != bravo_segment:
                raise ExportAuthorizationPlanError(
                    "export paths may differ only at the tenant segment"
                )
        alpha_canary = _text(self.alpha_canary, "alpha_canary", 256)
        bravo_canary = _text(self.bravo_canary, "bravo_canary", 256)
        if alpha_canary == bravo_canary:
            raise ExportAuthorizationPlanError("tenant export canaries must differ")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise ExportAuthorizationPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise ExportAuthorizationPlanError("timeout_ms is outside the safe range")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes, int
        ):
            raise ExportAuthorizationPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise ExportAuthorizationPlanError("max_response_bytes is outside the safe range")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body_sha256: str
    captured_bytes: int
    truncated: bool
    request_succeeded: bool
    alpha_canary_observed: bool
    bravo_canary_observed: bool

    @property
    def redirected(self) -> bool:
        return self.status is not None and 300 <= self.status <= 399

    def public(self) -> dict[str, object]:
        return {
            "status": self.status,
            "body_sha256": self.body_sha256,
            "captured_bytes": self.captured_bytes,
            "truncated": self.truncated,
            "request_succeeded": self.request_succeeded,
            "redirected": self.redirected,
            "alpha_canary_observed": self.alpha_canary_observed,
            "bravo_canary_observed": self.bravo_canary_observed,
        }


def _observe(
    plan: ExportAuthorizationPlan,
    origin: SplitResult,
    path: str,
    credential: BearerCredential,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port if origin.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        connection.request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {credential.token}",
                "Accept": "text/csv, application/octet-stream;q=0.9",
                "User-Agent": "pancito-red-team/export-authz-lab",
                "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            },
        )
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[: plan.max_response_bytes]
        return _Observation(
            response.status,
            "" if truncated else hashlib.sha256(body).hexdigest(),
            len(body),
            truncated,
            True,
            not truncated and plan.alpha_canary.encode("utf-8") in body,
            not truncated and plan.bravo_canary.encode("utf-8") in body,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, "", 0, False, False, False, False)
    finally:
        if connection is not None:
            connection.close()


def _control_passes(observation: _Observation, expected: str) -> bool:
    expected_seen = (
        observation.alpha_canary_observed
        if expected == "alpha"
        else observation.bravo_canary_observed
    )
    unexpected_seen = (
        observation.bravo_canary_observed
        if expected == "alpha"
        else observation.alpha_canary_observed
    )
    return bool(
        observation.request_succeeded
        and observation.status is not None
        and 200 <= observation.status <= 299
        and not observation.truncated
        and expected_seen
        and not unexpected_seen
    )


def run_export_authorization_experiment(
    plan: ExportAuthorizationPlan, *, alpha: BearerCredential, bravo: BearerCredential
) -> dict[str, object]:
    """Run two tenant export controls and one credential-only foreign replay."""
    if not isinstance(plan, ExportAuthorizationPlan):
        raise TypeError("plan must be an ExportAuthorizationPlan")
    if not isinstance(alpha, BearerCredential) or not isinstance(bravo, BearerCredential):
        raise TypeError("alpha and bravo must be BearerCredential values")
    if alpha.principal_id == bravo.principal_id or alpha.token == bravo.token:
        raise ExportAuthorizationPlanError("tenant credentials must differ")
    if len({alpha.token, bravo.token, plan.alpha_canary, plan.bravo_canary}) != 4:
        raise ExportAuthorizationPlanError("credentials and canaries must all differ")

    origin = _origin(plan.target_origin)
    alpha_control = _observe(plan, origin, plan.alpha_export_path, alpha)
    bravo_control = _observe(plan, origin, plan.bravo_export_path, bravo)
    test = _observe(plan, origin, plan.bravo_export_path, alpha)

    if not _control_passes(alpha_control, "alpha"):
        level, reason = "INCONCLUSIVE", "ALPHA_CONTROL_FAILED"
    elif not _control_passes(bravo_control, "bravo"):
        level, reason = "INCONCLUSIVE", "BRAVO_CONTROL_FAILED"
    elif not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    elif test.redirected:
        level, reason = "INCONCLUSIVE", "TEST_REDIRECTED"
    elif (
        test.status is not None
        and 200 <= test.status <= 299
        and test.bravo_canary_observed
        and not test.alpha_canary_observed
    ):
        level, reason = "CONFIRMED_BY_INDUCTION", "ALPHA_OBSERVED_BRAVO_EXPORT_CANARY"
    elif test.status in _DENIAL and not test.bravo_canary_observed:
        level, reason = "FALSIFIED", "ALPHA_BRAVO_EXPORT_DENIED"
    else:
        level, reason = "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-export-authorization-differential",
        "target_origin": plan.target_origin,
        "method": "GET",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "authorization_surface": {
            "actor": "AUTHENTICATED_TENANT_ALPHA",
            "resource": "TENANT_BRAVO_EXPORT",
            "action": "EXPORT",
        },
        "prediction": "If export authorization is missing, Alpha receives Bravo's export canary.",
        "falsifier": "Both tenant export controls succeed and Alpha is denied Bravo's canary.",
        "epistemic_level": level,
        "reason_code": reason,
        "controls": {
            "alpha_control_passed": _control_passes(alpha_control, "alpha"),
            "bravo_control_passed": _control_passes(bravo_control, "bravo"),
        },
        "alpha_control": alpha_control.public(),
        "bravo_control": bravo_control.public(),
        "test": test.public(),
        "request_count": 3,
        "maximum_request_count": 3,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": export_authz_blue_objective(plan.experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
