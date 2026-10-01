"""Bounded differential proof for authentication enforcement on a GET route."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import authn_blue_objective, exercise_marker


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL_STATUSES = frozenset({401, 403, 404})


class AuthnPlanError(ValueError):
    """The authentication experiment is ambiguous or outside its boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuthnPlanError(f"{name} must be non-empty text without outer whitespace")
    if len(value) > maximum:
        raise AuthnPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise AuthnPlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise AuthnPlanError("target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise AuthnPlanError("target_origin must use HTTP for this local-lab capability")
    if parsed.username is not None or parsed.password is not None:
        raise AuthnPlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise AuthnPlanError("target_origin must be an exact origin without path or query")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise AuthnPlanError("target_origin port is outside the valid range")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise AuthnPlanError("target_origin must use a literal loopback IP address") from exc
    if not address.is_loopback:
        raise AuthnPlanError("target_origin must use a loopback IP address")
    return parsed


def _relative_path(value: object) -> str:
    path = _text(value, "protected_path", 2_048)
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise AuthnPlanError("protected_path must be a relative HTTP path")
    return path


@dataclass(frozen=True)
class AuthnPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    protected_path: str
    protected_canary: str = field(repr=False)
    invalid_bearer: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        experiment_id = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(experiment_id):
            raise AuthnPlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}"
            )
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise AuthnPlanError("operator_acknowledged must be literal true")
        _loopback_origin(self.target_origin)
        _relative_path(self.protected_path)
        canary = _text(self.protected_canary, "protected_canary", 256)
        invalid = _text(self.invalid_bearer, "invalid_bearer", 8_192)
        if canary == invalid:
            raise AuthnPlanError("protected canary and invalid bearer must be distinct")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise AuthnPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise AuthnPlanError("timeout_ms must be between 100 and 10000")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
        ):
            raise AuthnPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise AuthnPlanError(
                "max_response_bytes must be between 1024 and 1048576"
            )


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body_sha256: str
    captured_bytes: int
    truncated: bool
    request_succeeded: bool
    protected_canary_observed: bool

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
            "protected_canary_observed": self.protected_canary_observed,
        }


def _request(
    plan: AuthnPlan,
    parsed_origin: SplitResult,
    *,
    step: str,
    bearer: str | None,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            parsed_origin.hostname,
            parsed_origin.port or 80,
            timeout=plan.timeout_ms / 1_000,
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "pancito-red-team/authn-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "X-Pancito-Step": step,
        }
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        connection.request("GET", plan.protected_path, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[: plan.max_response_bytes]
        return _Observation(
            status=response.status,
            body_sha256=("" if truncated else hashlib.sha256(body).hexdigest()),
            captured_bytes=len(body),
            truncated=truncated,
            request_succeeded=True,
            protected_canary_observed=(
                not truncated and plan.protected_canary.encode("utf-8") in body
            ),
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(
            status=None,
            body_sha256="",
            captured_bytes=0,
            truncated=False,
            request_succeeded=False,
            protected_canary_observed=False,
        )
    finally:
        if connection is not None:
            connection.close()


def _valid_control(observation: _Observation) -> bool:
    return bool(
        observation.request_succeeded
        and observation.status is not None
        and 200 <= observation.status <= 299
        and not observation.truncated
        and observation.protected_canary_observed
    )


def _confirmed(observation: _Observation) -> bool:
    return bool(
        observation.request_succeeded
        and observation.status is not None
        and 200 <= observation.status <= 299
        and not observation.truncated
        and observation.protected_canary_observed
    )


def _ambiguous_reason(prefix: str, observation: _Observation) -> str | None:
    if not observation.request_succeeded:
        return f"{prefix}_REQUEST_FAILED"
    if observation.truncated:
        return f"{prefix}_RESPONSE_TRUNCATED"
    if observation.redirected:
        return f"{prefix}_REDIRECTED"
    if observation.status in _DENIAL_STATUSES and not observation.protected_canary_observed:
        return None
    return f"{prefix}_ORACLE_NOT_SATISFIED"


def run_authn_experiment(
    plan: AuthnPlan, *, valid: BearerCredential
) -> dict[str, object]:
    """Run one positive control and two one-factor negative authentication cells."""
    if not isinstance(plan, AuthnPlan):
        raise TypeError("plan must be an AuthnPlan")
    if not isinstance(valid, BearerCredential):
        raise TypeError("valid must be a BearerCredential")
    if valid.token in {plan.invalid_bearer, plan.protected_canary}:
        raise AuthnPlanError("valid token, invalid bearer, and canary must be distinct")
    parsed_origin = _loopback_origin(plan.target_origin)
    control = _request(
        plan,
        parsed_origin,
        step="VALID_CREDENTIAL_CONTROL",
        bearer=valid.token,
    )
    anonymous = _request(
        plan, parsed_origin, step="ANONYMOUS_TEST", bearer=None
    )
    invalid = _request(
        plan,
        parsed_origin,
        step="INVALID_BEARER_TEST",
        bearer=plan.invalid_bearer,
    )

    if not _valid_control(control):
        epistemic_level, reason_code = "INCONCLUSIVE", "VALID_CONTROL_FAILED"
    elif _confirmed(anonymous) and _confirmed(invalid):
        epistemic_level = "CONFIRMED_BY_INDUCTION"
        reason_code = "ANONYMOUS_AND_INVALID_BEARER_OBSERVED_PROTECTED_CANARY"
    elif _confirmed(anonymous):
        epistemic_level = "CONFIRMED_BY_INDUCTION"
        reason_code = "ANONYMOUS_OBSERVED_PROTECTED_CANARY"
    elif _confirmed(invalid):
        epistemic_level = "CONFIRMED_BY_INDUCTION"
        reason_code = "INVALID_BEARER_OBSERVED_PROTECTED_CANARY"
    else:
        anonymous_ambiguity = _ambiguous_reason("ANONYMOUS_TEST", anonymous)
        invalid_ambiguity = _ambiguous_reason("INVALID_BEARER_TEST", invalid)
        if anonymous_ambiguity is not None:
            epistemic_level, reason_code = "INCONCLUSIVE", anonymous_ambiguity
        elif invalid_ambiguity is not None:
            epistemic_level, reason_code = "INCONCLUSIVE", invalid_ambiguity
        else:
            epistemic_level = "FALSIFIED"
            reason_code = "ANONYMOUS_AND_INVALID_BEARER_DENIED"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-authentication-enforcement-differential",
        "target_origin": plan.target_origin,
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "prediction": (
            "If authentication enforcement fails, an anonymous or invalid-bearer "
            "request will receive the protected marker."
        ),
        "falsifier": (
            "A valid positive control followed by denials for both negative cells "
            "falsifies this candidate for the tested route."
        ),
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "valid_control_passed": _valid_control(control),
        "valid_control": control.public(),
        "anonymous_test": anonymous.public(),
        "invalid_bearer_test": invalid.public(),
        "blue_objective": authn_blue_objective(plan.experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
