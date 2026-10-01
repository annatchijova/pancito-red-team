"""Bounded cross-tenant collection authorization differential for loopback labs."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import collection_authz_blue_objective, exercise_marker


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL_STATUSES = frozenset({401, 403, 404, 405})


class CollectionAuthorizationPlanError(ValueError):
    """The collection authorization experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CollectionAuthorizationPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise CollectionAuthorizationPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise CollectionAuthorizationPlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise CollectionAuthorizationPlanError(
            "target_origin is not a valid HTTP origin"
        ) from exc
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise CollectionAuthorizationPlanError(
            "target_origin must be an exact HTTP origin without user information"
        )
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise CollectionAuthorizationPlanError(
            "target_origin must use a literal loopback IP"
        ) from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise CollectionAuthorizationPlanError(
            "target_origin must use a valid loopback address"
        )
    return parsed


def _path(value: object, name: str) -> str:
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
        or any(segment in {"", ".", ".."} for segment in path.split("/")[1:])
    ):
        raise CollectionAuthorizationPlanError(
            f"{name} must be an unencoded relative path without query"
        )
    return path


@dataclass(frozen=True)
class CollectionAuthorizationPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    alpha_collection_path: str
    bravo_collection_path: str
    alpha_canary: str = field(repr=False)
    bravo_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise CollectionAuthorizationPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise CollectionAuthorizationPlanError(
                "operator_acknowledged must be literal true"
            )
        _loopback_origin(self.target_origin)
        alpha_path = _path(self.alpha_collection_path, "alpha_collection_path")
        bravo_path = _path(self.bravo_collection_path, "bravo_collection_path")
        if alpha_path == bravo_path:
            raise CollectionAuthorizationPlanError(
                "alpha and bravo collection paths must differ"
            )
        alpha_canary = _text(self.alpha_canary, "alpha_canary", 256)
        bravo_canary = _text(self.bravo_canary, "bravo_canary", 256)
        if alpha_canary == bravo_canary:
            raise CollectionAuthorizationPlanError(
                "alpha and bravo canaries must differ"
            )
        if (
            isinstance(self.timeout_ms, bool)
            or not isinstance(self.timeout_ms, int)
            or not 100 <= self.timeout_ms <= 10_000
        ):
            raise CollectionAuthorizationPlanError("timeout_ms is invalid")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1_024 <= self.max_response_bytes <= 1_048_576
        ):
            raise CollectionAuthorizationPlanError("max_response_bytes is invalid")


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
    plan: CollectionAuthorizationPlan,
    origin: SplitResult,
    path: str,
    credential: BearerCredential,
    step: str,
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
                "Accept": "application/json",
                "User-Agent": "pancito-red-team/collection-authz-lab",
                "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            },
        )
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[: plan.max_response_bytes]
        return _Observation(
            status=response.status,
            body_sha256="" if truncated else hashlib.sha256(body).hexdigest(),
            captured_bytes=len(body),
            truncated=truncated,
            request_succeeded=True,
            alpha_canary_observed=(
                not truncated and plan.alpha_canary.encode("utf-8") in body
            ),
            bravo_canary_observed=(
                not truncated and plan.bravo_canary.encode("utf-8") in body
            ),
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


def _adjudicate(
    alpha_control: _Observation,
    bravo_control: _Observation,
    test: _Observation,
) -> tuple[str, str]:
    if not _control_passes(alpha_control, "alpha"):
        return "INCONCLUSIVE", "ALPHA_CONTROL_FAILED"
    if not _control_passes(bravo_control, "bravo"):
        return "INCONCLUSIVE", "BRAVO_CONTROL_FAILED"
    if not test.request_succeeded:
        return "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    if test.truncated:
        return "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    if test.redirected:
        return "INCONCLUSIVE", "TEST_REDIRECTED"
    if (
        test.status is not None
        and 200 <= test.status <= 299
        and test.bravo_canary_observed
        and not test.alpha_canary_observed
    ):
        return "CONFIRMED_BY_INDUCTION", "ALPHA_OBSERVED_BRAVO_COLLECTION_CANARY"
    if test.status in _DENIAL_STATUSES and not test.bravo_canary_observed:
        return "FALSIFIED", "ALPHA_BRAVO_COLLECTION_DENIED"
    return "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"


def run_collection_authorization_experiment(
    plan: CollectionAuthorizationPlan,
    *,
    alpha: BearerCredential,
    bravo: BearerCredential,
) -> dict[str, object]:
    """Run two collection controls and one credential-only negative replay.

    The ``step`` argument is retained in the local call structure for explicit
    experiment ordering, but is not sent to the target. Blue reconstructs the
    three conceptual steps from request order, subject, and path so the negative
    replay differs from its benign twin only by the Authorization header.
    """
    if not isinstance(plan, CollectionAuthorizationPlan):
        raise TypeError("plan must be a CollectionAuthorizationPlan")
    if not isinstance(alpha, BearerCredential) or not isinstance(bravo, BearerCredential):
        raise TypeError("alpha and bravo must be BearerCredential values")
    if alpha.principal_id == bravo.principal_id or alpha.token == bravo.token:
        raise CollectionAuthorizationPlanError(
            "alpha and bravo credentials must differ"
        )
    if len({alpha.token, bravo.token, plan.alpha_canary, plan.bravo_canary}) != 4:
        raise CollectionAuthorizationPlanError(
            "credentials and canaries must all differ"
        )

    origin = _loopback_origin(plan.target_origin)
    alpha_control = _observe(
        plan, origin, plan.alpha_collection_path, alpha, "ALPHA_COLLECTION_CONTROL"
    )
    bravo_control = _observe(
        plan, origin, plan.bravo_collection_path, bravo, "BRAVO_COLLECTION_CONTROL"
    )
    test = _observe(
        plan, origin, plan.bravo_collection_path, alpha, "CROSS_TENANT_LIST_TEST"
    )
    level, reason = _adjudicate(alpha_control, bravo_control, test)

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-collection-authorization-differential",
        "target_origin": plan.target_origin,
        "method": "GET",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "authorization_surface": {
            "actor": "AUTHENTICATED_OTHER_TENANT",
            "resource": "FOREIGN_TENANT_COLLECTION",
            "action": "LIST",
        },
        "prediction": (
            "If collection isolation is absent, alpha receives bravo's collection canary."
        ),
        "falsifier": (
            "Both tenant controls succeed and alpha is denied on bravo's collection."
        ),
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
        "blue_objective": collection_authz_blue_objective(plan.experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
