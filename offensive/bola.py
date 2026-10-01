"""Bounded differential proof for BOLA/IDOR in a disposable HTTP lab.

This module deliberately exposes one narrow offensive capability.  It can make
three GET requests to an exact loopback origin, but it cannot select arbitrary
hosts, execute commands, follow redirects, or influence a forensic verdict.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.handoff import BolaCandidateHandoff, path_matches_candidate_template


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL_STATUSES = frozenset({401, 403, 404})


class BolaPlanError(ValueError):
    """The proposed experiment is ambiguous or exceeds its safety boundary."""


def _bounded_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BolaPlanError(f"{name} must be non-empty text without outer whitespace")
    if len(value) > maximum:
        raise BolaPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise BolaPlanError(f"{name} contains control characters")
    return value


def _parse_loopback_origin(value: object) -> SplitResult:
    origin = _bounded_text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise BolaPlanError("target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise BolaPlanError("target_origin must use HTTP for this local-lab capability")
    if parsed.username is not None or parsed.password is not None:
        raise BolaPlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise BolaPlanError("target_origin must be an exact origin without path or query")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise BolaPlanError("target_origin port is outside the valid range")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise BolaPlanError("target_origin must use a literal loopback IP address") from exc
    if not address.is_loopback:
        raise BolaPlanError("target_origin must use a loopback IP address")
    return parsed


def _relative_http_path(value: object, name: str) -> str:
    path = _bounded_text(value, name, 2_048)
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise BolaPlanError(f"{name} must be a relative HTTP path")
    return path


@dataclass(frozen=True)
class BearerCredential:
    """A principal-labelled bearer secret that is redacted from representations."""

    principal_id: str
    token: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not _ID_RE.fullmatch(
            self.principal_id
        ):
            raise BolaPlanError(
                "principal_id must match [A-Za-z0-9._-]{1,128}"
            )
        token = _bounded_text(self.token, "bearer token", 8_192)
        if "\r" in token or "\n" in token:
            raise BolaPlanError("bearer token must not contain header delimiters")


@dataclass(frozen=True)
class BolaPlan:
    """Operator-authored scope for one cross-principal object-read experiment."""

    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    owner_path: str
    peer_control_path: str
    owner_canary: str = field(repr=False)
    peer_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384
    candidate_handoff: BolaCandidateHandoff | None = None

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_bounded_text(self.experiment_id, "experiment_id", 128)):
            raise BolaPlanError("experiment_id must match [A-Za-z0-9._-]{1,128}")
        _bounded_text(self.authorization_reference, "authorization_reference", 512)
        _bounded_text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise BolaPlanError("operator_acknowledged must be literal true")
        _parse_loopback_origin(self.target_origin)
        owner_path = _relative_http_path(self.owner_path, "owner_path")
        peer_path = _relative_http_path(self.peer_control_path, "peer_control_path")
        if owner_path == peer_path:
            raise BolaPlanError("owner and peer control paths must be distinct")
        owner_canary = _bounded_text(self.owner_canary, "owner_canary", 256)
        peer_canary = _bounded_text(self.peer_canary, "peer_canary", 256)
        if owner_canary == peer_canary:
            raise BolaPlanError("owner and peer canaries must be distinct")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise BolaPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise BolaPlanError("timeout_ms must be between 100 and 10000")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
        ):
            raise BolaPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise BolaPlanError(
                "max_response_bytes must be between 1024 and 1048576"
            )
        if self.candidate_handoff is not None:
            if not isinstance(self.candidate_handoff, BolaCandidateHandoff):
                raise BolaPlanError("candidate_handoff must be a BolaCandidateHandoff")
            if not path_matches_candidate_template(
                self.candidate_handoff, owner_path
            ) or not path_matches_candidate_template(
                self.candidate_handoff, peer_path
            ):
                raise BolaPlanError(
                    "owner and peer paths must match the candidate path template"
                )


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body_sha256: str
    captured_bytes: int
    truncated: bool
    request_succeeded: bool
    owner_canary_observed: bool
    peer_canary_observed: bool

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
            "owner_canary_observed": self.owner_canary_observed,
            "peer_canary_observed": self.peer_canary_observed,
        }


def _observe(
    plan: BolaPlan,
    parsed_origin: SplitResult,
    path: str,
    credential: BearerCredential,
) -> _Observation:
    """Perform one bounded request without redirects, retries, or response bodies."""
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            parsed_origin.hostname,
            parsed_origin.port or 80,
            timeout=plan.timeout_ms / 1_000,
        )
        connection.request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {credential.token}",
                "Accept": "application/json",
                "User-Agent": "pancito-red-team/bola-lab",
            },
        )
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[: plan.max_response_bytes]
        body_sha256 = "" if truncated else hashlib.sha256(body).hexdigest()
        return _Observation(
            status=response.status,
            body_sha256=body_sha256,
            captured_bytes=len(body),
            truncated=truncated,
            request_succeeded=True,
            owner_canary_observed=(
                not truncated and plan.owner_canary.encode("utf-8") in body
            ),
            peer_canary_observed=(
                not truncated and plan.peer_canary.encode("utf-8") in body
            ),
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(
            status=None,
            body_sha256="",
            captured_bytes=0,
            truncated=False,
            request_succeeded=False,
            owner_canary_observed=False,
            peer_canary_observed=False,
        )
    finally:
        if connection is not None:
            connection.close()


def _control_passes(observation: _Observation, expected: str) -> bool:
    expected_seen = (
        observation.owner_canary_observed
        if expected == "owner"
        else observation.peer_canary_observed
    )
    unexpected_seen = (
        observation.peer_canary_observed
        if expected == "owner"
        else observation.owner_canary_observed
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
    owner_control: _Observation,
    peer_control: _Observation,
    test: _Observation,
) -> tuple[str, str]:
    if not _control_passes(owner_control, "owner"):
        return "INCONCLUSIVE", "OWNER_CONTROL_FAILED"
    if not _control_passes(peer_control, "peer"):
        return "INCONCLUSIVE", "PEER_CONTROL_FAILED"
    if not test.request_succeeded:
        return "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    if test.truncated:
        return "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    if test.redirected:
        return "INCONCLUSIVE", "TEST_REDIRECTED"
    if (
        test.status is not None
        and 200 <= test.status <= 299
        and test.owner_canary_observed
    ):
        return "CONFIRMED_BY_INDUCTION", "PEER_OBSERVED_OWNER_CANARY"
    if test.status in _DENIAL_STATUSES and not test.owner_canary_observed:
        return "FALSIFIED", "PEER_ACCESS_DENIED"
    return "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"


def run_bola_experiment(
    plan: BolaPlan,
    *,
    owner: BearerCredential,
    peer: BearerCredential,
) -> dict[str, object]:
    """Run the controls and cross-principal probe, then emit a body-free receipt."""
    if not isinstance(plan, BolaPlan):
        raise TypeError("plan must be a BolaPlan")
    if not isinstance(owner, BearerCredential) or not isinstance(peer, BearerCredential):
        raise TypeError("owner and peer must be BearerCredential instances")
    if owner.principal_id == peer.principal_id:
        raise BolaPlanError("owner and peer principals must be distinct")

    parsed_origin = _parse_loopback_origin(plan.target_origin)
    owner_control = _observe(plan, parsed_origin, plan.owner_path, owner)
    peer_control = _observe(plan, parsed_origin, plan.peer_control_path, peer)
    test = _observe(plan, parsed_origin, plan.owner_path, peer)
    epistemic_level, reason_code = _adjudicate(
        owner_control, peer_control, test
    )

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-bola-differential",
        "target_origin": plan.target_origin,
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "prediction": (
            "If object authorization is missing, the peer identity will receive "
            "the owner-only marker from the owner object."
        ),
        "falsifier": (
            "Valid owner and peer controls followed by an authorization denial "
            "for the cross-principal read falsify this candidate for this object."
        ),
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "controls": {
            "owner_control_passed": _control_passes(owner_control, "owner"),
            "peer_control_passed": _control_passes(peer_control, "peer"),
        },
        "owner_control": owner_control.public(),
        "peer_control": peer_control.public(),
        "test": test.public(),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
        "candidate_provenance": (
            plan.candidate_handoff.to_receipt()
            if plan.candidate_handoff is not None
            else None
        ),
    }
