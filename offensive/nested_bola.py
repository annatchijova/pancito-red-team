"""Bounded nested-resource authorization differential for a loopback lab.

The negative cell keeps the owner credential and parent identifier fixed while
substituting only a peer-owned child identifier.  A response status never proves
cross-parent disclosure; the peer child's canary must be observed in the body.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import exercise_marker, nested_bola_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL_STATUSES = frozenset({401, 403, 404})


class NestedBolaPlanError(ValueError):
    """The nested-resource experiment is ambiguous or outside its boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise NestedBolaPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise NestedBolaPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise NestedBolaPlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise NestedBolaPlanError("target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise NestedBolaPlanError("target_origin must use HTTP for this local lab")
    if parsed.username is not None or parsed.password is not None:
        raise NestedBolaPlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise NestedBolaPlanError("target_origin must be an exact origin")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise NestedBolaPlanError("target_origin port is invalid")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise NestedBolaPlanError("target_origin must use a literal loopback IP") from exc
    if not address.is_loopback:
        raise NestedBolaPlanError("target_origin must use a loopback IP")
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
        raise NestedBolaPlanError(f"{name} must be an unencoded relative path")
    segments = tuple(path.split("/")[1:])
    if not segments or any(not segment or segment in {".", ".."} for segment in segments):
        raise NestedBolaPlanError(f"{name} contains ambiguous path segments")
    return segments


@dataclass(frozen=True)
class NestedBolaPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    owner_control_path: str
    peer_control_path: str
    cross_child_path: str
    parent_segment_index: int
    child_segment_index: int
    owner_canary: str = field(repr=False)
    peer_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise NestedBolaPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise NestedBolaPlanError("operator_acknowledged must be literal true")
        _loopback_origin(self.target_origin)
        owner = _path_segments(self.owner_control_path, "owner_control_path")
        peer = _path_segments(self.peer_control_path, "peer_control_path")
        cross = _path_segments(self.cross_child_path, "cross_child_path")
        indexes = (self.parent_segment_index, self.child_segment_index)
        if any(isinstance(index, bool) or not isinstance(index, int) for index in indexes):
            raise NestedBolaPlanError("path segment indexes must be integers")
        if not 0 <= indexes[0] < indexes[1] < len(owner):
            raise NestedBolaPlanError(
                "segment indexes must identify parent before child within the path"
            )
        if len({len(owner), len(peer), len(cross)}) != 1:
            raise NestedBolaPlanError("all paths must have the same segment count")
        parent_index, child_index = indexes
        for index in range(len(owner)):
            if index not in indexes and not owner[index] == peer[index] == cross[index]:
                raise NestedBolaPlanError("only parent and child segments may differ")
        if owner[parent_index] == peer[parent_index]:
            raise NestedBolaPlanError("owner and peer parent identifiers must differ")
        if owner[child_index] == peer[child_index]:
            raise NestedBolaPlanError("owner and peer child identifiers must differ")
        if cross[parent_index] != owner[parent_index]:
            raise NestedBolaPlanError("negative cell must retain the owner parent")
        if cross[child_index] != peer[child_index]:
            raise NestedBolaPlanError("negative cell must substitute only the peer child")
        owner_canary = _text(self.owner_canary, "owner_canary", 256)
        peer_canary = _text(self.peer_canary, "peer_canary", 256)
        if owner_canary == peer_canary:
            raise NestedBolaPlanError("owner and peer canaries must be distinct")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise NestedBolaPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise NestedBolaPlanError("timeout_ms must be between 100 and 10000")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes, int
        ):
            raise NestedBolaPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise NestedBolaPlanError("max_response_bytes is outside the safe range")


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
    plan: NestedBolaPlan,
    origin: SplitResult,
    path: str,
    credential: BearerCredential,
    step: str,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname, origin.port or 80, timeout=plan.timeout_ms / 1_000
        )
        connection.request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {credential.token}",
                "Accept": "application/json",
                "User-Agent": "pancito-red-team/nested-bola-lab",
                "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
                "X-Pancito-Step": step,
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
            owner_canary_observed=(
                not truncated and plan.owner_canary.encode("utf-8") in body
            ),
            peer_canary_observed=(
                not truncated and plan.peer_canary.encode("utf-8") in body
            ),
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, "", 0, False, False, False, False)
    finally:
        if connection is not None:
            connection.close()


def _control_passes(item: _Observation, expected: str) -> bool:
    expected_seen = (
        item.owner_canary_observed if expected == "owner" else item.peer_canary_observed
    )
    unexpected_seen = (
        item.peer_canary_observed if expected == "owner" else item.owner_canary_observed
    )
    return bool(
        item.request_succeeded
        and item.status is not None
        and 200 <= item.status <= 299
        and not item.truncated
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
        and test.peer_canary_observed
        and not test.owner_canary_observed
    ):
        return "CONFIRMED_BY_INDUCTION", "FOREIGN_CHILD_CANARY_OBSERVED"
    if test.status in _DENIAL_STATUSES and not test.peer_canary_observed:
        return "FALSIFIED", "CROSS_PARENT_CHILD_ACCESS_DENIED"
    return "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"


def run_nested_bola_experiment(
    plan: NestedBolaPlan,
    *,
    owner: BearerCredential,
    peer: BearerCredential,
) -> dict[str, object]:
    """Run two controls and one child-only substitution request."""
    if not isinstance(plan, NestedBolaPlan):
        raise TypeError("plan must be a NestedBolaPlan")
    if not isinstance(owner, BearerCredential) or not isinstance(peer, BearerCredential):
        raise TypeError("owner and peer must be BearerCredential values")
    if owner.principal_id == peer.principal_id or owner.token == peer.token:
        raise NestedBolaPlanError("owner and peer credentials must be distinct")
    if len({owner.token, peer.token, plan.owner_canary, plan.peer_canary}) != 4:
        raise NestedBolaPlanError("credentials and canaries must all be distinct")
    origin = _loopback_origin(plan.target_origin)
    owner_control = _observe(
        plan, origin, plan.owner_control_path, owner, "OWNER_NESTED_CONTROL"
    )
    peer_control = _observe(
        plan, origin, plan.peer_control_path, peer, "PEER_NESTED_CONTROL"
    )
    test = _observe(
        plan, origin, plan.cross_child_path, owner, "CROSS_CHILD_TEST"
    )
    level, reason = _adjudicate(owner_control, peer_control, test)
    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-nested-bola-differential",
        "target_origin": plan.target_origin,
        "method": "GET",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "authorization_surface": {
            "actor": "AUTHENTICATED_OWNER",
            "resource": "PEER_CHILD_UNDER_OWNER_PARENT",
            "action": "READ",
            "changed_dimension": "CHILD_ID_ONLY",
        },
        "invariant": "parent(returned_child) == parent(authorised_path)",
        "prediction": (
            "If child authorization is resolved globally, the owner identity will "
            "receive the peer child's canary under the owner's parent path."
        ),
        "falsifier": (
            "Both controls succeed and the child-only substitution is denied without "
            "returning the peer child's canary."
        ),
        "epistemic_level": level,
        "reason_code": reason,
        "controls": {
            "owner_control_passed": _control_passes(owner_control, "owner"),
            "peer_control_passed": _control_passes(peer_control, "peer"),
        },
        "owner_control": owner_control.public(),
        "peer_control": peer_control.public(),
        "test": test.public(),
        "request_count": 3,
        "maximum_request_count": 3,
        "blue_objective": nested_bola_blue_objective(plan.experiment_id),
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
