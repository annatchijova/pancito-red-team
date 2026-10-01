"""Bounded proof of an unauthenticated state change in a loopback lab.

The capability changes one top-level JSON marker through PATCH, verifies the
result through an authenticated read-back, and restores the operator-supplied
baseline before proceeding.  A 2xx response alone is never treated as proof.
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
from offensive.handoff import (
    StateChangeCandidateHandoff,
    state_change_path_matches_candidate_template,
)
from offensive.purple import exercise_marker, state_change_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_DENIAL_STATUSES = frozenset({401, 403, 404, 405})


class StateChangePlanError(ValueError):
    """The mutation experiment is ambiguous or outside its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise StateChangePlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise StateChangePlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise StateChangePlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise StateChangePlanError("target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise StateChangePlanError(
            "target_origin must use HTTP for this local-lab capability"
        )
    if parsed.username is not None or parsed.password is not None:
        raise StateChangePlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise StateChangePlanError(
            "target_origin must be an exact origin without path or query"
        )
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise StateChangePlanError("target_origin port is outside the valid range")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise StateChangePlanError(
            "target_origin must use a literal loopback IP address"
        ) from exc
    if not address.is_loopback:
        raise StateChangePlanError("target_origin must use a loopback IP address")
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
        raise StateChangePlanError(f"{name} must be a relative path without query")
    return path


@dataclass(frozen=True)
class StateChangePlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    resource_path: str
    readback_path: str
    marker_field: str
    baseline_marker: str = field(repr=False)
    control_marker: str = field(repr=False)
    anonymous_marker: str = field(repr=False)
    invalid_marker: str = field(repr=False)
    invalid_bearer: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384
    candidate_handoff: StateChangeCandidateHandoff | None = None

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise StateChangePlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}"
            )
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise StateChangePlanError("operator_acknowledged must be literal true")
        _loopback_origin(self.target_origin)
        resource_path = _relative_path(self.resource_path, "resource_path")
        _relative_path(self.readback_path, "readback_path")
        marker_field = _text(self.marker_field, "marker_field", 128)
        if not _FIELD_RE.fullmatch(marker_field):
            raise StateChangePlanError("marker_field is invalid")
        secrets = (
            _text(self.baseline_marker, "baseline_marker", 256),
            _text(self.control_marker, "control_marker", 256),
            _text(self.anonymous_marker, "anonymous_marker", 256),
            _text(self.invalid_marker, "invalid_marker", 256),
            _text(self.invalid_bearer, "invalid_bearer", 8_192),
        )
        if len(set(secrets)) != len(secrets):
            raise StateChangePlanError(
                "markers and invalid bearer must all be distinct"
            )
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise StateChangePlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise StateChangePlanError("timeout_ms must be between 100 and 10000")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
        ):
            raise StateChangePlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise StateChangePlanError(
                "max_response_bytes must be between 1024 and 1048576"
            )
        if self.candidate_handoff is not None:
            if not isinstance(self.candidate_handoff, StateChangeCandidateHandoff):
                raise StateChangePlanError(
                    "candidate_handoff must be a StateChangeCandidateHandoff"
                )
            if not state_change_path_matches_candidate_template(
                self.candidate_handoff, resource_path
            ):
                raise StateChangePlanError(
                    "resource path must match the PATCH candidate path template"
                )


@dataclass(frozen=True)
class _Observation:
    step: str
    method: str
    status: int | None
    request_succeeded: bool
    redirected: bool
    truncated: bool
    marker_state: str | None

    def public(self) -> dict[str, object]:
        return {
            "step": self.step,
            "method": self.method,
            "status": self.status,
            "request_succeeded": self.request_succeeded,
            "redirected": self.redirected,
            "truncated": self.truncated,
            "marker_state": self.marker_state,
        }


def _classify_marker(plan: StateChangePlan, body: bytes) -> str:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "UNREADABLE"
    if not isinstance(value, dict):
        return "OTHER"
    marker = value.get(plan.marker_field)
    if not isinstance(marker, str):
        return "OTHER"
    identities = {
        plan.baseline_marker: "BASELINE",
        plan.control_marker: "CONTROL",
        plan.anonymous_marker: "ANONYMOUS",
        plan.invalid_marker: "INVALID_BEARER",
    }
    return identities.get(marker, "OTHER")


def _request(
    plan: StateChangePlan,
    origin: SplitResult,
    *,
    step: str,
    method: str,
    bearer: str | None,
    marker: str | None = None,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port or 80,
            timeout=plan.timeout_ms / 1_000,
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "pancito-red-team/state-change-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "X-Pancito-Step": step,
        }
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        body = None
        path = plan.readback_path
        if method == "PATCH":
            path = plan.resource_path
            headers["Content-Type"] = "application/merge-patch+json"
            body = json.dumps(
                {plan.marker_field: marker},
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
        marker_state = None
        if method == "GET" and not truncated:
            marker_state = _classify_marker(plan, bounded)
        return _Observation(
            step=step,
            method=method,
            status=response.status,
            request_succeeded=True,
            redirected=300 <= response.status <= 399,
            truncated=truncated,
            marker_state=marker_state,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(
            step=step,
            method=method,
            status=None,
            request_succeeded=False,
            redirected=False,
            truncated=False,
            marker_state=None,
        )
    finally:
        if connection is not None:
            connection.close()


def _read(
    plan: StateChangePlan, origin: SplitResult, token: str, step: str
) -> _Observation:
    return _request(plan, origin, step=step, method="GET", bearer=token)


def _write(
    plan: StateChangePlan,
    origin: SplitResult,
    *,
    step: str,
    bearer: str | None,
    marker: str,
) -> _Observation:
    return _request(
        plan,
        origin,
        step=step,
        method="PATCH",
        bearer=bearer,
        marker=marker,
    )


def _usable(observation: _Observation) -> bool:
    return bool(
        observation.request_succeeded
        and not observation.redirected
        and not observation.truncated
        and observation.status is not None
    )


def _restore(
    plan: StateChangePlan,
    origin: SplitResult,
    token: str,
    label: str,
    observations: list[_Observation],
) -> bool:
    observations.append(
        _write(
            plan,
            origin,
            step=f"{label}_RESTORE",
            bearer=token,
            marker=plan.baseline_marker,
        )
    )
    observations.append(
        _read(plan, origin, token, step=f"{label}_RESTORE_VERIFY")
    )
    return bool(
        _usable(observations[-1])
        and observations[-1].marker_state == "BASELINE"
    )


def run_state_change_experiment(
    plan: StateChangePlan, *, observer: BearerCredential
) -> dict[str, object]:
    """Execute bounded PATCH/read-back cells and always attempt restoration."""
    if not isinstance(plan, StateChangePlan):
        raise TypeError("plan must be a StateChangePlan")
    if not isinstance(observer, BearerCredential):
        raise TypeError("observer must be a BearerCredential")
    all_secrets = {
        plan.baseline_marker,
        plan.control_marker,
        plan.anonymous_marker,
        plan.invalid_marker,
        plan.invalid_bearer,
        observer.token,
    }
    if len(all_secrets) != 6:
        raise StateChangePlanError(
            "observer token, invalid bearer, and markers must all be distinct"
        )
    origin = _loopback_origin(plan.target_origin)
    observations: list[_Observation] = []
    confirmed_cells: list[str] = []
    cell_outcomes: dict[str, str] = {}
    epistemic_level = "INCONCLUSIVE"
    reason_code = "INITIAL_READBACK_FAILED"
    cleanup_status = "NOT_REQUIRED"

    observations.append(_read(plan, origin, observer.token, "BASELINE_READ"))
    baseline = observations[-1]
    if _usable(baseline) and baseline.marker_state == "BASELINE":
        observations.append(
            _write(
                plan,
                origin,
                step="VALID_CREDENTIAL_CONTROL",
                bearer=observer.token,
                marker=plan.control_marker,
            )
        )
        observations.append(
            _read(plan, origin, observer.token, "VALID_CONTROL_READBACK")
        )
        control_ok = bool(
            _usable(observations[-2])
            and 200 <= int(observations[-2].status) <= 299
            and _usable(observations[-1])
            and observations[-1].marker_state == "CONTROL"
        )
        if not control_ok:
            reason_code = "VALID_CONTROL_FAILED"
            cleanup_status = (
                "RESTORED_TO_BASELINE"
                if _restore(
                    plan, origin, observer.token, "CONTROL", observations
                )
                else "MANUAL_ACTION_REQUIRED"
            )
        elif not _restore(plan, origin, observer.token, "CONTROL", observations):
            reason_code = "CONTROL_RESTORE_FAILED"
            cleanup_status = "MANUAL_ACTION_REQUIRED"
        else:
            cleanup_status = "RESTORED_TO_BASELINE"
            cells = (
                ("ANONYMOUS", None, plan.anonymous_marker, "ANONYMOUS"),
                (
                    "INVALID_BEARER",
                    plan.invalid_bearer,
                    plan.invalid_marker,
                    "INVALID_BEARER",
                ),
            )
            ambiguity: str | None = None
            for label, bearer, marker, expected_state in cells:
                observations.append(
                    _write(
                        plan,
                        origin,
                        step=f"{label}_TEST",
                        bearer=bearer,
                        marker=marker,
                    )
                )
                write_observation = observations[-1]
                observations.append(
                    _read(plan, origin, observer.token, f"{label}_READBACK")
                )
                readback = observations[-1]
                changed = _usable(readback) and readback.marker_state == expected_state
                denied = bool(
                    _usable(write_observation)
                    and write_observation.status in _DENIAL_STATUSES
                    and _usable(readback)
                    and readback.marker_state == "BASELINE"
                )
                needs_restore = not (
                    _usable(readback) and readback.marker_state == "BASELINE"
                )
                if changed:
                    confirmed_cells.append(label)
                    cell_outcomes[label] = "MUTATION_CONFIRMED"
                elif denied:
                    cell_outcomes[label] = "MUTATION_DENIED"
                else:
                    cell_outcomes[label] = "INCONCLUSIVE"
                    if ambiguity is None:
                        ambiguity = f"{label}_ORACLE_NOT_SATISFIED"
                if needs_restore:
                    if not _restore(
                        plan, origin, observer.token, label, observations
                    ):
                        ambiguity = f"{label}_RESTORE_FAILED"
                        cleanup_status = "MANUAL_ACTION_REQUIRED"
                        break
                    cleanup_status = "RESTORED_TO_BASELINE"

            if cleanup_status == "MANUAL_ACTION_REQUIRED":
                reason_code = ambiguity or "RESTORE_FAILED"
            elif confirmed_cells:
                epistemic_level = "CONFIRMED_BY_INDUCTION"
                reason_code = "_AND_".join(confirmed_cells) + "_MUTATION_CONFIRMED"
            elif ambiguity is not None:
                reason_code = ambiguity
            else:
                epistemic_level = "FALSIFIED"
                reason_code = "ANONYMOUS_AND_INVALID_BEARER_MUTATIONS_DENIED"
    elif _usable(baseline):
        reason_code = "BASELINE_MARKER_MISMATCH"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-public-state-change-differential",
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
        "threat_model": {
            "attacker_can": "send one anonymous or invalid-bearer PATCH",
            "attacker_cannot": (
                "read the marker secrets, alter the observer credential, or "
                "change the experiment code"
            ),
        },
        "prediction": (
            "If the public state-change surface permits the tested caller, the "
            "authenticated read-back will observe that caller's unique marker."
        ),
        "falsifier": (
            "A working authenticated control plus baseline-preserving denials for "
            "both negative cells falsifies this candidate for the tested field."
        ),
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "confirmed_cells": confirmed_cells,
        "cell_outcomes": cell_outcomes,
        "cleanup_status": cleanup_status,
        "final_state_verified": cleanup_status == "RESTORED_TO_BASELINE",
        "request_count": len(observations),
        "maximum_request_count": 13,
        "observations": [item.public() for item in observations],
        "candidate_provenance": (
            plan.candidate_handoff.to_receipt()
            if plan.candidate_handoff is not None
            else None
        ),
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": state_change_blue_objective(
            plan.experiment_id, tuple(item.step for item in observations)
        ),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
