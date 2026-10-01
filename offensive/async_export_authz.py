"""Bounded lifecycle test for cross-tenant asynchronous export authorization."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import async_export_authz_blue_objective, exercise_marker

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIALS = frozenset({401, 403, 404})
_ABSENT = frozenset({404, 410})
_KNOWN_CREATE_REJECTIONS = frozenset({400, 401, 403, 404, 405, 409, 413, 415, 422})
_CREATE_BODY = b'{"format":"csv","scope":"current_tenant"}'


class AsyncExportAuthorizationPlanError(ValueError):
    """The asynchronous export experiment exceeds its declared boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AsyncExportAuthorizationPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise AsyncExportAuthorizationPlanError(f"{name} is outside its text boundary")
    return value


def _origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise AsyncExportAuthorizationPlanError("target_origin is invalid") from exc
    if (
        parsed.scheme != "http" or parsed.username is not None
        or parsed.password is not None or not parsed.hostname or parsed.path
        or parsed.query or parsed.fragment
    ):
        raise AsyncExportAuthorizationPlanError(
            "target_origin must be an exact HTTP origin without user information"
        )
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise AsyncExportAuthorizationPlanError(
            "target_origin must use a literal loopback IP"
        ) from exc
    if not address.is_loopback or not 1 <= (port or 80) <= 65_535:
        raise AsyncExportAuthorizationPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object, name: str) -> tuple[str, ...]:
    raw = _text(value, name, 2_048)
    parsed = urlsplit(raw)
    if (
        not raw.startswith("/") or raw.startswith("//") or "\\" in raw
        or "%" in raw or parsed.scheme or parsed.netloc or parsed.query
        or parsed.fragment
    ):
        raise AsyncExportAuthorizationPlanError(
            f"{name} must be an unencoded relative path without query"
        )
    parts = tuple(raw.split("/")[1:])
    if not parts or any(not item or item in {".", ".."} for item in parts):
        raise AsyncExportAuthorizationPlanError(f"{name} has ambiguous path segments")
    return parts


def _paired_paths(alpha_path: str, bravo_path: str, label: str) -> None:
    alpha, bravo = _path(alpha_path, f"alpha_{label}_path"), _path(
        bravo_path, f"bravo_{label}_path"
    )
    if len(alpha) != len(bravo):
        raise AsyncExportAuthorizationPlanError(f"{label} paths must have equal segments")
    differing = [index for index, pair in enumerate(zip(alpha, bravo, strict=True))
                 if pair[0] != pair[1]]
    if len(differing) != 1 or alpha[differing[0]] != "alpha" or bravo[differing[0]] != "bravo":
        raise AsyncExportAuthorizationPlanError(
            f"{label} paths may differ only at the literal tenant segment"
        )


@dataclass(frozen=True)
class AsyncExportAuthorizationPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    alpha_create_path: str
    bravo_create_path: str
    alpha_jobs_path: str
    bravo_jobs_path: str
    alpha_canary: str = field(repr=False)
    bravo_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 65_536

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise AsyncExportAuthorizationPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise AsyncExportAuthorizationPlanError("operator_acknowledged must be literal true")
        _origin(self.target_origin)
        _paired_paths(self.alpha_create_path, self.bravo_create_path, "create")
        _paired_paths(self.alpha_jobs_path, self.bravo_jobs_path, "jobs")
        if _path(self.alpha_create_path, "alpha_create_path") != _path(
            self.alpha_jobs_path, "alpha_jobs_path"
        ):
            raise AsyncExportAuthorizationPlanError(
                "create and job paths must share the same tenant route base"
            )
        alpha_canary = _text(self.alpha_canary, "alpha_canary", 256)
        bravo_canary = _text(self.bravo_canary, "bravo_canary", 256)
        if alpha_canary == bravo_canary:
            raise AsyncExportAuthorizationPlanError("tenant canaries must differ")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise AsyncExportAuthorizationPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise AsyncExportAuthorizationPlanError("timeout_ms is outside the safe range")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes, int
        ):
            raise AsyncExportAuthorizationPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise AsyncExportAuthorizationPlanError("max_response_bytes is outside the safe range")


@dataclass(frozen=True)
class _Response:
    status: int | None
    body: bytes = field(repr=False)
    request_succeeded: bool = False
    truncated: bool = False


@dataclass(frozen=True)
class _Event:
    step: str
    method: str
    status: int | None
    request_succeeded: bool
    truncated: bool
    oracle_satisfied: bool | None = None
    canary_observed: bool | None = None
    other_tenant_canary_observed: bool | None = None
    job_id_sha256: str | None = None
    response_capture_sha256: str = ""

    def public(self) -> dict[str, object]:
        return {
            "step": self.step, "method": self.method, "status": self.status,
            "request_succeeded": self.request_succeeded, "truncated": self.truncated,
            "oracle_satisfied": self.oracle_satisfied,
            "canary_observed": self.canary_observed,
            "other_tenant_canary_observed": self.other_tenant_canary_observed,
            "job_id_sha256": self.job_id_sha256,
            "response_capture_sha256": self.response_capture_sha256,
        }


def _request(
    plan: AsyncExportAuthorizationPlan, origin: SplitResult, method: str, path: str,
    credential: BearerCredential, body: bytes | None = None,
) -> _Response:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname, origin.port or 80, timeout=plan.timeout_ms / 1_000
        )
        headers = {
            "Authorization": f"Bearer {credential.token}",
            "Accept": "application/json, text/csv;q=0.9",
            "User-Agent": "pancito-red-team/async-export-authz-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        return _Response(response.status, captured[:plan.max_response_bytes], True,
                         len(captured) > plan.max_response_bytes)
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Response(None, b"")
    finally:
        if connection is not None:
            connection.close()


def _json_object(raw: bytes) -> dict[str, object] | None:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    def reject_number(_value):
        raise ValueError("non-integer JSON number")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                            parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None
    return result if isinstance(result, dict) else None


def _create_job(plan, origin, tenant: str, credential: BearerCredential) -> tuple[_Event, str | None]:
    path = plan.alpha_create_path if tenant == "alpha" else plan.bravo_create_path
    response = _request(plan, origin, "POST", path, credential, _CREATE_BODY)
    payload = _json_object(response.body) if response.request_succeeded and not response.truncated else None
    job_id = payload.get("job_id") if payload is not None else None
    ready = bool(response.status == 201 and payload is not None
                 and set(payload) == {"job_id", "status"}
                 and payload.get("status") == "READY")
    if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
        job_id = None
    return _Event(
        f"{tenant.upper()}_JOB_CREATE", "POST", response.status,
        response.request_succeeded, response.truncated,
        oracle_satisfied=ready,
        job_id_sha256=hashlib.sha256(job_id.encode()).hexdigest() if job_id else None,
        response_capture_sha256=hashlib.sha256(response.body).hexdigest(),
    ), job_id


def _status_control(plan, origin, tenant: str, job_id: str,
                    credential: BearerCredential) -> _Event:
    base = plan.alpha_jobs_path if tenant == "alpha" else plan.bravo_jobs_path
    response = _request(plan, origin, "GET", f"{base}/{job_id}", credential)
    payload = _json_object(response.body) if response.request_succeeded and not response.truncated else None
    ready = bool(response.status is not None and 200 <= response.status < 300
                 and payload is not None and set(payload) == {"job_id", "status"}
                 and payload.get("job_id") == job_id and payload.get("status") == "READY")
    return _Event(
        f"{tenant.upper()}_JOB_STATUS_CONTROL", "GET", response.status,
        response.request_succeeded, response.truncated,
        oracle_satisfied=ready,
        job_id_sha256=hashlib.sha256(job_id.encode()).hexdigest(),
        response_capture_sha256=hashlib.sha256(response.body).hexdigest(),
    )


def _download(plan, origin, tenant: str, job_id: str,
              credential: BearerCredential, step: str, expected_canary: str,
              other_tenant_canary: str) -> _Event:
    base = plan.alpha_jobs_path if tenant == "alpha" else plan.bravo_jobs_path
    response = _request(plan, origin, "GET", f"{base}/{job_id}/download", credential)
    found = bool(response.request_succeeded and not response.truncated
                 and expected_canary.encode("utf-8") in response.body)
    found_other = bool(response.request_succeeded and not response.truncated
                       and other_tenant_canary.encode("utf-8") in response.body)
    return _Event(
        step, "GET", response.status, response.request_succeeded, response.truncated,
        oracle_satisfied=found,
        canary_observed=found,
        other_tenant_canary_observed=found_other,
        job_id_sha256=hashlib.sha256(job_id.encode()).hexdigest(),
        response_capture_sha256=hashlib.sha256(response.body).hexdigest(),
    )


def _delete_and_verify(plan, origin, tenant: str, job_id: str,
                       credential: BearerCredential) -> tuple[_Event, _Event, bool]:
    base = plan.alpha_jobs_path if tenant == "alpha" else plan.bravo_jobs_path
    deleted = _request(plan, origin, "DELETE", f"{base}/{job_id}", credential)
    delete_event = _Event(
        f"{tenant.upper()}_JOB_CLEANUP", "DELETE", deleted.status,
        deleted.request_succeeded, deleted.truncated,
        job_id_sha256=hashlib.sha256(job_id.encode()).hexdigest(),
        response_capture_sha256=hashlib.sha256(deleted.body).hexdigest(),
    )
    verified = _request(plan, origin, "GET", f"{base}/{job_id}", credential)
    absent = verified.request_succeeded and not verified.truncated and verified.status in _ABSENT
    verify_event = _Event(
        f"{tenant.upper()}_JOB_CLEANUP_VERIFY", "GET", verified.status,
        verified.request_succeeded, verified.truncated,
        oracle_satisfied=absent,
        job_id_sha256=hashlib.sha256(job_id.encode()).hexdigest(),
        response_capture_sha256=hashlib.sha256(verified.body).hexdigest(),
    )
    return delete_event, verify_event, absent


def run_async_export_authorization_experiment(
    plan: AsyncExportAuthorizationPlan, *, alpha: BearerCredential,
    bravo: BearerCredential,
) -> dict[str, object]:
    """Create two disposable jobs, replay one download, then delete and verify both."""
    if not isinstance(plan, AsyncExportAuthorizationPlan):
        raise TypeError("plan must be an AsyncExportAuthorizationPlan")
    if not isinstance(alpha, BearerCredential) or not isinstance(bravo, BearerCredential):
        raise TypeError("alpha and bravo must be BearerCredential values")
    if alpha.principal_id == bravo.principal_id or alpha.token == bravo.token:
        raise AsyncExportAuthorizationPlanError("tenant credentials must differ")
    if len({alpha.token, bravo.token, plan.alpha_canary, plan.bravo_canary}) != 4:
        raise AsyncExportAuthorizationPlanError("credentials and canaries must all differ")

    origin = _origin(plan.target_origin)
    events: list[_Event] = []
    jobs: list[tuple[str, str, BearerCredential]] = []
    unknown_created_jobs = 0
    alpha_create, alpha_job = _create_job(plan, origin, "alpha", alpha)
    events.append(alpha_create)
    if alpha_job is not None:
        jobs.append(("alpha", alpha_job, alpha))
    elif not alpha_create.request_succeeded or alpha_create.status not in _KNOWN_CREATE_REJECTIONS:
        unknown_created_jobs += 1
    bravo_create, bravo_job = _create_job(plan, origin, "bravo", bravo)
    events.append(bravo_create)
    if bravo_job is not None:
        jobs.append(("bravo", bravo_job, bravo))
    elif not bravo_create.request_succeeded or bravo_create.status not in _KNOWN_CREATE_REJECTIONS:
        unknown_created_jobs += 1

    alpha_status = alpha_download = bravo_status = bravo_download = test = None
    if alpha_job is not None:
        alpha_status = _status_control(plan, origin, "alpha", alpha_job, alpha)
        events.append(alpha_status)
        alpha_download = _download(plan, origin, "alpha", alpha_job, alpha,
                                   "ALPHA_JOB_DOWNLOAD_CONTROL", plan.alpha_canary,
                                   plan.bravo_canary)
        events.append(alpha_download)
    if bravo_job is not None:
        bravo_status = _status_control(plan, origin, "bravo", bravo_job, bravo)
        events.append(bravo_status)
        bravo_download = _download(plan, origin, "bravo", bravo_job, bravo,
                                   "BRAVO_JOB_DOWNLOAD_CONTROL", plan.bravo_canary,
                                   plan.alpha_canary)
        events.append(bravo_download)
    if bravo_job is not None and alpha_job is not None:
        test = _download(plan, origin, "bravo", bravo_job, alpha,
                         "CROSS_TENANT_JOB_DOWNLOAD_TEST", plan.bravo_canary,
                         plan.alpha_canary)
        events.append(test)
        bravo_post_test = _download(
            plan, origin, "bravo", bravo_job, bravo,
            "BRAVO_JOB_POST_TEST_DOWNLOAD_CONTROL", plan.bravo_canary,
            plan.alpha_canary,
        )
        events.append(bravo_post_test)
    else:
        bravo_post_test = None

    cleanup_failures = 0
    for tenant, job_id, credential in jobs:
        deleted, verified, absent = _delete_and_verify(plan, origin, tenant, job_id, credential)
        events.extend((deleted, verified))
        cleanup_failures += int(not absent)

    if alpha_job is None or not alpha_create.oracle_satisfied:
        level, reason = "INCONCLUSIVE", "ALPHA_JOB_CREATE_FAILED"
    elif bravo_job is None or not bravo_create.oracle_satisfied:
        level, reason = "INCONCLUSIVE", "BRAVO_JOB_CREATE_FAILED"
    elif alpha_status is None or not alpha_status.oracle_satisfied:
        level, reason = "INCONCLUSIVE", "ALPHA_JOB_CONTROL_FAILED"
    elif (alpha_download is None or not alpha_download.oracle_satisfied
          or alpha_download.status is None or not 200 <= alpha_download.status < 300):
        level, reason = "INCONCLUSIVE", "ALPHA_DOWNLOAD_CONTROL_FAILED"
    elif bravo_status is None or not bravo_status.oracle_satisfied:
        level, reason = "INCONCLUSIVE", "BRAVO_JOB_CONTROL_FAILED"
    elif (bravo_download is None or not bravo_download.oracle_satisfied
          or bravo_download.status is None or not 200 <= bravo_download.status < 300):
        level, reason = "INCONCLUSIVE", "BRAVO_DOWNLOAD_CONTROL_FAILED"
    elif test is None or not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    elif test.oracle_satisfied:
        level, reason = "CONFIRMED_BY_INDUCTION", "ALPHA_OBSERVED_BRAVO_ASYNC_EXPORT_CANARY"
    elif test.status in _DENIALS and bravo_post_test is not None and bravo_post_test.oracle_satisfied:
        level, reason = "FALSIFIED", "ALPHA_BRAVO_ASYNC_EXPORT_DENIED"
    elif test.status in _DENIALS:
        level, reason = "INCONCLUSIVE", "BRAVO_POST_TEST_CONTROL_FAILED"
    else:
        level, reason = "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"

    request_count = len(events)
    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-async-export-authorization-lifecycle",
        "target_origin": plan.target_origin,
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "authorization_surface": {
            "actor": "AUTHENTICATED_TENANT_ALPHA",
            "resource": "TENANT_BRAVO_ASYNC_EXPORT_JOB",
            "action": "READ_AND_DOWNLOAD",
        },
        "method": "MIXED",
        "epistemic_level": level,
        "reason_code": reason,
        "cleanup_status": "MANUAL_ACTION_REQUIRED" if cleanup_failures or unknown_created_jobs else "RESTORED_TO_BASELINE",
        "manual_cleanup_count": cleanup_failures + unknown_created_jobs,
        "events": [event.public() for event in events],
        "request_count": request_count,
        "maximum_request_count": 12,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": async_export_authz_blue_objective(plan.experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
