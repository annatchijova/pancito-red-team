"""Bounded parser/storage differential using only synthetic inert uploads."""

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
from offensive.handoff import FileIngressCandidateHandoff, file_ingress_path_matches
from offensive.purple import exercise_marker, file_ingress_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DENIAL_STATUSES = frozenset({400, 413, 415, 422})
_ABSENT_STATUSES = frozenset({404, 410})


class FileIngressPlanError(ValueError):
    """The synthetic upload experiment is ambiguous or outside its boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise FileIngressPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise FileIngressPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise FileIngressPlanError(f"{name} contains control characters")
    return value


def _origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise FileIngressPlanError("target_origin is invalid") from exc
    if parsed.scheme != "http":
        raise FileIngressPlanError("target_origin must use HTTP for this local lab")
    if parsed.username is not None or parsed.password is not None:
        raise FileIngressPlanError("target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise FileIngressPlanError("target_origin must be an exact origin")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise FileIngressPlanError("target_origin port is invalid")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise FileIngressPlanError("target_origin must use a literal loopback IP") from exc
    if not address.is_loopback:
        raise FileIngressPlanError("target_origin must use a loopback IP")
    return parsed


def _path(value: object, name: str) -> str:
    raw = _text(value, name, 2_048)
    parsed = urlsplit(raw)
    if (
        not raw.startswith("/")
        or raw.startswith("//")
        or "\\" in raw
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise FileIngressPlanError(f"{name} must be a relative path without query")
    return raw


@dataclass(frozen=True)
class FileIngressPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    upload_path: str
    readback_path_template: str
    upload_field: str
    expected_max_bytes: int
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384
    candidate_handoff: FileIngressCandidateHandoff | None = None

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise FileIngressPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise FileIngressPlanError("operator_acknowledged must be literal true")
        _origin(self.target_origin)
        upload_path = _path(self.upload_path, "upload_path")
        template = _path(self.readback_path_template, "readback_path_template")
        if template.count("{upload_id}") != 1:
            raise FileIngressPlanError(
                "readback_path_template requires exactly one {upload_id} segment"
            )
        if "{upload_id}" not in template.split("/"):
            raise FileIngressPlanError("{upload_id} must occupy a whole path segment")
        field_name = _text(self.upload_field, "upload_field", 128)
        if not _FIELD_RE.fullmatch(field_name):
            raise FileIngressPlanError("upload_field is invalid")
        if isinstance(self.expected_max_bytes, bool) or not isinstance(
            self.expected_max_bytes, int
        ):
            raise FileIngressPlanError("expected_max_bytes must be an integer")
        if not 1_024 <= self.expected_max_bytes <= 65_536:
            raise FileIngressPlanError(
                "expected_max_bytes must be between 1024 and 65536"
            )
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise FileIngressPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise FileIngressPlanError("timeout_ms must be between 100 and 10000")
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes, int
        ):
            raise FileIngressPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise FileIngressPlanError("max_response_bytes is outside its bound")
        if self.candidate_handoff is not None:
            if not isinstance(self.candidate_handoff, FileIngressCandidateHandoff):
                raise FileIngressPlanError(
                    "candidate_handoff must be a FileIngressCandidateHandoff"
                )
            if not file_ingress_path_matches(self.candidate_handoff, upload_path):
                raise FileIngressPlanError(
                    "upload path must match the POST file-ingress candidate"
                )


@dataclass(frozen=True)
class _Sample:
    cell: str
    filename: str
    media_type: str
    content: bytes = field(repr=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class _Observation:
    step: str
    cell: str
    method: str
    status: int | None
    request_succeeded: bool
    redirected: bool
    truncated: bool
    upload_id_sha256: str | None = None
    stored_exactly: bool | None = None

    def public(self) -> dict[str, object]:
        return {
            "step": self.step,
            "cell": self.cell,
            "method": self.method,
            "status": self.status,
            "request_succeeded": self.request_succeeded,
            "redirected": self.redirected,
            "truncated": self.truncated,
            "upload_id_sha256": self.upload_id_sha256,
            "stored_exactly": self.stored_exactly,
        }


def _samples(plan: FileIngressPlan) -> tuple[_Sample, ...]:
    marker = exercise_marker(plan.experiment_id).encode("ascii")
    control = b"PANCITO-INERT-TEXT-V1\n" + marker + b"\n"
    mismatch = b"PANCITO-NOT-A-PNG-V1\n" + marker + b"\n"
    oversized = (b"PANCITO-INERT-OVERSIZE-V1\n" + marker + b"\n")
    oversized += b"X" * (plan.expected_max_bytes + 1 - len(oversized))
    return (
        _Sample("CONTROL", "control.txt", "text/plain", control),
        _Sample("TYPE_MISMATCH", "mismatch.png", "image/png", mismatch),
        _Sample(
            "OVERSIZE",
            "oversize.bin",
            "application/octet-stream",
            oversized,
        ),
    )


def _multipart(plan: FileIngressPlan, sample: _Sample) -> tuple[bytes, str]:
    suffix = hashlib.sha256(
        f"{plan.experiment_id}\x00{sample.cell}".encode("utf-8")
    ).hexdigest()[:24]
    boundary = f"PANCITO{suffix}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{plan.upload_field}"; '
        f'filename="{sample.filename}"\r\n'
        f"Content-Type: {sample.media_type}\r\n\r\n"
    ).encode("ascii")
    body = head + sample.content + f"\r\n--{boundary}--\r\n".encode("ascii")
    return body, boundary


def _connection(plan: FileIngressPlan, origin: SplitResult) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(
        origin.hostname, origin.port or 80, timeout=plan.timeout_ms / 1_000
    )


def _base_headers(plan: FileIngressPlan, step: str, token: str) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "pancito-red-team/file-ingress-lab",
        "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
        "X-Pancito-Step": step,
    }


def _bounded_response(response, maximum: int) -> tuple[bytes, bool]:
    captured = response.read(maximum + 1)
    return captured[:maximum], len(captured) > maximum


def _upload(
    plan: FileIngressPlan,
    origin: SplitResult,
    token: str,
    sample: _Sample,
) -> tuple[_Observation, str | None]:
    connection = _connection(plan, origin)
    step = f"{sample.cell}_UPLOAD"
    try:
        body, boundary = _multipart(plan, sample)
        headers = _base_headers(plan, step, token)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        headers["Content-Length"] = str(len(body))
        connection.request("POST", plan.upload_path, body=body, headers=headers)
        response = connection.getresponse()
        payload, truncated = _bounded_response(response, plan.max_response_bytes)
        upload_id = None
        if not truncated:
            try:
                decoded = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
            if isinstance(decoded, dict) and isinstance(decoded.get("upload_id"), str):
                candidate = decoded["upload_id"]
                if _ID_RE.fullmatch(candidate):
                    upload_id = candidate
        return _Observation(
            step, sample.cell, "POST", response.status, True,
            300 <= response.status <= 399, truncated,
            hashlib.sha256(upload_id.encode("utf-8")).hexdigest()
            if upload_id is not None else None,
        ), upload_id
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(step, sample.cell, "POST", None, False, False, False), None
    finally:
        connection.close()


def _resource_path(plan: FileIngressPlan, upload_id: str) -> str:
    if not _ID_RE.fullmatch(upload_id):
        raise FileIngressPlanError("upload_id is invalid")
    return plan.readback_path_template.replace("{upload_id}", upload_id)


def _readback(
    plan: FileIngressPlan,
    origin: SplitResult,
    token: str,
    sample: _Sample,
    upload_id: str,
    *,
    cleanup_verify: bool = False,
) -> _Observation:
    connection = _connection(plan, origin)
    step = f"{sample.cell}_{'CLEANUP_VERIFY' if cleanup_verify else 'READBACK'}"
    upload_hash = hashlib.sha256(upload_id.encode("utf-8")).hexdigest()
    try:
        connection.request(
            "GET", _resource_path(plan, upload_id),
            headers=_base_headers(plan, step, token),
        )
        response = connection.getresponse()
        payload, truncated = _bounded_response(response, plan.max_response_bytes)
        exact = None
        if cleanup_verify:
            exact = response.status in _ABSENT_STATUSES
        elif response.status == 200 and not truncated:
            try:
                metadata = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                metadata = None
            if isinstance(metadata, dict):
                size = metadata.get("size")
                digest = metadata.get("sha256")
                exact = bool(
                    not isinstance(size, bool)
                    and size == len(sample.content)
                    and isinstance(digest, str)
                    and _SHA256_RE.fullmatch(digest)
                    and digest == sample.sha256
                )
        return _Observation(
            step, sample.cell, "GET", response.status, True,
            300 <= response.status <= 399, truncated, upload_hash, exact,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(
            step, sample.cell, "GET", None, False, False, False, upload_hash, None
        )
    finally:
        connection.close()


def _delete(
    plan: FileIngressPlan,
    origin: SplitResult,
    token: str,
    sample: _Sample,
    upload_id: str,
) -> _Observation:
    connection = _connection(plan, origin)
    step = f"{sample.cell}_CLEANUP"
    upload_hash = hashlib.sha256(upload_id.encode("utf-8")).hexdigest()
    try:
        connection.request(
            "DELETE", _resource_path(plan, upload_id),
            headers=_base_headers(plan, step, token),
        )
        response = connection.getresponse()
        _, truncated = _bounded_response(response, plan.max_response_bytes)
        return _Observation(
            step, sample.cell, "DELETE", response.status, True,
            300 <= response.status <= 399, truncated, upload_hash,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(
            step, sample.cell, "DELETE", None, False, False, False, upload_hash
        )
    finally:
        connection.close()


def run_file_ingress_experiment(
    plan: FileIngressPlan, *, observer: BearerCredential
) -> dict[str, object]:
    """Run three inert cells; retained objects are always deleted and verified."""
    if not isinstance(plan, FileIngressPlan):
        raise TypeError("plan must be a FileIngressPlan")
    if not isinstance(observer, BearerCredential):
        raise TypeError("observer must be a BearerCredential")
    origin = _origin(plan.target_origin)
    observations: list[_Observation] = []
    outcomes: dict[str, str] = {}
    confirmed: list[str] = []
    cleanup_status = "NOT_REQUIRED"
    reason_code = "CONTROL_UPLOAD_FAILED"
    level = "INCONCLUSIVE"

    for sample in _samples(plan):
        upload, upload_id = _upload(plan, origin, observer.token, sample)
        observations.append(upload)
        denied = bool(
            upload.request_succeeded
            and not upload.redirected
            and not upload.truncated
            and upload.status in _DENIAL_STATUSES
            and upload_id is None
        )
        stored = False
        if upload_id is None and not denied:
            cleanup_status = "MANUAL_ACTION_REQUIRED"
            outcomes[sample.cell] = "INCONCLUSIVE"
            reason_code = f"{sample.cell}_UPLOAD_NOT_TRACKABLE"
            break
        if upload_id is not None:
            readback = _readback(plan, origin, observer.token, sample, upload_id)
            observations.append(readback)
            upload_accepted = bool(
                upload.request_succeeded
                and not upload.redirected
                and not upload.truncated
                and upload.status is not None
                and 200 <= upload.status <= 299
            )
            stored = upload_accepted and readback.stored_exactly is True
            observations.append(_delete(plan, origin, observer.token, sample, upload_id))
            cleanup_verify = _readback(
                plan, origin, observer.token, sample, upload_id, cleanup_verify=True
            )
            observations.append(cleanup_verify)
            if cleanup_verify.stored_exactly is not True:
                cleanup_status = "MANUAL_ACTION_REQUIRED"
                outcomes[sample.cell] = "INCONCLUSIVE"
                reason_code = f"{sample.cell}_CLEANUP_NOT_VERIFIED"
                break
            cleanup_status = "VERIFIED_ABSENT"

        if sample.cell == "CONTROL":
            if not stored:
                outcomes[sample.cell] = "CONTROL_FAILED"
                reason_code = "CONTROL_NOT_STORED_EXACTLY"
                break
            outcomes[sample.cell] = "STORED_EXACTLY"
            continue
        if stored:
            outcomes[sample.cell] = "STORED_EXACTLY"
            confirmed.append(sample.cell)
        elif denied:
            outcomes[sample.cell] = "REJECTED"
        else:
            outcomes[sample.cell] = "INCONCLUSIVE"

    if cleanup_status != "MANUAL_ACTION_REQUIRED" and outcomes.get("CONTROL") == "STORED_EXACTLY":
        if confirmed:
            level = "CONFIRMED_BY_INDUCTION"
            reason_code = "_AND_".join(confirmed) + "_STORED_EXACTLY"
        elif outcomes.get("TYPE_MISMATCH") == "REJECTED" and outcomes.get("OVERSIZE") == "REJECTED":
            level = "FALSIFIED"
            reason_code = "TYPE_MISMATCH_AND_OVERSIZE_REJECTED"
        else:
            reason_code = "ONE_OR_MORE_NEGATIVE_CELLS_INCONCLUSIVE"

    sample_facts = {
        sample.cell: {
            "filename": sample.filename,
            "declared_media_type": sample.media_type,
            "size": len(sample.content),
            "sha256": sample.sha256,
            "synthetic_inert": True,
        }
        for sample in _samples(plan)
    }
    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-file-ingress-differential",
        "target_origin": plan.target_origin,
        "upload_path": plan.upload_path,
        "method": "POST",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "threat_model": {
            "attacker_can": "submit bytes with misleading type or excess size",
            "attacker_cannot": (
                "choose arbitrary bytes, a remote target, an executable sample, "
                "or an unbounded upload size"
            ),
        },
        "prediction": (
            "If ingress validation disagrees with storage, authenticated metadata "
            "will reproduce the exact synthetic mismatch or oversize sample digest."
        ),
        "falsifier": (
            "A stored valid control followed by explicit rejection of both negative "
            "cells falsifies these candidates for the tested endpoint and policy."
        ),
        "epistemic_level": level,
        "reason_code": reason_code,
        "confirmed_cells": confirmed,
        "cell_outcomes": outcomes,
        "cleanup_status": cleanup_status,
        "final_absence_verified": cleanup_status in {"NOT_REQUIRED", "VERIFIED_ABSENT"},
        "request_count": len(observations),
        "maximum_request_count": 12,
        "expected_max_bytes": plan.expected_max_bytes,
        "samples": sample_facts,
        "observations": [item.public() for item in observations],
        "candidate_provenance": (
            plan.candidate_handoff.to_receipt()
            if plan.candidate_handoff is not None else None
        ),
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": file_ingress_blue_objective(
            plan.experiment_id, tuple(item.step for item in observations)
        ),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
