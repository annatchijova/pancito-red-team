"""Bounded CORS-origin-trust differential for a loopback lab.

Idea credit: the specific CORS bug class this module tests -- a server that
reflects an arbitrary request ``Origin`` back in ``Access-Control-Allow-Origin``
instead of checking it against an allowlist, sometimes paired with
``Access-Control-Allow-Credentials: true`` -- is the headline check in
chenjj/CORScanner (MIT). No code was ported; this module reimplements the
idea as a bounded, two-request Red/Blue differential in PANCITO's own style.
See ``ATTRIBUTIONS.md``.

The falsifiable question: does the server trust the *value of the Origin
header itself* as a credential, echoing it back verbatim instead of checking
it against a real allowlist? A baseline request with no ``Origin`` header
establishes that the probe path answers cleanly; a second request carries a
canary origin the application has never seen. The oracle reads
``Access-Control-Allow-Origin`` the way a browser's CORS algorithm does --
an exact origin match or the literal wildcard ``*`` -- never a substring
check, because a value that merely *contains* the canary is not the same as
a value that *is* the canary.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from offensive.purple import cors_misconfiguration_blue_objective, exercise_marker


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class CorsMisconfigurationPlanError(ValueError):
    """The CORS-origin-trust experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CorsMisconfigurationPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise CorsMisconfigurationPlanError(f"{name} is outside its text boundary")
    return value


def _bare_origin(raw: str) -> SplitResult | None:
    """Parse text as a bare origin: scheme + host[:port], nothing else.

    Returns ``None`` -- never raises -- when the text is not a clean origin,
    because this is also used to read an untrusted response header, and a
    malformed header is evidence, not a crash.
    """
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if (parsed.scheme not in ("http", "https") or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        return None
    try:
        parsed.port
    except ValueError:
        return None
    return parsed


def _origin_key(parsed: SplitResult) -> tuple[str, str, int]:
    default_port = 443 if parsed.scheme == "https" else 80
    return (parsed.scheme, parsed.hostname.lower(), parsed.port or default_port)


def _target_origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    parsed = _bare_origin(raw)
    if parsed is None or parsed.scheme != "http":
        raise CorsMisconfigurationPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise CorsMisconfigurationPlanError("target_origin must use literal loopback") from exc
    effective_port = parsed.port if parsed.port is not None else 80
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise CorsMisconfigurationPlanError("target_origin must use valid loopback")
    return parsed


def _canary_origin(value: object, target: SplitResult) -> SplitResult:
    raw = _text(value, "canary_origin", 512)
    parsed = _bare_origin(raw)
    if parsed is None:
        raise CorsMisconfigurationPlanError("canary_origin must be a bare http(s) origin")
    if _origin_key(parsed) == _origin_key(target):
        raise CorsMisconfigurationPlanError("canary_origin must differ from target_origin")
    return parsed


def _path(value: object) -> str:
    raw = _text(value, "probe_path", 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise CorsMisconfigurationPlanError("probe_path must be a relative path without query")
    return raw


@dataclass(frozen=True)
class CorsMisconfigurationPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    probe_path: str
    canary_origin: str
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise CorsMisconfigurationPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise CorsMisconfigurationPlanError("operator_acknowledged must be literal true")
        target = _target_origin(self.target_origin)
        _canary_origin(self.canary_origin, target)
        _path(self.probe_path)
        if (isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int)
                or not 100 <= self.timeout_ms <= 10_000):
            raise CorsMisconfigurationPlanError("timeout_ms is invalid")
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or not 1_024 <= self.max_response_bytes <= 1_048_576):
            raise CorsMisconfigurationPlanError("max_response_bytes is invalid")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    allow_origin: str | None
    allow_credentials: str | None
    truncated: bool
    request_succeeded: bool

    def public(self) -> dict[str, object]:
        return {"status": self.status, "allow_origin": self.allow_origin,
                "allow_credentials": self.allow_credentials,
                "truncated": self.truncated, "request_succeeded": self.request_succeeded}


def _observe(plan: CorsMisconfigurationPlan, target: SplitResult,
             origin_header: str | None) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(
            target.hostname,
            target.port if target.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        headers = {
            "User-Agent": "pancito-red-team/cors-misconfiguration-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
        }
        if origin_header is not None:
            headers["Origin"] = origin_header
        connection.request("GET", plan.probe_path, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        return _Observation(
            response.status,
            response.getheader("Access-Control-Allow-Origin"),
            response.getheader("Access-Control-Allow-Credentials"),
            truncated, True,
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, None, None, False, False)
    finally:
        if connection is not None:
            connection.close()


def run_cors_misconfiguration_experiment(plan: CorsMisconfigurationPlan) -> dict[str, object]:
    if not isinstance(plan, CorsMisconfigurationPlan):
        raise TypeError("plan must be a CorsMisconfigurationPlan")
    target = _target_origin(plan.target_origin)
    canary = _canary_origin(plan.canary_origin, target)

    baseline = _observe(plan, target, None)
    test = _observe(plan, target, plan.canary_origin)
    baseline_passed = baseline.request_succeeded and not baseline.truncated

    credentials_exposed = test.allow_credentials == "true"

    if not baseline.request_succeeded:
        level, reason = "INCONCLUSIVE", "BASELINE_CONTROL_FAILED"
    elif baseline.truncated:
        level, reason = "INCONCLUSIVE", "BASELINE_RESPONSE_TRUNCATED"
    elif not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    elif not test.allow_origin:
        level, reason = "FALSIFIED", "CORS_ORIGIN_NOT_REFLECTED"
    elif test.allow_origin == "*":
        level, reason = "FALSIFIED", "CORS_WILDCARD_NOT_ORIGIN_SPECIFIC"
    else:
        parsed_reflection = _bare_origin(test.allow_origin)
        if parsed_reflection is None:
            level, reason = "INCONCLUSIVE", "TEST_ORIGIN_UNPARSEABLE"
        elif _origin_key(parsed_reflection) == _origin_key(canary):
            level, reason = "CONFIRMED_BY_INDUCTION", "ARBITRARY_ORIGIN_REFLECTED"
        else:
            level, reason = "FALSIFIED", "CORS_ORIGIN_NOT_REFLECTED"

    if level != "CONFIRMED_BY_INDUCTION":
        credentials_exposed = False

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-cors-origin-trust-differential",
        "target_origin": plan.target_origin, "method": "GET",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "canary_origin": plan.canary_origin,
        "prediction": ("If the server reflects the request Origin instead of checking it "
                        "against a real allowlist, Access-Control-Allow-Origin echoes the "
                        "canary origin verbatim."),
        "falsifier": ("Access-Control-Allow-Origin is absent, is the literal wildcard, or "
                       "names an origin other than the canary."),
        "epistemic_level": level, "reason_code": reason,
        "credentials_exposed": credentials_exposed,
        "controls": {"baseline_control_passed": baseline_passed},
        "baseline_control": baseline.public(), "test": test.public(),
        "request_count": 2, "maximum_request_count": 2,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": cors_misconfiguration_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
