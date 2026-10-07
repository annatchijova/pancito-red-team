"""Bounded forwarded-metadata redirect-authority differential for a loopback lab.

Some reverse-proxy-aware code builds an absolute redirect URL from request
metadata it trusts without validating it against the application's own
canonical origin: the literal ``Host`` header, or a comma-joined
``X-Forwarded-Proto`` value taken at face value. This experiment asks one
falsifiable question: does a value the client controls become the *authority*
of a server-issued ``Location`` header, as resolved by a real URL parser --
never by a substring match, because the checkpoint and the eventual consumer
(a browser, a link-following client) are two different parsers and the bug
lives in where they disagree.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from offensive.purple import exercise_marker, forwarded_redirect_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# Closed capability catalogue: only the header mechanisms this experiment
# actually knows how to craft a canary injection for. Not a free-form header
# name -- the plan never lets the operator choose an arbitrary header.
_HEADER_STRATEGIES = ("Host", "X-Forwarded-Proto")


class ForwardedRedirectPlanError(ValueError):
    """The forwarded-metadata redirect experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ForwardedRedirectPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise ForwardedRedirectPlanError(f"{name} is outside its text boundary")
    return value


def _origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed, port = urlsplit(raw), urlsplit(raw).port
    except ValueError as exc:
        raise ForwardedRedirectPlanError("target_origin is invalid") from exc
    if (parsed.scheme != "http" or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        raise ForwardedRedirectPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ForwardedRedirectPlanError("target_origin must use literal loopback") from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise ForwardedRedirectPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object, name: str) -> str:
    raw = _text(value, name, 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise ForwardedRedirectPlanError(f"{name} must be a relative path without query")
    return raw


def _hostname(value: object, name: str) -> str:
    raw = _text(value, name, 253)
    if not _HOSTNAME_RE.fullmatch(raw):
        raise ForwardedRedirectPlanError(f"{name} must be a syntactically valid hostname")
    return raw


@dataclass(frozen=True)
class ForwardedRedirectPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    redirect_path: str
    forwarded_header_name: str
    canary_host: str
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise ForwardedRedirectPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise ForwardedRedirectPlanError("operator_acknowledged must be literal true")
        origin = _origin(self.target_origin)
        _path(self.redirect_path, "redirect_path")
        if self.forwarded_header_name not in _HEADER_STRATEGIES:
            raise ForwardedRedirectPlanError("forwarded_header_name is not a bounded strategy")
        canary = _hostname(self.canary_host, "canary_host")
        if canary.lower() == origin.hostname.lower():
            raise ForwardedRedirectPlanError("canary_host must differ from target_origin")
        if (isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int)
                or not 100 <= self.timeout_ms <= 10_000):
            raise ForwardedRedirectPlanError("timeout_ms is invalid")
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or not 1_024 <= self.max_response_bytes <= 1_048_576):
            raise ForwardedRedirectPlanError("max_response_bytes is invalid")


def _injected_headers(plan: ForwardedRedirectPlan) -> dict[str, str]:
    """The exact, bounded header construction for each closed strategy.

    The operator never supplies a header value directly -- only a bare
    ``canary_host`` and a strategy name. This is what turns that canary into
    the probe for each mechanism this module knows how to test.
    """
    if plan.forwarded_header_name == "Host":
        return {"Host": plan.canary_host}
    if plan.forwarded_header_name == "X-Forwarded-Proto":
        # The scheme-smuggling construction: a forwarded-proto value that
        # already contains its own "://authority" collapses, under a
        # standards-compliant URL parser, into an absolute URL whose
        # authority is the smuggled host and whose original path becomes
        # harmless path text.
        return {"X-Forwarded-Proto": f"https://{plan.canary_host},https"}
    raise AssertionError("unreachable: forwarded_header_name is bounded at construction")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    location: str | None
    resolved_authority: str | None
    redirect_has_authority: bool
    truncated: bool
    request_succeeded: bool

    @property
    def redirected(self) -> bool:
        return self.status is not None and 300 <= self.status <= 399

    def public(self) -> dict[str, object]:
        return {"status": self.status, "location": self.location,
                "resolved_authority": self.resolved_authority,
                "redirect_has_authority": self.redirect_has_authority,
                "truncated": self.truncated, "request_succeeded": self.request_succeeded,
                "redirected": self.redirected}


def _resolve_authority(location: str | None) -> tuple[str | None, bool]:
    """Resolve a Location header the way a standards-compliant client would.

    This must use a real URL parser, never a substring check: the whole point
    of the bug class is that a naive check at the checkpoint and a real parse
    at the consumer (the browser) can disagree. An empty ``netloc`` means the
    reference is relative -- there is no authority to have been hijacked.
    """
    if not location:
        return None, False
    split = urlsplit(location)
    if not split.netloc:
        return None, False
    hostname = split.hostname
    return (hostname.lower() if hostname else None), True


def _observe(plan: ForwardedRedirectPlan, origin: SplitResult,
             headers: dict[str, str]) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port if origin.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        request_headers = {
            "User-Agent": "pancito-red-team/forwarded-redirect-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            **headers,
        }
        connection.request("GET", plan.redirect_path, headers=request_headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        location = response.getheader("Location")
        resolved_authority, has_authority = _resolve_authority(location)
        return _Observation(response.status, location, resolved_authority,
                             has_authority, truncated, True)
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, None, None, False, False, False)
    finally:
        if connection is not None:
            connection.close()


def _baseline_passed(observation: _Observation, own_host: str) -> bool:
    if not observation.request_succeeded or observation.truncated:
        return False
    if not observation.redirected or not observation.redirect_has_authority:
        return True
    return observation.resolved_authority == own_host


def run_forwarded_redirect_experiment(plan: ForwardedRedirectPlan) -> dict[str, object]:
    if not isinstance(plan, ForwardedRedirectPlan):
        raise TypeError("plan must be a ForwardedRedirectPlan")
    origin = _origin(plan.target_origin)
    own_host = origin.hostname.lower()
    canary_host = plan.canary_host.lower()

    baseline = _observe(plan, origin, {})
    test = _observe(plan, origin, _injected_headers(plan))
    baseline_passed = _baseline_passed(baseline, own_host)

    if not baseline.request_succeeded:
        level, reason = "INCONCLUSIVE", "BASELINE_CONTROL_FAILED"
    elif baseline.truncated:
        level, reason = "INCONCLUSIVE", "BASELINE_RESPONSE_TRUNCATED"
    elif baseline.redirected and baseline.redirect_has_authority and baseline.resolved_authority != own_host:
        level, reason = "INCONCLUSIVE", "BASELINE_ALREADY_EXTERNAL"
    elif not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    elif not test.redirected:
        level, reason = "FALSIFIED", "TEST_NOT_REDIRECTED"
    elif not test.redirect_has_authority:
        level, reason = "FALSIFIED", "TEST_REDIRECT_HAS_NO_AUTHORITY"
    elif test.resolved_authority is None:
        level, reason = "INCONCLUSIVE", "TEST_LOCATION_UNPARSEABLE"
    elif test.resolved_authority == canary_host:
        level, reason = "CONFIRMED_BY_INDUCTION", "FORWARDED_HEADER_BECAME_REDIRECT_AUTHORITY"
    elif test.resolved_authority == own_host:
        level, reason = "FALSIFIED", "FORWARDED_HEADER_REJECTED_OR_IGNORED"
    else:
        level, reason = "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-forwarded-redirect-authority-differential",
        "target_origin": plan.target_origin, "method": "GET",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "forwarded_header_name": plan.forwarded_header_name,
        "prediction": ("If the redirect authority is built from this header without "
                        "validating it against the application's own origin, the resolved "
                        "Location authority becomes the canary host."),
        "falsifier": ("The redirect either does not occur, carries no authority, or "
                       "resolves to the application's own origin despite the injected header."),
        "epistemic_level": level, "reason_code": reason,
        "controls": {"baseline_control_passed": baseline_passed},
        "baseline_control": baseline.public(), "test": test.public(),
        "request_count": 2, "maximum_request_count": 2,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": forwarded_redirect_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
