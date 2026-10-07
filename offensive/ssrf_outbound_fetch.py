"""Bounded server-side-outbound-fetch (SSRF) differential for a loopback lab.

Idea credit: the specific bug class this module tests -- a server that
fetches a URL taken from an unvalidated request parameter, reaching
whatever destination the caller names -- is the premise of
swisskyrepo/SSRFmap (MIT). No code was ported; SSRFmap's exploitation
modules (cloud metadata, Redis, etc.) are out of scope entirely. This module
reimplements only the detection premise as a bounded, self-contained
Red/Blue differential: did the target's backend reach a destination the
caller named, at all.

Unlike the CORS, forwarded-redirect, and GraphQL differentials, the oracle
here cannot live inside the HTTP response the target returns -- a server
performing SSRF often returns 200 with unrelated content, or an opaque
error, regardless of whether the outbound fetch happened. The only reliable
oracle is a second, independent witness: a canary HTTP receiver that
PANCITO itself starts on loopback, with an ephemeral OS-assigned port, for
the duration of one experiment only. A baseline request (the probe path
with no URL parameter at all) establishes the path is reachable and that
nothing reaches the canary without it. A single test request names the
canary as the URL parameter's value; the receiver either observes an
inbound request bearing this experiment's exact marker path, or it does
not. There is no third outcome to interpret -- either the witness saw the
request, or it did not, within one bounded grace window.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import threading
import time
import unicodedata
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import SplitResult, quote, urlsplit

from offensive.purple import exercise_marker, ssrf_outbound_fetch_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class SsrfOutboundFetchPlanError(ValueError):
    """The SSRF outbound-fetch experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SsrfOutboundFetchPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise SsrfOutboundFetchPlanError(f"{name} is outside its text boundary")
    return value


def _target_origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed, port = urlsplit(raw), urlsplit(raw).port
    except ValueError as exc:
        raise SsrfOutboundFetchPlanError("target_origin is invalid") from exc
    if (parsed.scheme != "http" or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        raise SsrfOutboundFetchPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise SsrfOutboundFetchPlanError("target_origin must use literal loopback") from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise SsrfOutboundFetchPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object) -> str:
    raw = _text(value, "probe_path", 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise SsrfOutboundFetchPlanError("probe_path must be a relative path without query")
    return raw


def _param_name(value: object) -> str:
    raw = _text(value, "url_parameter_name", 64)
    if not _PARAM_RE.fullmatch(raw):
        raise SsrfOutboundFetchPlanError("url_parameter_name must be a bare identifier")
    return raw


@dataclass(frozen=True)
class SsrfOutboundFetchPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    probe_path: str
    url_parameter_name: str
    timeout_ms: int = 2_000
    canary_grace_ms: int = 300
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise SsrfOutboundFetchPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise SsrfOutboundFetchPlanError("operator_acknowledged must be literal true")
        _target_origin(self.target_origin)
        _path(self.probe_path)
        _param_name(self.url_parameter_name)
        if (isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int)
                or not 100 <= self.timeout_ms <= 10_000):
            raise SsrfOutboundFetchPlanError("timeout_ms is invalid")
        if (isinstance(self.canary_grace_ms, bool) or not isinstance(self.canary_grace_ms, int)
                or not 0 <= self.canary_grace_ms <= 5_000):
            raise SsrfOutboundFetchPlanError("canary_grace_ms is invalid")
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or not 1_024 <= self.max_response_bytes <= 1_048_576):
            raise SsrfOutboundFetchPlanError("max_response_bytes is invalid")


class _CanaryReceiver:
    """A loopback-only, ephemeral-port witness for one experiment's lifetime.

    Records only the request path of every inbound hit. Carries no secret,
    executes no target-supplied content, and is torn down unconditionally
    when the experiment ends.
    """

    def __init__(self) -> None:
        self._hits: list[str] = []
        self._lock = threading.Lock()
        handler = self._make_handler()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _make_handler(self):
        receiver = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                with receiver._lock:
                    receiver._hits.append(self.path)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        return _Handler

    def start(self) -> int:
        self._thread.start()
        return self._server.server_port

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def saw_path(self, expected_path: str) -> bool:
        with self._lock:
            return expected_path in self._hits

    def hit_count(self) -> int:
        with self._lock:
            return len(self._hits)


@dataclass(frozen=True)
class _Observation:
    status: int | None
    truncated: bool
    request_succeeded: bool


def _request(plan: SsrfOutboundFetchPlan, origin: SplitResult, path: str) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port if origin.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        headers = {
            "User-Agent": "pancito-red-team/ssrf-outbound-fetch-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
        }
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        return _Observation(response.status, truncated, True)
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, False, False)
    finally:
        if connection is not None:
            connection.close()


def run_ssrf_outbound_fetch_experiment(plan: SsrfOutboundFetchPlan) -> dict[str, object]:
    if not isinstance(plan, SsrfOutboundFetchPlan):
        raise TypeError("plan must be a SsrfOutboundFetchPlan")
    origin = _target_origin(plan.target_origin)
    marker = exercise_marker(plan.experiment_id)
    canary_path = f"/ssrf-canary/{marker}"

    try:
        receiver = _CanaryReceiver()
        canary_port = receiver.start()
    except OSError:
        return _result(plan, "INCONCLUSIVE", "CANARY_RECEIVER_START_FAILED",
                        False, None, None, 0, request_count=0)

    try:
        # Both requests always run, regardless of outcome -- the same
        # unconditional baseline-then-test shape every other PANCITO
        # differential uses. A canary that never starts is the only case
        # that skips the target entirely (handled above).
        baseline = _request(plan, origin, plan.probe_path)
        baseline_contaminated = receiver.hit_count() > 0

        canary_url = f"http://127.0.0.1:{canary_port}{canary_path}"
        test_path = f"{plan.probe_path}?{plan.url_parameter_name}={quote(canary_url, safe='')}"
        test = _request(plan, origin, test_path)

        baseline_passed = (
            baseline.request_succeeded and not baseline.truncated and not baseline_contaminated
        )

        if not baseline.request_succeeded:
            level, reason = "INCONCLUSIVE", "BASELINE_CONTROL_FAILED"
        elif baseline.truncated:
            level, reason = "INCONCLUSIVE", "BASELINE_RESPONSE_TRUNCATED"
        elif baseline_contaminated:
            level, reason = "INCONCLUSIVE", "BASELINE_CANARY_CONTAMINATED"
        elif not test.request_succeeded:
            level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
        elif test.truncated:
            level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
        else:
            if plan.canary_grace_ms:
                time.sleep(plan.canary_grace_ms / 1_000)
            if receiver.saw_path(canary_path):
                level, reason = "CONFIRMED_BY_INDUCTION", "SSRF_OUTBOUND_FETCH_REACHED_CANARY"
            else:
                level, reason = "FALSIFIED", "CANARY_NOT_REACHED"

        return _result(plan, level, reason, baseline_passed, baseline, test,
                       receiver.hit_count(), request_count=2)
    finally:
        receiver.stop()


def _result(
    plan: SsrfOutboundFetchPlan, level: str, reason: str, baseline_passed: bool,
    baseline: _Observation | None, test: _Observation | None, canary_hit_count: int,
    *, request_count: int,
) -> dict[str, object]:
    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-ssrf-outbound-fetch-differential",
        "target_origin": plan.target_origin, "method": "GET",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "url_parameter_name": plan.url_parameter_name,
        "prediction": ("If the target fetches the URL named by this parameter, PANCITO's own "
                        "loopback canary receiver observes an inbound request bearing this "
                        "experiment's exact marker path."),
        "falsifier": ("The canary receiver observes no request bearing the marker path "
                       "within the bounded grace window after the test request completes."),
        "epistemic_level": level, "reason_code": reason,
        "controls": {"baseline_control_passed": baseline_passed},
        "baseline_control": None if baseline is None else {
            "status": baseline.status, "truncated": baseline.truncated,
            "request_succeeded": baseline.request_succeeded,
        },
        "test": None if test is None else {
            "status": test.status, "truncated": test.truncated,
            "request_succeeded": test.request_succeeded,
        },
        "canary_hit_count": canary_hit_count,
        "request_count": request_count, "maximum_request_count": 2,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": ssrf_outbound_fetch_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
