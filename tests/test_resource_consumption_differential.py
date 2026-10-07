"""A resource-consumption control is proved present or absent against loopback.

CONFIRMED means the control is ABSENT (an over-limit burst was served in full);
FALSIFIED means it is PRESENT (the limit fired); INCONCLUSIVE covers a control
that could not be established cleanly or an ambiguous over-limit burst.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.resource_consumption import (
    ResourceConsumptionPlan,
    ResourceConsumptionPlanError,
    run_resource_consumption_experiment,
)


VALID_TOKEN = "valid-rate-limit-token-canary"
SUCCESS_CANARY = "SERVED-RESOURCE-CANARY-001"


class _RateLimitLabHandler(BaseHTTPRequestHandler):
    # None means "never throttle". An integer N means: serve the first N
    # requests, then reply 429 with Retry-After.
    throttle_after = None
    omit_canary_after = None  # serve 200 without the canary past this count
    always_missing = False    # route returns 404 for every request
    never_canary = False      # 200 without the canary for every request
    counter = 0

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
        type(self).counter += 1
        count = type(self).counter
        if self.path != "/report":
            self._send(404, {"error": "missing"})
            return
        if self.always_missing:
            self._send(404, {"error": "missing"})
            return
        if self.throttle_after is not None and count > self.throttle_after:
            self.send_response(429)
            self.send_header("Retry-After", "1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.never_canary or (
            self.omit_canary_after is not None and count > self.omit_canary_after
        ):
            self._send(200, {"status": "ok-without-marker"})
            return
        self._send(200, {"marker": SUCCESS_CANARY})

    def log_message(self, _format, *_args):
        return

    def _send(self, status, value):
        payload = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def rate_lab():
    _RateLimitLabHandler.throttle_after = None
    _RateLimitLabHandler.omit_canary_after = None
    _RateLimitLabHandler.always_missing = False
    _RateLimitLabHandler.never_canary = False
    _RateLimitLabHandler.counter = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RateLimitLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _RateLimitLabHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _plan(origin: str, **overrides) -> ResourceConsumptionPlan:
    values = {
        "experiment_id": "RATELIMIT-LOCAL-001",
        "authorization_reference": "written-lab-scope-011",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "probed_path": "/report",
        "success_canary": SUCCESS_CANARY,
        "declared_limit": 3,
        "control_requests": 3,
        "probe_requests": 5,
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    values.update(overrides)
    return ResourceConsumptionPlan(**values)


def _credential() -> BearerCredential:
    return BearerCredential("valid-principal", VALID_TOKEN)


def test_an_unthrottled_over_limit_burst_confirms_the_control_is_absent(rate_lab):
    origin, handler = rate_lab
    handler.throttle_after = None  # server never throttles

    result = run_resource_consumption_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "NO_THROTTLING_ABOVE_DECLARED_LIMIT"
    assert result["within_limit_control_passed"] is True
    assert result["over_limit_test"]["served_count"] == 5
    assert result["over_limit_test"]["throttled_count"] == 0
    assert result["request_count"] == 8
    assert result["model_used"] is False
    assert result["receipt_integrity"] == "UNSEALED"


def test_a_throttle_in_the_over_limit_burst_falsifies_the_candidate(rate_lab):
    origin, handler = rate_lab
    handler.throttle_after = 3  # serve the 3-request control, throttle the rest

    result = run_resource_consumption_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "RATE_LIMIT_ENFORCED_ABOVE_DECLARED_LIMIT"
    assert result["within_limit_control_passed"] is True
    assert result["over_limit_test"]["throttled_count"] >= 1
    assert 429 in result["over_limit_test"]["statuses"]


def test_a_throttle_inside_the_control_is_inconclusive_not_a_finding(rate_lab):
    origin, handler = rate_lab
    handler.throttle_after = 2  # server throttles before the declared limit of 3

    result = run_resource_consumption_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "THROTTLED_WITHIN_DECLARED_LIMIT"
    assert result["within_limit_control_passed"] is False
    # The over-limit cell must not have run once the control was not established.
    assert result["over_limit_test"]["requests"] == 0


def test_a_control_that_never_serves_the_canary_is_inconclusive(rate_lab):
    origin, handler = rate_lab
    handler.never_canary = True

    result = run_resource_consumption_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "WITHIN_LIMIT_CONTROL_FAILED"
    assert result["over_limit_test"]["requests"] == 0


def test_an_over_limit_burst_that_is_neither_served_nor_throttled_is_inconclusive(
    rate_lab,
):
    origin, handler = rate_lab
    # The control (first 3) is served; afterwards the route returns 200 without
    # the canary instead of a 429 — ambiguous, not a confirmed absence.
    handler.omit_canary_after = 3

    result = run_resource_consumption_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "OVER_LIMIT_TEST_ORACLE_NOT_SATISFIED"
    assert result["over_limit_test"]["throttled_count"] == 0
    assert result["over_limit_test"]["served_count"] == 0


def test_a_missing_route_is_inconclusive(rate_lab):
    origin, handler = rate_lab
    handler.always_missing = True

    result = run_resource_consumption_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "WITHIN_LIMIT_CONTROL_FAILED"


# ---- plan boundary ---------------------------------------------------------

def test_a_non_loopback_origin_is_refused():
    with pytest.raises(ResourceConsumptionPlanError, match="loopback"):
        _plan("http://93.184.216.34:80")


def test_a_probe_that_does_not_exceed_the_declared_limit_is_refused():
    with pytest.raises(ResourceConsumptionPlanError, match="exceed the declared limit"):
        _plan("http://127.0.0.1:9", declared_limit=5, control_requests=5,
              probe_requests=4)


def test_a_control_above_the_declared_limit_is_refused():
    with pytest.raises(ResourceConsumptionPlanError, match="control_requests"):
        _plan("http://127.0.0.1:9", declared_limit=2, control_requests=3,
              probe_requests=4)


def test_a_total_above_the_hard_maximum_is_refused():
    with pytest.raises(ResourceConsumptionPlanError, match="total requests"):
        _plan("http://127.0.0.1:9", declared_limit=40, control_requests=40,
              probe_requests=41)


def test_a_success_canary_equal_to_the_token_is_refused(rate_lab):
    origin, _ = rate_lab
    plan = _plan(origin, success_canary=VALID_TOKEN)
    with pytest.raises(ResourceConsumptionPlanError, match="distinct"):
        run_resource_consumption_experiment(plan, valid=_credential())
