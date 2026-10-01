"""Authentication enforcement is proved with one valid and two negative cells."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.authn import AuthnPlan, AuthnPlanError, run_authn_experiment
from offensive.bola import BearerCredential


VALID_TOKEN = "valid-authn-token-canary"
INVALID_TOKEN = "invalid-authn-token-canary"
PROTECTED_CANARY = "PROTECTED-AUTHN-CANARY-001"


class _AuthnLabHandler(BaseHTTPRequestHandler):
    anonymous_vulnerable = False
    invalid_vulnerable = False
    anonymous_redacted = False
    redirect_anonymous = False
    exercise_events = []

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
        type(self).exercise_events.append(
            {
                "marker": self.headers.get("X-Pancito-Exercise"),
                "step": self.headers.get("X-Pancito-Step"),
                "authorization_present": self.headers.get("Authorization") is not None,
            }
        )
        if self.path == "/protected":
            authorization = self.headers.get("Authorization")
            if authorization == f"Bearer {VALID_TOKEN}":
                self._send(200, {"marker": PROTECTED_CANARY})
                return
            if authorization is None and self.redirect_anonymous:
                self.send_response(302)
                self.send_header("Location", "/protected")
                self.end_headers()
                return
            if authorization is None and self.anonymous_vulnerable:
                self._send(200, {"marker": PROTECTED_CANARY})
                return
            if authorization is None and self.anonymous_redacted:
                self._send(200, {"status": "authenticated-content-redacted"})
                return
            if authorization == f"Bearer {INVALID_TOKEN}" and self.invalid_vulnerable:
                self._send(200, {"marker": PROTECTED_CANARY})
                return
            self._send(401, {"error": "unauthorized"})
            return
        self._send(404, {"error": "missing"})

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
def authn_lab():
    _AuthnLabHandler.anonymous_vulnerable = False
    _AuthnLabHandler.invalid_vulnerable = False
    _AuthnLabHandler.anonymous_redacted = False
    _AuthnLabHandler.redirect_anonymous = False
    _AuthnLabHandler.exercise_events = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthnLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _AuthnLabHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _plan(origin: str, **overrides) -> AuthnPlan:
    values = {
        "experiment_id": "AUTHN-LOCAL-001",
        "authorization_reference": "written-lab-scope-006",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "protected_path": "/protected",
        "protected_canary": PROTECTED_CANARY,
        "invalid_bearer": INVALID_TOKEN,
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    values.update(overrides)
    return AuthnPlan(**values)


def _credential() -> BearerCredential:
    return BearerCredential("valid-principal", VALID_TOKEN)


def test_anonymous_read_of_protected_canary_confirms_bypass(authn_lab):
    origin, handler = authn_lab
    handler.anonymous_vulnerable = True

    result = run_authn_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ANONYMOUS_OBSERVED_PROTECTED_CANARY"
    assert result["valid_control_passed"] is True
    assert result["anonymous_test"]["protected_canary_observed"] is True


def test_invalid_bearer_read_confirms_separate_bypass_cell(authn_lab):
    origin, handler = authn_lab
    handler.invalid_vulnerable = True

    result = run_authn_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "INVALID_BEARER_OBSERVED_PROTECTED_CANARY"
    assert result["invalid_bearer_test"]["protected_canary_observed"] is True


def test_both_denials_falsify_candidate_for_the_tested_route(authn_lab):
    origin, _handler = authn_lab

    result = run_authn_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "ANONYMOUS_AND_INVALID_BEARER_DENIED"
    assert result["anonymous_test"]["status"] == 401
    assert result["invalid_bearer_test"]["status"] == 401


def test_failed_valid_control_makes_result_inconclusive(authn_lab):
    origin, _handler = authn_lab
    wrong_valid = BearerCredential("valid-principal", "wrong-control-token")

    result = run_authn_experiment(_plan(origin), valid=wrong_valid)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "VALID_CONTROL_FAILED"


def test_redirect_is_not_followed_and_remains_inconclusive(authn_lab):
    origin, handler = authn_lab
    handler.redirect_anonymous = True

    result = run_authn_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "ANONYMOUS_TEST_REDIRECTED"
    assert result["anonymous_test"]["status"] == 302


def test_http_200_without_protected_canary_is_not_a_bypass(authn_lab):
    origin, handler = authn_lab
    handler.anonymous_redacted = True

    result = run_authn_experiment(_plan(origin), valid=_credential())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "ANONYMOUS_TEST_ORACLE_NOT_SATISFIED"
    assert result["anonymous_test"]["status"] == 200
    assert result["anonymous_test"]["protected_canary_observed"] is False


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.com",
        "http://10.0.0.10:8080",
        "http://127.0.0.1:8080/base",
        "http://user:pass@127.0.0.1:8080",
    ],
)
def test_plan_rejects_non_loopback_or_ambiguous_origins(origin):
    with pytest.raises(AuthnPlanError):
        _plan(origin)


def test_plan_rejects_secret_aliasing_and_absolute_path(authn_lab):
    origin, _handler = authn_lab
    with pytest.raises(AuthnPlanError, match="distinct"):
        _plan(origin, invalid_bearer=PROTECTED_CANARY)
    with pytest.raises(AuthnPlanError, match="relative HTTP path"):
        _plan(origin, protected_path="https://example.com/protected")


def test_receipt_and_repr_never_expose_tokens_canary_or_body(authn_lab):
    origin, handler = authn_lab
    handler.anonymous_vulnerable = True
    plan = _plan(origin)

    result = run_authn_experiment(plan, valid=_credential())
    serialized = json.dumps(result, sort_keys=True)

    assert VALID_TOKEN not in serialized
    assert INVALID_TOKEN not in serialized
    assert PROTECTED_CANARY not in serialized
    assert "body" not in result["anonymous_test"]
    assert VALID_TOKEN not in repr(_credential())
    assert INVALID_TOKEN not in repr(plan)
    assert PROTECTED_CANARY not in repr(plan)
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False


def test_all_three_requests_are_marked_for_blue_and_marker_is_not_detection(authn_lab):
    origin, handler = authn_lab

    result = run_authn_experiment(_plan(origin), valid=_credential())

    objective = result["blue_objective"]
    assert [event["step"] for event in handler.exercise_events] == [
        "VALID_CREDENTIAL_CONTROL",
        "ANONYMOUS_TEST",
        "INVALID_BEARER_TEST",
    ]
    assert {event["marker"] for event in handler.exercise_events} == {
        objective["exercise_marker"]
    }
    assert handler.exercise_events[1]["authorization_present"] is False
    assert objective["correlation_marker_is_detection"] is False
