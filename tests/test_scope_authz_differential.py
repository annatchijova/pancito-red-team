"""Token-scope enforcement requires two controls and a privileged canary."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.scope_authz import (
    ScopeAuthorizationPlan,
    ScopeAuthorizationPlanError,
    run_scope_authorization_experiment,
)


BROAD_TOKEN = "scope-broad-token"
NARROW_TOKEN = "scope-narrow-token"
PRIVILEGED_CANARY = "SCOPE-BROAD-CANARY"
NARROW_CANARY = "SCOPE-NARROW-CANARY"


class _FunctionLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        type(self).events.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "marker": self.headers.get("X-Pancito-Exercise"),
        })
        token = self.headers.get("Authorization")
        if self.path == "/scoped/privileged":
            if token == f"Bearer {BROAD_TOKEN}" or (
                token == f"Bearer {NARROW_TOKEN}" and type(self).vulnerable
            ):
                self._send(200, {"marker": PRIVILEGED_CANARY})
            elif token == f"Bearer {NARROW_TOKEN}" and type(self).empty_success:
                self._send(200, {})
            else:
                self._send(403, {"error": "forbidden"})
        elif self.path == "/scoped/allowed" and token == f"Bearer {NARROW_TOKEN}":
            self._send(200, {"marker": NARROW_CANARY})
        else:
            self._send(404, {"error": "missing"})

    def _send(self, status, value):
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def scope_lab():
    handler = _FunctionLab
    handler.vulnerable = False
    handler.empty_success = False
    handler.events = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _plan(origin, **overrides):
    values = {
        "experiment_id": "SCOPE-LOCAL-001",
        "authorization_reference": "written-loopback-scope-authz-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "privileged_resource_path": "/scoped/privileged",
        "narrow_control_path": "/scoped/allowed",
        "privileged_canary": PRIVILEGED_CANARY,
        "narrow_canary": NARROW_CANARY,
    }
    values.update(overrides)
    return ScopeAuthorizationPlan(**values)


def _credentials():
    return BearerCredential("broad", BROAD_TOKEN), BearerCredential("narrow", NARROW_TOKEN)


def test_narrow_token_access_is_confirmed_only_by_privileged_canary(scope_lab):
    origin, handler = scope_lab
    handler.vulnerable = True
    broad, narrow = _credentials()
    result = run_scope_authorization_experiment(_plan(origin), broad=broad, narrow=narrow)

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "NARROW_OBSERVED_PRIVILEGED_CANARY"
    assert result["test"]["privileged_canary_observed"] is True
    broad_twin = dict(handler.events[0])
    negative = dict(handler.events[2])
    assert broad_twin.pop("authorization") != negative.pop("authorization")
    assert broad_twin == negative


def test_scope_denial_falsifies_the_tested_cell(scope_lab):
    origin, _handler = scope_lab
    broad, narrow = _credentials()
    result = run_scope_authorization_experiment(_plan(origin), broad=broad, narrow=narrow)
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "NARROW_PRIVILEGED_SCOPE_DENIED"


def test_http_200_without_privileged_canary_is_inconclusive(scope_lab):
    origin, handler = scope_lab
    handler.empty_success = True
    broad, narrow = _credentials()
    result = run_scope_authorization_experiment(_plan(origin), broad=broad, narrow=narrow)
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"


def test_receipt_is_secret_free_and_blue_marked(scope_lab):
    origin, handler = scope_lab
    handler.vulnerable = True
    broad, narrow = _credentials()
    result = run_scope_authorization_experiment(_plan(origin), broad=broad, narrow=narrow)
    serialized = json.dumps(result, sort_keys=True)
    for secret in (BROAD_TOKEN, NARROW_TOKEN, PRIVILEGED_CANARY, NARROW_CANARY):
        assert secret not in serialized
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert {event["marker"] for event in handler.events} == {
        result["blue_objective"]["exercise_marker"]
    }


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://10.0.0.8:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"privileged_resource_path": "/scoped/privileged?format=json"},
    {"privileged_resource_path": "/broad/%72eport"},
    {"privileged_resource_path": "/broad//report"},
    {"privileged_resource_path": "/broad/../report"},
    {"narrow_control_path": "/scoped/privileged"},
    {"narrow_canary": PRIVILEGED_CANARY},
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(ScopeAuthorizationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
