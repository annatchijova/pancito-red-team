"""Function-level authorization requires role controls and an admin canary."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.function_authz import (
    FunctionAuthorizationPlan,
    FunctionAuthorizationPlanError,
    run_function_authorization_experiment,
)


ADMIN_TOKEN = "bfla-admin-token"
MEMBER_TOKEN = "bfla-member-token"
ADMIN_CANARY = "BFLA-ADMIN-CANARY"
MEMBER_CANARY = "BFLA-MEMBER-CANARY"


class _FunctionLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        type(self).events.append({
            "step": self.headers.get("X-Pancito-Step"),
            "marker": self.headers.get("X-Pancito-Exercise"),
        })
        token = self.headers.get("Authorization")
        if self.path == "/admin/report":
            if token == f"Bearer {ADMIN_TOKEN}" or (
                token == f"Bearer {MEMBER_TOKEN}" and type(self).vulnerable
            ):
                self._send(200, {"marker": ADMIN_CANARY})
            elif token == f"Bearer {MEMBER_TOKEN}" and type(self).empty_success:
                self._send(200, {})
            else:
                self._send(403, {"error": "forbidden"})
        elif self.path == "/member/profile" and token == f"Bearer {MEMBER_TOKEN}":
            self._send(200, {"marker": MEMBER_CANARY})
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
def function_lab():
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
        "experiment_id": "BFLA-LOCAL-001",
        "authorization_reference": "written-loopback-scope-bfla-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "admin_path": "/admin/report",
        "member_control_path": "/member/profile",
        "admin_canary": ADMIN_CANARY,
        "member_canary": MEMBER_CANARY,
    }
    values.update(overrides)
    return FunctionAuthorizationPlan(**values)


def _credentials():
    return BearerCredential("admin", ADMIN_TOKEN), BearerCredential("member", MEMBER_TOKEN)


def test_member_admin_function_access_is_confirmed_only_by_admin_canary(function_lab):
    origin, handler = function_lab
    handler.vulnerable = True
    admin, member = _credentials()
    result = run_function_authorization_experiment(_plan(origin), admin=admin, member=member)

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "MEMBER_OBSERVED_ADMIN_CANARY"
    assert result["test"]["admin_canary_observed"] is True


def test_role_denial_falsifies_the_tested_function_cell(function_lab):
    origin, _handler = function_lab
    admin, member = _credentials()
    result = run_function_authorization_experiment(_plan(origin), admin=admin, member=member)
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "MEMBER_ADMIN_FUNCTION_DENIED"


def test_http_200_without_admin_canary_is_inconclusive(function_lab):
    origin, handler = function_lab
    handler.empty_success = True
    admin, member = _credentials()
    result = run_function_authorization_experiment(_plan(origin), admin=admin, member=member)
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"


def test_receipt_is_secret_free_and_blue_marked(function_lab):
    origin, handler = function_lab
    handler.vulnerable = True
    admin, member = _credentials()
    result = run_function_authorization_experiment(_plan(origin), admin=admin, member=member)
    serialized = json.dumps(result, sort_keys=True)
    for secret in (ADMIN_TOKEN, MEMBER_TOKEN, ADMIN_CANARY, MEMBER_CANARY):
        assert secret not in serialized
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert {event["marker"] for event in handler.events} == {
        result["blue_objective"]["exercise_marker"]
    }


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://10.0.0.8:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"admin_path": "/admin/report?format=json"},
    {"admin_path": "/admin/%72eport"},
    {"admin_path": "/admin//report"},
    {"admin_path": "/admin/../report"},
    {"member_control_path": "/admin/report"},
    {"member_canary": ADMIN_CANARY},
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(FunctionAuthorizationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
