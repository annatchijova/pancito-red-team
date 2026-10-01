"""Stale authority requires a verified revoke transition and verified restore."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.stale_authority import (
    StaleAuthorityPlan,
    StaleAuthorityPlanError,
    run_stale_authority_experiment,
)


ACTOR_TOKEN = "stale-actor-issued-token"
ADMIN_TOKEN = "stale-admin-token"
RESOURCE_CANARY = "STALE-PROTECTED-CANARY"
ACTIVE = "STALE-ACTIVE-ROLE"
REVOKED = "STALE-REVOKED-ROLE"


class _StaleAuthorityLab(BaseHTTPRequestHandler):
    membership = ACTIVE
    stale_vulnerable = False
    empty_success = False
    ignore_revoke = False
    fail_restore = False
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        self._record()
        token = self.headers.get("Authorization")
        if self.path == "/membership/actor":
            if token == f"Bearer {ADMIN_TOKEN}":
                self._send(200, {"role": type(self).membership})
            else:
                self._send(403, {"error": "forbidden"})
        elif self.path == "/protected/report":
            if token != f"Bearer {ACTOR_TOKEN}":
                self._send(403, {"error": "forbidden"})
            elif type(self).membership == ACTIVE or type(self).stale_vulnerable:
                self._send(200, {"marker": RESOURCE_CANARY})
            elif type(self).empty_success:
                self._send(200, {})
            else:
                self._send(403, {"error": "revoked"})
        else:
            self._send(404, {"error": "missing"})

    def do_PATCH(self):  # noqa: N802
        self._record()
        if (
            self.path != "/membership/actor"
            or self.headers.get("Authorization") != f"Bearer {ADMIN_TOKEN}"
        ):
            self._send(403, {"error": "forbidden"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        role = json.loads(self.rfile.read(length).decode("utf-8"))["role"]
        if role == REVOKED and type(self).ignore_revoke:
            self._send(200, {"updated": True})
        elif role == ACTIVE and type(self).fail_restore:
            self._send(500, {"error": "restore failed"})
        else:
            type(self).membership = role
            self._send(200, {"updated": True})

    def _record(self):
        type(self).events.append(
            {
                "method": self.command,
                "step": self.headers.get("X-Pancito-Step"),
                "marker": self.headers.get("X-Pancito-Exercise"),
            }
        )

    def _send(self, status, value):
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def stale_lab():
    handler = _StaleAuthorityLab
    handler.membership = ACTIVE
    handler.stale_vulnerable = False
    handler.empty_success = False
    handler.ignore_revoke = False
    handler.fail_restore = False
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


def _plan(origin: str, **overrides) -> StaleAuthorityPlan:
    values = {
        "experiment_id": "STALE-AUTH-001",
        "authorization_reference": "written-loopback-scope-stale-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "resource_path": "/protected/report",
        "membership_path": "/membership/actor",
        "membership_field": "role",
        "resource_canary": RESOURCE_CANARY,
        "active_marker": ACTIVE,
        "revoked_marker": REVOKED,
    }
    values.update(overrides)
    return StaleAuthorityPlan(**values)


def _credentials():
    return (
        BearerCredential("stale-actor", ACTOR_TOKEN),
        BearerCredential("stale-admin", ADMIN_TOKEN),
    )


def test_preissued_credential_access_after_revoke_is_confirmed_and_restored(stale_lab):
    origin, handler = stale_lab
    handler.stale_vulnerable = True
    actor, admin = _credentials()

    result = run_stale_authority_experiment(_plan(origin), actor=actor, admin=admin)

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "STALE_CREDENTIAL_ACCESS_CONFIRMED"
    assert result["revoke_verified"] is True
    assert result["stale_access_observed"] is True
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert result["final_state_verified"] is True
    assert result["request_count"] == result["maximum_request_count"] == 7
    assert handler.membership == ACTIVE


def test_denial_after_verified_revoke_falsifies_the_tested_session(stale_lab):
    origin, handler = stale_lab
    actor, admin = _credentials()

    result = run_stale_authority_experiment(_plan(origin), actor=actor, admin=admin)

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "REVOKED_CREDENTIAL_ACCESS_DENIED"
    assert result["stale_access_observed"] is False
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert handler.membership == ACTIVE


def test_http_200_without_protected_canary_is_inconclusive(stale_lab):
    origin, handler = stale_lab
    handler.empty_success = True
    actor, admin = _credentials()

    result = run_stale_authority_experiment(_plan(origin), actor=actor, admin=admin)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "STALE_ACCESS_ORACLE_NOT_SATISFIED"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"


def test_unverified_revoke_never_runs_stale_credential_cell(stale_lab):
    origin, handler = stale_lab
    handler.ignore_revoke = True
    actor, admin = _credentials()

    result = run_stale_authority_experiment(_plan(origin), actor=actor, admin=admin)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "REVOKE_CONTROL_FAILED"
    assert result["request_count"] == 4
    assert result["cleanup_status"] == "BASELINE_VERIFIED"
    assert not any(event["step"] == "STALE_CREDENTIAL_TEST" for event in handler.events)


def test_restore_failure_demands_manual_action_and_suppresses_confirmation(stale_lab):
    origin, handler = stale_lab
    handler.stale_vulnerable = True
    handler.fail_restore = True
    actor, admin = _credentials()

    result = run_stale_authority_experiment(_plan(origin), actor=actor, admin=admin)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "RESTORE_FAILED"
    assert result["stale_access_observed"] is True
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["final_state_verified"] is False
    assert handler.membership == REVOKED


def test_receipt_omits_secrets_and_marks_every_request_for_blue(stale_lab):
    origin, handler = stale_lab
    handler.stale_vulnerable = True
    actor, admin = _credentials()
    result = run_stale_authority_experiment(_plan(origin), actor=actor, admin=admin)
    serialized = json.dumps(result, sort_keys=True)

    for secret in (ACTOR_TOKEN, ADMIN_TOKEN, RESOURCE_CANARY, ACTIVE, REVOKED):
        assert secret not in serialized
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["blue_objective"]["correlation_marker_is_detection"] is False
    assert {event["marker"] for event in handler.events} == {
        result["blue_objective"]["exercise_marker"]
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_origin": "https://127.0.0.1:8443"},
        {"target_origin": "http://10.0.0.8:8080"},
        {"resource_path": "/protected/report?fresh=true"},
        {"membership_field": "role/nested"},
        {"revoked_marker": ACTIVE},
    ],
)
def test_plan_rejects_ambiguous_or_non_loopback_boundaries(overrides):
    with pytest.raises(StaleAuthorityPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
