"""Mass-assignment proof requires field-level read-back and restoration."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.mass_assignment import (
    MassAssignmentPlan,
    MassAssignmentPlanError,
    run_mass_assignment_experiment,
)


ACTOR_TOKEN = "mass-low-privilege-actor"
OBSERVER_TOKEN = "mass-privileged-observer"
BASE_ALLOWED = "ALLOWED-BASELINE"
BASE_PROTECTED = "PROTECTED-BASELINE"
CONTROL_ALLOWED = "ALLOWED-CONTROL"
NEGATIVE_ALLOWED = "ALLOWED-NEGATIVE"
NEGATIVE_PROTECTED = "PROTECTED-NEGATIVE"


class _MassAssignmentLab(BaseHTTPRequestHandler):
    allowed = BASE_ALLOWED
    protected = BASE_PROTECTED
    vulnerable = False
    filters_protected = False
    fail_restore = False
    events: list[dict[str, object]] = []

    def do_GET(self):  # noqa: N802
        self._record()
        if self.path != "/profiles/mine":
            self._send(404, {"error": "missing"})
        elif self.headers.get("Authorization") != f"Bearer {OBSERVER_TOKEN}":
            self._send(403, {"error": "forbidden"})
        else:
            self._send(
                200,
                {"display_name": type(self).allowed, "role": type(self).protected},
            )

    def do_PATCH(self):  # noqa: N802
        self._record()
        if self.path != "/profiles/mine":
            self._send(404, {"error": "missing"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        authorization = self.headers.get("Authorization")
        if authorization == f"Bearer {OBSERVER_TOKEN}":
            if type(self).fail_restore and type(self).protected == NEGATIVE_PROTECTED:
                self._send(500, {"error": "restore failed"})
                return
            type(self).allowed = payload["display_name"]
            type(self).protected = payload["role"]
            self._send(200, {"updated": True})
            return
        if authorization != f"Bearer {ACTOR_TOKEN}":
            self._send(403, {"error": "forbidden"})
            return
        if "role" in payload and type(self).vulnerable:
            type(self).protected = payload["role"]
        if (
            "role" not in payload
            or type(self).vulnerable
            or type(self).filters_protected
        ):
            type(self).allowed = payload["display_name"]
            self._send(200, {"updated": True})
        else:
            self._send(403, {"error": "protected field"})

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
def mass_assignment_lab():
    handler = _MassAssignmentLab
    handler.allowed = BASE_ALLOWED
    handler.protected = BASE_PROTECTED
    handler.vulnerable = False
    handler.filters_protected = False
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


def _plan(origin: str, **overrides) -> MassAssignmentPlan:
    values = {
        "experiment_id": "MASS-LOCAL-001",
        "authorization_reference": "written-loopback-scope-mass-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "resource_path": "/profiles/mine",
        "readback_path": "/profiles/mine",
        "allowed_field": "display_name",
        "protected_field": "role",
        "baseline_allowed": BASE_ALLOWED,
        "baseline_protected": BASE_PROTECTED,
        "control_allowed": CONTROL_ALLOWED,
        "negative_allowed": NEGATIVE_ALLOWED,
        "negative_protected": NEGATIVE_PROTECTED,
    }
    values.update(overrides)
    return MassAssignmentPlan(**values)


def _actor() -> BearerCredential:
    return BearerCredential("low-privilege-actor", ACTOR_TOKEN)


def _observer() -> BearerCredential:
    return BearerCredential("privileged-observer", OBSERVER_TOKEN)


def test_protected_field_mutation_is_confirmed_and_restored(mass_assignment_lab):
    origin, handler = mass_assignment_lab
    handler.vulnerable = True

    result = run_mass_assignment_experiment(
        _plan(origin), actor=_actor(), observer=_observer()
    )

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "PROTECTED_FIELD_MUTATION_CONFIRMED"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert result["final_state_verified"] is True
    assert result["request_count"] == result["maximum_request_count"] == 9
    assert handler.allowed == BASE_ALLOWED
    assert handler.protected == BASE_PROTECTED


def test_field_level_denial_falsifies_candidate_after_working_control(
    mass_assignment_lab,
):
    origin, handler = mass_assignment_lab

    result = run_mass_assignment_experiment(
        _plan(origin), actor=_actor(), observer=_observer()
    )

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "PROTECTED_FIELD_MUTATION_PREVENTED"
    assert result["control_outcome"] == "ALLOWED_FIELD_MUTATION_CONFIRMED"
    assert result["negative_outcome"] == "PROTECTED_FIELD_UNCHANGED"
    assert handler.allowed == BASE_ALLOWED
    assert handler.protected == BASE_PROTECTED


def test_http_2xx_and_allowed_change_do_not_promote_protected_field(mass_assignment_lab):
    origin, handler = mass_assignment_lab
    handler.filters_protected = True

    result = run_mass_assignment_experiment(
        _plan(origin), actor=_actor(), observer=_observer()
    )

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["negative_outcome"] == "PROTECTED_FIELD_UNCHANGED"
    readback = next(
        item
        for item in result["observations"]
        if item["step"] == "PROTECTED_TEST_READBACK"
    )
    assert readback["allowed_state"] == "NEGATIVE"
    assert readback["protected_state"] == "BASELINE"
    assert handler.allowed == BASE_ALLOWED
    assert handler.protected == BASE_PROTECTED


def test_failed_restoration_requires_manual_action(mass_assignment_lab):
    origin, handler = mass_assignment_lab
    handler.vulnerable = True
    handler.fail_restore = True

    result = run_mass_assignment_experiment(
        _plan(origin), actor=_actor(), observer=_observer()
    )

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "NEGATIVE_RESTORE_FAILED"
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["final_state_verified"] is False


def test_receipt_is_secret_free_and_blue_marked(mass_assignment_lab):
    origin, handler = mass_assignment_lab
    result = run_mass_assignment_experiment(
        _plan(origin), actor=_actor(), observer=_observer()
    )
    serialized = json.dumps(result, sort_keys=True)

    for secret in (
        ACTOR_TOKEN,
        OBSERVER_TOKEN,
        BASE_ALLOWED,
        BASE_PROTECTED,
        CONTROL_ALLOWED,
        NEGATIVE_ALLOWED,
        NEGATIVE_PROTECTED,
    ):
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
        {"allowed_field": "role"},
        {"target_origin": "https://127.0.0.1:8443"},
        {"target_origin": "http://10.0.0.8:8080"},
        {"resource_path": "/profiles/mine?role=owner"},
    ],
)
def test_plan_rejects_ambiguous_or_non_loopback_boundaries(overrides):
    with pytest.raises(MassAssignmentPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
