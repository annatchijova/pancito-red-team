"""Public state change needs authenticated read-back and verified restoration."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.handoff import StateChangeCandidateHandoff
from offensive.state_change import (
    StateChangePlan,
    StateChangePlanError,
    _classify_marker,
    run_state_change_experiment,
)
from offensive.state_change_cli import main as state_change_cli_main


VALID_TOKEN = "state-valid-observer-token"
INVALID_TOKEN = "state-invalid-bearer-token"
BASELINE = "STATE-BASELINE-CANARY"
CONTROL = "STATE-CONTROL-CANARY"
ANONYMOUS = "STATE-ANONYMOUS-CANARY"
INVALID = "STATE-INVALID-CANARY"


class _StateLabHandler(BaseHTTPRequestHandler):
    marker = BASELINE
    anonymous_vulnerable = False
    invalid_vulnerable = False
    anonymous_2xx_without_mutation = False
    fail_restore_after_anonymous = False
    restore_applies_with_500 = False
    events: list[dict[str, object]] = []

    def do_GET(self):  # noqa: N802
        self._record()
        if self.path != "/settings/lab":
            self._send(404, {"error": "missing"})
        elif self.headers.get("Authorization") != f"Bearer {VALID_TOKEN}":
            self._send(401, {"error": "unauthorized"})
        else:
            self._send(200, {"marker": type(self).marker})

    def do_PATCH(self):  # noqa: N802
        self._record()
        if self.path != "/settings/lab":
            self._send(404, {"error": "missing"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        marker = payload.get("marker")
        authorization = self.headers.get("Authorization")
        allowed = authorization == f"Bearer {VALID_TOKEN}"
        allowed = allowed or (
            authorization is None and type(self).anonymous_vulnerable
        )
        allowed = allowed or (
            authorization == f"Bearer {INVALID_TOKEN}"
            and type(self).invalid_vulnerable
        )
        if (
            marker == BASELINE
            and type(self).marker == ANONYMOUS
            and type(self).fail_restore_after_anonymous
        ):
            self._send(500, {"error": "restore failed"})
        elif (
            marker == BASELINE
            and type(self).marker == ANONYMOUS
            and type(self).restore_applies_with_500
        ):
            type(self).marker = BASELINE
            self._send(500, {"error": "response failed after commit"})
        elif authorization is None and type(self).anonymous_2xx_without_mutation:
            self._send(200, {"accepted": True})
        elif allowed:
            type(self).marker = marker
            self._send(200, {"accepted": True})
        else:
            self._send(401, {"error": "unauthorized"})

    def _record(self):
        type(self).events.append(
            {
                "method": self.command,
                "marker": self.headers.get("X-Pancito-Exercise"),
                "step": self.headers.get("X-Pancito-Step"),
                "authorization_present": self.headers.get("Authorization") is not None,
            }
        )

    def _send(self, status, value):
        payload = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def state_lab():
    handler = _StateLabHandler
    handler.marker = BASELINE
    handler.anonymous_vulnerable = False
    handler.invalid_vulnerable = False
    handler.anonymous_2xx_without_mutation = False
    handler.fail_restore_after_anonymous = False
    handler.restore_applies_with_500 = False
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


def _plan(origin: str, **overrides) -> StateChangePlan:
    values = {
        "experiment_id": "STATE-LOCAL-001",
        "authorization_reference": "written-lab-scope-state-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "resource_path": "/settings/lab",
        "readback_path": "/settings/lab",
        "marker_field": "marker",
        "baseline_marker": BASELINE,
        "control_marker": CONTROL,
        "anonymous_marker": ANONYMOUS,
        "invalid_marker": INVALID,
        "invalid_bearer": INVALID_TOKEN,
    }
    values.update(overrides)
    return StateChangePlan(**values)


def _observer() -> BearerCredential:
    return BearerCredential("state-observer", VALID_TOKEN)


def test_anonymous_mutation_is_confirmed_by_readback_and_restored(state_lab):
    origin, handler = state_lab
    handler.anonymous_vulnerable = True

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ANONYMOUS_MUTATION_CONFIRMED"
    assert result["confirmed_cells"] == ["ANONYMOUS"]
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert result["final_state_verified"] is True
    assert handler.marker == BASELINE
    assert result["request_count"] == 11
    assert result["maximum_request_count"] == 13
    assert result["cell_outcomes"] == {
        "ANONYMOUS": "MUTATION_CONFIRMED",
        "INVALID_BEARER": "MUTATION_DENIED",
    }


def test_denied_negative_cells_falsify_candidate_for_tested_field(state_lab):
    origin, handler = state_lab

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "ANONYMOUS_AND_INVALID_BEARER_MUTATIONS_DENIED"
    assert result["confirmed_cells"] == []
    assert result["request_count"] == 9
    assert handler.marker == BASELINE


def test_two_confirmed_cells_consume_the_declared_maximum_and_both_restore(state_lab):
    origin, handler = state_lab
    handler.anonymous_vulnerable = True
    handler.invalid_vulnerable = True

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["confirmed_cells"] == ["ANONYMOUS", "INVALID_BEARER"]
    assert result["request_count"] == result["maximum_request_count"] == 13
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert handler.marker == BASELINE


def test_http_2xx_without_readback_change_is_not_promoted(state_lab):
    origin, handler = state_lab
    handler.anonymous_2xx_without_mutation = True

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "ANONYMOUS_ORACLE_NOT_SATISFIED"
    assert result["confirmed_cells"] == []
    assert handler.marker == BASELINE


def test_restore_failure_stops_experiment_and_demands_manual_action(state_lab):
    origin, handler = state_lab
    handler.anonymous_vulnerable = True
    handler.fail_restore_after_anonymous = True

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "ANONYMOUS_RESTORE_FAILED"
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["final_state_verified"] is False
    assert handler.marker == ANONYMOUS
    assert not any(
        event["step"] == "INVALID_BEARER_TEST" for event in handler.events
    )


def test_authenticated_readback_proves_restore_even_if_patch_returns_500(state_lab):
    origin, handler = state_lab
    handler.anonymous_vulnerable = True
    handler.restore_applies_with_500 = True

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert result["final_state_verified"] is True
    assert handler.marker == BASELINE


def test_unexpected_baseline_aborts_before_any_write(state_lab):
    origin, handler = state_lab
    handler.marker = "operator-did-not-authorize-overwrite"

    result = run_state_change_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "BASELINE_MARKER_MISMATCH"
    assert result["request_count"] == 1
    assert result["final_state_verified"] is False
    assert [event["method"] for event in handler.events] == ["GET"]


def test_receipt_never_exposes_tokens_markers_or_response_bodies(state_lab):
    origin, handler = state_lab
    handler.anonymous_vulnerable = True
    plan = _plan(origin)

    result = run_state_change_experiment(plan, observer=_observer())
    serialized = json.dumps(result, sort_keys=True)

    for secret in (VALID_TOKEN, INVALID_TOKEN, BASELINE, CONTROL, ANONYMOUS, INVALID):
        assert secret not in serialized
        assert secret not in repr(plan)
    assert "body" not in serialized
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["impact_assessment"] == "REQUIRES_HUMAN_CONTEXT"


def test_every_request_is_marked_for_blue_but_marker_is_not_detection(state_lab):
    origin, handler = state_lab
    result = run_state_change_experiment(_plan(origin), observer=_observer())

    objective = result["blue_objective"]
    assert {event["marker"] for event in handler.events} == {
        objective["exercise_marker"]
    }
    assert objective["correlation_marker_is_detection"] is False
    assert objective["benign_twin_step"] == "VALID_CREDENTIAL_CONTROL"
    anonymous = next(
        event for event in handler.events if event["step"] == "ANONYMOUS_TEST"
    )
    assert anonymous["authorization_present"] is False


@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1:8443",
        "http://10.0.0.4:8080",
        "http://127.0.0.1:8080/base",
        "http://user:pass@127.0.0.1:8080",
    ],
)
def test_plan_rejects_non_loopback_or_ambiguous_origins(origin):
    with pytest.raises(StateChangePlanError):
        _plan(origin)


def test_plan_rejects_query_paths_and_secret_aliasing(state_lab):
    origin, _handler = state_lab
    with pytest.raises(StateChangePlanError, match="without query"):
        _plan(origin, resource_path="/settings/lab?admin=true")
    with pytest.raises(StateChangePlanError, match="distinct"):
        _plan(origin, anonymous_marker=BASELINE)


def test_hostile_json_marker_type_degrades_to_other_without_exception(state_lab):
    origin, _handler = state_lab
    plan = _plan(origin)

    assert _classify_marker(plan, b'{"marker":[]}') == "OTHER"
    assert _classify_marker(plan, b'{"marker":{"nested":true}}') == "OTHER"


def test_candidate_handoff_binds_method_and_concrete_path(state_lab):
    origin, _handler = state_lab
    handoff = StateChangeCandidateHandoff(
        candidate_id="CANDIDATE-0123456789abcdef",
        source_label="api/openapi.json@state1",
        source_sha256="a" * 64,
        entry_point="PATCH /settings/{tenant_id}",
        json_pointer="/paths/~1settings~1{tenant_id}/patch",
    )

    plan = _plan(origin, candidate_handoff=handoff)
    assert plan.candidate_handoff is handoff

    with pytest.raises(StateChangePlanError, match="candidate path"):
        _plan(origin, resource_path="/admin/lab", candidate_handoff=handoff)
    with pytest.raises(ValueError, match="must use PATCH"):
        StateChangeCandidateHandoff(
            candidate_id="CANDIDATE-0123456789abcdef",
            source_label="api/openapi.json@state1",
            source_sha256="a" * 64,
            entry_point="POST /settings/{tenant_id}",
        )


def test_cli_executes_bounded_experiment_and_emits_no_secret(
    state_lab, tmp_path, capsys
):
    origin, handler = state_lab
    handler.anonymous_vulnerable = True
    manifest = {
        "schema_version": 1,
        "experiment_id": "STATE-CLI-E2E-001",
        "authorization_reference": "written-lab-scope-state-003",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "resource_path": "/settings/lab",
        "readback_path": "/settings/lab",
        "marker_field": "marker",
        "observer_principal_id": "state-observer",
        "observer_token_env": "PANCITO_STATE_OBSERVER_TOKEN",
        "invalid_bearer_env": "PANCITO_STATE_INVALID_BEARER",
        "baseline_marker_env": "PANCITO_STATE_BASELINE",
        "control_marker_env": "PANCITO_STATE_CONTROL",
        "anonymous_marker_env": "PANCITO_STATE_ANONYMOUS",
        "invalid_marker_env": "PANCITO_STATE_INVALID",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    environment = {
        "PANCITO_STATE_OBSERVER_TOKEN": VALID_TOKEN,
        "PANCITO_STATE_INVALID_BEARER": INVALID_TOKEN,
        "PANCITO_STATE_BASELINE": BASELINE,
        "PANCITO_STATE_CONTROL": CONTROL,
        "PANCITO_STATE_ANONYMOUS": ANONYMOUS,
        "PANCITO_STATE_INVALID": INVALID,
    }
    path = tmp_path / "state-change.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    exit_code = state_change_cli_main([str(path)], environ=environment)
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert handler.marker == BASELINE
    assert all(secret not in captured.out for secret in environment.values())
