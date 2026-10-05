"""Resource-consumption prevention and detection are evaluated independently."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_resource_consumption_detection,
    resource_consumption_blue_objective,
)
from offensive.resource_consumption import (
    ResourceConsumptionPlan,
    run_resource_consumption_experiment,
)

STEPS = ("WITHIN_LIMIT_CONTROL", "OVER_LIMIT_TEST")


def _receipt(experiment_id: str, *, epistemic_level: str, reason_code: str) -> dict:
    return {
        "experiment_id": experiment_id,
        "capability": "http-resource-consumption-differential",
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "declared_limit": 3,
        "request_count": 8,
        "maximum_request_count": 8,
        "method": "GET",
        "blue_objective": resource_consumption_blue_objective(experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def test_an_enforced_limit_is_prevention_without_claiming_alerting():
    experiment_id = "RATELIMIT-PURPLE-001"
    receipt = _receipt(experiment_id, epistemic_level="FALSIFIED",
                       reason_code="RATE_LIMIT_ENFORCED_ABOVE_DECLARED_LIMIT")
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False)

    result = evaluate_resource_consumption_detection(receipt, observation)

    assert result["preventive_outcome"] == "PREVENTED"
    assert result["detection_outcome"] == "LOGGED_NOT_ALERTED"


def test_an_absent_limit_is_a_failure_to_prevent():
    experiment_id = "RATELIMIT-PURPLE-002"
    receipt = _receipt(experiment_id, epistemic_level="CONFIRMED_BY_INDUCTION",
                       reason_code="NO_THROTTLING_ABOVE_DECLARED_LIMIT")
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "FIRED", "soc-alert-77", True)

    result = evaluate_resource_consumption_detection(receipt, observation)

    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
    # The alert fired, but it depends on the exercise marker, so it is not a
    # standalone detection the control could have produced on its own.
    assert result["detection_outcome"] != "ALERTED"


def test_an_inconclusive_control_is_unresolved_prevention():
    experiment_id = "RATELIMIT-PURPLE-003"
    receipt = _receipt(experiment_id, epistemic_level="INCONCLUSIVE",
                       reason_code="WITHIN_LIMIT_CONTROL_FAILED")
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", ("WITHIN_LIMIT_CONTROL",),
        "NOT_FIRED", None, False)

    result = evaluate_resource_consumption_detection(receipt, observation)

    assert result["preventive_outcome"] == "UNRESOLVED"


def test_an_observation_marker_mismatch_is_refused():
    experiment_id = "RATELIMIT-PURPLE-004"
    receipt = _receipt(experiment_id, epistemic_level="FALSIFIED",
                       reason_code="RATE_LIMIT_ENFORCED_ABOVE_DECLARED_LIMIT")
    foreign_marker = resource_consumption_blue_objective("OTHER-EXPERIMENT")["exercise_marker"]
    observation = BlueObservation(
        foreign_marker, "COMPLETE", STEPS, "NOT_FIRED", None, False)

    with pytest.raises(BlueObservationError, match="marker"):
        evaluate_resource_consumption_detection(receipt, observation)


# ---- end to end: a real Red receipt satisfies the purple contract ----------

class _OpenHandler(BaseHTTPRequestHandler):
    counter = 0

    def do_GET(self):  # noqa: N802
        type(self).counter += 1
        payload = json.dumps({"marker": "E2E-CANARY"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


def test_a_real_confirmed_receipt_is_accepted_by_the_blue_evaluator():
    _OpenHandler.counter = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OpenHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        plan = ResourceConsumptionPlan(
            experiment_id="RATELIMIT-E2E-001",
            authorization_reference="written-lab-scope-011",
            authorized_by="Lab Owner", operator_acknowledged=True,
            target_origin=f"http://127.0.0.1:{server.server_port}",
            probed_path="/report", success_canary="E2E-CANARY",
            declared_limit=2, control_requests=2, probe_requests=3)
        receipt = run_resource_consumption_experiment(
            plan, valid=BearerCredential("p", "e2e-token"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert receipt["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    observation = BlueObservation(
        receipt["blue_objective"]["exercise_marker"], "COMPLETE", STEPS,
        "NOT_FIRED", None, False)
    result = evaluate_resource_consumption_detection(receipt, observation)
    assert result["preventive_outcome"] == "FAILED_TO_PREVENT"
