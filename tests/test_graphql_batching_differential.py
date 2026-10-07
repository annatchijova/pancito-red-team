"""A GraphQL endpoint must never process more operations than one HTTP request should count as."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.graphql_batching import (
    GraphqlBatchingPlan,
    GraphqlBatchingPlanError,
    run_graphql_batching_experiment,
)


class _GraphqlLab(BaseHTTPRequestHandler):
    # "batching": processes an array body as N independent operations -- the
    # graphql-cop headline batching check.
    # "no_batching": rejects an array-shaped body outright.
    # "not_graphql": never emits a GraphQL-shaped body at all.
    mode = "no_batching"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.mode == "not_graphql":
            self._respond_json({"ok": True})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, list):
            if self.mode == "batching":
                self._respond_json([{"data": {"__typename": "Query"}} for _ in payload])
            else:
                self._respond_json({"errors": [{"message": "batch requests not supported"}]})
            return
        self._respond_json({"data": {"__typename": "Query"}})

    def _respond_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def graphql_lab():
    handler = _GraphqlLab
    handler.mode = "no_batching"
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
        "experiment_id": "GQLBATCH-LOCAL-001",
        "authorization_reference": "written-loopback-graphql-batching-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "endpoint_path": "/graphql",
        "batch_size": 3,
    }
    values.update(overrides)
    return GraphqlBatchingPlan(**values)


def test_batching_endpoint_processes_the_array_is_confirmed(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "batching"
    result = run_graphql_batching_experiment(_plan(origin))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "BATCHING_ACCEPTED"
    assert result["controls"]["baseline_control_passed"] is True


def test_non_batching_endpoint_falsifies_the_hypothesis(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "no_batching"
    result = run_graphql_batching_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "BATCHING_REJECTED"


def test_wrong_length_batch_response_is_inconclusive_not_confirmed(graphql_lab):
    origin, handler = graphql_lab

    class _ShortBatch(_GraphqlLab):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, list):
                self._respond_json([{"data": {"__typename": "Query"}}])
                return
            self._respond_json({"data": {"__typename": "Query"}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ShortBatch)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        short_origin = f"http://127.0.0.1:{server.server_port}"
        result = run_graphql_batching_experiment(_plan(short_origin))
        assert result["epistemic_level"] == "INCONCLUSIVE"
        assert result["reason_code"] == "TEST_BATCH_RESPONSE_MALFORMED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_non_graphql_endpoint_is_inconclusive_not_falsified(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "not_graphql"
    result = run_graphql_batching_experiment(_plan(origin))
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "BASELINE_NOT_A_GRAPHQL_ENDPOINT"
    assert result["controls"]["baseline_control_passed"] is False


def test_receipt_carries_no_secret_and_is_blue_marked(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "batching"
    result = run_graphql_batching_experiment(_plan(origin))
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["blue_objective"]["exercise_marker"]


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://10.0.0.8:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"endpoint_path": "/graphql?format=json"},
    {"endpoint_path": "/graphql/%72eport"},
    {"endpoint_path": "/graphql//nested"},
    {"endpoint_path": "/graphql/../elsewhere"},
    {"batch_size": 1},
    {"batch_size": 11},
    {"batch_size": 2.0},
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(GraphqlBatchingPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
