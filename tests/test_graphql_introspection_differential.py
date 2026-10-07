"""A GraphQL endpoint's schema must never be disclosed to an unverified caller."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.graphql_introspection import (
    GraphqlIntrospectionPlan,
    GraphqlIntrospectionPlanError,
    run_graphql_introspection_experiment,
)


class _GraphqlLab(BaseHTTPRequestHandler):
    # "open": answers every query, introspection included -- the graphql-cop
    # headline check.
    # "hardened": answers __typename but rejects any query containing __schema.
    # "not_graphql": a plain HTTP endpoint that happens to live at the path --
    # never emits a GraphQL-shaped body at all.
    mode = "hardened"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.mode == "not_graphql":
            self._respond_json({"ok": True})
            return
        try:
            query = json.loads(raw.decode("utf-8")).get("query", "")
        except (UnicodeDecodeError, json.JSONDecodeError):
            query = ""
        if "__schema" in query:
            if self.mode == "open":
                self._respond_json(
                    {"data": {"__schema": {"queryType": {"name": "Query"}}}}
                )
            else:
                self._respond_json(
                    {"errors": [{"message": "introspection is disabled"}]}
                )
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
    handler.mode = "hardened"
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
        "experiment_id": "GQLINTRO-LOCAL-001",
        "authorization_reference": "written-loopback-graphql-introspection-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "endpoint_path": "/graphql",
    }
    values.update(overrides)
    return GraphqlIntrospectionPlan(**values)


def test_open_endpoint_discloses_schema_is_confirmed(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "open"
    result = run_graphql_introspection_experiment(_plan(origin))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "INTROSPECTION_SCHEMA_DISCLOSED"
    assert result["controls"]["baseline_control_passed"] is True


def test_hardened_endpoint_falsifies_the_disclosure_hypothesis(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "hardened"
    result = run_graphql_introspection_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "INTROSPECTION_REJECTED_OR_DISABLED"
    assert result["controls"]["baseline_control_passed"] is True


def test_non_graphql_endpoint_is_inconclusive_not_falsified(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "not_graphql"
    result = run_graphql_introspection_experiment(_plan(origin))
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "BASELINE_NOT_A_GRAPHQL_ENDPOINT"
    assert result["controls"]["baseline_control_passed"] is False


def test_oracle_requires_structured_disclosure_not_a_substring_match(graphql_lab):
    """A response that merely *mentions* __schema in an error is not disclosure."""
    origin, handler = graphql_lab

    class _Decoy(_GraphqlLab):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self._respond_json(
                {"errors": [{"message": "unknown field __schema requested"}]}
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Decoy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        decoy_origin = f"http://127.0.0.1:{server.server_port}"
        result = run_graphql_introspection_experiment(_plan(decoy_origin))
        assert result["epistemic_level"] == "INCONCLUSIVE"
        assert result["reason_code"] == "BASELINE_NOT_A_GRAPHQL_ENDPOINT"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_receipt_carries_no_secret_and_is_blue_marked(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "open"
    result = run_graphql_introspection_experiment(_plan(origin))
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
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(GraphqlIntrospectionPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
