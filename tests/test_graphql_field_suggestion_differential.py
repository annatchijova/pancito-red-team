"""A GraphQL validation error must never propose the real field name to the caller."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.graphql_field_suggestion import (
    GraphqlFieldSuggestionPlan,
    GraphqlFieldSuggestionPlanError,
    run_graphql_field_suggestion_experiment,
)


class _GraphqlLab(BaseHTTPRequestHandler):
    # "suggesting": default error formatting -- proposes the closest valid
    # field name back to the caller (the graphql-cop headline leak).
    # "suppressed": returns a generic validation error with no suggestion.
    # "not_graphql": never emits a GraphQL-shaped body at all.
    mode = "suppressed"

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
        if "__typenam}" in query:
            if self.mode == "suggesting":
                self._respond_json({"errors": [
                    {"message": 'Cannot query field "__typenam". Did you mean "__typename"?'}
                ]})
            else:
                self._respond_json({"errors": [{"message": "validation error"}]})
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
    handler.mode = "suppressed"
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
        "experiment_id": "GQLSUGGEST-LOCAL-001",
        "authorization_reference": "written-loopback-graphql-field-suggestion-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "endpoint_path": "/graphql",
    }
    values.update(overrides)
    return GraphqlFieldSuggestionPlan(**values)


def test_default_formatting_discloses_the_field_name_is_confirmed(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "suggesting"
    result = run_graphql_field_suggestion_experiment(_plan(origin))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "FIELD_SUGGESTION_DISCLOSED_SCHEMA_NAME"
    assert result["controls"]["baseline_control_passed"] is True


def test_suppressed_formatting_falsifies_the_leak_hypothesis(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "suppressed"
    result = run_graphql_field_suggestion_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "FIELD_SUGGESTION_SUPPRESSED"
    assert result["controls"]["baseline_control_passed"] is True


def test_non_graphql_endpoint_is_inconclusive_not_falsified(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "not_graphql"
    result = run_graphql_field_suggestion_experiment(_plan(origin))
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "BASELINE_NOT_A_GRAPHQL_ENDPOINT"
    assert result["controls"]["baseline_control_passed"] is False


def test_oracle_requires_both_the_suggestion_phrase_and_the_exact_field_name(graphql_lab):
    """A generic 'did you mean' with no field name, or the field name with no
    suggestion phrasing, must not be mistaken for disclosure."""
    origin, handler = graphql_lab

    class _Decoy(_GraphqlLab):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self._respond_json({"errors": [
                {"message": "Did you mean to check your query syntax?"}
            ]})

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Decoy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        decoy_origin = f"http://127.0.0.1:{server.server_port}"
        result = run_graphql_field_suggestion_experiment(_plan(decoy_origin))
        assert result["epistemic_level"] == "INCONCLUSIVE"
        assert result["reason_code"] == "BASELINE_NOT_A_GRAPHQL_ENDPOINT"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_receipt_carries_no_secret_and_is_blue_marked(graphql_lab):
    origin, handler = graphql_lab
    handler.mode = "suggesting"
    result = run_graphql_field_suggestion_experiment(_plan(origin))
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
    with pytest.raises(GraphqlFieldSuggestionPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
