"""Search isolation requires two tenant controls and a foreign-result canary."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from offensive.bola import BearerCredential
from offensive.search_authz import (
    SearchAuthorizationPlan,
    SearchAuthorizationPlanError,
    run_search_authorization_experiment,
)


ALPHA_TOKEN = "search-alpha-token"
BRAVO_TOKEN = "search-bravo-token"
ALPHA_QUERY = "alpha-unique-record"
BRAVO_QUERY = "bravo-unique-record"
ALPHA_CANARY = "SEARCH-ALPHA-RESULT-CANARY"
BRAVO_CANARY = "SEARCH-BRAVO-RESULT-CANARY"


class _SearchLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        value = query.get("q", [None])[0]
        token = self.headers.get("Authorization")
        type(self).events.append(
            {
                "path": parsed.path,
                "query": value,
                "authorization": token,
                "accept": self.headers.get("Accept"),
                "user_agent": self.headers.get("User-Agent"),
                "marker": self.headers.get("X-Pancito-Exercise"),
            }
        )
        if parsed.path != "/api/search":
            self._send(404, {"error": "missing"})
        elif value == ALPHA_QUERY and token == f"Bearer {ALPHA_TOKEN}":
            self._send(200, {"results": [{"marker": ALPHA_CANARY}]})
        elif value == BRAVO_QUERY and (
            token == f"Bearer {BRAVO_TOKEN}"
            or (token == f"Bearer {ALPHA_TOKEN}" and type(self).vulnerable)
        ):
            self._send(200, {"results": [{"marker": BRAVO_CANARY}]})
        elif (
            value == BRAVO_QUERY
            and token == f"Bearer {ALPHA_TOKEN}"
            and type(self).empty_success
        ):
            self._send(200, {"results": []})
        else:
            self._send(403, {"error": "forbidden"})

    def _send(self, status, value):
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def search_lab():
    handler = _SearchLab
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
        "experiment_id": "SEARCH-LOCAL-001",
        "authorization_reference": "written-loopback-search-scope-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "search_path": "/api/search",
        "query_parameter": "q",
        "alpha_query": ALPHA_QUERY,
        "bravo_query": BRAVO_QUERY,
        "alpha_canary": ALPHA_CANARY,
        "bravo_canary": BRAVO_CANARY,
    }
    values.update(overrides)
    return SearchAuthorizationPlan(**values)


def _credentials():
    return (
        BearerCredential("alpha-member", ALPHA_TOKEN),
        BearerCredential("bravo-member", BRAVO_TOKEN),
    )


def test_foreign_search_result_requires_bravo_canary_and_only_credential_changes(search_lab):
    origin, handler = search_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()

    result = run_search_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ALPHA_OBSERVED_BRAVO_SEARCH_CANARY"
    assert result["test"]["bravo_canary_observed"] is True
    benign_twin = dict(handler.events[1])
    negative = dict(handler.events[2])
    assert benign_twin.pop("authorization") != negative.pop("authorization")
    assert benign_twin == negative


def test_search_denial_falsifies_only_the_tested_cell(search_lab):
    origin, _handler = search_lab
    alpha, bravo = _credentials()

    result = run_search_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "ALPHA_BRAVO_SEARCH_DENIED"


def test_empty_search_success_is_inconclusive(search_lab):
    origin, handler = search_lab
    handler.empty_success = True
    alpha, bravo = _credentials()

    result = run_search_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"


def test_receipt_omits_tokens_queries_and_canaries(search_lab):
    origin, handler = search_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()

    result = run_search_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )
    serialized = json.dumps(result, sort_keys=True)

    assert all(
        secret not in serialized
        for secret in (
            ALPHA_TOKEN,
            BRAVO_TOKEN,
            ALPHA_QUERY,
            BRAVO_QUERY,
            ALPHA_CANARY,
            BRAVO_CANARY,
        )
    )
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert {event["marker"] for event in handler.events} == {
        result["blue_objective"]["exercise_marker"]
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_origin": "http://10.0.0.8:8080"},
        {"search_path": "/api/%73earch"},
        {"search_path": "/api//search"},
        {"search_path": "/api/../search"},
        {"search_path": "/api/search?tenant=alpha"},
        {"query_parameter": "q&tenant=alpha"},
        {"bravo_query": ALPHA_QUERY},
        {"bravo_canary": ALPHA_CANARY},
    ],
)
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(SearchAuthorizationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
