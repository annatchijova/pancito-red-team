"""Collection isolation requires two controls and a foreign-tenant canary."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.collection_authz import (
    CollectionAuthorizationPlan,
    CollectionAuthorizationPlanError,
    run_collection_authorization_experiment,
)


ALPHA_TOKEN = "collection-alpha-token"
BRAVO_TOKEN = "collection-bravo-token"
ALPHA_CANARY = "COLLECTION-ALPHA-CANARY"
BRAVO_CANARY = "COLLECTION-BRAVO-CANARY"


class _CollectionLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        type(self).events.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "step": self.headers.get("X-Pancito-Step"),
                "marker": self.headers.get("X-Pancito-Exercise"),
            }
        )
        token = self.headers.get("Authorization")
        if self.path == "/tenants/alpha/items" and token == f"Bearer {ALPHA_TOKEN}":
            self._send(200, {"items": [{"marker": ALPHA_CANARY}]})
        elif self.path == "/tenants/bravo/items":
            if token == f"Bearer {BRAVO_TOKEN}" or (
                token == f"Bearer {ALPHA_TOKEN}" and type(self).vulnerable
            ):
                self._send(200, {"items": [{"marker": BRAVO_CANARY}]})
            elif token == f"Bearer {ALPHA_TOKEN}" and type(self).empty_success:
                self._send(200, {"items": []})
            else:
                self._send(403, {"error": "forbidden"})
        else:
            self._send(404, {"error": "missing"})

    def _send(self, status, value):
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def collection_lab():
    handler = _CollectionLab
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
        "experiment_id": "COLLECTION-LOCAL-001",
        "authorization_reference": "written-loopback-scope-collection-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "alpha_collection_path": "/tenants/alpha/items",
        "bravo_collection_path": "/tenants/bravo/items",
        "alpha_canary": ALPHA_CANARY,
        "bravo_canary": BRAVO_CANARY,
    }
    values.update(overrides)
    return CollectionAuthorizationPlan(**values)


def _credentials():
    return (
        BearerCredential("alpha-member", ALPHA_TOKEN),
        BearerCredential("bravo-member", BRAVO_TOKEN),
    )


def test_foreign_collection_is_confirmed_only_by_foreign_canary(collection_lab):
    origin, handler = collection_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()

    result = run_collection_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ALPHA_OBSERVED_BRAVO_COLLECTION_CANARY"
    assert result["test"]["bravo_canary_observed"] is True
    benign_twin = dict(handler.events[1])
    negative = dict(handler.events[2])
    assert benign_twin.pop("authorization") != negative.pop("authorization")
    assert benign_twin == negative


def test_foreign_collection_denial_falsifies_only_the_tested_cell(collection_lab):
    origin, _handler = collection_lab
    alpha, bravo = _credentials()

    result = run_collection_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "ALPHA_BRAVO_COLLECTION_DENIED"


def test_empty_success_is_inconclusive(collection_lab):
    origin, handler = collection_lab
    handler.empty_success = True
    alpha, bravo = _credentials()

    result = run_collection_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"


def test_receipt_is_secret_free_and_blue_marked(collection_lab):
    origin, handler = collection_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()
    result = run_collection_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )
    serialized = json.dumps(result, sort_keys=True)

    assert all(
        secret not in serialized
        for secret in (ALPHA_TOKEN, BRAVO_TOKEN, ALPHA_CANARY, BRAVO_CANARY)
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
        {"target_origin": "http://127.0.0.1:0"},
        {"alpha_collection_path": "/tenants/%61lpha/items"},
        {"alpha_collection_path": "/tenants//items"},
        {"alpha_collection_path": "/tenants/../items"},
        {"bravo_collection_path": "/tenants/alpha/items"},
        {"bravo_canary": ALPHA_CANARY},
    ],
)
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(CollectionAuthorizationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
