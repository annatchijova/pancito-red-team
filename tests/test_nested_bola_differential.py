"""Nested BOLA changes only the child identifier under an authorized parent."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.nested_bola import (
    NestedBolaPlan,
    NestedBolaPlanError,
    run_nested_bola_experiment,
)


OWNER_TOKEN = "nested-owner-token"
PEER_TOKEN = "nested-peer-token"
OWNER_CANARY = "NESTED-OWNER-CANARY"
PEER_CANARY = "NESTED-PEER-CANARY"


class _NestedLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    redirect_test = False
    leak_hits = 0
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        type(self).events.append(
            {
                "path": self.path,
                "step": self.headers.get("X-Pancito-Step"),
                "marker": self.headers.get("X-Pancito-Exercise"),
            }
        )
        token = self.headers.get("Authorization")
        if self.path == "/orgs/a/docs/a-doc" and token == f"Bearer {OWNER_TOKEN}":
            self._send(200, {"marker": OWNER_CANARY})
        elif self.path == "/orgs/b/docs/b-doc" and token == f"Bearer {PEER_TOKEN}":
            self._send(200, {"marker": PEER_CANARY})
        elif self.path == "/orgs/a/docs/b-doc" and token == f"Bearer {OWNER_TOKEN}":
            if type(self).redirect_test:
                self.send_response(302)
                self.send_header("Location", "/leak")
                self.end_headers()
            elif type(self).vulnerable:
                self._send(200, {"marker": PEER_CANARY})
            elif type(self).empty_success:
                self._send(200, {})
            else:
                self._send(403, {"error": "child outside parent"})
        elif self.path == "/leak":
            type(self).leak_hits += 1
            self._send(200, {"marker": PEER_CANARY})
        else:
            self._send(404, {"error": "missing"})

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
def nested_lab():
    handler = _NestedLab
    handler.vulnerable = False
    handler.empty_success = False
    handler.redirect_test = False
    handler.leak_hits = 0
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


def _plan(origin: str, **overrides) -> NestedBolaPlan:
    values = {
        "experiment_id": "NESTED-BOLA-001",
        "authorization_reference": "written-loopback-scope-nested-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "owner_control_path": "/orgs/a/docs/a-doc",
        "peer_control_path": "/orgs/b/docs/b-doc",
        "cross_child_path": "/orgs/a/docs/b-doc",
        "parent_segment_index": 1,
        "child_segment_index": 3,
        "owner_canary": OWNER_CANARY,
        "peer_canary": PEER_CANARY,
    }
    values.update(overrides)
    return NestedBolaPlan(**values)


def _credentials():
    return (
        BearerCredential("nested-owner", OWNER_TOKEN),
        BearerCredential("nested-peer", PEER_TOKEN),
    )


def test_cross_parent_child_confusion_is_confirmed_by_foreign_canary(nested_lab):
    origin, handler = nested_lab
    handler.vulnerable = True
    owner, peer = _credentials()

    result = run_nested_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "FOREIGN_CHILD_CANARY_OBSERVED"
    assert result["test"]["peer_canary_observed"] is True
    assert result["authorization_surface"]["changed_dimension"] == "CHILD_ID_ONLY"


def test_denied_child_substitution_falsifies_the_tested_cell(nested_lab):
    origin, _handler = nested_lab
    owner, peer = _credentials()

    result = run_nested_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "CROSS_PARENT_CHILD_ACCESS_DENIED"
    assert result["test"]["status"] == 403


def test_http_200_without_foreign_canary_is_not_a_finding(nested_lab):
    origin, handler = nested_lab
    handler.empty_success = True
    owner, peer = _credentials()

    result = run_nested_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"


def test_redirect_is_not_followed(nested_lab):
    origin, handler = nested_lab
    handler.redirect_test = True
    owner, peer = _credentials()

    result = run_nested_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_REDIRECTED"
    assert handler.leak_hits == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"cross_child_path": "/orgs/b/docs/b-doc"},
        {"cross_child_path": "/orgs/a/other/b-doc"},
        {"peer_control_path": "/orgs/a/docs/b-doc"},
        {"parent_segment_index": 3, "child_segment_index": 1},
        {"owner_control_path": "/orgs/a/docs/%61-doc"},
        {"target_origin": "http://10.0.0.8:8080"},
        {"target_origin": "http://127.0.0.1:0"},
    ],
)
def test_plan_rejects_non_differential_or_ambiguous_path_matrices(overrides):
    with pytest.raises(NestedBolaPlanError):
        _plan("http://127.0.0.1:8080", **overrides)


def test_receipt_is_body_token_and_canary_free_and_blue_marked(nested_lab):
    origin, handler = nested_lab
    handler.vulnerable = True
    owner, peer = _credentials()

    result = run_nested_bola_experiment(_plan(origin), owner=owner, peer=peer)
    serialized = json.dumps(result, sort_keys=True)

    for secret in (OWNER_TOKEN, PEER_TOKEN, OWNER_CANARY, PEER_CANARY):
        assert secret not in serialized
    assert "body" not in result["test"]
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["blue_objective"]["correlation_marker_is_detection"] is False
    assert {event["marker"] for event in handler.events} == {
        result["blue_objective"]["exercise_marker"]
    }
