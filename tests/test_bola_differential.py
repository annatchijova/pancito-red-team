"""BOLA proof requires live controls and a binary cross-principal oracle."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import (
    BearerCredential,
    BolaPlan,
    BolaPlanError,
    run_bola_experiment,
)
from offensive.handoff import BolaCandidateHandoff


OWNER_TOKEN = "owner-token-for-test"
PEER_TOKEN = "peer-token-for-test"
OWNER_CANARY = "CANARY-OWNER-ALPHA-001"
PEER_CANARY = "CANARY-PEER-BETA-002"


class _LabHandler(BaseHTTPRequestHandler):
    vulnerable = False
    redirect_test = False
    leak_hits = 0

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
        token = self.headers.get("Authorization", "")
        if self.path == "/objects/a":
            if token == f"Bearer {OWNER_TOKEN}":
                self._send(200, {"owner_marker": OWNER_CANARY})
                return
            if token == f"Bearer {PEER_TOKEN}" and self.redirect_test:
                self.send_response(302)
                self.send_header("Location", "/leak")
                self.end_headers()
                return
            if token == f"Bearer {PEER_TOKEN}" and self.vulnerable:
                self._send(200, {"owner_marker": OWNER_CANARY})
                return
            self._send(403, {"error": "forbidden"})
            return
        if self.path == "/objects/b":
            if token == f"Bearer {PEER_TOKEN}":
                self._send(200, {"peer_marker": PEER_CANARY})
                return
            self._send(403, {"error": "forbidden"})
            return
        if self.path == "/leak":
            type(self).leak_hits += 1
            self._send(200, {"owner_marker": OWNER_CANARY})
            return
        self._send(404, {"error": "missing"})

    def log_message(self, _format, *_args):
        return

    def _send(self, status, value):
        payload = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def bola_lab():
    _LabHandler.vulnerable = False
    _LabHandler.redirect_test = False
    _LabHandler.leak_hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _LabHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _plan(origin: str, **overrides) -> BolaPlan:
    values = {
        "experiment_id": "BOLA-LOCAL-001",
        "authorization_reference": "written-lab-scope-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "owner_path": "/objects/a",
        "peer_control_path": "/objects/b",
        "owner_canary": OWNER_CANARY,
        "peer_canary": PEER_CANARY,
        "timeout_ms": 2_000,
        "max_response_bytes": 16_384,
    }
    values.update(overrides)
    return BolaPlan(**values)


def _credentials():
    return (
        BearerCredential("principal-a", OWNER_TOKEN),
        BearerCredential("principal-b", PEER_TOKEN),
    )


def test_vulnerable_cross_principal_read_is_confirmed_by_induction(bola_lab):
    origin, handler = bola_lab
    handler.vulnerable = True
    owner, peer = _credentials()

    result = run_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "PEER_OBSERVED_OWNER_CANARY"
    assert result["controls"]["owner_control_passed"] is True
    assert result["controls"]["peer_control_passed"] is True
    assert result["test"]["owner_canary_observed"] is True


def test_cross_principal_denial_falsifies_the_candidate_for_this_object(bola_lab):
    origin, _handler = bola_lab
    owner, peer = _credentials()

    result = run_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "PEER_ACCESS_DENIED"
    assert result["test"]["status"] == 403


def test_invalid_peer_identity_makes_the_experiment_inconclusive(bola_lab):
    origin, _handler = bola_lab
    owner = BearerCredential("principal-a", OWNER_TOKEN)
    invalid_peer = BearerCredential("principal-b", "invalid-token")

    result = run_bola_experiment(_plan(origin), owner=owner, peer=invalid_peer)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "PEER_CONTROL_FAILED"
    assert result["controls"]["peer_control_passed"] is False


def test_redirect_is_not_followed_and_cannot_confirm_the_candidate(bola_lab):
    origin, handler = bola_lab
    handler.redirect_test = True
    owner, peer = _credentials()

    result = run_bola_experiment(_plan(origin), owner=owner, peer=peer)

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_REDIRECTED"
    assert result["test"]["status"] == 302
    assert handler.leak_hits == 0


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.com",
        "http://192.168.1.10:8080",
        "http://127.0.0.1:8080/base",
        "http://user:pass@127.0.0.1:8080",
        "http://127.0.0.1:8080?x=1",
    ],
)
def test_plan_rejects_targets_outside_an_exact_loopback_origin(origin):
    with pytest.raises(BolaPlanError):
        _plan(origin)


def test_plan_rejects_ambiguous_canaries_and_paths(bola_lab):
    origin, _handler = bola_lab
    with pytest.raises(BolaPlanError, match="distinct"):
        _plan(origin, peer_canary=OWNER_CANARY)
    with pytest.raises(BolaPlanError, match="relative HTTP path"):
        _plan(origin, owner_path="https://example.com/objects/a")


def test_receipt_contains_hashes_and_booleans_but_no_bodies_or_tokens(bola_lab):
    origin, handler = bola_lab
    handler.vulnerable = True
    owner, peer = _credentials()

    result = run_bola_experiment(_plan(origin), owner=owner, peer=peer)
    serialized = json.dumps(result, sort_keys=True)

    assert OWNER_TOKEN not in serialized
    assert PEER_TOKEN not in serialized
    assert OWNER_CANARY not in serialized
    assert PEER_CANARY not in serialized
    assert "body" not in result["test"]
    assert len(result["test"]["body_sha256"]) == 64
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False


def test_credential_repr_never_exposes_the_token():
    credential = BearerCredential("principal-a", OWNER_TOKEN)
    assert OWNER_TOKEN not in repr(credential)


def test_execution_receipt_keeps_candidate_provenance_at_candidate_level(bola_lab):
    origin, handler = bola_lab
    handler.vulnerable = True
    owner, peer = _credentials()
    handoff = BolaCandidateHandoff(
        candidate_id="CANDIDATE-0123456789abcdef",
        source_label="api/openapi.json@def456",
        source_sha256="a" * 64,
        entry_point="GET /objects/{object_id}",
    )

    result = run_bola_experiment(
        _plan(origin, candidate_handoff=handoff), owner=owner, peer=peer
    )

    assert result["candidate_provenance"] == handoff.to_receipt()
    assert result["candidate_provenance"]["epistemic_level"] == "CANDIDATE"
