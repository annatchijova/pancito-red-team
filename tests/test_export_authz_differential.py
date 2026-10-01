"""Cross-tenant export access requires role controls and a foreign canary."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.export_authz import (
    ExportAuthorizationPlan,
    ExportAuthorizationPlanError,
    run_export_authorization_experiment,
)


ALPHA_TOKEN = "export-alpha-token"
BRAVO_TOKEN = "export-bravo-token"
ALPHA_CANARY = "EXPORT-ALPHA-CSV-CANARY"
BRAVO_CANARY = "EXPORT-BRAVO-CSV-CANARY"


class _ExportLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    events: list[dict[str, str | None]] = []

    def do_GET(self):  # noqa: N802
        type(self).events.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "accept": self.headers.get("Accept"),
                "user_agent": self.headers.get("User-Agent"),
                "marker": self.headers.get("X-Pancito-Exercise"),
            }
        )
        token = self.headers.get("Authorization")
        if self.path == "/tenants/alpha/export.csv" and token == f"Bearer {ALPHA_TOKEN}":
            self._send(200, f"record_id\n{ALPHA_CANARY}\n".encode())
        elif self.path == "/tenants/bravo/export.csv":
            if token == f"Bearer {BRAVO_TOKEN}" or (
                token == f"Bearer {ALPHA_TOKEN}" and type(self).vulnerable
            ):
                self._send(200, f"record_id\n{BRAVO_CANARY}\n".encode())
            elif token == f"Bearer {ALPHA_TOKEN}" and type(self).empty_success:
                self._send(200, b"record_id\n")
            else:
                self._send(403, b"forbidden\n")
        else:
            self._send(404, b"missing\n")

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def export_lab():
    handler = _ExportLab
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
        "experiment_id": "EXPORT-LOCAL-001",
        "authorization_reference": "written-loopback-export-scope-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "alpha_export_path": "/tenants/alpha/export.csv",
        "bravo_export_path": "/tenants/bravo/export.csv",
        "tenant_segment_index": 1,
        "alpha_canary": ALPHA_CANARY,
        "bravo_canary": BRAVO_CANARY,
    }
    values.update(overrides)
    return ExportAuthorizationPlan(**values)


def _credentials():
    return (
        BearerCredential("alpha-member", ALPHA_TOKEN),
        BearerCredential("bravo-member", BRAVO_TOKEN),
    )


def test_foreign_export_requires_bravo_canary_and_only_credential_changes(export_lab):
    origin, handler = export_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()

    result = run_export_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ALPHA_OBSERVED_BRAVO_EXPORT_CANARY"
    assert result["test"]["bravo_canary_observed"] is True
    benign_twin = dict(handler.events[1])
    negative = dict(handler.events[2])
    assert benign_twin.pop("authorization") != negative.pop("authorization")
    assert benign_twin == negative


def test_foreign_export_denial_falsifies_only_the_tested_cell(export_lab):
    origin, _handler = export_lab
    alpha, bravo = _credentials()
    result = run_export_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "ALPHA_BRAVO_EXPORT_DENIED"


def test_empty_export_success_is_inconclusive(export_lab):
    origin, handler = export_lab
    handler.empty_success = True
    alpha, bravo = _credentials()
    result = run_export_authorization_experiment(
        _plan(origin), alpha=alpha, bravo=bravo
    )

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"


def test_receipt_omits_tokens_and_canaries(export_lab):
    origin, handler = export_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()
    result = run_export_authorization_experiment(
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
        {"alpha_export_path": "/tenants/%61lpha/export.csv"},
        {"alpha_export_path": "/tenants//export.csv"},
        {"alpha_export_path": "/tenants/../export.csv"},
        {"bravo_export_path": "/teams/bravo/export.csv"},
        {"tenant_segment_index": 0},
        {"alpha_canary": BRAVO_CANARY},
    ],
)
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(ExportAuthorizationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
