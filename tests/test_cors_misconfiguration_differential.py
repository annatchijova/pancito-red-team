"""The server's Origin reflection must never become an attacker-chosen credential."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.cors_misconfiguration import (
    CorsMisconfigurationPlan,
    CorsMisconfigurationPlanError,
    run_cors_misconfiguration_experiment,
)


CANARY_ORIGIN = "http://canary.pancito-lab.invalid"


class _CorsLab(BaseHTTPRequestHandler):
    # "naive": reflects whatever Origin it receives, with credentials true --
    # the CORScanner headline bug (trusts the Origin header as a credential).
    # "safe": allowlists one fixed partner origin and never reflects the request.
    # "wildcard": static "*" regardless of Origin -- public-API design, not
    # attacker-specific trust.
    mode = "safe"

    def do_GET(self):  # noqa: N802
        origin = self.headers.get("Origin")
        if self.mode == "naive" and origin:
            self._respond({"Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true"})
            return
        if self.mode == "wildcard":
            self._respond({"Access-Control-Allow-Origin": "*"})
            return
        self._respond({"Access-Control-Allow-Origin": "https://partner.pancito-lab.invalid"})

    def _respond(self, extra_headers):
        self.send_response(200)
        for name, value in extra_headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def cors_lab():
    handler = _CorsLab
    handler.mode = "safe"
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
        "experiment_id": "CORSMIS-LOCAL-001",
        "authorization_reference": "written-loopback-cors-misconfiguration-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "probe_path": "/unmatched-probe-path",
        "canary_origin": CANARY_ORIGIN,
    }
    values.update(overrides)
    return CorsMisconfigurationPlan(**values)


def test_naive_reflection_with_credentials_is_confirmed(cors_lab):
    origin, handler = cors_lab
    handler.mode = "naive"
    result = run_cors_misconfiguration_experiment(_plan(origin))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ARBITRARY_ORIGIN_REFLECTED"
    assert result["test"]["allow_origin"] == CANARY_ORIGIN
    assert result["credentials_exposed"] is True
    assert result["controls"]["baseline_control_passed"] is True


def test_fixed_allowlist_falsifies_the_reflection_hypothesis(cors_lab):
    origin, handler = cors_lab
    handler.mode = "safe"
    result = run_cors_misconfiguration_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "CORS_ORIGIN_NOT_REFLECTED"
    assert result["credentials_exposed"] is False


def test_wildcard_is_falsified_as_not_origin_specific(cors_lab):
    origin, handler = cors_lab
    handler.mode = "wildcard"
    result = run_cors_misconfiguration_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "CORS_WILDCARD_NOT_ORIGIN_SPECIFIC"


def test_oracle_is_an_exact_origin_match_not_a_substring_match(cors_lab):
    """A reflection that merely *contains* the canary host is not the canary origin."""
    origin, handler = cors_lab

    class _Decoy(_CorsLab):
        def do_GET(self):  # noqa: N802
            self._respond({
                "Access-Control-Allow-Origin":
                    f"https://not-{CANARY_ORIGIN.split('//', 1)[1]}.evil.invalid",
            })

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Decoy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        decoy_origin = f"http://127.0.0.1:{server.server_port}"
        result = run_cors_misconfiguration_experiment(_plan(decoy_origin))
        assert result["epistemic_level"] == "FALSIFIED"
        assert result["reason_code"] == "CORS_ORIGIN_NOT_REFLECTED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_receipt_carries_no_secret_and_is_blue_marked(cors_lab):
    origin, handler = cors_lab
    handler.mode = "naive"
    result = run_cors_misconfiguration_experiment(_plan(origin))
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["blue_objective"]["exercise_marker"]


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://10.0.0.8:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"probe_path": "/probe?format=json"},
    {"probe_path": "/probe/%72eport"},
    {"probe_path": "/probe//nested"},
    {"probe_path": "/probe/../elsewhere"},
    {"canary_origin": "not-a-origin"},
    {"canary_origin": "http://127.0.0.1:8080"},
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(CorsMisconfigurationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
