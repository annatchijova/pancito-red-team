"""A server-side fetch must never reach a destination named by the caller."""

from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from offensive.ssrf_outbound_fetch import (
    SsrfOutboundFetchPlan,
    SsrfOutboundFetchPlanError,
    run_ssrf_outbound_fetch_experiment,
)


class _SsrfLab(BaseHTTPRequestHandler):
    # "vulnerable": fetches the "url" parameter server-side, asynchronously,
    # after already responding to the caller -- the realistic shape the
    # canary_grace_ms wait exists for.
    # "vulnerable_sync": fetches it BEFORE responding, so the hit is already
    # recorded by the time the caller's request completes.
    # "safe": never touches the parameter at all.
    mode = "safe"

    def do_GET(self):  # noqa: N802
        query = parse_qs(urlsplit(self.path).query)
        url_values = query.get("url")
        if self.mode == "vulnerable_sync" and url_values:
            self._fetch(url_values[0])
            self._respond()
            return
        if self.mode == "vulnerable" and url_values:
            self._respond()
            threading.Thread(target=self._fetch, args=(url_values[0],), daemon=True).start()
            return
        self._respond()

    @staticmethod
    def _fetch(url):
        try:
            urllib.request.urlopen(url, timeout=2).read()
        except OSError:
            pass

    def _respond(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def ssrf_lab():
    handler = _SsrfLab
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
        "experiment_id": "SSRF-LOCAL-001",
        "authorization_reference": "written-loopback-ssrf-outbound-fetch-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "probe_path": "/fetch",
        "url_parameter_name": "url",
        "canary_grace_ms": 500,
    }
    values.update(overrides)
    return SsrfOutboundFetchPlan(**values)


def test_vulnerable_async_fetch_is_confirmed_within_the_grace_window(ssrf_lab):
    origin, handler = ssrf_lab
    handler.mode = "vulnerable"
    result = run_ssrf_outbound_fetch_experiment(_plan(origin))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "SSRF_OUTBOUND_FETCH_REACHED_CANARY"
    assert result["controls"]["baseline_control_passed"] is True
    assert result["canary_hit_count"] == 1


def test_vulnerable_sync_fetch_is_confirmed_with_zero_grace(ssrf_lab):
    origin, handler = ssrf_lab
    handler.mode = "vulnerable_sync"
    result = run_ssrf_outbound_fetch_experiment(_plan(origin, canary_grace_ms=0))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "SSRF_OUTBOUND_FETCH_REACHED_CANARY"


def test_safe_target_falsifies_the_ssrf_hypothesis(ssrf_lab):
    origin, handler = ssrf_lab
    handler.mode = "safe"
    result = run_ssrf_outbound_fetch_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "CANARY_NOT_REACHED"
    assert result["canary_hit_count"] == 0


def test_receipt_carries_no_secret_and_is_blue_marked(ssrf_lab):
    origin, handler = ssrf_lab
    handler.mode = "vulnerable"
    result = run_ssrf_outbound_fetch_experiment(_plan(origin))
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["blue_objective"]["exercise_marker"]
    assert result["request_count"] == 2


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://10.0.0.8:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"probe_path": "/fetch?format=json"},
    {"probe_path": "/fetch/%72eport"},
    {"probe_path": "/fetch//nested"},
    {"probe_path": "/fetch/../elsewhere"},
    {"url_parameter_name": "has spaces"},
    {"url_parameter_name": "123starts-with-digit"},
    {"url_parameter_name": ""},
    {"timeout_ms": 50},
    {"canary_grace_ms": -1},
    {"canary_grace_ms": 10_000},
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(SsrfOutboundFetchPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
