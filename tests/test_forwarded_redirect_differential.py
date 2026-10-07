"""A forwarded header must never become a redirect's resolved authority."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.forwarded_redirect import (
    ForwardedRedirectPlan,
    ForwardedRedirectPlanError,
    run_forwarded_redirect_experiment,
)


CANARY_HOST = "canary.pancito-lab.invalid"


class _RedirectLab(BaseHTTPRequestHandler):
    # "naive": reproduces the vpn-honeypots catchall bug -- builds the
    # Location by concatenating proto/Host without validating either.
    # "safe": always redirects to its own origin regardless of headers.
    # "external_baseline": already redirects off-origin with no header at all
    # (a contaminated instrument -- the experiment must call this out).
    mode = "safe"

    def do_GET(self):  # noqa: N802
        if self.mode == "external_baseline":
            self._redirect("https://already-external.invalid/elsewhere")
            return
        own_host = self.headers.get("Host", "127.0.0.1")
        if self.mode == "naive":
            proto = self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
            host = self.headers.get("Host", own_host)
            self._redirect(f"{proto}://{host}/landed")
            return
        self._redirect(f"http://{own_host}/landed")

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def redirect_lab():
    handler = _RedirectLab
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
        "experiment_id": "FWDREDIR-LOCAL-001",
        "authorization_reference": "written-loopback-forwarded-redirect-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "redirect_path": "/unmatched-probe-path",
        "forwarded_header_name": "X-Forwarded-Proto",
        "canary_host": CANARY_HOST,
    }
    values.update(overrides)
    return ForwardedRedirectPlan(**values)


def test_naive_scheme_smuggling_is_confirmed_by_a_real_url_parser(redirect_lab):
    origin, handler = redirect_lab
    handler.mode = "naive"
    result = run_forwarded_redirect_experiment(_plan(origin))
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "FORWARDED_HEADER_BECAME_REDIRECT_AUTHORITY"
    assert result["test"]["resolved_authority"] == CANARY_HOST
    assert result["controls"]["baseline_control_passed"] is True


def test_host_header_strategy_is_independent_of_proto_strategy(redirect_lab):
    origin, handler = redirect_lab
    handler.mode = "naive"
    result = run_forwarded_redirect_experiment(
        _plan(origin, forwarded_header_name="Host")
    )
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["test"]["resolved_authority"] == CANARY_HOST


def test_safe_app_falsifies_the_forwarded_header_hypothesis(redirect_lab):
    origin, handler = redirect_lab
    handler.mode = "safe"
    result = run_forwarded_redirect_experiment(_plan(origin))
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "FORWARDED_HEADER_REJECTED_OR_IGNORED"


def test_already_external_baseline_is_inconclusive_not_confirmed(redirect_lab):
    origin, handler = redirect_lab
    handler.mode = "external_baseline"
    result = run_forwarded_redirect_experiment(_plan(origin))
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "BASELINE_ALREADY_EXTERNAL"
    assert result["controls"]["baseline_control_passed"] is False


def test_oracle_is_a_real_parser_not_a_substring_match(redirect_lab):
    """A canary that merely *appears* in the path must not be mistaken for authority."""
    origin, handler = redirect_lab

    class _Decoy(_RedirectLab):
        def do_GET(self):  # noqa: N802
            own_host = self.headers.get("Host", "127.0.0.1")
            self._redirect(f"http://{own_host}/path-mentions-{CANARY_HOST}-but-is-not-it")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Decoy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        decoy_origin = f"http://127.0.0.1:{server.server_port}"
        result = run_forwarded_redirect_experiment(_plan(decoy_origin))
        assert result["epistemic_level"] == "FALSIFIED"
        assert result["reason_code"] == "FORWARDED_HEADER_REJECTED_OR_IGNORED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_receipt_carries_no_secret_and_is_blue_marked(redirect_lab):
    origin, handler = redirect_lab
    handler.mode = "naive"
    result = run_forwarded_redirect_experiment(_plan(origin))
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["blue_objective"]["exercise_marker"]


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://10.0.0.8:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"redirect_path": "/probe?format=json"},
    {"redirect_path": "/probe/%72eport"},
    {"redirect_path": "/probe//nested"},
    {"redirect_path": "/probe/../elsewhere"},
    {"forwarded_header_name": "X-Forwarded-Host"},
    {"forwarded_header_name": "not-a-real-header-at-all"},
    {"canary_host": "127.0.0.1"},
])
def test_plan_rejects_ambiguous_boundaries(overrides):
    with pytest.raises(ForwardedRedirectPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
