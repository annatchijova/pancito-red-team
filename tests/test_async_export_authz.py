"""Stateful authorization checks for disposable asynchronous export jobs."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.async_export_authz import (
    AsyncExportAuthorizationPlan,
    AsyncExportAuthorizationPlanError,
    run_async_export_authorization_experiment,
)


ALPHA_TOKEN = "async-alpha-token"
BRAVO_TOKEN = "async-bravo-token"
ALPHA_CANARY = "ASYNC-ALPHA-EXPORT-CANARY"
BRAVO_CANARY = "ASYNC-BRAVO-EXPORT-CANARY"


class _AsyncExportLab(BaseHTTPRequestHandler):
    vulnerable = False
    empty_success = False
    cleanup_fails_for: str | None = None
    drop_create_response_for: str | None = None
    jobs: dict[str, tuple[str, str]] = {}
    serial = 0
    events: list[dict[str, str | None]] = []

    def do_POST(self):  # noqa: N802
        type(self).events.append(self._event("POST"))
        tenant = self.path.split("/")[2] if self.path.count("/") == 3 else ""
        token = self.headers.get("Authorization")
        if (tenant, token) not in {
            ("alpha", f"Bearer {ALPHA_TOKEN}"),
            ("bravo", f"Bearer {BRAVO_TOKEN}"),
        }:
            return self._send(403, b"forbidden")
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if body != b'{"format":"csv","scope":"current_tenant"}':
            return self._send(400, b"invalid request")
        type(self).serial += 1
        job_id = f"job-{type(self).serial}"
        canary = ALPHA_CANARY if tenant == "alpha" else BRAVO_CANARY
        type(self).jobs[job_id] = (tenant, canary)
        if tenant == type(self).drop_create_response_for:
            self.close_connection = True
            self.connection.close()
            return
        return self._send(201, json.dumps({"job_id": job_id, "status": "READY"}).encode())

    def do_GET(self):  # noqa: N802
        type(self).events.append(self._event("GET"))
        parts = self.path.split("/")
        if len(parts) not in {5, 6} or parts[1] != "tenants" or parts[3] != "exports":
            return self._send(404, b"missing")
        tenant, job_id = parts[2], parts[4]
        download = len(parts) == 6 and parts[5] == "download"
        job = type(self).jobs.get(job_id)
        if job is None or job[0] != tenant:
            return self._send(404, b"missing")
        expected_token = ALPHA_TOKEN if tenant == "alpha" else BRAVO_TOKEN
        token = self.headers.get("Authorization")
        if token != f"Bearer {expected_token}":
            if not (download and tenant == "bravo" and token == f"Bearer {ALPHA_TOKEN}" and type(self).vulnerable):
                if download and tenant == "bravo" and token == f"Bearer {ALPHA_TOKEN}" and type(self).empty_success:
                    return self._send(200, b"record_id\n")
                return self._send(403, b"forbidden")
        if download:
            return self._send(200, f"record_id\n{job[1]}\n".encode())
        return self._send(200, json.dumps({"job_id": job_id, "status": "READY"}).encode())

    def do_DELETE(self):  # noqa: N802
        type(self).events.append(self._event("DELETE"))
        parts = self.path.split("/")
        if len(parts) != 5 or parts[1] != "tenants" or parts[3] != "exports":
            return self._send(404, b"missing")
        tenant, job_id = parts[2], parts[4]
        job = type(self).jobs.get(job_id)
        token = self.headers.get("Authorization")
        expected_token = ALPHA_TOKEN if tenant == "alpha" else BRAVO_TOKEN
        if job is None or job[0] != tenant or token != f"Bearer {expected_token}":
            return self._send(403, b"forbidden")
        if job_id == type(self).cleanup_fails_for:
            return self._send(503, b"unavailable")
        del type(self).jobs[job_id]
        return self._send(204, b"")

    def _event(self, method):
        return {"method": method, "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "accept": self.headers.get("Accept"),
                "user_agent": self.headers.get("User-Agent"),
                "marker": self.headers.get("X-Pancito-Exercise")}

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def async_export_lab():
    handler = _AsyncExportLab
    handler.vulnerable = False
    handler.empty_success = False
    handler.cleanup_fails_for = None
    handler.drop_create_response_for = None
    handler.jobs = {}
    handler.serial = 0
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
        "experiment_id": "ASYNC-EXPORT-LOCAL-001",
        "authorization_reference": "written-disposable-loopback-scope-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "alpha_create_path": "/tenants/alpha/exports",
        "bravo_create_path": "/tenants/bravo/exports",
        "alpha_jobs_path": "/tenants/alpha/exports",
        "bravo_jobs_path": "/tenants/bravo/exports",
        "alpha_canary": ALPHA_CANARY,
        "bravo_canary": BRAVO_CANARY,
    }
    values.update(overrides)
    return AsyncExportAuthorizationPlan(**values)


def _credentials():
    return (BearerCredential("alpha-member", ALPHA_TOKEN),
            BearerCredential("bravo-member", BRAVO_TOKEN))


def test_cross_tenant_job_download_requires_canary_and_cleans_both_jobs(async_export_lab):
    origin, handler = async_export_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()
    result = run_async_export_authorization_experiment(_plan(origin), alpha=alpha, bravo=bravo)

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["reason_code"] == "ALPHA_OBSERVED_BRAVO_ASYNC_EXPORT_CANARY"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert result["request_count"] == 12
    assert handler.jobs == {}
    owner_download, cross_download = dict(handler.events[5]), dict(handler.events[6])
    assert owner_download["method"] == cross_download["method"] == "GET"
    assert owner_download["path"] == cross_download["path"]
    owner_auth = owner_download.pop("authorization")
    cross_auth = cross_download.pop("authorization")
    assert owner_auth != cross_auth
    assert owner_download == cross_download
    post_test_control = dict(handler.events[7])
    bravo_pretest_control = dict(handler.events[5])
    assert post_test_control == bravo_pretest_control
    assert all(len(event["response_capture_sha256"]) == 64
               for event in result["events"])
    cross_event = next(event for event in result["events"]
                       if event["step"] == "CROSS_TENANT_JOB_DOWNLOAD_TEST")
    assert cross_event["canary_observed"] is True
    assert cross_event["other_tenant_canary_observed"] is False


def test_denied_cross_tenant_job_download_falsifies_only_tested_cell(async_export_lab):
    origin, handler = async_export_lab
    alpha, bravo = _credentials()
    result = run_async_export_authorization_experiment(_plan(origin), alpha=alpha, bravo=bravo)
    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "ALPHA_BRAVO_ASYNC_EXPORT_DENIED"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert handler.jobs == {}


def test_success_without_foreign_canary_is_inconclusive_and_cleans(async_export_lab):
    origin, handler = async_export_lab
    handler.empty_success = True
    alpha, bravo = _credentials()
    result = run_async_export_authorization_experiment(_plan(origin), alpha=alpha, bravo=bravo)
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "TEST_ORACLE_NOT_SATISFIED"
    assert result["cleanup_status"] == "RESTORED_TO_BASELINE"
    assert handler.jobs == {}


def test_failed_cleanup_is_explicit_and_reports_remaining_job(async_export_lab):
    origin, handler = async_export_lab
    handler.vulnerable = True
    handler.cleanup_fails_for = "job-2"
    alpha, bravo = _credentials()
    result = run_async_export_authorization_experiment(_plan(origin), alpha=alpha, bravo=bravo)
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["manual_cleanup_count"] == 1
    assert len(handler.jobs) == 1


def test_lost_create_response_is_reported_as_unknown_possible_orphan(async_export_lab):
    origin, handler = async_export_lab
    handler.drop_create_response_for = "bravo"
    alpha, bravo = _credentials()
    result = run_async_export_authorization_experiment(_plan(origin), alpha=alpha, bravo=bravo)
    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["manual_cleanup_count"] == 1
    assert len(handler.jobs) == 1


def test_receipt_never_contains_credentials_or_canaries(async_export_lab):
    origin, handler = async_export_lab
    handler.vulnerable = True
    alpha, bravo = _credentials()
    result = run_async_export_authorization_experiment(_plan(origin), alpha=alpha, bravo=bravo)
    encoded = json.dumps(result, sort_keys=True)
    assert all(secret not in encoded for secret in
               (ALPHA_TOKEN, BRAVO_TOKEN, ALPHA_CANARY, BRAVO_CANARY))
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False


@pytest.mark.parametrize("overrides", [
    {"target_origin": "http://192.0.2.1:8080"},
    {"target_origin": "http://127.0.0.1:0"},
    {"alpha_create_path": "http://127.0.0.1/tenants/alpha/exports"},
    {"bravo_jobs_path": "/tenants/other/exports"},
    {"bravo_canary": ALPHA_CANARY},
    {"operator_acknowledged": False},
])
def test_plan_rejects_out_of_scope_or_ambiguous_contract(overrides):
    with pytest.raises(AsyncExportAuthorizationPlanError):
        _plan("http://127.0.0.1:8080", **overrides)
