"""Synthetic uploads prove storage by digest and are deleted after each cell."""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.bola import BearerCredential
from offensive.file_ingress import (
    FileIngressPlan,
    FileIngressPlanError,
    run_file_ingress_experiment,
)


TOKEN = "file-ingress-observer-token"


class _UploadLab(BaseHTTPRequestHandler):
    accept_mismatch = False
    accept_oversize = False
    omit_upload_id = False
    fail_delete = False
    upload_status = 201
    objects: dict[str, bytes] = {}
    events: list[dict[str, object]] = []
    counter = 0

    def _authorized(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def _record(self):
        type(self).events.append({
            "method": self.command,
            "step": self.headers.get("X-Pancito-Step"),
            "marker": self.headers.get("X-Pancito-Exercise"),
        })

    def do_POST(self):  # noqa: N802
        self._record()
        if self.path != "/uploads" or not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        header, content_and_tail = raw.split(b"\r\n\r\n", 1)
        content = content_and_tail.rsplit(b"\r\n--", 1)[0]
        filename = header.split(b'filename="', 1)[1].split(b'"', 1)[0].decode()
        if filename == "mismatch.png" and not type(self).accept_mismatch:
            self._send(415, {"error": "type mismatch"})
            return
        if filename == "oversize.bin" and not type(self).accept_oversize:
            self._send(413, {"error": "too large"})
            return
        if type(self).omit_upload_id:
            self._send(200, {"accepted": True})
            return
        type(self).counter += 1
        upload_id = f"upload-{type(self).counter}"
        type(self).objects[upload_id] = content
        self._send(type(self).upload_status, {"upload_id": upload_id})

    def do_GET(self):  # noqa: N802
        self._record()
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        upload_id = self.path.removeprefix("/uploads/")
        content = type(self).objects.get(upload_id)
        if content is None:
            self._send(404, {"error": "missing"})
            return
        self._send(200, {
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })

    def do_DELETE(self):  # noqa: N802
        self._record()
        upload_id = self.path.removeprefix("/uploads/")
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
        elif type(self).fail_delete:
            self._send(500, {"error": "delete failed"})
        else:
            type(self).objects.pop(upload_id, None)
            self._send(204, None)

    def _send(self, status, value):
        payload = b"" if value is None else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def upload_lab():
    handler = _UploadLab
    handler.accept_mismatch = False
    handler.accept_oversize = False
    handler.omit_upload_id = False
    handler.fail_delete = False
    handler.upload_status = 201
    handler.objects = {}
    handler.events = []
    handler.counter = 0
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
        "experiment_id": "FILE-LOCAL-001",
        "authorization_reference": "written-lab-file-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": origin,
        "upload_path": "/uploads",
        "readback_path_template": "/uploads/{upload_id}",
        "upload_field": "file",
        "expected_max_bytes": 1024,
    }
    values.update(overrides)
    return FileIngressPlan(**values)


def _observer():
    return BearerCredential("file-observer", TOKEN)


def test_negative_cells_rejected_falsifies_tested_candidates(upload_lab):
    origin, handler = upload_lab
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "FALSIFIED"
    assert result["reason_code"] == "TYPE_MISMATCH_AND_OVERSIZE_REJECTED"
    assert result["cell_outcomes"] == {
        "CONTROL": "STORED_EXACTLY",
        "TYPE_MISMATCH": "REJECTED",
        "OVERSIZE": "REJECTED",
    }
    assert result["cleanup_status"] == "VERIFIED_ABSENT"
    assert handler.objects == {}
    assert result["request_count"] == 6


def test_exact_persistence_confirms_both_parser_policy_gaps(upload_lab):
    origin, handler = upload_lab
    handler.accept_mismatch = True
    handler.accept_oversize = True
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert result["confirmed_cells"] == ["TYPE_MISMATCH", "OVERSIZE"]
    assert result["request_count"] == result["maximum_request_count"] == 12
    assert result["cleanup_status"] == "VERIFIED_ABSENT"
    assert handler.objects == {}


def test_2xx_without_id_or_readback_is_inconclusive_not_acceptance(upload_lab):
    origin, handler = upload_lab
    handler.omit_upload_id = True
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "CONTROL_UPLOAD_NOT_TRACKABLE"
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["final_absence_verified"] is False
    assert result["request_count"] == 1


def test_redirect_with_id_is_cleaned_but_never_treated_as_acceptance(upload_lab):
    origin, handler = upload_lab
    handler.upload_status = 307
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["reason_code"] == "CONTROL_NOT_STORED_EXACTLY"
    assert result["cell_outcomes"] == {"CONTROL": "CONTROL_FAILED"}
    assert result["cleanup_status"] == "VERIFIED_ABSENT"
    assert handler.objects == {}
    assert result["observations"][0]["redirected"] is True


def test_cleanup_failure_stops_before_next_cell(upload_lab):
    origin, handler = upload_lab
    handler.fail_delete = True
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())

    assert result["epistemic_level"] == "INCONCLUSIVE"
    assert result["cleanup_status"] == "MANUAL_ACTION_REQUIRED"
    assert result["final_absence_verified"] is False
    assert "upload-1" in handler.objects
    assert not any(event["step"] == "TYPE_MISMATCH_UPLOAD" for event in handler.events)


def test_samples_are_synthetic_bounded_and_receipt_contains_no_body_or_token(upload_lab):
    origin, _handler = upload_lab
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())
    serialized = json.dumps(result, sort_keys=True)

    assert TOKEN not in serialized
    assert '"body"' not in serialized
    assert all(item["synthetic_inert"] is True for item in result["samples"].values())
    assert result["samples"]["OVERSIZE"]["size"] == 1025
    assert result["model_used"] is False
    assert result["part_of_forensic_verdict"] is False
    assert result["impact_assessment"] == "REQUIRES_HUMAN_CONTEXT"


def test_blue_marker_covers_upload_readback_and_cleanup(upload_lab):
    origin, handler = upload_lab
    result = run_file_ingress_experiment(_plan(origin), observer=_observer())
    objective = result["blue_objective"]

    assert {event["marker"] for event in handler.events} == {
        objective["exercise_marker"]
    }
    assert [event["step"] for event in handler.events] == objective["expected_steps"]
    assert objective["correlation_marker_is_detection"] is False


@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1",
        "http://10.0.0.2",
        "http://127.0.0.1/base",
        "http://127.0.0.1:0",
    ],
)
def test_non_loopback_or_ambiguous_origins_are_rejected(origin):
    with pytest.raises(FileIngressPlanError):
        _plan(origin)


def test_readback_template_and_size_policy_are_bounded(upload_lab):
    origin, _handler = upload_lab
    with pytest.raises(FileIngressPlanError, match="whole path segment"):
        _plan(origin, readback_path_template="/uploads/id-{upload_id}")
    with pytest.raises(FileIngressPlanError, match="between 1024 and 65536"):
        _plan(origin, expected_max_bytes=100_000)
