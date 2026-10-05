"""The resource-consumption CLI keeps oracles and credentials out of manifests."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive.resource_consumption_cli import (
    ResourceConsumptionManifestError,
    main,
    parse_resource_consumption_manifest,
    preflight_resource_consumption_manifest,
    resolve_resource_consumption_secrets,
)


VALID_TOKEN = "cli-valid-rate-token"
SUCCESS_CANARY = "CLI-SERVED-RESOURCE-CANARY"


def _manifest(**overrides) -> bytes:
    value = {
        "schema_version": 1,
        "experiment_id": "RATELIMIT-CLI-001",
        "authorization_reference": "written-lab-scope-012",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "probed_path": "/report",
        "valid_principal_id": "valid-principal",
        "valid_token_env": "PANCITO_RATE_VALID_TOKEN",
        "success_canary_env": "PANCITO_RATE_SUCCESS_CANARY",
        "declared_limit": 3,
        "control_requests": 3,
        "probe_requests": 5,
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _environment() -> dict[str, str]:
    return {
        "PANCITO_RATE_VALID_TOKEN": VALID_TOKEN,
        "PANCITO_RATE_SUCCESS_CANARY": SUCCESS_CANARY,
    }


def test_preflight_validates_plan_and_secrets_without_execution():
    manifest = parse_resource_consumption_manifest(_manifest())
    secrets = resolve_resource_consumption_secrets(manifest, _environment())

    result = preflight_resource_consumption_manifest(manifest, secrets)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 8
    assert result["active_probe_performed"] is False
    assert result["model_used"] is False


def test_unknown_fields_are_refused():
    with pytest.raises(ResourceConsumptionManifestError, match="unknown fields"):
        parse_resource_consumption_manifest(_manifest(surprise="no"))


def test_floating_point_values_are_refused():
    raw = _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2000.5')
    with pytest.raises(ResourceConsumptionManifestError, match="floating-point"):
        parse_resource_consumption_manifest(raw)


def test_a_probe_not_exceeding_the_declared_limit_is_refused_at_parse():
    with pytest.raises(ResourceConsumptionManifestError, match="exceed the declared limit"):
        parse_resource_consumption_manifest(
            _manifest(declared_limit=5, control_requests=5, probe_requests=4))


def test_missing_secret_environment_variable_is_a_config_error():
    manifest = parse_resource_consumption_manifest(_manifest())
    with pytest.raises(ResourceConsumptionManifestError, match="missing or empty"):
        resolve_resource_consumption_secrets(manifest, {})


def test_main_dry_run_prints_a_validated_plan(tmp_path, capsys):
    path = tmp_path / "manifest.json"
    path.write_bytes(_manifest())

    code = main(["--dry-run", str(path)], environ=_environment())

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "VALIDATED_NOT_EXECUTED"
    assert payload["maximum_request_count"] == 8


def test_main_reports_a_config_error_without_executing(tmp_path, capsys):
    path = tmp_path / "manifest.json"
    path.write_bytes(_manifest())

    code = main([str(path)], environ={})  # no secrets in the environment

    assert code == 2
    assert "PANCITO_RESOURCE_CONSUMPTION_CONFIG_ERROR" in capsys.readouterr().err


def test_main_executes_against_a_loopback_lab(tmp_path, capsys):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({"marker": SUCCESS_CANARY}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        path = tmp_path / "manifest.json"
        path.write_bytes(
            _manifest(target_origin=f"http://127.0.0.1:{server.server_port}"))
        code = main([str(path)], environ=_environment())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["capability"] == "http-resource-consumption-differential"
    assert payload["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert payload["request_count"] == 8
