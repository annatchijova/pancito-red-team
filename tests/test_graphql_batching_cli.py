"""GRAPHQL_BATCHING CLI validates its manifest without any secret material."""

import json
import pytest

from offensive.graphql_batching_cli import (
    GraphqlBatchingManifestError, main, parse_graphql_batching_manifest,
    preflight_graphql_batching_manifest, read_graphql_batching_manifest,
)


def _manifest(**overrides):
    value = {
        "schema_version": 1, "experiment_id": "GQLBATCH-CLI-001",
        "authorization_reference": "written-loopback-graphql-batching-002",
        "authorized_by": "Lab Owner", "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080", "endpoint_path": "/graphql",
        "batch_size": 3, "timeout_ms": 2000, "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode()


def test_preflight_is_zero_request():
    manifest = parse_graphql_batching_manifest(_manifest())
    result = preflight_graphql_batching_manifest(manifest)
    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 2
    assert result["active_probe_performed"] is False


def test_manifest_rejects_unknown_duplicate_float_and_invalid_batch_size():
    with pytest.raises(GraphqlBatchingManifestError, match="unknown fields"):
        parse_graphql_batching_manifest(_manifest(extra_field="nope"))
    with pytest.raises(GraphqlBatchingManifestError, match="duplicate key"):
        parse_graphql_batching_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(GraphqlBatchingManifestError, match="floating-point"):
        parse_graphql_batching_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5'))
    with pytest.raises(GraphqlBatchingManifestError, match="batch_size must be"):
        parse_graphql_batching_manifest(_manifest(batch_size=11))


def test_missing_field_and_symlink_fail_closed(tmp_path):
    raw = json.loads(_manifest())
    del raw["batch_size"]
    with pytest.raises(GraphqlBatchingManifestError, match="missing fields"):
        parse_graphql_batching_manifest(json.dumps(raw).encode())
    real, linked = tmp_path / "real.json", tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(GraphqlBatchingManifestError, match="symlink"):
        read_graphql_batching_manifest(linked)


def test_cli_dry_run_validates_without_a_network_call(tmp_path, capsys):
    path = tmp_path / "graphql_batching.json"
    path.write_bytes(_manifest())
    assert main(["--dry-run", str(path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "VALIDATED_NOT_EXECUTED"
    assert payload["batch_size"] == 3
