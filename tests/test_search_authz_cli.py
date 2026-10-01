"""Search authorization CLI keeps tokens, queries, and canaries out of manifests."""

import json

import pytest

from offensive.search_authz_cli import (
    SearchAuthorizationManifestError,
    main,
    parse_search_authorization_manifest,
    preflight_search_authorization_manifest,
    read_search_authorization_manifest,
    resolve_search_authorization_secrets,
)


SECRETS = {
    "PANCITO_SEARCH_ALPHA_TOKEN": "cli-search-alpha-token",
    "PANCITO_SEARCH_BRAVO_TOKEN": "cli-search-bravo-token",
    "PANCITO_SEARCH_ALPHA_QUERY": "cli-alpha-record-query",
    "PANCITO_SEARCH_BRAVO_QUERY": "cli-bravo-record-query",
    "PANCITO_SEARCH_ALPHA_CANARY": "CLI-SEARCH-ALPHA-CANARY",
    "PANCITO_SEARCH_BRAVO_CANARY": "CLI-SEARCH-BRAVO-CANARY",
}


def _manifest(**overrides):
    value = {
        "schema_version": 1,
        "experiment_id": "SEARCH-CLI-001",
        "authorization_reference": "written-loopback-search-scope-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "search_path": "/api/search",
        "query_parameter": "q",
        "alpha_principal_id": "alpha-member",
        "bravo_principal_id": "bravo-member",
        "alpha_token_env": "PANCITO_SEARCH_ALPHA_TOKEN",
        "bravo_token_env": "PANCITO_SEARCH_BRAVO_TOKEN",
        "alpha_query_env": "PANCITO_SEARCH_ALPHA_QUERY",
        "bravo_query_env": "PANCITO_SEARCH_BRAVO_QUERY",
        "alpha_canary_env": "PANCITO_SEARCH_ALPHA_CANARY",
        "bravo_canary_env": "PANCITO_SEARCH_BRAVO_CANARY",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_makes_zero_requests_and_exposes_no_secret():
    manifest = parse_search_authorization_manifest(_manifest())
    secrets = resolve_search_authorization_secrets(manifest, SECRETS)

    result = preflight_search_authorization_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 3
    assert all(value not in serialized for value in SECRETS.values())


def test_manifest_rejects_inline_secret_duplicate_float_and_alias():
    with pytest.raises(SearchAuthorizationManifestError, match="unknown fields"):
        parse_search_authorization_manifest(_manifest(alpha_token="inline"))
    with pytest.raises(SearchAuthorizationManifestError, match="duplicate key"):
        parse_search_authorization_manifest(
            b'{"schema_version":1,"schema_version":1}'
        )
    with pytest.raises(SearchAuthorizationManifestError, match="floating-point"):
        parse_search_authorization_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )
    with pytest.raises(SearchAuthorizationManifestError, match="distinct"):
        parse_search_authorization_manifest(
            _manifest(bravo_query_env="PANCITO_SEARCH_ALPHA_QUERY")
        )


def test_missing_secrets_and_symlink_fail_closed(tmp_path):
    manifest = parse_search_authorization_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_SEARCH_BRAVO_QUERY"]
    with pytest.raises(SearchAuthorizationManifestError, match="PANCITO_SEARCH_BRAVO_QUERY"):
        resolve_search_authorization_secrets(manifest, missing)

    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(SearchAuthorizationManifestError, match="symlink"):
        read_search_authorization_manifest(linked)


def test_cli_dry_run_prints_no_secret(tmp_path, capsys):
    path = tmp_path / "search.json"
    path.write_bytes(_manifest())

    assert main(["--dry-run", str(path)], environ=SECRETS) == 0
    captured = capsys.readouterr()

    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert all(value not in captured.out for value in SECRETS.values())
