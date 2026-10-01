"""Collection authorization CLI keeps credentials and canaries out of manifests."""

import json

import pytest

from offensive.collection_authz_cli import (
    CollectionAuthorizationManifestError,
    main,
    parse_collection_authorization_manifest,
    preflight_collection_authorization_manifest,
    read_collection_authorization_manifest,
    resolve_collection_authorization_secrets,
)


SECRETS = {
    "PANCITO_COLLECTION_ALPHA_TOKEN": "cli-collection-alpha-token",
    "PANCITO_COLLECTION_BRAVO_TOKEN": "cli-collection-bravo-token",
    "PANCITO_COLLECTION_ALPHA_CANARY": "CLI-COLLECTION-ALPHA-CANARY",
    "PANCITO_COLLECTION_BRAVO_CANARY": "CLI-COLLECTION-BRAVO-CANARY",
}


def _manifest(**overrides):
    value = {
        "schema_version": 1,
        "experiment_id": "COLLECTION-CLI-001",
        "authorization_reference": "written-loopback-scope-collection-002",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
        "target_origin": "http://127.0.0.1:8080",
        "alpha_collection_path": "/tenants/alpha/items",
        "bravo_collection_path": "/tenants/bravo/items",
        "alpha_principal_id": "alpha-member",
        "bravo_principal_id": "bravo-member",
        "alpha_token_env": "PANCITO_COLLECTION_ALPHA_TOKEN",
        "bravo_token_env": "PANCITO_COLLECTION_BRAVO_TOKEN",
        "alpha_canary_env": "PANCITO_COLLECTION_ALPHA_CANARY",
        "bravo_canary_env": "PANCITO_COLLECTION_BRAVO_CANARY",
        "timeout_ms": 2000,
        "max_response_bytes": 16384,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_preflight_is_zero_request_and_secret_free():
    manifest = parse_collection_authorization_manifest(_manifest())
    secrets = resolve_collection_authorization_secrets(manifest, SECRETS)

    result = preflight_collection_authorization_manifest(manifest, secrets)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "VALIDATED_NOT_EXECUTED"
    assert result["request_count"] == 0
    assert result["maximum_request_count"] == 3
    assert all(secret not in serialized for secret in SECRETS.values())


def test_manifest_rejects_inline_secret_duplicate_float_and_alias():
    with pytest.raises(CollectionAuthorizationManifestError, match="unknown fields"):
        parse_collection_authorization_manifest(_manifest(alpha_token="inline"))
    with pytest.raises(CollectionAuthorizationManifestError, match="duplicate key"):
        parse_collection_authorization_manifest(
            b'{"schema_version":1,"schema_version":1}'
        )
    with pytest.raises(CollectionAuthorizationManifestError, match="floating-point"):
        parse_collection_authorization_manifest(
            _manifest().replace(b'"timeout_ms": 2000', b'"timeout_ms": 2.5')
        )
    with pytest.raises(CollectionAuthorizationManifestError, match="distinct"):
        parse_collection_authorization_manifest(
            _manifest(bravo_token_env="PANCITO_COLLECTION_ALPHA_TOKEN")
        )


def test_missing_secrets_and_symlink_fail_closed(tmp_path):
    manifest = parse_collection_authorization_manifest(_manifest())
    missing = dict(SECRETS)
    del missing["PANCITO_COLLECTION_BRAVO_TOKEN"]
    with pytest.raises(
        CollectionAuthorizationManifestError,
        match="PANCITO_COLLECTION_BRAVO_TOKEN",
    ):
        resolve_collection_authorization_secrets(manifest, missing)

    real = tmp_path / "real.json"
    linked = tmp_path / "linked.json"
    real.write_bytes(_manifest())
    linked.symlink_to(real)
    with pytest.raises(CollectionAuthorizationManifestError, match="symlink"):
        read_collection_authorization_manifest(linked)


def test_cli_dry_run_prints_no_secret(tmp_path, capsys):
    path = tmp_path / "collection.json"
    path.write_bytes(_manifest())

    assert main(["--dry-run", str(path)], environ=SECRETS) == 0
    captured = capsys.readouterr()

    assert json.loads(captured.out)["status"] == "VALIDATED_NOT_EXECUTED"
    assert all(secret not in captured.out for secret in SECRETS.values())
