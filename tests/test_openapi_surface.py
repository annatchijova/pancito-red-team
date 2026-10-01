"""Passive OpenAPI triage produces candidates, never vulnerability claims."""

from __future__ import annotations

import json

import pytest

from offensive.openapi_surface import (
    AssetAnnotation,
    OpenApiTriageError,
    OpenApiTriagePlan,
    triage_openapi,
)


def _document(paths: dict, **overrides) -> bytes:
    value = {
        "openapi": "3.1.0",
        "info": {"title": "Disposable API", "version": "1"},
        "security": [{"bearerAuth": []}],
        "paths": paths,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _plan(*annotations: AssetAnnotation) -> OpenApiTriagePlan:
    return OpenApiTriagePlan(
        engagement_id="OPENAPI-LAB-001",
        authorization_reference="written-lab-scope-002",
        authorized_by="Lab Owner",
        operator_acknowledged=True,
        source_label="api/openapi.json@abc123",
        asset_annotations=annotations,
    )


def test_authenticated_object_route_becomes_ranked_bola_candidate():
    raw = _document(
        {
            "/invoices/{invoice_id}": {
                "get": {
                    "operationId": "readInvoice",
                    "parameters": [
                        {
                            "name": "invoice_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "invoice"}},
                }
            }
        }
    )
    annotation = AssetAnnotation(
        entry_point="GET /invoices/{invoice_id}",
        value=3,
        basis="Cross-tenant billing records",
    )

    result = triage_openapi(raw, _plan(annotation))

    candidate = result["candidate_queue"][0]
    assert candidate["candidate_type"] == "OBJECT_AUTHORIZATION_REVIEW"
    assert candidate["entry_point"] == "GET /invoices/{invoice_id}"
    assert candidate["reachability"] == "AUTHENTICATED_DECLARED"
    assert candidate["asset_value"] == 3
    assert candidate["priority_score"] == 18
    assert candidate["epistemic_level"] == "CANDIDATE"
    assert candidate["provenance"]["json_pointer"].endswith(
        "/paths/~1invoices~1{invoice_id}/get"
    )
    assert "authorization" in candidate["falsifier"].lower()


def test_unvalued_candidate_is_visible_but_not_ranked():
    raw = _document(
        {
            "/accounts/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path"}],
                    "responses": {"200": {"description": "account"}},
                }
            }
        }
    )

    result = triage_openapi(raw, _plan())

    assert result["candidate_queue"] == []
    assert result["below_the_line"][0]["reason"] == "ASSET_VALUE_UNANNOTATED"
    assert result["below_the_line"][0]["priority_score"] is None


def test_operation_security_override_is_not_mistaken_for_inherited_authentication():
    raw = _document(
        {
            "/session/reset": {
                "post": {
                    "security": [],
                    "responses": {"204": {"description": "reset"}},
                }
            }
        }
    )
    annotation = AssetAnnotation(
        entry_point="POST /session/reset",
        value=2,
        basis="Account recovery state",
    )

    result = triage_openapi(raw, _plan(annotation))

    candidate = result["candidate_queue"][0]
    assert candidate["candidate_type"] == "PUBLIC_STATE_CHANGE_REVIEW"
    assert candidate["reachability"] == "PUBLIC_DECLARED"
    assert candidate["priority_score"] == 18


def test_authenticated_get_route_becomes_a_separate_authn_enforcement_candidate():
    raw = _document(
        {"/profile": {"get": {"responses": {"200": {"description": "profile"}}}}}
    )
    annotation = AssetAnnotation(
        entry_point="GET /profile",
        value=3,
        basis="Authenticated user profile",
    )

    result = triage_openapi(raw, _plan(annotation))

    assert len(result["candidate_queue"]) == 1
    candidate = result["candidate_queue"][0]
    assert candidate["candidate_type"] == "AUTHENTICATION_ENFORCEMENT_REVIEW"
    assert candidate["entry_point"] == "GET /profile"
    assert candidate["reachability"] == "AUTHENTICATED_DECLARED"
    assert candidate["priority_score"] == 12
    assert candidate["epistemic_level"] == "CANDIDATE"
    assert "runtime" in candidate["falsifier"].lower()


def test_absent_security_is_unknown_not_public():
    raw = _document(
        {
            "/jobs": {
                "post": {"responses": {"202": {"description": "queued"}}}
            }
        },
        security=None,
    )
    document = json.loads(raw)
    del document["security"]
    raw = json.dumps(document).encode("utf-8")
    annotation = AssetAnnotation(
        entry_point="POST /jobs", value=2, basis="Background compute capacity"
    )

    result = triage_openapi(raw, _plan(annotation))

    assert result["surfaces"][0]["reachability"] == "UNKNOWN"
    assert result["candidate_queue"] == []


def test_file_ingress_is_a_boundary_candidate_not_a_vulnerability_claim():
    raw = _document(
        {
            "/imports": {
                "post": {
                    "requestBody": {
                        "content": {"multipart/form-data": {"schema": {}}}
                    },
                    "responses": {"202": {"description": "accepted"}},
                }
            }
        }
    )
    annotation = AssetAnnotation(
        entry_point="POST /imports", value=3, basis="Asynchronous parser boundary"
    )

    result = triage_openapi(raw, _plan(annotation))

    assert [item["candidate_type"] for item in result["candidate_queue"]] == [
        "FILE_INGRESS_REVIEW"
    ]
    assert result["candidate_queue"][0]["priority_score"] == 12


def test_result_is_order_independent_and_keeps_passive_scope_explicit():
    paths_a = {
        "/z/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
        "/a": {"get": {"responses": {"200": {"description": "ok"}}}},
    }
    paths_b = dict(reversed(list(paths_a.items())))
    annotation = AssetAnnotation(
        entry_point="GET /z/{id}", value=1, basis="Low-value test record"
    )

    first = triage_openapi(_document(paths_a), _plan(annotation))
    second = triage_openapi(_document(paths_b), _plan(annotation))

    assert first["candidate_queue"] == second["candidate_queue"]
    assert first["surfaces"] == second["surfaces"]
    assert first["active_probe_performed"] is False
    assert first["model_used"] is False
    assert first["part_of_forensic_verdict"] is False
    assert first["coverage_gaps"]


def test_strict_parser_rejects_ambiguous_documents_and_annotation_drift():
    duplicate = b'{"openapi":"3.1.0","paths":{},"paths":{}}'
    floating = b'{"openapi":"3.1.0","paths":{},"x-score":1.5}'
    unknown = AssetAnnotation(
        entry_point="GET /not-in-document", value=1, basis="Should not drift"
    )

    with pytest.raises(OpenApiTriageError, match="duplicate key"):
        triage_openapi(duplicate, _plan())
    with pytest.raises(OpenApiTriageError, match="floating-point"):
        triage_openapi(floating, _plan())
    with pytest.raises(OpenApiTriageError, match="not present"):
        triage_openapi(_document({}), _plan(unknown))


def test_output_does_not_promote_candidates_to_findings_or_severity():
    raw = _document(
        {
            "/objects/{id}": {
                "get": {"parameters": [{"name": "id", "in": "path"}]}
            }
        }
    )
    annotation = AssetAnnotation(
        entry_point="GET /objects/{id}", value=2, basis="Tenant-owned object"
    )

    result = triage_openapi(raw, _plan(annotation))
    serialized = json.dumps(result, sort_keys=True)

    assert '"severity"' not in serialized
    assert '"finding"' not in serialized
    assert '"CONFIRMED"' not in serialized
    assert len(result["source_sha256"]) == 64
