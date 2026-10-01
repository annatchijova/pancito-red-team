"""A triage candidate keeps its scope and epistemic level on the way to BOLA."""

from __future__ import annotations

import json

import pytest

from offensive.authn import AuthnPlan, AuthnPlanError
from offensive.bola import BolaPlan, BolaPlanError
from offensive.handoff import (
    HandoffError,
    select_authn_candidate,
    select_bola_candidate,
)
from offensive.openapi_surface import (
    AssetAnnotation,
    OpenApiTriagePlan,
    triage_openapi,
)


def _triage(*, annotated: bool = True) -> dict[str, object]:
    raw = json.dumps(
        {
            "openapi": "3.1.0",
            "info": {"title": "Object API", "version": "1"},
            "security": [{"bearerAuth": []}],
            "paths": {
                "/objects/{object_id}": {
                    "get": {
                        "parameters": [
                            {"name": "object_id", "in": "path", "required": True}
                        ]
                    }
                }
            },
        },
        sort_keys=True,
    ).encode("utf-8")
    annotations = (
        (
            AssetAnnotation(
                entry_point="GET /objects/{object_id}",
                value=2,
                basis="Tenant-owned object",
            ),
        )
        if annotated
        else ()
    )
    plan = OpenApiTriagePlan(
        engagement_id="HANDOFF-LAB-001",
        authorization_reference="written-lab-scope-003",
        authorized_by="Lab Owner",
        operator_acknowledged=True,
        source_label="api/openapi.json@def456",
        asset_annotations=annotations,
    )
    return triage_openapi(raw, plan)


def _bola_plan(handoff) -> BolaPlan:
    return BolaPlan(
        experiment_id="BOLA-HANDOFF-001",
        authorization_reference="written-lab-scope-003",
        authorized_by="Lab Owner",
        operator_acknowledged=True,
        target_origin="http://127.0.0.1:8080",
        owner_path="/objects/a",
        peer_control_path="/objects/b",
        owner_canary="OWNER-MARKER-001",
        peer_canary="PEER-MARKER-002",
        candidate_handoff=handoff,
    )


def _authn_triage(*, annotated: bool = True) -> dict[str, object]:
    raw = json.dumps(
        {
            "openapi": "3.1.0",
            "info": {"title": "Protected API", "version": "1"},
            "security": [{"bearerAuth": []}],
            "paths": {"/profile": {"get": {"responses": {"200": {}}}}},
        },
        sort_keys=True,
    ).encode("utf-8")
    annotations = (
        (
            AssetAnnotation(
                entry_point="GET /profile",
                value=2,
                basis="Authenticated user profile",
            ),
        )
        if annotated
        else ()
    )
    return triage_openapi(
        raw,
        OpenApiTriagePlan(
            engagement_id="AUTHN-HANDOFF-LAB-001",
            authorization_reference="written-lab-scope-009",
            authorized_by="Lab Owner",
            operator_acknowledged=True,
            source_label="api/openapi.json@authn789",
            asset_annotations=annotations,
        ),
    )


def _authn_plan(handoff, *, protected_path: str = "/profile") -> AuthnPlan:
    return AuthnPlan(
        experiment_id="AUTHN-HANDOFF-001",
        authorization_reference="written-lab-scope-009",
        authorized_by="Lab Owner",
        operator_acknowledged=True,
        target_origin="http://127.0.0.1:8080",
        protected_path=protected_path,
        protected_canary="AUTHN-HANDOFF-CANARY",
        invalid_bearer="authn-handoff-invalid-bearer",
        candidate_handoff=handoff,
    )


def test_ranked_bola_candidate_preserves_provenance_without_promotion():
    receipt = _triage()
    candidate_id = receipt["candidate_queue"][0]["candidate_id"]

    handoff = select_bola_candidate(receipt, candidate_id)
    plan = _bola_plan(handoff)

    assert handoff.source_sha256 == receipt["source_sha256"]
    assert handoff.source_label == "api/openapi.json@def456"
    assert handoff.entry_point == "GET /objects/{object_id}"
    assert handoff.epistemic_level == "CANDIDATE"
    assert handoff.integrity == "UNSEALED_TRIAGE_HANDOFF"
    assert plan.candidate_handoff == handoff


def test_unranked_candidate_cannot_silently_cross_the_handoff():
    receipt = _triage(annotated=False)
    candidate_id = receipt["below_the_line"][0]["candidate_id"]

    with pytest.raises(HandoffError, match="ranked candidate queue"):
        select_bola_candidate(receipt, candidate_id)


def test_missing_or_wrong_candidate_is_rejected():
    receipt = _triage()

    with pytest.raises(HandoffError, match="not found"):
        select_bola_candidate(receipt, "CANDIDATE-0000000000000000")

    receipt["candidate_queue"][0]["candidate_type"] = "FILE_INGRESS_REVIEW"
    with pytest.raises(HandoffError, match="not a BOLA"):
        select_bola_candidate(
            receipt, receipt["candidate_queue"][0]["candidate_id"]
        )


@pytest.mark.parametrize(
    "owner_path,peer_path",
    [
        ("/other/a", "/other/b"),
        ("/objects/a/details", "/objects/b/details"),
        ("/objects/a", "/accounts/b"),
    ],
)
def test_bola_paths_must_match_the_handoff_template(owner_path, peer_path):
    receipt = _triage()
    handoff = select_bola_candidate(
        receipt, receipt["candidate_queue"][0]["candidate_id"]
    )

    with pytest.raises(BolaPlanError, match="candidate path template"):
        _bola_plan(handoff).__class__(
            **{
                **_bola_plan(handoff).__dict__,
                "owner_path": owner_path,
                "peer_control_path": peer_path,
            }
        )


def test_handoff_receipt_contains_no_priority_or_asset_judgment():
    receipt = _triage()
    handoff = select_bola_candidate(
        receipt, receipt["candidate_queue"][0]["candidate_id"]
    )

    serialized = json.dumps(handoff.to_receipt(), sort_keys=True)

    assert "priority" not in serialized
    assert "asset_value" not in serialized
    assert '"epistemic_level": "CANDIDATE"' in serialized


def test_ranked_authn_candidate_preserves_provenance_without_promotion():
    receipt = _authn_triage()
    candidate_id = receipt["candidate_queue"][0]["candidate_id"]

    handoff = select_authn_candidate(receipt, candidate_id)
    plan = _authn_plan(handoff)

    assert handoff.source_sha256 == receipt["source_sha256"]
    assert handoff.source_label == "api/openapi.json@authn789"
    assert handoff.entry_point == "GET /profile"
    assert handoff.epistemic_level == "CANDIDATE"
    assert handoff.integrity == "UNSEALED_TRIAGE_HANDOFF"
    assert plan.candidate_handoff == handoff


def test_authn_handoff_rejects_unranked_wrong_type_and_route_drift():
    unranked = _authn_triage(annotated=False)
    candidate_id = unranked["below_the_line"][0]["candidate_id"]
    with pytest.raises(HandoffError, match="ranked candidate queue"):
        select_authn_candidate(unranked, candidate_id)

    receipt = _authn_triage()
    candidate_id = receipt["candidate_queue"][0]["candidate_id"]
    receipt["candidate_queue"][0]["candidate_type"] = "FILE_INGRESS_REVIEW"
    with pytest.raises(HandoffError, match="not an authentication"):
        select_authn_candidate(receipt, candidate_id)

    handoff = select_authn_candidate(_authn_triage(), candidate_id)
    with pytest.raises(AuthnPlanError, match="candidate path template"):
        _authn_plan(handoff, protected_path="/admin")
    with pytest.raises(AuthnPlanError, match="candidate path template"):
        _authn_plan(handoff, protected_path="/profile?view=expanded")
