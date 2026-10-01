"""Authorization artifacts and Blue evidence oracles fail closed."""

from __future__ import annotations

import json

import pytest

from offensive.engagement import EngagementFormatError, load_engagement
from offensive.oracle import DetectionExpectation, evaluate_detection
from offensive.replay import AuthorizationGrant, ReplayCampaign


def _manifest(**overrides):
    value = {
        "schema_version": 1,
        "engagement_id": "ENG-LOCAL-001",
        "authorization_reference": "written-lab-approval-001",
        "authorized_by": "Blue Lab Owner",
        "operator_acknowledged": True,
        "target": "bundled-replay-lab",
        "objective": "blue-control-validation",
        "allowed_scenarios": ["process-hollowing-timestomp"],
        "max_runs": 1,
    }
    value.update(overrides)
    return value


def _write_manifest(tmp_path, value):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_manifest_loads_into_the_existing_closed_replay_grant(tmp_path):
    plan = load_engagement(_write_manifest(tmp_path, _manifest()))
    grant = plan.to_grant()

    assert grant.authorization_id == "ENG-LOCAL-001"
    assert grant.allowed_scenarios == ("process-hollowing-timestomp",)
    assert grant.authorized_by == "Blue Lab Owner"
    assert len(grant.scope_sha256) == 64
    assert len(grant.source_sha256) == 64


def test_semantic_scope_hash_is_stable_across_json_formatting(tmp_path):
    compact = tmp_path / "compact.json"
    pretty = tmp_path / "pretty.json"
    compact.write_text(json.dumps(_manifest(), separators=(",", ":")), encoding="utf-8")
    pretty.write_text(json.dumps(_manifest(), indent=2, sort_keys=True), encoding="utf-8")

    a = load_engagement(compact)
    b = load_engagement(pretty)
    assert a.scope_sha256 == b.scope_sha256
    assert a.source_sha256 != b.source_sha256


def test_manifest_rejects_duplicate_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema_version":1,"engagement_id":"ENG-1",'
        '"engagement_id":"ENG-2"}',
        encoding="utf-8",
    )
    with pytest.raises(EngagementFormatError, match="duplicate key"):
        load_engagement(path)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"operator_acknowledged": "true"}, "literal true"),
        ({"allowed_scenarios": []}, "must not be empty"),
        ({"allowed_scenarios": ["unknown-scenario"]}, "curated catalogue"),
        ({"max_runs": True}, "integer"),
        ({"target": "example.com"}, "bundled-replay-lab"),
        ({"objective": "gain-access"}, "blue-control-validation"),
        ({"verdict": "MALICE_HIGH"}, "unknown fields"),
    ],
)
def test_manifest_rejects_ambiguous_or_authority_expanding_input(
    tmp_path, change, message
):
    with pytest.raises(EngagementFormatError, match=message):
        load_engagement(_write_manifest(tmp_path, _manifest(**change)))


def test_manifest_has_a_hard_size_limit(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * 65_537)
    with pytest.raises(EngagementFormatError, match="65536 bytes"):
        load_engagement(path)


def test_manifest_provenance_is_returned_by_the_campaign(tmp_path):
    plan = load_engagement(_write_manifest(tmp_path, _manifest()))
    receipt = ReplayCampaign(plan.to_grant(), out_dir=tmp_path / "runs").run(
        "process-hollowing-timestomp"
    )

    provenance = receipt["authorization_provenance"]
    assert provenance == {
        "mode": "engagement-manifest",
        "authentication": "unverified-operator-assertion",
        "authorized_by": "Blue Lab Owner",
        "authorization_reference": "written-lab-approval-001",
        "scope_sha256": plan.scope_sha256,
        "source_sha256": plan.source_sha256,
        "part_of_forensic_verdict": False,
    }


def test_grant_rejects_partial_manifest_provenance():
    with pytest.raises(ValueError, match="must be provided together"):
        AuthorizationGrant(
            authorization_id="ENG-LOCAL-001",
            target="bundled-replay-lab",
            objective="blue-control-validation",
            allowed_scenarios=("process-hollowing-timestomp",),
            max_runs=1,
            scope_sha256="a" * 64,
        )


def test_oracle_distinguishes_execution_from_detection_evidence():
    expectation = DetectionExpectation(
        expected_techniques=("T1055.012", "T1070.006"),
        expected_state_prefix="MALICE",
    )
    result = evaluate_detection(
        verdict={
            "sealed": True,
            "verdict_state": "MALICE_HIGH",
            "mitre_techniques": ["T1055.012"],
        },
        custody={"chain_ok": True},
        expectation=expectation,
    )

    assert result["status"] == "CONTROL_GAP"
    assert result["execution_succeeded"] is True
    assert result["missing_techniques"] == ["T1070.006"]
    assert "MISSING_EXPECTED_TECHNIQUE" in result["reason_codes"]


def test_oracle_fails_closed_when_custody_does_not_verify():
    result = evaluate_detection(
        verdict={
            "sealed": True,
            "verdict_state": "MALICE_HIGH",
            "mitre_techniques": ["T1055.012"],
        },
        custody={"chain_ok": False},
        expectation=DetectionExpectation(
            expected_techniques=("T1055.012",),
            expected_state_prefix="MALICE",
        ),
    )

    assert result["status"] == "INTEGRITY_FAILURE"
    assert result["evidence_trusted"] is False
    assert result["part_of_forensic_verdict"] is False
