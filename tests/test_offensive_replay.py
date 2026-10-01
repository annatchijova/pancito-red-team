"""Authorized offensive replay exists only to validate blue controls."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from offensive.replay import (
    AuthorizationError,
    AuthorizationGrant,
    ReplayCampaign,
    scenario_catalog,
)


def _grant(**overrides) -> AuthorizationGrant:
    values = {
        "authorization_id": "AUTH-LOCAL-001",
        "target": "bundled-replay-lab",
        "objective": "blue-control-validation",
        "allowed_scenarios": ("process-hollowing-timestomp",),
        "max_runs": 1,
    }
    values.update(overrides)
    return AuthorizationGrant(**values)


def test_catalog_contains_only_replay_scenarios_and_no_free_form_command():
    catalog = scenario_catalog()
    assert catalog
    assert all(item["execution_mode"] == "replay-only" for item in catalog)
    assert all("command" not in item and "shell" not in item for item in catalog)


def test_campaign_refuses_a_target_outside_the_bundled_lab(tmp_path):
    with pytest.raises(AuthorizationError, match="bundled-replay-lab"):
        ReplayCampaign(_grant(target="example.com"), out_dir=tmp_path)


def test_campaign_refuses_a_scenario_not_named_in_the_grant(tmp_path):
    campaign = ReplayCampaign(_grant(allowed_scenarios=()), out_dir=tmp_path)
    with pytest.raises(AuthorizationError, match="not authorized"):
        campaign.run("process-hollowing-timestomp")


def test_campaign_has_a_hard_run_budget(tmp_path):
    campaign = ReplayCampaign(_grant(), out_dir=tmp_path)
    campaign.run("process-hollowing-timestomp")
    with pytest.raises(AuthorizationError, match="run budget"):
        campaign.run("process-hollowing-timestomp")


def test_concurrent_callers_cannot_spend_one_run_twice(tmp_path):
    campaign = ReplayCampaign(_grant(), out_dir=tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(campaign.run, "process-hollowing-timestomp")
                   for _ in range(2)]
    outcomes = []
    for future in futures:
        try:
            outcomes.append(future.result()["sealed_verdict"]["sealed"])
        except AuthorizationError:
            outcomes.append("refused")
    assert sorted(outcomes, key=str) == [True, "refused"]


def test_replay_produces_a_blue_validation_receipt_from_a_real_seal(tmp_path):
    campaign = ReplayCampaign(_grant(), out_dir=tmp_path)
    receipt = campaign.run("process-hollowing-timestomp")

    assert receipt["execution_mode"] == "replay-only"
    assert receipt["objective"] == "blue-control-validation"
    assert receipt["model_used"] is False
    assert receipt["sealed_verdict"]["sealed"] is True
    assert receipt["sealed_verdict"]["verdict_state"] == "MALICE_HIGH"
    assert receipt["custody"]["chain_ok"] is True
    assert receipt["detection_validation"]["status"] == "DETECTED_AS_EXPECTED"
    assert receipt["detection_validation"]["missing_techniques"] == []
    assert set(receipt["detection_validation"]["observed_techniques"]) == {
        "T1055.012", "T1070.006"
    }


def test_authorization_cannot_supply_or_override_a_verdict():
    fields = set(AuthorizationGrant.__dataclass_fields__)
    assert fields.isdisjoint({"verdict", "score", "confidence", "entry_hash"})
