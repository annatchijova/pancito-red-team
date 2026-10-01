"""The forensic-evasion differential validates SIFT without promoting it to verdict."""

from __future__ import annotations

import json

import pytest

from offensive.forensic_evasion import (
    ForensicEvasionPlan,
    ForensicEvasionPlanError,
    run_forensic_evasion_differential,
)


def _plan(**overrides: object) -> ForensicEvasionPlan:
    values: dict[str, object] = {
        "experiment_id": "SIFT-EVASION-001",
        "authorization_reference": "written-lab-scope-sift-001",
        "authorized_by": "Lab Owner",
        "operator_acknowledged": True,
    }
    values.update(overrides)
    return ForensicEvasionPlan(**values)  # type: ignore[arg-type]


def _contains_float(value: object) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_contains_float(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_float(item) for item in value)
    return False


def test_sift_detects_both_mutations_and_keeps_control_clean():
    receipt = run_forensic_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert receipt["reason_code"] == "BOTH_EVASION_CELLS_DETECTED"
    assert receipt["cell_outcomes"] == {
        "CONTROL": "CLEAN",
        "LOG_WIPE": "DETECTED",
        "TIMESTOMP": "DETECTED",
    }
    assert receipt["observed_signals"] == {
        "CONTROL": [],
        "LOG_WIPE": ["EVENT_LOG_WIPE_CHAIN"],
        "TIMESTOMP": ["MFT_SI_FN_MISMATCH"],
    }


def test_receipt_is_exact_bounded_unsealed_and_model_free():
    first = run_forensic_evasion_differential(_plan())
    second = run_forensic_evasion_differential(_plan())

    assert first == second
    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        second, sort_keys=True, separators=(",", ":")
    )
    assert _contains_float(first) is False
    assert first["cell_count"] == 3
    assert first["maximum_cell_count"] == 3
    assert first["model_used"] is False
    assert first["part_of_forensic_verdict"] is False
    assert first["receipt_integrity"] == "UNSEALED"
    assert first["impact_assessment"] == "BLUE_CONTROL_VALIDATION_ONLY"
    assert first["sensor_contract"]["output_role"] == "UNSEALED_BLUE_SENSOR_OBSERVATION"
    assert first["sensor_contract"]["affects_forensic_verdict"] is False
    assert set(first["artifacts"]) == {"CONTROL", "LOG_WIPE", "TIMESTOMP"}
    for facts in first["artifacts"].values():
        assert facts["synthetic_inert"] is True
        assert facts["size"] <= 4096
        assert len(facts["sha256"]) == 64


def test_plan_rejects_ambiguous_authorization():
    with pytest.raises(ForensicEvasionPlanError, match="literal true"):
        _plan(operator_acknowledged=False)
    with pytest.raises(ForensicEvasionPlanError, match="experiment_id"):
        _plan(experiment_id="bad id")


def test_sensor_failure_is_inconclusive(monkeypatch):
    from offensive import forensic_evasion

    def fail_sensor(_sample: bytes) -> set[str]:
        raise RuntimeError("controlled sensor failure")

    monkeypatch.setattr(forensic_evasion, "_observe_mft", fail_sensor)
    receipt = run_forensic_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "INCONCLUSIVE"
    assert receipt["reason_code"] == "SENSOR_EXECUTION_FAILED"
    assert receipt["sensor_errors"] == [
        {"cell": "CONTROL", "sensor": "SIFT_MFT", "error": "RuntimeError"},
        {"cell": "LOG_WIPE", "sensor": "SIFT_MFT", "error": "RuntimeError"},
        {"cell": "TIMESTOMP", "sensor": "SIFT_MFT", "error": "RuntimeError"},
    ]


def test_clean_control_with_missed_mutation_falsifies_prediction(monkeypatch):
    from offensive import forensic_evasion

    monkeypatch.setattr(forensic_evasion, "_observe_mft", lambda _sample: set())
    receipt = run_forensic_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "FALSIFIED"
    assert receipt["reason_code"] == "ONE_OR_MORE_EVASION_CELLS_MISSED"
    assert receipt["cell_outcomes"]["CONTROL"] == "CLEAN"
    assert receipt["cell_outcomes"]["TIMESTOMP"] == "MISSED"


def test_dirty_control_is_inconclusive_not_a_false_confirmation(monkeypatch):
    from offensive import forensic_evasion

    monkeypatch.setattr(
        forensic_evasion,
        "_observe_event_log",
        lambda _events: {"EVENT_LOG_WIPE_CHAIN"},
    )
    receipt = run_forensic_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "INCONCLUSIVE"
    assert receipt["reason_code"] == "UNEXPECTED_SENSOR_SIGNAL"
    assert receipt["cell_outcomes"]["CONTROL"] == "INCONCLUSIVE"
