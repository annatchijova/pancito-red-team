"""Synthetic Prefetch cells validate the real SIFT analyzer."""

from __future__ import annotations

from offensive.prefetch_evasion import (
    PrefetchEvasionPlan,
    run_prefetch_evasion_differential,
)


def _plan() -> PrefetchEvasionPlan:
    return PrefetchEvasionPlan(
        experiment_id="PREFETCH-001",
        authorization_reference="written-scope-prefetch",
        authorized_by="Lab Owner",
        operator_acknowledged=True,
    )


def _has_float(value: object) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_float(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_float(item) for item in value)
    return False


def test_prefetch_control_suspicious_execution_and_wipe_are_discriminated():
    receipt = run_prefetch_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert receipt["cell_outcomes"] == {
        "CONTROL": "CLEAN",
        "PREFETCH_WIPE": "DETECTED",
        "SUSPICIOUS_EXECUTION": "DETECTED",
    }
    assert receipt["observed_signals"] == {
        "CONTROL": [],
        "PREFETCH_WIPE": ["PREFETCH_WIPE"],
        "SUSPICIOUS_EXECUTION": ["SUSPICIOUS_EXECUTION"],
    }


def test_prefetch_receipt_is_deterministic_unsealed_and_bounded():
    first = run_prefetch_evasion_differential(_plan())
    second = run_prefetch_evasion_differential(_plan())

    assert first == second
    assert _has_float(first) is False
    assert first["part_of_forensic_verdict"] is False
    assert first["receipt_integrity"] == "UNSEALED"
    assert first["model_used"] is False
    assert first["maximum_cell_count"] == 3
    for artifact in first["artifacts"].values():
        assert artifact["synthetic_inert"] is True
        assert artifact["file_count"] <= 10
        assert artifact["size"] <= 4096


def test_prefetch_missed_mutations_falsify_the_prediction(monkeypatch):
    from offensive import prefetch_evasion

    monkeypatch.setattr(prefetch_evasion, "_observe", lambda _files: set())
    receipt = run_prefetch_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "FALSIFIED"
    assert receipt["reason_code"] == "ONE_OR_MORE_PREFETCH_CELLS_MISSED"


def test_prefetch_sensor_failure_is_inconclusive(monkeypatch):
    from offensive import prefetch_evasion

    def fail(_files):
        raise RuntimeError("controlled failure")

    monkeypatch.setattr(prefetch_evasion, "_observe", fail)
    receipt = run_prefetch_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "INCONCLUSIVE"
    assert receipt["reason_code"] == "SENSOR_EXECUTION_FAILED"
