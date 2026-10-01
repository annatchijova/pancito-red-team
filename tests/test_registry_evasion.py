"""Synthetic Registry cells validate SIFT persistence and timestomp sensors."""

from __future__ import annotations

from offensive.registry_evasion import (
    RegistryEvasionPlan,
    run_registry_evasion_differential,
)


def _plan() -> RegistryEvasionPlan:
    return RegistryEvasionPlan(
        experiment_id="REGISTRY-001",
        authorization_reference="written-scope-registry",
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


def test_registry_control_run_key_and_timestamp_collision_are_discriminated():
    receipt = run_registry_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "CONFIRMED_BY_INDUCTION"
    assert receipt["cell_outcomes"] == {
        "CONTROL": "CLEAN",
        "RUN_KEY_PERSISTENCE": "DETECTED",
        "TIMESTAMP_COLLISION": "DETECTED",
    }
    assert receipt["observed_signals"] == {
        "CONTROL": [],
        "RUN_KEY_PERSISTENCE": ["SUSPICIOUS_RUN_KEY"],
        "TIMESTAMP_COLLISION": ["REGISTRY_TIMESTAMP_COLLISION"],
    }


def test_registry_receipt_is_deterministic_unsealed_and_contains_no_payload():
    first = run_registry_evasion_differential(_plan())
    second = run_registry_evasion_differential(_plan())

    assert first == second
    assert first["part_of_forensic_verdict"] is False
    assert first["receipt_integrity"] == "UNSEALED"
    assert first["model_used"] is False
    assert _has_float(first) is False
    serialized = str(first)
    assert "powershell" not in serialized.lower()
    assert "synthetic_inert_marker" not in serialized.lower()


def test_registry_missed_mutations_falsify_the_prediction(monkeypatch):
    from offensive import registry_evasion

    monkeypatch.setattr(
        registry_evasion, "_observe", lambda _run_output, _keys: set()
    )
    receipt = run_registry_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "FALSIFIED"
    assert receipt["reason_code"] == "ONE_OR_MORE_REGISTRY_CELLS_MISSED"


def test_registry_sensor_failure_is_inconclusive(monkeypatch):
    from offensive import registry_evasion

    def fail(_run_output, _keys):
        raise RuntimeError("controlled failure")

    monkeypatch.setattr(registry_evasion, "_observe", fail)
    receipt = run_registry_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "INCONCLUSIVE"
    assert receipt["reason_code"] == "SENSOR_EXECUTION_FAILED"
