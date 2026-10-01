"""Production-shaped SIFT summaries must not hide cross-source identity loss."""

from __future__ import annotations

from offensive.timeline_evasion import (
    TimelineEvasionPlan,
    run_timeline_evasion_differential,
)


def _plan() -> TimelineEvasionPlan:
    return TimelineEvasionPlan(
        experiment_id="TIMELINE-001",
        authorization_reference="written-scope-timeline",
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


def test_production_shaped_pair_falsifies_cross_source_correlation():
    receipt = run_timeline_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "FALSIFIED"
    assert receipt["reason_code"] == "PRODUCTION_METADATA_LOSES_CORRELATION_IDENTITY"
    assert receipt["cell_outcomes"] == {
        "CONTROL_SHARED_ENTITY": "DETECTED",
        "MISSING_MFT": "DETECTED",
        "PRODUCTION_SHAPED_PAIR": "MISSED",
    }
    assert receipt["observed_signals"] == {
        "CONTROL_SHARED_ENTITY": ["CAUSAL_INVERSION"],
        "MISSING_MFT": ["MEMORY_WITHOUT_DISK"],
        "PRODUCTION_SHAPED_PAIR": ["MEMORY_WITHOUT_DISK"],
    }
    production = receipt["observation_facts"]["PRODUCTION_SHAPED_PAIR"]
    assert production["entity_ids"] == ["tool:MEMORY_FORENSICS", "tool:MFT_ANALYZER"]
    assert production["timestamps"] == [0, 0]


def test_timeline_receipt_is_deterministic_unsealed_and_scoped():
    first = run_timeline_evasion_differential(_plan())
    second = run_timeline_evasion_differential(_plan())

    assert first == second
    assert _has_float(first) is False
    assert first["audit_base_commit"] == "209db4d"
    assert first["model_used"] is False
    assert first["part_of_forensic_verdict"] is False
    assert first["receipt_integrity"] == "UNSEALED"
    assert first["impact_assessment"] == "BLUE_CONTROL_VALIDATION_ONLY"
    assert first["cell_count"] == first["maximum_cell_count"] == 3
    assert first["fixture_sha256"] == (
        "b924baa5da8e77c4ace4e84ba9b791cb247d0a99b98c2ebfc68fdcbc66a9a098"
    )


def test_timeline_sensor_failure_is_inconclusive(monkeypatch):
    from offensive import timeline_evasion

    class BrokenTimeline:
        def build_timeline(self, _signals):
            raise RuntimeError("controlled timeline failure")

    monkeypatch.setattr(timeline_evasion, "UnifiedTimelineEngine", BrokenTimeline)
    receipt = run_timeline_evasion_differential(_plan())

    assert receipt["epistemic_level"] == "INCONCLUSIVE"
    assert receipt["reason_code"] == "SENSOR_EXECUTION_FAILED"
    assert len(receipt["sensor_errors"]) == 3
