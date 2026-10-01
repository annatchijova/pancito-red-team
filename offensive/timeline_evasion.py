"""Reproduce cross-source identity loss in the SIFT unified timeline.

This is an offensive control-validation experiment, not a patch.  It compares
a hand-shaped positive control with the real summary contracts emitted by the
Memory and MFT analyzers.  The output is deliberately unsealed and cannot
alter a forensic verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from fractions import Fraction

from core.ebs_v1 import SignalOutput
from sift.disk_forensics import MFTAnalysisResult
from sift.memory_forensics import MemoryAnalysisResult, ProcessRecord
from sift.unified_timeline_engine import UnifiedTimelineEngine


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PROCESS_NAME = "pancito-agent.exe"
_CELLS = (
    "CONTROL_SHARED_ENTITY",
    "MISSING_MFT",
    "PRODUCTION_SHAPED_PAIR",
)
_EXPECTED = {
    "CONTROL_SHARED_ENTITY": frozenset({"CAUSAL_INVERSION"}),
    "MISSING_MFT": frozenset({"MEMORY_WITHOUT_DISK"}),
    "PRODUCTION_SHAPED_PAIR": frozenset({"CAUSAL_INVERSION"}),
}


class TimelineEvasionPlanError(ValueError):
    """The timeline experiment lacks strict authorization metadata."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TimelineEvasionPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise TimelineEvasionPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise TimelineEvasionPlanError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class TimelineEvasionPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise TimelineEvasionPlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}"
            )
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise TimelineEvasionPlanError(
                "operator_acknowledged must be literal true"
            )


def _memory_result() -> MemoryAnalysisResult:
    return MemoryAnalysisResult(
        dump_path="module-owned-synthetic-memory",
        dump_sha256="a" * 64,
        processes=[
            ProcessRecord(
                pid=4242,
                ppid=4,
                name=_PROCESS_NAME,
                path=f"C:/Pancito/{_PROCESS_NAME}",
                cmdline=_PROCESS_NAME,
                create_time="2025-01-01T00:00:00Z",
                session_id=1,
                parent_name="services.exe",
                threads=1,
                handles=1,
            )
        ],
    )


def _mft_result() -> MFTAnalysisResult:
    return MFTAnalysisResult(
        mft_hash="b" * 64,
        total_entries=1,
        timestomp_entries=[
            {
                "record": 1,
                "filename": _PROCESS_NAME,
                "anomalies": [
                    {
                        "type": "CREATED_MISMATCH",
                        "si": "2025-01-01T00:06:41Z",
                        "fn": "2025-01-01T00:00:00Z",
                    }
                ],
            }
        ],
        hardlink_anomalies=[],
        ads_entries=[],
        slack_suspects=[],
        recreation_gaps=[],
        sequence_anomalies=[],
        composite_score=Fraction(1, 2),
    )


def _control_signals() -> list[SignalOutput]:
    return [
        SignalOutput(
            tool_name="MEMORY_CONTROL",
            value=0.0,
            z_score=0.0,
            confidence=1.0,
            metadata={
                "artifact_type": "memory",
                "filename": _PROCESS_NAME,
                "timestamp": 1_000,
            },
        ),
        SignalOutput(
            tool_name="MFT_CONTROL",
            value=0.0,
            z_score=0.0,
            confidence=1.0,
            metadata={
                "artifact_type": "mft",
                "filename": _PROCESS_NAME,
                "timestamp": 1_401,
            },
        ),
    ]


def _cell_signals(name: str) -> list[SignalOutput]:
    if name == "CONTROL_SHARED_ENTITY":
        return _control_signals()
    memory = _memory_result().to_signal()
    if name == "MISSING_MFT":
        return [memory]
    return [memory, _mft_result().to_signal()]


def _fixture_bytes() -> bytes:
    facts = {
        "cells": {
            "CONTROL_SHARED_ENTITY": {
                "memory_timestamp": 1000,
                "mft_timestamp": 1401,
                "shared_filename": _PROCESS_NAME,
            },
            "MISSING_MFT": {"memory_process": _PROCESS_NAME},
            "PRODUCTION_SHAPED_PAIR": {
                "memory_process": _PROCESS_NAME,
                "mft_filename": _PROCESS_NAME,
                "contracts": ["MemoryAnalysisResult.to_signal", "MFTAnalysisResult.to_signal"],
            },
        },
        "expected": {name: sorted(_EXPECTED[name]) for name in _CELLS},
    }
    return json.dumps(
        facts, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _observe(signals: list[SignalOutput]) -> tuple[set[str], dict[str, object]]:
    result = UnifiedTimelineEngine().build_timeline(signals)
    anomaly_types = {
        item.get("type")
        for item in result.temporal_anomalies
        if isinstance(item, dict) and isinstance(item.get("type"), str)
    }
    gap_types = {
        item.get("type")
        for item in result.cross_source_gaps
        if isinstance(item, dict) and isinstance(item.get("type"), str)
    }
    facts = {
        "entity_ids": [event.entity_id for event in result.timeline],
        "timestamps": [event.timestamp for event in result.timeline],
        "temporal_anomalies": sorted(anomaly_types),
        "cross_source_gaps": sorted(gap_types),
    }
    return anomaly_types | gap_types, facts


def run_timeline_evasion_differential(
    plan: TimelineEvasionPlan,
) -> dict[str, object]:
    """Execute positive controls and the production-shaped composition cell."""
    if not isinstance(plan, TimelineEvasionPlan):
        raise TypeError("plan must be a TimelineEvasionPlan")
    observed: dict[str, set[str]] = {}
    observation_facts: dict[str, dict[str, object]] = {}
    errors: list[dict[str, str]] = []
    for name in _CELLS:
        try:
            observed[name], observation_facts[name] = _observe(_cell_signals(name))
        except Exception as exc:
            observed[name] = set()
            observation_facts[name] = {
                "entity_ids": [],
                "timestamps": [],
                "temporal_anomalies": [],
                "cross_source_gaps": [],
            }
            errors.append(
                {"cell": name, "sensor": "SIFT_UNIFIED_TIMELINE", "error": type(exc).__name__}
            )

    outcomes: dict[str, str] = {}
    error_cells = {error["cell"] for error in errors}
    for name in _CELLS:
        if name in error_cells:
            outcomes[name] = "INCONCLUSIVE"
        elif observed[name] == _EXPECTED[name]:
            outcomes[name] = "DETECTED"
        elif name == "PRODUCTION_SHAPED_PAIR" and not (
            observed[name] & _EXPECTED[name]
        ):
            outcomes[name] = "MISSED"
        else:
            outcomes[name] = "INCONCLUSIVE"

    if errors:
        epistemic_level = "INCONCLUSIVE"
        reason_code = "SENSOR_EXECUTION_FAILED"
    elif any(
        outcomes[name] != "DETECTED"
        for name in ("CONTROL_SHARED_ENTITY", "MISSING_MFT")
    ):
        epistemic_level = "INCONCLUSIVE"
        reason_code = "POSITIVE_CONTROL_FAILED"
    elif outcomes["PRODUCTION_SHAPED_PAIR"] == "MISSED":
        epistemic_level = "FALSIFIED"
        reason_code = "PRODUCTION_METADATA_LOSES_CORRELATION_IDENTITY"
    elif outcomes["PRODUCTION_SHAPED_PAIR"] == "DETECTED":
        epistemic_level = "CONFIRMED_BY_INDUCTION"
        reason_code = "PRODUCTION_METADATA_PRESERVES_CORRELATION_IDENTITY"
    else:
        epistemic_level = "INCONCLUSIVE"
        reason_code = "UNEXPECTED_SENSOR_SIGNAL"

    fixture = _fixture_bytes()
    return {
        "schema_version": 1,
        "experiment_id": plan.experiment_id,
        "capability": "offline-timeline-composition-differential",
        "audit_base_commit": "209db4d",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "threat_model": {
            "attacker_can": [
                "cause the same process identity to appear in memory and MFT evidence",
                "cause a causal separation greater than the timeline correlation window",
            ],
            "attacker_cannot": [
                "modify PANCITO code",
                "modify SIFT sensor code",
                "modify module-owned ground truth",
            ],
        },
        "prediction": "production Memory and MFT summaries preserve enough identity for causal correlation",
        "falsifier": "positive controls pass but the production-shaped pair misses CAUSAL_INVERSION",
        "ground_truth": {name: sorted(_EXPECTED[name]) for name in _CELLS},
        "observed_signals": {name: sorted(observed[name]) for name in _CELLS},
        "observation_facts": observation_facts,
        "cell_outcomes": outcomes,
        "sensor_errors": errors,
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "discarded_vectors": [
            {
                "vector": "timeline causal rule is absent",
                "result": "FALSIFIED_BY_CONTROL",
            },
            {
                "vector": "missing-source rule is entirely inactive",
                "result": "FALSIFIED_BY_CONTROL",
            },
        ],
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "fixture_size": len(fixture),
        "sensor_contract": {
            "implementation": "sift.unified_timeline_engine.UnifiedTimelineEngine",
            "production_inputs": [
                "sift.memory_forensics.MemoryAnalysisResult.to_signal",
                "sift.disk_forensics.MFTAnalysisResult.to_signal",
            ],
            "output_role": "UNSEALED_BLUE_SENSOR_OBSERVATION",
            "affects_forensic_verdict": False,
        },
        "cell_count": 3,
        "maximum_cell_count": 3,
        "sample_source": "MODULE_OWNED_SYNTHETIC_FACTS",
        "impact_assessment": "BLUE_CONTROL_VALIDATION_ONLY",
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
