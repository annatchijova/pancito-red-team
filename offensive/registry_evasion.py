"""Validate SIFT Registry detectors with fixed inert facts, not live hives."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from fractions import Fraction

from sift.registry_timeline_reconstructor import (
    PersistenceDetector,
    RegistryKey,
    TimestompDetector,
)


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CELLS = ("CONTROL", "RUN_KEY_PERSISTENCE", "TIMESTAMP_COLLISION")
_EXPECTED = {
    "CONTROL": frozenset(),
    "RUN_KEY_PERSISTENCE": frozenset({"SUSPICIOUS_RUN_KEY"}),
    "TIMESTAMP_COLLISION": frozenset({"REGISTRY_TIMESTAMP_COLLISION"}),
}


class RegistryEvasionPlanError(ValueError):
    """The Registry experiment lacks strict authorization metadata."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RegistryEvasionPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise RegistryEvasionPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise RegistryEvasionPlanError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class RegistryEvasionPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise RegistryEvasionPlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}"
            )
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise RegistryEvasionPlanError(
                "operator_acknowledged must be literal true"
            )


def _keys(*, collision: bool) -> tuple[RegistryKey, ...]:
    count = 10 if collision else 3
    return tuple(
        RegistryKey(
            hive="SOFTWARE",
            path=f"SOFTWARE\\Pancito\\Control\\Key{index:02d}",
            name=f"Key{index:02d}",
            last_write=133_801_632_000_000_000 if collision else 133_801_632_000_000_000 + index,
            values=(),
            subkey_count=0,
            value_count=0,
            entropy_score=Fraction(0),
        )
        for index in range(count)
    )


def _run_output(*, suspicious: bool) -> str:
    if suspicious:
        return (
            "LastWrite Time 2025-01-16T00:00:00Z\n"
            "SyntheticUpdater -> C:\\Temp\\powershell.exe -enc SYNTHETIC_INERT_MARKER"
        )
    return (
        "LastWrite Time 2025-01-16T00:00:00Z\n"
        "SyntheticUpdater -> C:\\Program Files\\Pancito\\updater.exe"
    )


def _cell_facts(name: str) -> tuple[str, tuple[RegistryKey, ...]]:
    return (
        _run_output(suspicious=name == "RUN_KEY_PERSISTENCE"),
        _keys(collision=name == "TIMESTAMP_COLLISION"),
    )


def _artifact_bytes(run_output: str, keys: tuple[RegistryKey, ...]) -> bytes:
    facts = {
        "keys": [
            {"hive": key.hive, "last_write": key.last_write, "path": key.path}
            for key in keys
        ],
        "run_output": run_output,
    }
    return json.dumps(
        facts, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _observe(run_output: str, keys: tuple[RegistryKey, ...]) -> set[str]:
    persistence = PersistenceDetector().detect_from_regripper(run_output, "")
    timestomp = TimestompDetector().detect(list(keys))
    observed: set[str] = set()
    if any(finding.persistence_type == "run_key" for finding in persistence):
        observed.add("SUSPICIOUS_RUN_KEY")
    if any(finding.rule_ref == "RTR-TS-R1" for finding in timestomp):
        observed.add("REGISTRY_TIMESTAMP_COLLISION")
    return observed


def _classify(
    observed: dict[str, set[str]], errors: list[dict[str, str]]
) -> tuple[dict[str, str], str, str]:
    error_cells = {error["cell"] for error in errors}
    outcomes: dict[str, str] = {}
    for name in _CELLS:
        if name in error_cells or observed[name] - _EXPECTED[name]:
            outcomes[name] = "INCONCLUSIVE"
        elif name == "CONTROL":
            outcomes[name] = "CLEAN"
        elif observed[name] == _EXPECTED[name]:
            outcomes[name] = "DETECTED"
        else:
            outcomes[name] = "MISSED"
    if errors:
        return outcomes, "INCONCLUSIVE", "SENSOR_EXECUTION_FAILED"
    if any(value == "INCONCLUSIVE" for value in outcomes.values()):
        return outcomes, "INCONCLUSIVE", "UNEXPECTED_SENSOR_SIGNAL"
    if all(outcomes[name] == "DETECTED" for name in _CELLS if name != "CONTROL"):
        return outcomes, "CONFIRMED_BY_INDUCTION", "BOTH_REGISTRY_CELLS_DETECTED"
    return outcomes, "FALSIFIED", "ONE_OR_MORE_REGISTRY_CELLS_MISSED"


def run_registry_evasion_differential(
    plan: RegistryEvasionPlan,
) -> dict[str, object]:
    """Run three fixed fact sets without opening a hive or invoking RegRipper."""
    if not isinstance(plan, RegistryEvasionPlan):
        raise TypeError("plan must be a RegistryEvasionPlan")
    observed: dict[str, set[str]] = {}
    artifacts: dict[str, dict[str, object]] = {}
    errors: list[dict[str, str]] = []
    for name in _CELLS:
        run_output, keys = _cell_facts(name)
        artifact = _artifact_bytes(run_output, keys)
        artifacts[name] = {
            "fact_count": len(keys) + 1,
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "size": len(artifact),
            "synthetic_inert": True,
        }
        try:
            observed[name] = _observe(run_output, keys)
        except Exception as exc:
            observed[name] = set()
            errors.append(
                {"cell": name, "sensor": "SIFT_REGISTRY", "error": type(exc).__name__}
            )

    outcomes, epistemic_level, reason_code = _classify(observed, errors)
    return {
        "schema_version": 1,
        "experiment_id": plan.experiment_id,
        "capability": "offline-registry-evasion-differential",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "threat_model": {
            "attacker_can": [
                "cause artifacts consistent with suspicious Run-key persistence",
                "cause artifacts consistent with Registry timestamp collision",
            ],
            "attacker_cannot": [
                "modify PANCITO code",
                "modify SIFT sensor code",
                "modify module-owned ground truth",
            ],
        },
        "prediction": "SIFT distinguishes suspicious Run keys and timestamp collision from control",
        "falsifier": "a clean control with either Registry mutation missed",
        "ground_truth": {name: sorted(_EXPECTED[name]) for name in _CELLS},
        "observed_signals": {name: sorted(observed[name]) for name in _CELLS},
        "cell_outcomes": outcomes,
        "sensor_errors": errors,
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "artifacts": artifacts,
        "sensor_contract": {
            "implementation": [
                "sift.registry_timeline_reconstructor.PersistenceDetector",
                "sift.registry_timeline_reconstructor.TimestompDetector",
            ],
            "output_role": "UNSEALED_BLUE_SENSOR_OBSERVATION",
            "affects_forensic_verdict": False,
        },
        "cell_count": 3,
        "maximum_cell_count": 3,
        "sample_source": "MODULE_OWNED_SYNTHETIC_FIXTURES",
        "impact_assessment": "BLUE_CONTROL_VALIDATION_ONLY",
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
