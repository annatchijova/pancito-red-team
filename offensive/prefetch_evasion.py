"""Validate the inherited SIFT Prefetch sensor with fixed inert artifacts."""

from __future__ import annotations

import hashlib
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from sift.prefetch_analyzer import PrefetchAnalyzer


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CELLS = ("CONTROL", "PREFETCH_WIPE", "SUSPICIOUS_EXECUTION")
_EXPECTED = {
    "CONTROL": frozenset(),
    "PREFETCH_WIPE": frozenset({"PREFETCH_WIPE"}),
    "SUSPICIOUS_EXECUTION": frozenset({"SUSPICIOUS_EXECUTION"}),
}


class PrefetchEvasionPlanError(ValueError):
    """The Prefetch experiment lacks strict authorization metadata."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PrefetchEvasionPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise PrefetchEvasionPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise PrefetchEvasionPlanError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class PrefetchEvasionPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise PrefetchEvasionPlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}"
            )
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise PrefetchEvasionPlanError(
                "operator_acknowledged must be literal true"
            )


def _prefetch_bytes(index: int) -> bytes:
    return b"\x1e\x00\x00\x00SCCA" + index.to_bytes(2, "little") + b"PANCITO"


def _cell_files(name: str) -> tuple[tuple[str, bytes], ...]:
    count = 3 if name == "PREFETCH_WIPE" else 10
    files = [
        (f"SYSTEM{index:02d}.EXE-{index:08X}.pf", _prefetch_bytes(index))
        for index in range(count)
    ]
    if name == "SUSPICIOUS_EXECUTION":
        files[0] = ("MIMIKATZ.EXE-A1B2C3D4.pf", _prefetch_bytes(0))
    return tuple(files)


def _artifact_bytes(files: tuple[tuple[str, bytes], ...]) -> bytes:
    parts = [b"PANCITO-PREFETCH-CELL-V1\x00"]
    for filename, content in files:
        encoded_name = filename.encode("ascii")
        parts.extend(
            (
                len(encoded_name).to_bytes(2, "big"),
                encoded_name,
                len(content).to_bytes(2, "big"),
                content,
            )
        )
    return b"".join(parts)


def _observe(files: tuple[tuple[str, bytes], ...]) -> set[str]:
    with tempfile.TemporaryDirectory(prefix="pancito-prefetch-") as directory:
        root = Path(directory)
        for filename, content in files:
            (root / filename).write_bytes(content)
        result = PrefetchAnalyzer().analyze_directory(str(root))
    observed = {
        finding.get("type")
        for finding in result.suspicious_executions + result.anti_forensic_deletions
        if isinstance(finding, dict)
    }
    return {
        signal
        for signal in observed
        if signal in {"PREFETCH_WIPE", "SUSPICIOUS_EXECUTION"}
    }


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
        return outcomes, "CONFIRMED_BY_INDUCTION", "BOTH_PREFETCH_CELLS_DETECTED"
    return outcomes, "FALSIFIED", "ONE_OR_MORE_PREFETCH_CELLS_MISSED"


def run_prefetch_evasion_differential(
    plan: PrefetchEvasionPlan,
) -> dict[str, object]:
    """Run three fixed cells without retaining a path or executable sample."""
    if not isinstance(plan, PrefetchEvasionPlan):
        raise TypeError("plan must be a PrefetchEvasionPlan")
    observed: dict[str, set[str]] = {}
    artifacts: dict[str, dict[str, object]] = {}
    errors: list[dict[str, str]] = []
    for name in _CELLS:
        files = _cell_files(name)
        artifact = _artifact_bytes(files)
        artifacts[name] = {
            "file_count": len(files),
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "size": len(artifact),
            "synthetic_inert": True,
        }
        try:
            observed[name] = _observe(files)
        except Exception as exc:
            observed[name] = set()
            errors.append(
                {"cell": name, "sensor": "SIFT_PREFETCH", "error": type(exc).__name__}
            )

    outcomes, epistemic_level, reason_code = _classify(observed, errors)
    return {
        "schema_version": 1,
        "experiment_id": plan.experiment_id,
        "capability": "offline-prefetch-evasion-differential",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "threat_model": {
            "attacker_can": [
                "cause artifacts consistent with suspicious executable Prefetch",
                "cause artifacts consistent with selective Prefetch removal",
            ],
            "attacker_cannot": [
                "modify PANCITO code",
                "modify SIFT sensor code",
                "modify module-owned ground truth",
            ],
        },
        "prediction": "SIFT distinguishes suspicious execution and Prefetch wipe from control",
        "falsifier": "a clean control with either Prefetch mutation missed",
        "ground_truth": {name: sorted(_EXPECTED[name]) for name in _CELLS},
        "observed_signals": {name: sorted(observed[name]) for name in _CELLS},
        "cell_outcomes": outcomes,
        "sensor_errors": errors,
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "artifacts": artifacts,
        "sensor_contract": {
            "implementation": "sift.prefetch_analyzer.PrefetchAnalyzer",
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
