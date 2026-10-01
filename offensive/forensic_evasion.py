"""Synthetic forensic-evasion differential for the inherited SIFT sensors.

The module owns every input byte.  It compares exact, predeclared ground truth
with SIFT observations and emits an unsealed Blue-control validation receipt.
SIFT is deliberately a sensor under test: it cannot create or alter a forensic
verdict, score, custody record, or seal through this capability.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import unicodedata
from dataclasses import dataclass

from sift.disk_forensics import MFTTimelineAnalyzer
from sift.event_log_correlator import AttackChainDetector, EventRecord
from sift.mft_parser import parse_mft_bytes


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ANALYSIS_TIME = "2025-02-01T00:00:00Z"
_CELLS = ("CONTROL", "LOG_WIPE", "TIMESTOMP")
_TARGET_SIGNALS = frozenset({"EVENT_LOG_WIPE_CHAIN", "MFT_SI_FN_MISMATCH"})
_EXPECTED_SIGNALS = {
    "CONTROL": frozenset(),
    "LOG_WIPE": frozenset({"EVENT_LOG_WIPE_CHAIN"}),
    "TIMESTOMP": frozenset({"MFT_SI_FN_MISMATCH"}),
}


class ForensicEvasionPlanError(ValueError):
    """The experiment metadata is ambiguous or lacks explicit authorization."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ForensicEvasionPlanError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise ForensicEvasionPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ForensicEvasionPlanError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class ForensicEvasionPlan:
    """Authorization metadata for one fixed three-cell offline experiment."""

    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool

    def __post_init__(self) -> None:
        identifier = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(identifier):
            raise ForensicEvasionPlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}"
            )
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise ForensicEvasionPlanError(
                "operator_acknowledged must be literal true"
            )


@dataclass(frozen=True)
class _SyntheticCell:
    mft: bytes
    events: tuple[EventRecord, ...]

    def artifact_bytes(self) -> bytes:
        event_facts = [
            {
                "channel": event.channel,
                "computer": event.computer,
                "event_id": event.event_id,
                "message": event.message,
                "process_id": event.process_id,
                "thread_id": event.thread_id,
                "timestamp": event.timestamp,
                "user": event.user,
            }
            for event in self.events
        ]
        encoded_events = json.dumps(
            event_facts, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return b"PANCITO-SIFT-CELL-V1\x00" + self.mft + b"\x00" + encoded_events


def _filetime(unix_seconds: int, microseconds: int) -> int:
    return (unix_seconds + 11_644_473_600) * 10_000_000 + microseconds * 10


def _resident_attribute(attribute_type: int, content: bytes) -> bytes:
    total_length = (24 + len(content) + 7) & ~7
    attribute = bytearray(total_length)
    struct.pack_into("<II", attribute, 0, attribute_type, total_length)
    struct.pack_into("<I", attribute, 16, len(content))
    struct.pack_into("<H", attribute, 20, 24)
    attribute[24 : 24 + len(content)] = content
    return bytes(attribute)


def _synthetic_mft(*, timestomp: bool) -> bytes:
    """Build one inert NTFS FILE record sufficient for two real SIFT stages."""
    base = 1_737_000_000
    microseconds = (123_457, 284_913, 396_751, 847_263)
    si_times = tuple(
        _filetime(base + index * 71, microsecond)
        for index, microsecond in enumerate(microseconds)
    )
    fn_times = si_times
    if timestomp:
        fn_times = (
            _filetime(base - 86_400, 512_347),
            _filetime(base - 43_200, 671_923),
            si_times[2],
            si_times[3],
        )

    standard_information = struct.pack("<QQQQ", *si_times)
    filename = "pancito-control.txt".encode("utf-16-le")
    file_name = bytearray(66 + len(filename))
    struct.pack_into("<QQQQ", file_name, 8, *fn_times)
    file_name[64] = len(filename) // 2
    file_name[65] = 1
    file_name[66:] = filename

    record = bytearray(1024)
    record[0:4] = b"FILE"
    struct.pack_into("<H", record, 0x12, 1)
    struct.pack_into("<H", record, 0x14, 0x38)
    struct.pack_into("<H", record, 0x16, 1)
    offset = 0x38
    for attribute in (
        _resident_attribute(0x10, standard_information),
        _resident_attribute(0x30, bytes(file_name)),
    ):
        record[offset : offset + len(attribute)] = attribute
        offset += len(attribute)
    struct.pack_into("<I", record, offset, 0xFFFFFFFF)
    return bytes(record)


def _event(event_id: int, timestamp: int) -> EventRecord:
    return EventRecord(
        event_id=event_id,
        timestamp=timestamp,
        channel="Security",
        computer="PANCITO-LAB",
        user="SYNTHETIC\\analyst",
        process_id=4242,
        thread_id=7,
        message="module-owned inert validation event",
    )


def _cells() -> dict[str, _SyntheticCell]:
    login = _event(4624, 1_737_100_000)
    return {
        "CONTROL": _SyntheticCell(_synthetic_mft(timestomp=False), (login,)),
        "LOG_WIPE": _SyntheticCell(
            _synthetic_mft(timestomp=False),
            (login, _event(1102, login.timestamp + 60)),
        ),
        "TIMESTOMP": _SyntheticCell(
            _synthetic_mft(timestomp=True), (login,)
        ),
    }


def _observe_mft(sample: bytes) -> set[str]:
    parsed = parse_mft_bytes(sample)
    parsed_json = json.dumps(
        parsed, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    analysis = MFTTimelineAnalyzer().analyze(
        sample, parsed_json=parsed_json, timestamp_utc=_ANALYSIS_TIME
    )
    for entry in analysis.timestomp_entries:
        anomaly_types = {
            anomaly.get("type")
            for anomaly in entry.get("anomalies", [])
            if isinstance(anomaly, dict)
        }
        if anomaly_types & {"CREATED_MISMATCH", "MODIFIED_MISMATCH"}:
            return {"MFT_SI_FN_MISMATCH"}
    return set()


def _observe_event_log(events: tuple[EventRecord, ...]) -> set[str]:
    chains = AttackChainDetector().detect(list(events))
    if any(chain.get("chain_name") == "LOG_WIPE_AFTER_ATTACK" for chain in chains):
        return {"EVENT_LOG_WIPE_CHAIN"}
    return set()


def _classify_cells(
    observed: dict[str, set[str]], sensor_errors: list[dict[str, str]]
) -> tuple[dict[str, str], str, str]:
    outcomes: dict[str, str] = {}
    error_cells = {error["cell"] for error in sensor_errors}
    for name in _CELLS:
        if name in error_cells:
            outcomes[name] = "INCONCLUSIVE"
        elif observed[name] - _EXPECTED_SIGNALS[name]:
            outcomes[name] = "INCONCLUSIVE"
        elif name == "CONTROL":
            outcomes[name] = "CLEAN"
        elif observed[name] == _EXPECTED_SIGNALS[name]:
            outcomes[name] = "DETECTED"
        else:
            outcomes[name] = "MISSED"

    if sensor_errors:
        return outcomes, "INCONCLUSIVE", "SENSOR_EXECUTION_FAILED"
    if any(outcome == "INCONCLUSIVE" for outcome in outcomes.values()):
        return outcomes, "INCONCLUSIVE", "UNEXPECTED_SENSOR_SIGNAL"
    if all(outcomes[name] == "DETECTED" for name in _CELLS if name != "CONTROL"):
        return outcomes, "CONFIRMED_BY_INDUCTION", "BOTH_EVASION_CELLS_DETECTED"
    return outcomes, "FALSIFIED", "ONE_OR_MORE_EVASION_CELLS_MISSED"


def run_forensic_evasion_differential(
    plan: ForensicEvasionPlan,
) -> dict[str, object]:
    """Run the fixed matrix and return a deterministic, explicitly unsealed receipt."""
    if not isinstance(plan, ForensicEvasionPlan):
        raise TypeError("plan must be a ForensicEvasionPlan")
    cells = _cells()
    observed = {name: set() for name in _CELLS}
    sensor_errors: list[dict[str, str]] = []
    artifacts: dict[str, dict[str, object]] = {}

    for name in _CELLS:
        cell = cells[name]
        artifact = cell.artifact_bytes()
        artifacts[name] = {
            "kind": "SYNTHETIC_MFT_AND_EVENT_FACTS",
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "size": len(artifact),
            "synthetic_inert": True,
        }
        for sensor, observe, value in (
            ("SIFT_MFT", _observe_mft, cell.mft),
            ("SIFT_EVENT_LOG", _observe_event_log, cell.events),
        ):
            try:
                observed[name].update(observe(value))  # type: ignore[arg-type]
            except Exception as exc:  # Sensor failure is evidence, not clean output.
                sensor_errors.append(
                    {"cell": name, "sensor": sensor, "error": type(exc).__name__}
                )
        observed[name].intersection_update(_TARGET_SIGNALS)

    outcomes, epistemic_level, reason_code = _classify_cells(
        observed, sensor_errors
    )
    return {
        "schema_version": 1,
        "experiment_id": plan.experiment_id,
        "capability": "offline-forensic-evasion-differential",
        "execution_mode": "SYNTHETIC_OFFLINE",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "threat_model": {
            "attacker_can": [
                "cause evidence consistent with timestamp manipulation",
                "cause evidence consistent with audit-log clearing",
            ],
            "attacker_cannot": [
                "modify PANCITO code",
                "modify SIFT sensor code",
                "modify module-owned ground truth",
            ],
        },
        "prediction": "SIFT distinguishes both known mutations from the clean control",
        "falsifier": "a clean control with either mutation missed",
        "ground_truth": {
            name: sorted(_EXPECTED_SIGNALS[name]) for name in _CELLS
        },
        "observed_signals": {name: sorted(observed[name]) for name in _CELLS},
        "cell_outcomes": outcomes,
        "sensor_errors": sensor_errors,
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "artifacts": artifacts,
        "sensor_contract": {
            "implementation": "SIFT",
            "modules": [
                "sift.disk_forensics.MFTTimelineAnalyzer",
                "sift.event_log_correlator.AttackChainDetector",
                "sift.mft_parser.parse_mft_bytes",
            ],
            "output_role": "UNSEALED_BLUE_SENSOR_OBSERVATION",
            "affects_forensic_verdict": False,
        },
        "cell_count": 3,
        "maximum_cell_count": 3,
        "impact_assessment": "BLUE_CONTROL_VALIDATION_ONLY",
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
