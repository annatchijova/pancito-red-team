"""Deterministic post-seal oracle for Blue control validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


_TECHNIQUE_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


@dataclass(frozen=True)
class DetectionExpectation:
    expected_techniques: tuple[str, ...]
    expected_state_prefix: str

    def __post_init__(self) -> None:
        if not isinstance(self.expected_techniques, tuple):
            raise TypeError("expected_techniques must be a tuple")
        if not self.expected_techniques:
            raise ValueError("expected_techniques must not be empty")
        if any(not isinstance(item, str) or not _TECHNIQUE_RE.fullmatch(item)
               for item in self.expected_techniques):
            raise ValueError("expected_techniques contains an invalid ATT&CK ID")
        if len(set(self.expected_techniques)) != len(self.expected_techniques):
            raise ValueError("expected_techniques must not contain duplicates")
        if (not isinstance(self.expected_state_prefix, str)
                or not self.expected_state_prefix
                or len(self.expected_state_prefix) > 64):
            raise ValueError("expected_state_prefix must be non-empty text")


def evaluate_detection(
    *,
    verdict: Mapping[str, Any],
    custody: Mapping[str, Any],
    expectation: DetectionExpectation,
    execution_succeeded: bool = True,
) -> dict[str, Any]:
    """Compare sealed evidence with explicit expectations without an LLM."""
    if not isinstance(execution_succeeded, bool):
        raise TypeError("execution_succeeded must be a bool")

    sealed = verdict.get("sealed") is True
    chain_ok = custody.get("chain_ok") is True
    state = verdict.get("verdict_state")
    state = state if isinstance(state, str) else ""
    raw_techniques = verdict.get("mitre_techniques")
    if isinstance(raw_techniques, (list, tuple)):
        observed = sorted({item for item in raw_techniques if isinstance(item, str)})
    else:
        observed = []
    missing = sorted(set(expectation.expected_techniques) - set(observed))
    state_matches = state.startswith(expectation.expected_state_prefix)

    reason_codes: list[str] = []
    if not execution_succeeded:
        status = "EXECUTION_FAILED"
        reason_codes.append("REPLAY_EXECUTION_FAILED")
    elif not sealed or not chain_ok:
        status = "INTEGRITY_FAILURE"
        if not sealed:
            reason_codes.append("VERDICT_NOT_SEALED")
        if not chain_ok:
            reason_codes.append("CUSTODY_CHAIN_INVALID")
    else:
        if missing:
            reason_codes.append("MISSING_EXPECTED_TECHNIQUE")
        if not state_matches:
            reason_codes.append("UNEXPECTED_VERDICT_STATE")
        status = "DETECTED_AS_EXPECTED" if not reason_codes else "CONTROL_GAP"

    return {
        "oracle": "deterministic-blue-control-v1",
        "status": status,
        "execution_succeeded": execution_succeeded,
        "evidence_trusted": sealed and chain_ok,
        "expected_state_prefix": expectation.expected_state_prefix,
        "observed_state": state,
        "expected_techniques": list(expectation.expected_techniques),
        "observed_techniques": observed,
        "missing_techniques": missing,
        "reason_codes": reason_codes,
        "derived_after_sealing": True,
        "part_of_forensic_verdict": False,
        "model_used": False,
    }
