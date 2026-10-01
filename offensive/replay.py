"""Authorized, deterministic attack-trace replay for blue validation.

This is the first offensive level of PANCITO-RED-TEAM: it replays committed hostile
telemetry through the real sealed engine and returns a validation receipt.  It
does not execute an attack.  The fixed catalogue is the capability boundary;
neither a caller nor a model can provide commands, scores, verdicts, or hashes.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport


_REPO_ROOT = Path(__file__).resolve().parent.parent
_LAB_TARGET = "bundled-replay-lab"
_BLUE_OBJECTIVE = "blue-control-validation"
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

_SCENARIOS: dict[str, dict[str, Any]] = {
    "process-hollowing-timestomp": {
        "description": (
            "Replay the committed process-hollowing and timestomp telemetry "
            "to verify the correlator detects both ATT&CK techniques."
        ),
        "fixture": "attack",
        "hunts": ("pslist", "netstat"),
        "expected_techniques": ("T1055.012", "T1070.006"),
        "expected_state_prefix": "MALICE",
    },
}


class AuthorizationError(PermissionError):
    """The requested emulation is outside the explicit local grant."""


@dataclass(frozen=True)
class AuthorizationGrant:
    authorization_id: str
    target: str
    objective: str
    allowed_scenarios: tuple[str, ...]
    max_runs: int

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.authorization_id):
            raise ValueError("authorization_id must match [A-Za-z0-9._-]{1,128}")
        if not isinstance(self.allowed_scenarios, tuple):
            raise TypeError("allowed_scenarios must be a tuple")
        if isinstance(self.max_runs, bool) or not isinstance(self.max_runs, int):
            raise TypeError("max_runs must be an integer")
        if not 1 <= self.max_runs <= 100:
            raise ValueError("max_runs must be between 1 and 100")


def scenario_catalog() -> list[dict[str, Any]]:
    """Publish capabilities without exposing an executable command surface."""
    return [
        {
            "scenario_id": scenario_id,
            "description": spec["description"],
            "execution_mode": "replay-only",
            "expected_techniques": list(spec["expected_techniques"]),
        }
        for scenario_id, spec in sorted(_SCENARIOS.items())
    ]


class ReplayCampaign:
    """A stateful, budgeted use of the immutable replay catalogue."""

    def __init__(self, grant: AuthorizationGrant, *, out_dir: str | Path) -> None:
        if grant.target != _LAB_TARGET:
            raise AuthorizationError(
                f"target must be {_LAB_TARGET!r}; live or remote targets are "
                "outside this replay-only capability"
            )
        if grant.objective != _BLUE_OBJECTIVE:
            raise AuthorizationError(
                f"objective must be {_BLUE_OBJECTIVE!r}"
            )
        self.grant = grant
        self.out_dir = Path(out_dir)
        self._runs = 0
        self._budget_lock = threading.Lock()

    def run(self, scenario_id: str) -> dict[str, Any]:
        if scenario_id not in self.grant.allowed_scenarios:
            raise AuthorizationError(
                f"scenario {scenario_id!r} is not authorized by this grant"
            )
        try:
            spec = _SCENARIOS[scenario_id]
        except KeyError as exc:
            raise AuthorizationError(
                f"scenario {scenario_id!r} is not in the curated catalogue"
            ) from exc

        # Reserve before executing. A failed run consumes budget deliberately:
        # retrying is another action and requires another authorized slot.
        with self._budget_lock:
            if self._runs >= self.grant.max_runs:
                raise AuthorizationError("authorization run budget exhausted")
            self._runs += 1
            run_number = self._runs
        run_dir = self.out_dir / self.grant.authorization_id / f"run-{run_number:04d}"
        fixture = _REPO_ROOT / "tests" / "fixtures" / spec["fixture"]
        session = PurpleTeamSession(
            MockTransport(fixture),
            case_id=f"OFF-{self.grant.authorization_id}-{run_number:04d}",
            host={
                "client_id": "C.bundled-lab",
                "hostname": "ANNACONDA2-REPLAY-LAB",
                "os": "windows",
            },
            examiner_id=f"grant:{self.grant.authorization_id}",
            out_dir=run_dir,
            # The sealed evidence schema intentionally has a closed source
            # vocabulary.  Authorization provenance stays in the session's
            # audit reason; replay remains the truthful custody source.
            source="replay",
            time_base="2026-08-12T14:10:00Z",
        )

        summary = session.run_hunt(
            list(spec["hunts"]),
            reason=(
                f"authorized replay {self.grant.authorization_id}: "
                f"{self.grant.objective}"
            ),
        )
        if "error" in summary:
            raise RuntimeError(summary["error"])
        verdict = session.adjudicate(summary["window_id"])
        if "error" in verdict:
            raise RuntimeError(verdict["error"])
        custody = session.verify_chain()
        if not custody["chain_ok"]:
            raise RuntimeError(
                "replay produced a verdict whose custody chain did not verify"
            )
        observed = tuple(verdict["mitre_techniques"])
        missing = sorted(set(spec["expected_techniques"]) - set(observed))
        state_matches = verdict["verdict_state"].startswith(
            spec["expected_state_prefix"])
        validation_status = (
            "DETECTED_AS_EXPECTED" if state_matches and not missing
            else "CONTROL_GAP"
        )
        return {
            "authorization_id": self.grant.authorization_id,
            "target": self.grant.target,
            "objective": self.grant.objective,
            "scenario_id": scenario_id,
            "execution_mode": "replay-only",
            "model_used": False,
            "run_number": run_number,
            "sealed_verdict": verdict,
            "custody": custody,
            "detection_validation": {
                "status": validation_status,
                "expected_techniques": list(spec["expected_techniques"]),
                "observed_techniques": list(observed),
                "missing_techniques": missing,
                "derived_after_sealing": True,
                "part_of_forensic_verdict": False,
            },
        }
