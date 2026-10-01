"""Loss-resistant handoffs from passive OpenAPI triage to bounded experiments."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


_CANDIDATE_ID_RE = re.compile(r"^CANDIDATE-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER_RE = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_.-]{0,127}\}$")


class HandoffError(ValueError):
    """A triage receipt cannot support the requested BOLA handoff."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HandoffError(f"{name} must be non-empty text without outer whitespace")
    if len(value) > maximum:
        raise HandoffError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise HandoffError(f"{name} contains control characters")
    return value


def _template_from_entry_point(value: object) -> str:
    entry_point = _text(value, "entry_point", 2_128)
    method, separator, template = entry_point.partition(" ")
    if method != "GET" or not separator:
        raise HandoffError("BOLA candidate entry_point must use GET")
    parsed = urlsplit(template)
    if (
        not template.startswith("/")
        or template.startswith("//")
        or "\\" in template
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise HandoffError("BOLA candidate must use a relative path template")
    segments = template.split("/")[1:]
    placeholders = [segment for segment in segments if segment.startswith("{")]
    if not placeholders or any(not _PLACEHOLDER_RE.fullmatch(item) for item in placeholders):
        raise HandoffError("BOLA candidate requires whole-segment path placeholders")
    if any(("{" in item or "}" in item) and item not in placeholders for item in segments):
        raise HandoffError("BOLA candidate contains an ambiguous path placeholder")
    return template


def _authn_template_from_entry_point(value: object) -> str:
    entry_point = _text(value, "entry_point", 2_128)
    method, separator, template = entry_point.partition(" ")
    if method != "GET" or not separator:
        raise HandoffError("authentication candidate entry_point must use GET")
    parsed = urlsplit(template)
    if (
        not template.startswith("/")
        or template.startswith("//")
        or "\\" in template
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise HandoffError(
            "authentication candidate must use a relative path template"
        )
    segments = template.split("/")[1:]
    placeholders = [segment for segment in segments if segment.startswith("{")]
    if any(not _PLACEHOLDER_RE.fullmatch(item) for item in placeholders):
        raise HandoffError(
            "authentication candidate contains an invalid path placeholder"
        )
    if any(("{" in item or "}" in item) and item not in placeholders for item in segments):
        raise HandoffError(
            "authentication candidate contains an ambiguous path placeholder"
        )
    return template


def _state_change_template_from_entry_point(value: object) -> str:
    entry_point = _text(value, "entry_point", 2_128)
    method, separator, template = entry_point.partition(" ")
    if method != "PATCH" or not separator:
        raise HandoffError("state-change candidate entry_point must use PATCH")
    parsed = urlsplit(template)
    if (
        not template.startswith("/")
        or template.startswith("//")
        or "\\" in template
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise HandoffError(
            "state-change candidate must use a relative path template"
        )
    segments = template.split("/")[1:]
    placeholders = [segment for segment in segments if segment.startswith("{")]
    if any(not _PLACEHOLDER_RE.fullmatch(item) for item in placeholders):
        raise HandoffError(
            "state-change candidate contains an invalid path placeholder"
        )
    if any(("{" in item or "}" in item) and item not in placeholders for item in segments):
        raise HandoffError(
            "state-change candidate contains an ambiguous path placeholder"
        )
    return template


def _file_ingress_template_from_entry_point(value: object) -> str:
    entry_point = _text(value, "entry_point", 2_128)
    method, separator, template = entry_point.partition(" ")
    if method != "POST" or not separator:
        raise HandoffError("file-ingress candidate entry_point must use POST")
    parsed = urlsplit(template)
    if (
        not template.startswith("/")
        or template.startswith("//")
        or "\\" in template
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise HandoffError("file-ingress candidate must use a relative path template")
    segments = template.split("/")[1:]
    placeholders = [segment for segment in segments if segment.startswith("{")]
    if any(not _PLACEHOLDER_RE.fullmatch(item) for item in placeholders):
        raise HandoffError("file-ingress candidate has an invalid path placeholder")
    if any(("{" in item or "}" in item) and item not in placeholders for item in segments):
        raise HandoffError("file-ingress candidate has an ambiguous path placeholder")
    return template


@dataclass(frozen=True)
class BolaCandidateHandoff:
    """Unsealed provenance pointer; it preserves a candidate, not a conclusion."""

    candidate_id: str
    source_label: str
    source_sha256: str
    entry_point: str
    json_pointer: str = "/unavailable"

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not _CANDIDATE_ID_RE.fullmatch(
            self.candidate_id
        ):
            raise HandoffError("candidate_id is invalid")
        _text(self.source_label, "source_label", 512)
        if not isinstance(self.source_sha256, str) or not _SHA256_RE.fullmatch(
            self.source_sha256
        ):
            raise HandoffError("source_sha256 must be lowercase SHA-256")
        _template_from_entry_point(self.entry_point)
        pointer = _text(self.json_pointer, "json_pointer", 2_048)
        if not pointer.startswith("/"):
            raise HandoffError("json_pointer must be an absolute JSON pointer")

    @property
    def epistemic_level(self) -> str:
        return "CANDIDATE"

    @property
    def integrity(self) -> str:
        return "UNSEALED_TRIAGE_HANDOFF"

    @property
    def path_template(self) -> str:
        return _template_from_entry_point(self.entry_point)

    def to_receipt(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "source_label": self.source_label,
            "source_sha256": self.source_sha256,
            "json_pointer": self.json_pointer,
            "entry_point": self.entry_point,
            "epistemic_level": self.epistemic_level,
            "integrity": self.integrity,
        }


@dataclass(frozen=True)
class AuthnCandidateHandoff:
    """Unsealed authentication candidate provenance, never a finding."""

    candidate_id: str
    source_label: str
    source_sha256: str
    entry_point: str
    json_pointer: str = "/unavailable"

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not _CANDIDATE_ID_RE.fullmatch(
            self.candidate_id
        ):
            raise HandoffError("candidate_id is invalid")
        _text(self.source_label, "source_label", 512)
        if not isinstance(self.source_sha256, str) or not _SHA256_RE.fullmatch(
            self.source_sha256
        ):
            raise HandoffError("source_sha256 must be lowercase SHA-256")
        _authn_template_from_entry_point(self.entry_point)
        pointer = _text(self.json_pointer, "json_pointer", 2_048)
        if not pointer.startswith("/"):
            raise HandoffError("json_pointer must be an absolute JSON pointer")

    @property
    def epistemic_level(self) -> str:
        return "CANDIDATE"

    @property
    def integrity(self) -> str:
        return "UNSEALED_TRIAGE_HANDOFF"

    @property
    def path_template(self) -> str:
        return _authn_template_from_entry_point(self.entry_point)

    def to_receipt(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "source_label": self.source_label,
            "source_sha256": self.source_sha256,
            "json_pointer": self.json_pointer,
            "entry_point": self.entry_point,
            "epistemic_level": self.epistemic_level,
            "integrity": self.integrity,
        }


@dataclass(frozen=True)
class StateChangeCandidateHandoff:
    """Unsealed provenance for one passive public-PATCH candidate."""

    candidate_id: str
    source_label: str
    source_sha256: str
    entry_point: str
    json_pointer: str = "/unavailable"

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not _CANDIDATE_ID_RE.fullmatch(
            self.candidate_id
        ):
            raise HandoffError("candidate_id is invalid")
        _text(self.source_label, "source_label", 512)
        if not isinstance(self.source_sha256, str) or not _SHA256_RE.fullmatch(
            self.source_sha256
        ):
            raise HandoffError("source_sha256 must be lowercase SHA-256")
        _state_change_template_from_entry_point(self.entry_point)
        pointer = _text(self.json_pointer, "json_pointer", 2_048)
        if not pointer.startswith("/"):
            raise HandoffError("json_pointer must be an absolute JSON pointer")

    @property
    def epistemic_level(self) -> str:
        return "CANDIDATE"

    @property
    def integrity(self) -> str:
        return "UNSEALED_TRIAGE_HANDOFF"

    @property
    def path_template(self) -> str:
        return _state_change_template_from_entry_point(self.entry_point)

    def to_receipt(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "source_label": self.source_label,
            "source_sha256": self.source_sha256,
            "json_pointer": self.json_pointer,
            "entry_point": self.entry_point,
            "epistemic_level": self.epistemic_level,
            "integrity": self.integrity,
        }


@dataclass(frozen=True)
class FileIngressCandidateHandoff:
    """Unsealed provenance for one passive POST file-ingress candidate."""

    candidate_id: str
    source_label: str
    source_sha256: str
    entry_point: str
    json_pointer: str = "/unavailable"

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not _CANDIDATE_ID_RE.fullmatch(
            self.candidate_id
        ):
            raise HandoffError("candidate_id is invalid")
        _text(self.source_label, "source_label", 512)
        if not isinstance(self.source_sha256, str) or not _SHA256_RE.fullmatch(
            self.source_sha256
        ):
            raise HandoffError("source_sha256 must be lowercase SHA-256")
        _file_ingress_template_from_entry_point(self.entry_point)
        if not _text(self.json_pointer, "json_pointer", 2_048).startswith("/"):
            raise HandoffError("json_pointer must be an absolute JSON pointer")

    @property
    def epistemic_level(self) -> str:
        return "CANDIDATE"

    @property
    def integrity(self) -> str:
        return "UNSEALED_TRIAGE_HANDOFF"

    @property
    def path_template(self) -> str:
        return _file_ingress_template_from_entry_point(self.entry_point)

    def to_receipt(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "source_label": self.source_label,
            "source_sha256": self.source_sha256,
            "json_pointer": self.json_pointer,
            "entry_point": self.entry_point,
            "epistemic_level": self.epistemic_level,
            "integrity": self.integrity,
        }


def path_matches_candidate_template(
    handoff: BolaCandidateHandoff, concrete_path: str
) -> bool:
    """Match literal segments exactly and placeholders to one non-empty segment."""
    if not isinstance(handoff, BolaCandidateHandoff) or not isinstance(concrete_path, str):
        return False
    return _path_matches_template(handoff.path_template, concrete_path)


def _path_matches_template(template: str, concrete_path: str) -> bool:
    parsed = urlsplit(concrete_path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return False
    template_segments = template.split("/")[1:]
    concrete_segments = concrete_path.split("/")[1:]
    if len(template_segments) != len(concrete_segments):
        return False
    for expected, observed in zip(template_segments, concrete_segments, strict=True):
        if _PLACEHOLDER_RE.fullmatch(expected):
            if not observed or observed in {".", ".."}:
                return False
        elif expected != observed:
            return False
    return True


def authn_path_matches_candidate_template(
    handoff: AuthnCandidateHandoff, concrete_path: str
) -> bool:
    """Match one protected path to its passive authentication candidate."""
    if not isinstance(handoff, AuthnCandidateHandoff) or not isinstance(
        concrete_path, str
    ):
        return False
    return _path_matches_template(handoff.path_template, concrete_path)


def state_change_path_matches_candidate_template(
    handoff: StateChangeCandidateHandoff, concrete_path: str
) -> bool:
    """Bind a concrete PATCH path to its passive OpenAPI candidate."""
    if not isinstance(handoff, StateChangeCandidateHandoff) or not isinstance(
        concrete_path, str
    ):
        return False
    return _path_matches_template(handoff.path_template, concrete_path)


def file_ingress_path_matches(
    handoff: FileIngressCandidateHandoff, concrete_path: str
) -> bool:
    if not isinstance(handoff, FileIngressCandidateHandoff) or not isinstance(
        concrete_path, str
    ):
        return False
    return _path_matches_template(handoff.path_template, concrete_path)


def _select_ranked_candidate(
    triage_receipt: dict[str, object],
    candidate_id: str,
    *,
    expected_type: str,
    wrong_type_message: str,
) -> tuple[dict[str, object], dict[str, object], object]:
    if not isinstance(triage_receipt, dict):
        raise HandoffError("triage receipt must be an object")
    if not isinstance(candidate_id, str) or not _CANDIDATE_ID_RE.fullmatch(candidate_id):
        raise HandoffError("candidate_id is invalid")
    if triage_receipt.get("mode") != "PASSIVE_ARTIFACT_TRIAGE":
        raise HandoffError("receipt is not passive OpenAPI triage")
    if triage_receipt.get("active_probe_performed") is not False:
        raise HandoffError("receipt active-probe status is inconsistent")
    if triage_receipt.get("model_used") is not False:
        raise HandoffError("receipt model status is inconsistent")
    if triage_receipt.get("part_of_forensic_verdict") is not False:
        raise HandoffError("receipt verdict status is inconsistent")

    queue = triage_receipt.get("candidate_queue")
    below = triage_receipt.get("below_the_line")
    if not isinstance(queue, list) or not isinstance(below, list):
        raise HandoffError("triage receipt candidate collections are invalid")
    matches = [
        item
        for item in queue
        if isinstance(item, dict) and item.get("candidate_id") == candidate_id
    ]
    if not matches:
        if any(
            isinstance(item, dict) and item.get("candidate_id") == candidate_id
            for item in below
        ):
            raise HandoffError("candidate is not in the ranked candidate queue")
        raise HandoffError("candidate_id was not found in the triage receipt")
    if len(matches) != 1:
        raise HandoffError("candidate_id is duplicated in the ranked candidate queue")
    candidate = matches[0]
    if candidate.get("candidate_type") != expected_type:
        raise HandoffError(wrong_type_message)
    if candidate.get("epistemic_level") != "CANDIDATE":
        raise HandoffError("selected candidate has an invalid epistemic level")
    if isinstance(candidate.get("priority_score"), bool) or not isinstance(
        candidate.get("priority_score"), int
    ):
        raise HandoffError("selected candidate has no deterministic priority")
    provenance = candidate.get("provenance")
    if not isinstance(provenance, dict):
        raise HandoffError("selected candidate provenance is missing")
    source_label = triage_receipt.get("source_label")
    if provenance.get("source_label") != source_label:
        raise HandoffError("selected candidate source label is inconsistent")
    return candidate, provenance, source_label


def select_bola_candidate(
    triage_receipt: dict[str, object], candidate_id: str
) -> BolaCandidateHandoff:
    """Select a ranked BOLA candidate without importing its priority judgment."""
    candidate, provenance, source_label = _select_ranked_candidate(
        triage_receipt,
        candidate_id,
        expected_type="OBJECT_AUTHORIZATION_REVIEW",
        wrong_type_message="selected candidate is not a BOLA authorization candidate",
    )

    return BolaCandidateHandoff(
        candidate_id=candidate_id,
        source_label=_text(source_label, "source_label", 512),
        source_sha256=_text(
            triage_receipt.get("source_sha256"), "source_sha256", 64
        ),
        entry_point=_text(candidate.get("entry_point"), "entry_point", 2_128),
        json_pointer=_text(
            provenance.get("json_pointer"), "json_pointer", 2_048
        ),
    )


def select_authn_candidate(
    triage_receipt: dict[str, object], candidate_id: str
) -> AuthnCandidateHandoff:
    """Select a ranked authentication candidate without promoting its level."""
    candidate, provenance, source_label = _select_ranked_candidate(
        triage_receipt,
        candidate_id,
        expected_type="AUTHENTICATION_ENFORCEMENT_REVIEW",
        wrong_type_message=(
            "selected candidate is not an authentication enforcement candidate"
        ),
    )

    return AuthnCandidateHandoff(
        candidate_id=candidate_id,
        source_label=_text(source_label, "source_label", 512),
        source_sha256=_text(
            triage_receipt.get("source_sha256"), "source_sha256", 64
        ),
        entry_point=_text(candidate.get("entry_point"), "entry_point", 2_128),
        json_pointer=_text(
            provenance.get("json_pointer"), "json_pointer", 2_048
        ),
    )


def select_state_change_candidate(
    triage_receipt: dict[str, object], candidate_id: str
) -> StateChangeCandidateHandoff:
    """Select one ranked public PATCH candidate without promoting its level."""
    candidate, provenance, source_label = _select_ranked_candidate(
        triage_receipt,
        candidate_id,
        expected_type="PUBLIC_STATE_CHANGE_REVIEW",
        wrong_type_message="selected candidate is not a public state-change candidate",
    )
    return StateChangeCandidateHandoff(
        candidate_id=candidate_id,
        source_label=_text(source_label, "source_label", 512),
        source_sha256=_text(
            triage_receipt.get("source_sha256"), "source_sha256", 64
        ),
        entry_point=_text(candidate.get("entry_point"), "entry_point", 2_128),
        json_pointer=_text(
            provenance.get("json_pointer"), "json_pointer", 2_048
        ),
    )


def select_file_ingress_candidate(
    triage_receipt: dict[str, object], candidate_id: str
) -> FileIngressCandidateHandoff:
    """Select one ranked POST file-ingress candidate without promotion."""
    candidate, provenance, source_label = _select_ranked_candidate(
        triage_receipt,
        candidate_id,
        expected_type="FILE_INGRESS_REVIEW",
        wrong_type_message="selected candidate is not a file-ingress candidate",
    )
    return FileIngressCandidateHandoff(
        candidate_id=candidate_id,
        source_label=_text(source_label, "source_label", 512),
        source_sha256=_text(
            triage_receipt.get("source_sha256"), "source_sha256", 64
        ),
        entry_point=_text(candidate.get("entry_point"), "entry_point", 2_128),
        json_pointer=_text(provenance.get("json_pointer"), "json_pointer", 2_048),
    )
