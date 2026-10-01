"""Fail-closed reading for bounded local artifacts used by offensive CLIs."""

from __future__ import annotations

import errno
import os
import stat
import unicodedata
from pathlib import Path


class LocalArtifactError(ValueError):
    """A local artifact cannot be read under the declared boundary."""


def _label(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise LocalArtifactError("artifact label must be non-empty text")
    if len(value) > 128:
        raise LocalArtifactError("artifact label exceeds 128 characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise LocalArtifactError("artifact label contains control characters")
    return value


def read_bounded_regular_file(
    path: str | Path, *, maximum_bytes: int, label: str
) -> bytes:
    """Read one regular file through the descriptor that passed validation."""
    artifact_label = _label(label)
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int):
        raise LocalArtifactError("maximum_bytes must be an integer")
    if not 1 <= maximum_bytes <= 16_777_216:
        raise LocalArtifactError("maximum_bytes must be between 1 and 16777216")
    artifact_path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise LocalArtifactError("secure no-follow file opening is unavailable")
    flags |= no_follow
    descriptor: int | None = None
    try:
        descriptor = os.open(artifact_path, flags)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LocalArtifactError(
                f"{artifact_label} path must not be a symlink"
            ) from exc
        raise LocalArtifactError(f"cannot inspect {artifact_label}: {exc}") from exc
    try:
        if not stat.S_ISREG(metadata.st_mode):
            raise LocalArtifactError(f"{artifact_label} path must be a regular file")
        if metadata.st_size > maximum_bytes:
            raise LocalArtifactError(
                f"{artifact_label} exceeds {maximum_bytes} bytes"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise LocalArtifactError(f"cannot read {artifact_label}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > maximum_bytes:
        raise LocalArtifactError(f"{artifact_label} exceeds {maximum_bytes} bytes")
    return raw
