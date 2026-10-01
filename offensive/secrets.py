"""Small secret wrapper shared by bounded offensive manifest boundaries."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field


class SecretValueError(ValueError):
    """A secret cannot be represented safely by the bounded wrapper."""


@dataclass(frozen=True)
class SecretValue:
    """A secret that redacts string representations and resists serialization."""

    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._value, str) or not self._value:
            raise SecretValueError("secret value must be non-empty text")
        if len(self._value) > 8_192:
            raise SecretValueError("secret value exceeds 8192 characters")
        if any(unicodedata.category(char).startswith("C") for char in self._value):
            raise SecretValueError("secret value contains control characters")

    def __str__(self) -> str:
        return "***"

    def __repr__(self) -> str:
        return "SecretValue(***)"

    def reveal(self) -> str:
        """Return the value only at a credential or plan construction boundary."""
        return self._value
