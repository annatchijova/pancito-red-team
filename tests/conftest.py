"""Keep service tests isolated from any operator-configured cloud project."""

from __future__ import annotations

import os

import pytest


# service.app constructs its process-global case store during import. Set this
# before test modules import the app so a developer's GOOGLE_CLOUD_PROJECT can
# never make the suite read or write a real Firestore database.
os.environ["VIGIA_CASE_BACKEND"] = "memory"


@pytest.fixture(autouse=True)
def _keep_service_storage_in_memory(monkeypatch):
    """Prevent an individual test from exposing later tests to cloud storage."""
    monkeypatch.setenv("VIGIA_CASE_BACKEND", "memory")
