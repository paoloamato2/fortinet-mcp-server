"""Shared test fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_fortios_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every FORTIOS_* variable so tests never inherit a real .env."""
    for key in list(os.environ):
        if key.startswith("FORTIOS_"):
            monkeypatch.delenv(key, raising=False)
