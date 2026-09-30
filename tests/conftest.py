"""Pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.mock_data import MockDataProvider


@pytest.fixture
def mock_provider() -> MockDataProvider:
    """Return a MockDataProvider using the default mock_cluster.json."""
    return MockDataProvider()


@pytest.fixture
def mock_config() -> RuntimeConfig:
    """Return a RuntimeConfig configured for mock mode."""
    return RuntimeConfig(mock=True, namespace="frontend")


@pytest.fixture
def real_config() -> RuntimeConfig:
    """Return a RuntimeConfig configured for real mode."""
    return RuntimeConfig(mock=False, namespace="frontend")


@pytest.fixture
def mock_data_path() -> Path:
    """Return the path to the default mock data file."""
    from ovn_netdiag.mock_data import DEFAULT_MOCK_PATH
    return DEFAULT_MOCK_PATH
