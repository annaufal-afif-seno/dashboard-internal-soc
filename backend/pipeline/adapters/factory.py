"""
Adapter Factory - Central Config-Driven Port Switcher
=====================================================
Allows switching between Mock and Live adapters with zero changes to core pipeline logic.
Controlled via environment variables:
- WAZUH_ADAPTER_MODE: 'mock' (default) or 'live'
- MISP_ADAPTER_MODE: 'mock' (default) or 'live'
- IRIS_ADAPTER_MODE: 'mock' (default) or 'live'
"""

import os
import logging
from typing import Optional

from pipeline.adapters.base import (
    WazuhAdapterInterface, MISPAdapterInterface, IRISAdapterInterface
)
from pipeline.adapters.wazuh_adapter import MockWazuhAdapter, LiveWazuhAdapter
from pipeline.adapters.misp_adapter import MockMispAdapter, LiveMispAdapter
from pipeline.adapters.iris_adapter import MockIrisAdapter, LiveIrisAdapter
from pipeline.adapters.vector_adapter import MockVectorAdapter, RealVectorAdapter
from pipeline.adapters.base import VectorAdapterInterface


def get_vector_adapter(mode: Optional[str] = None) -> VectorAdapterInterface:
    """Return active Vector adapter instance."""
    resolved_mode = (mode or os.getenv("VECTOR_ADAPTER_MODE", "mock")).lower()
    if resolved_mode in ("live", "real"):
        logger.info("[AdapterFactory] Initializing REAL Vector Adapter")
        return RealVectorAdapter()
    logger.info("[AdapterFactory] Initializing MOCK Vector Adapter")
    return MockVectorAdapter()

logger = logging.getLogger(__name__)


def get_wazuh_adapter(mode: Optional[str] = None) -> WazuhAdapterInterface:
    """Return active Wazuh adapter instance."""
    resolved_mode = (mode or os.getenv("WAZUH_ADAPTER_MODE", "mock")).lower()
    if resolved_mode == "live":
        logger.info("[AdapterFactory] Initializing LIVE Wazuh Adapter")
        return LiveWazuhAdapter()
    logger.info("[AdapterFactory] Initializing MOCK Wazuh Adapter")
    return MockWazuhAdapter()


def get_misp_adapter(mode: Optional[str] = None) -> MISPAdapterInterface:
    """Return active MISP adapter instance."""
    resolved_mode = (mode or os.getenv("MISP_ADAPTER_MODE", "mock")).lower()
    if resolved_mode == "live":
        logger.info("[AdapterFactory] Initializing LIVE MISP Adapter")
        return LiveMispAdapter()
    logger.info("[AdapterFactory] Initializing MOCK MISP Adapter")
    return MockMispAdapter()


def get_iris_adapter(mode: Optional[str] = None) -> IRISAdapterInterface:
    """Return active DFIR-IRIS adapter instance."""
    resolved_mode = (mode or os.getenv("IRIS_ADAPTER_MODE", "mock")).lower()
    if resolved_mode == "live":
        logger.info("[AdapterFactory] Initializing LIVE DFIR-IRIS Adapter")
        return LiveIrisAdapter()
    logger.info("[AdapterFactory] Initializing MOCK DFIR-IRIS Adapter")
    return MockIrisAdapter()
