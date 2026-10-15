"""
Wazuh ASOC Multi-Stage Alert Pipeline Package
=============================================
Modular, high-throughput security event processing architecture:

- Stage 1 (pipeline.ingest):
    AlertStreamReader, CanonicalAssetResolver, classify_event_archetype,
    extract_os_platform, route_event_track.
- Stage 2 (pipeline.deduplicate):
    SlidingWindowAggregator, AggregatedWindow, calculate_canonical_dedup_key.
- Stage 3 (pipeline.governance):
    SuppressionGovernanceManager, NeverSuppressGuard.
- Stage 4 (pipeline.score):
    RiskScorer, CompositeRiskEvaluator.
- Stage 5 (pipeline.correlate):
    CorrelationEngine, AttackStageClassifier.
- Data Layer (pipeline.database):
    DatabaseManager.
- API Backend (pipeline.api):
    FastAPI REST application.
"""

from pipeline.models import (
    CommonEventModel,
    AggregatedAlertDB,
    CumulativeAlertDB,
    AggregateEvidenceMappingDB,
    WazuhRawAlert,
)
from pipeline.ingest import (
    AlertStreamReader,
    CanonicalAssetResolver,
    classify_event_archetype,
    extract_os_platform,
    route_event_track,
)
from pipeline.deduplicate import (
    SlidingWindowAggregator,
    AggregatedWindow,
    calculate_canonical_dedup_key,
)
from pipeline.governance import (
    SuppressionGovernanceManager,
)
from pipeline.score import (
    RiskScorer,
    PriorityEngine,
    SLA_MATRIX_MINUTES,
)
from pipeline.correlate import (
    CorrelationEngine,
)
from pipeline.database import (
    DatabaseManager,
)

__version__ = "2.1.0"

__all__ = [
    "CommonEventModel",
    "AggregatedAlertDB",
    "CumulativeAlertDB",
    "AggregateEvidenceMappingDB",
    "WazuhRawAlert",
    "AlertStreamReader",
    "CanonicalAssetResolver",
    "classify_event_archetype",
    "extract_os_platform",
    "route_event_track",
    "SlidingWindowAggregator",
    "AggregatedWindow",
    "calculate_canonical_dedup_key",
    "SuppressionGovernanceManager",
    "RiskScorer",
    "CorrelationEngine",
    "DatabaseManager",
]


