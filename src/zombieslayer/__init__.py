"""ZombieSlayer: safeguard against zombie prompt injections for Claude-centered agents."""

from zombieslayer.admin import AdminPolicy, AllowDenyEntry
from zombieslayer.audit import AuditLog
from zombieslayer.behavior import BehaviorAlert, BehaviorMonitor
from zombieslayer.detector import Detector
from zombieslayer.persistence import PersistenceGuard
from zombieslayer.plugin import (
    DeferredAction,
    RollbackEntry,
    RollbackPlan,
    ZombieSlayer,
)
from zombieslayer.policy import Policy
from zombieslayer.quarantine import JSONFileQuarantineStore, QuarantineStore
from zombieslayer.remediation import Recommendation, recommend
from zombieslayer.replay import ReplayTracker
from zombieslayer.review import ReviewFlow
from zombieslayer.scanner import IntakeScanner
from zombieslayer.topology import HandoffGraph
from zombieslayer.types import (
    ContentItem,
    Finding,
    PersistenceDecision,
    PersistenceTarget,
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
    RiskCategory,
    ScanMode,
    ScanResult,
    SourceTrust,
)

__all__ = [
    "AdminPolicy",
    "AllowDenyEntry",
    "AuditLog",
    "BehaviorAlert",
    "BehaviorMonitor",
    "ContentItem",
    "DeferredAction",
    "Detector",
    "Finding",
    "HandoffGraph",
    "IntakeScanner",
    "PersistenceDecision",
    "PersistenceGuard",
    "PersistenceTarget",
    "Policy",
    "JSONFileQuarantineStore",
    "QuarantineRecord",
    "QuarantineStore",
    "Recommendation",
    "ReplayTracker",
    "RollbackEntry",
    "RollbackPlan",
    "ReviewAction",
    "ReviewFlow",
    "ReviewSummary",
    "RiskCategory",
    "ScanMode",
    "ScanResult",
    "SourceTrust",
    "ZombieSlayer",
    "recommend",
]
