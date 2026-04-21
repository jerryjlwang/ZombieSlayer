"""ZombieSlayer: safeguard against zombie prompt injections for Claude-centered agents."""

from zombieslayer.admin import AdminPolicy
from zombieslayer.audit import AuditLog
from zombieslayer.detector import Detector
from zombieslayer.persistence import PersistenceGuard
from zombieslayer.plugin import DeferredAction, ZombieSlayer
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.remediation import Recommendation, recommend
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
    "AuditLog",
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
    "QuarantineRecord",
    "QuarantineStore",
    "Recommendation",
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
