"""ZombieSlayer: safeguard against zombie prompt injections for Claude-centered agents."""

from zombieslayer.types import (
    ContentItem,
    Finding,
    RiskCategory,
    ScanResult,
    SourceTrust,
    ScanMode,
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
    PersistenceTarget,
    PersistenceDecision,
)
from zombieslayer.detector import Detector
from zombieslayer.quarantine import QuarantineStore, QuarantineStoreProtocol
from zombieslayer.policy import Policy
from zombieslayer.scanner import IntakeScanner
from zombieslayer.persistence import PersistenceGuard
from zombieslayer.review import ReviewFlow
from zombieslayer.plugin import ZombieSlayer

__all__ = [
    "ContentItem",
    "Finding",
    "RiskCategory",
    "ScanResult",
    "SourceTrust",
    "ScanMode",
    "QuarantineRecord",
    "ReviewAction",
    "ReviewSummary",
    "PersistenceTarget",
    "PersistenceDecision",
    "Detector",
    "QuarantineStore",
    "QuarantineStoreProtocol",
    "Policy",
    "IntakeScanner",
    "PersistenceGuard",
    "ReviewFlow",
    "ZombieSlayer",
]
