from __future__ import annotations

from zombieslayer.types import (
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
    ScanResult,
)


class QuarantineStore:
    """In-memory quarantine store keyed by ContentItem.id.

    Developers can swap this out via `ZombieSlayer(store=...)` to persist
    across sessions (e.g., for retro-scan of historical artifacts).
    """

    def __init__(self) -> None:
        self._records: dict[str, QuarantineRecord] = {}

    def add(self, result: ScanResult) -> QuarantineRecord:
        record = QuarantineRecord(result=result)
        self._records[result.item.id] = record
        return record

    def get(self, item_id: str) -> QuarantineRecord | None:
        return self._records.get(item_id)

    def all(self) -> list[QuarantineRecord]:
        return list(self._records.values())

    def pending(self) -> list[QuarantineRecord]:
        return [r for r in self._records.values() if r.action is None]

    def set_action(self, item_id: str, action: ReviewAction) -> QuarantineRecord:
        rec = self._records[item_id]
        rec.action = action
        return rec

    def summary(self) -> ReviewSummary:
        return ReviewSummary(records=list(self._records.values()))

    def clear(self) -> None:
        self._records.clear()
