from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from zombieslayer.types import (
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
    ScanResult,
)


class QuarantineStore:
    """In-memory quarantine store keyed by ContentItem.id.

    Developers can swap this out via `ZombieSlayer(store=...)` to persist
    across sessions (e.g., for retro-scan of historical artifacts). See
    `JSONFileQuarantineStore` for the durable variant.
    """

    def __init__(self) -> None:
        self._records: dict[str, QuarantineRecord] = {}

    def add(self, result: ScanResult) -> QuarantineRecord:
        record = QuarantineRecord(result=result)
        self._records[result.item.id] = record
        self._on_change()
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
        self._on_change()
        return rec

    def summary(self) -> ReviewSummary:
        return ReviewSummary(records=list(self._records.values()))

    def clear(self) -> None:
        self._records.clear()
        self._on_change()

    # ---- subclass hook ------------------------------------------------
    def _on_change(self) -> None:
        """Subclasses override to persist after each mutation."""
        return None


class JSONFileQuarantineStore(QuarantineStore):
    """File-backed quarantine store (issue #6 §9).

    Persists to a single JSON file with `os.replace` for atomic writes —
    crash-safe at the granularity of one mutation. Loads existing records
    on construction. Stdlib-only.

    Suitable for hundreds of records per session. For higher volumes a
    SQLite backend can subclass `QuarantineStore` with the same surface.
    """

    def __init__(self, path: Path | str) -> None:
        super().__init__()
        self.path = Path(path)
        self._loading = True
        try:
            self._load()
        finally:
            self._loading = False

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text() or "{}")
        except (OSError, ValueError):
            return
        records = payload.get("records") or []
        for raw in records:
            try:
                rec = QuarantineRecord.from_dict(raw)
            except (KeyError, ValueError, TypeError):
                continue
            self._records[rec.result.item.id] = rec

    def _on_change(self) -> None:
        if self._loading:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "records": [rec.to_dict() for rec in self._records.values()],
        }
        # Atomic write: tmp file in same dir, then os.replace.
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=str(self.path.parent),
        )
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp_name, self.path)
        except Exception:
            # Best-effort cleanup; original file (if any) is untouched.
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def reload(self) -> None:
        """Re-read the on-disk file (for processes sharing the store)."""
        self._records.clear()
        self._loading = True
        try:
            self._load()
        finally:
            self._loading = False
