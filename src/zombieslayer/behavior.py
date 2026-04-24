from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from zombieslayer.types import ScanResult


@dataclass(frozen=True)
class BehaviorAlert:
    """An operator-facing signal about scanning behavior (issue #2 §5)."""
    source: str
    kind: str      # 'rate' | 'probing'
    detail: str
    severity: float  # 0.0 - 1.0


@dataclass
class BehaviorMonitor:
    """Track scan patterns per source to catch threshold probing / fuzzing.

    Does **not** block — this is signal for operators. `ZombieSlayer` fires
    `on_behavior_alert` callbacks so integrators can wire their own throttle
    or notifier.
    """

    window_seconds: float = 60.0
    rate_threshold: int = 20
    probe_epsilon: float = 0.05
    probe_threshold: int = 5
    _seen: dict[str, deque[tuple[float, float, float]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    _alerts: list[BehaviorAlert] = field(default_factory=list)

    def record(
        self,
        result: ScanResult,
        *,
        threshold: float,
        now: float | None = None,
    ) -> list[BehaviorAlert]:
        """Record a scan outcome and return any new alerts it triggered."""
        t = time.monotonic() if now is None else now
        source = result.item.source
        buf = self._seen[source]
        buf.append((t, result.score, threshold))
        cutoff = t - self.window_seconds
        while buf and buf[0][0] < cutoff:
            buf.popleft()

        new: list[BehaviorAlert] = []
        if len(buf) >= self.rate_threshold:
            new.append(BehaviorAlert(
                source=source, kind="rate",
                detail=(
                    f"{len(buf)} scans in last {int(self.window_seconds)}s "
                    f"(threshold {self.rate_threshold})"
                ),
                severity=min(0.4 + 0.02 * (len(buf) - self.rate_threshold), 0.95),
            ))

        probes = sum(
            1 for (_ts, score, thr) in buf
            if abs(score - thr) <= self.probe_epsilon
        )
        if probes >= self.probe_threshold:
            new.append(BehaviorAlert(
                source=source, kind="probing",
                detail=(
                    f"{probes} scans within \u00b1{self.probe_epsilon:.2f} of quarantine "
                    f"threshold (likely fuzzing)"
                ),
                severity=min(0.5 + 0.05 * (probes - self.probe_threshold), 0.95),
            ))

        self._alerts.extend(new)
        return new

    def alerts(self) -> list[BehaviorAlert]:
        return list(self._alerts)

    def clear(self) -> None:
        self._seen.clear()
        self._alerts.clear()
