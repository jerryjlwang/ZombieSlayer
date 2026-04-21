from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class HandoffGraph:
    """Tracks the lineage of derivations across agents/artifacts (PRD §12 post-MVP).

    Each edge says "artifact B was derived from source A". Operators can trace
    whether a tainted source reached a downstream summary, memory store, or
    handoff by walking descendants; the render method produces a compact
    indent-based view for end-of-task review.
    """

    # node_id -> human label (e.g. URL, "summary:task-123", "memory:abc")
    labels: dict[str, str] = field(default_factory=dict)
    # parent -> set of children
    _edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # child -> set of parents (for reverse lookup)
    _rev: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # nodes flagged as tainted (quarantined source, blocked write, etc.)
    tainted: set[str] = field(default_factory=set)

    def add_node(self, node_id: str, label: str | None = None) -> None:
        self.labels.setdefault(node_id, label or node_id)

    def add_edge(self, parent: str, child: str) -> None:
        self.add_node(parent)
        self.add_node(child)
        self._edges[parent].add(child)
        self._rev[child].add(parent)

    def mark_tainted(self, node_id: str) -> None:
        self.add_node(node_id)
        self.tainted.add(node_id)

    def descendants(self, node_id: str) -> set[str]:
        """Every node reachable downstream of `node_id` (excluding itself)."""
        out: set[str] = set()
        stack = list(self._edges.get(node_id, ()))
        while stack:
            cur = stack.pop()
            if cur in out:
                continue
            out.add(cur)
            stack.extend(self._edges.get(cur, ()))
        return out

    def tainted_reach(self) -> set[str]:
        """All nodes reachable from any tainted source."""
        out: set[str] = set()
        for src in self.tainted:
            out.add(src)
            out |= self.descendants(src)
        return out

    def roots(self) -> list[str]:
        return sorted(n for n in self.labels if not self._rev.get(n))

    def render(self) -> str:
        """Indent-tree view marking tainted nodes and tainted-reachable ones."""
        if not self.labels:
            return "ZombieSlayer \u2014 no handoff edges recorded."

        reach = self.tainted_reach()
        lines: list[str] = ["ZombieSlayer \u2014 handoff topology"]
        seen: set[str] = set()

        def walk(node: str, depth: int) -> None:
            if node in seen:
                lines.append("  " * (depth + 1) + f"\u2514 {self.labels[node]} (cycle)")
                return
            seen.add(node)
            if node in self.tainted:
                marker = "[\u2620 tainted]"
            elif node in reach:
                marker = "[! tainted-reach]"
            else:
                marker = ""
            prefix = "  " * depth + ("\u2514 " if depth else "")
            lines.append(f"{prefix}{self.labels[node]} {marker}".rstrip())
            for child in sorted(self._edges.get(node, ())):
                walk(child, depth + 1)

        for root in self.roots():
            walk(root, 0)
        return "\n".join(lines)
