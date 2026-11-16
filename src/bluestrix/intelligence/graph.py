"""Lightweight directed graph for attack-path analysis (pure Python; NetworkX optional)."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


@dataclass
class GraphNode:
    node_id: str
    kind: str = "asset"  # asset | contract | role | oracle | bridge | finding
    label: str = ""
    risk: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str = "related"  # calls | owns | upgrades | feeds | bridges | exposes
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


class AttackGraph:
    """In-memory digraph. Not a network exploit engine — defensive path ranking only."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.adj: dict[str, list[GraphEdge]] = defaultdict(list)
        self._rev: dict[str, list[GraphEdge]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError("edge endpoints must exist as nodes")
        self.adj[edge.source].append(edge)
        self._rev[edge.target].append(edge)

    def successors(self, node_id: str) -> list[GraphEdge]:
        return list(self.adj.get(node_id, []))

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.node_id,
                    "kind": n.kind,
                    "label": n.label or n.node_id,
                    "risk": n.risk,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    "weight": e.weight,
                }
                for edges in self.adj.values()
                for e in edges
            ],
        }

    def shortest_paths(
        self, source: str, target: str, *, max_depth: int = 8
    ) -> list[list[str]]:
        """BFS paths source→target (limited)."""
        if source not in self.nodes or target not in self.nodes:
            return []
        paths: list[list[str]] = []
        q: deque[list[str]] = deque([[source]])
        while q:
            path = q.popleft()
            if len(path) > max_depth:
                continue
            node = path[-1]
            if node == target and len(path) > 1:
                paths.append(path)
                continue
            for edge in self.adj.get(node, []):
                if edge.target in path:
                    continue
                q.append(path + [edge.target])
        return paths

    def path_score(self, path: list[str]) -> float:
        if len(path) < 2:
            return 0.0
        node_risk = sum(self.nodes[n].risk for n in path if n in self.nodes) / len(path)
        edge_w = 0.0
        count = 0
        for a, b in zip(path, path[1:]):
            for e in self.adj.get(a, []):
                if e.target == b:
                    edge_w += e.weight
                    count += 1
                    break
        edge_avg = (edge_w / count) if count else 1.0
        # Higher risk nodes + stronger edges → higher path priority; shorter slightly preferred
        length_penalty = 1.0 / max(len(path) - 1, 1)
        return round(min(1.0, 0.6 * node_risk + 0.3 * min(edge_avg, 1.0) + 0.1 * length_penalty), 4)


def build_graph_from_payload(payload: dict[str, Any]) -> AttackGraph:
    g = AttackGraph()
    for n in payload.get("nodes") or []:
        g.add_node(
            GraphNode(
                node_id=str(n["id"]),
                kind=str(n.get("kind") or "asset"),
                label=str(n.get("label") or n["id"]),
                risk=float(n.get("risk") or 0.0),
                metadata=dict(n.get("metadata") or {}),
            )
        )
    for e in payload.get("edges") or []:
        g.add_edge(
            GraphEdge(
                source=str(e["source"]),
                target=str(e["target"]),
                relation=str(e.get("relation") or "related"),
                weight=float(e.get("weight") or 1.0),
                metadata=dict(e.get("metadata") or {}),
            )
        )
    return g


def visualization_dot(graph: AttackGraph) -> str:
    """Graphviz DOT for path visualization (render externally)."""
    lines = ["digraph BlueStrixAttackPath {", "  rankdir=LR;"]
    for n in graph.nodes.values():
        label = f"{n.label}\\n{n.kind}\\nrisk={n.risk:.2f}"
        lines.append(f'  "{n.node_id}" [label="{label}"];')
    for edges in graph.adj.values():
        for e in edges:
            lines.append(
                f'  "{e.source}" -> "{e.target}" [label="{e.relation}"];'
            )
    lines.append("}")
    return "\n".join(lines)
