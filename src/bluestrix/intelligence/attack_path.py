"""Attack path analysis: rank paths and suggest human mitigations (no auto-actions)."""

from __future__ import annotations

from typing import Any, Optional

from bluestrix.intelligence.graph import AttackGraph, build_graph_from_payload, visualization_dot
from bluestrix.intelligence.risk import remediation_suggestions, RiskFactors


def analyze_attack_paths(
    graph_payload: dict[str, Any],
    *,
    source: str,
    target: str,
    max_depth: int = 8,
    max_paths: int = 20,
) -> dict[str, Any]:
    graph = build_graph_from_payload(graph_payload)
    raw_paths = graph.shortest_paths(source, target, max_depth=max_depth)
    ranked: list[dict[str, Any]] = []
    for path in raw_paths:
        score = graph.path_score(path)
        ranked.append(
            {
                "path": path,
                "score": score,
                "hops": len(path) - 1,
                "nodes": [
                    {
                        "id": nid,
                        "kind": graph.nodes[nid].kind,
                        "label": graph.nodes[nid].label,
                        "risk": graph.nodes[nid].risk,
                    }
                    for nid in path
                    if nid in graph.nodes
                ],
            }
        )
    ranked.sort(key=lambda p: (-p["score"], p["hops"]))
    ranked = ranked[:max_paths]
    for i, row in enumerate(ranked, start=1):
        row["priority"] = i

    suggestions = path_remediation_suggestions(graph, ranked[:3])
    return {
        "source": source,
        "target": target,
        "path_count": len(ranked),
        "paths": ranked,
        "graph": graph.to_dict(),
        "visualization": {"format": "dot", "content": visualization_dot(graph)},
        "remediation_suggestions": suggestions,
        "auto_actions": [],
        "disclaimer": "BlueStrix ranks exposure paths for defenders only; no exploit execution or auto-remediation.",
    }


def path_remediation_suggestions(
    graph: AttackGraph, top_paths: list[dict[str, Any]]
) -> list[str]:
    tips: list[str] = []
    kinds = set()
    for p in top_paths:
        for n in p.get("nodes") or []:
            kinds.add(str(n.get("kind") or ""))
    if "oracle" in kinds:
        tips.append("Harden oracle usage on critical path nodes (human-gated pause only).")
    if "bridge" in kinds:
        tips.append("Review bridge/IBC hop; coordinate operators — do not auto-transfer.")
    if "role" in kinds or "contract" in kinds:
        tips.append("Audit privileged roles and upgradeability along the path.")
    if not tips:
        tips.append("Document path evidence and open a remediation proposal for human approval.")
    # Merge generic factor-based tips at medium aggregate risk
    avg_risk = 0.0
    count = 0
    for p in top_paths:
        for n in p.get("nodes") or []:
            avg_risk += float(n.get("risk") or 0)
            count += 1
    if count:
        avg_risk /= count
        tips.extend(
            remediation_suggestions(
                RiskFactors(
                    technical_severity=avg_risk,
                    exploitability=avg_risk,
                    asset_exposure=avg_risk,
                ),
                avg_risk,
            )[:2]
        )
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for t in tips:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
