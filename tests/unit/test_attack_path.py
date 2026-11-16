from bluestrix.intelligence.attack_path import analyze_attack_paths
from bluestrix.intelligence.graph import AttackGraph, GraphEdge, GraphNode, visualization_dot


def test_path_finding_and_ranking():
    g = {
        "nodes": [
            {"id": "attacker", "kind": "role", "risk": 0.2},
            {"id": "proxy", "kind": "contract", "risk": 0.8},
            {"id": "oracle", "kind": "oracle", "risk": 0.9},
            {"id": "vault", "kind": "asset", "risk": 0.95},
        ],
        "edges": [
            {"source": "attacker", "target": "proxy", "relation": "calls", "weight": 0.7},
            {"source": "proxy", "target": "oracle", "relation": "feeds", "weight": 0.8},
            {"source": "oracle", "target": "vault", "relation": "exposes", "weight": 0.9},
            {"source": "proxy", "target": "vault", "relation": "calls", "weight": 0.5},
        ],
    }
    result = analyze_attack_paths(g, source="attacker", target="vault")
    assert result["path_count"] >= 1
    assert result["paths"][0]["priority"] == 1
    assert result["auto_actions"] == []
    assert "digraph" in result["visualization"]["content"]
    assert result["remediation_suggestions"]


def test_dot_export():
    graph = AttackGraph()
    graph.add_node(GraphNode("a", kind="contract", risk=0.5))
    graph.add_node(GraphNode("b", kind="asset", risk=0.9))
    graph.add_edge(GraphEdge("a", "b", relation="exposes"))
    dot = visualization_dot(graph)
    assert '"a" -> "b"' in dot
