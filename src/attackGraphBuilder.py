#!/usr/bin/env python3
"""
HUNTЕРТRACE v3 — ATTACK GRAPH BUILDER
=======================================

Builds an interactive attack infrastructure graph from campaign correlation
results. Outputs two formats:

  1. NetworkX DiGraph — for programmatic analysis
  2. Self-contained HTML/D3.js — interactive visualization, zero dependencies

Node types:
  actor        — Threat actor (one per cluster)
  email        — Individual phishing email
  ip_vpn       — VPN exit node IP
  ip_real      — Real attacker IP (webmail-leaked)
  asn          — Autonomous System Number
  vpn_provider — VPN service (NordVPN, etc.)
  webmail      — Webmail provider (Gmail, Yahoo, etc.)
  timezone     — Timezone region

Edge types:
  sent_via       — actor → email
  used_vpn_ip    — email → ip_vpn
  leaked_real_ip — email → ip_real
  belongs_to_asn — ip → asn
  used_provider  — ip_vpn → vpn_provider
  used_webmail   — email → webmail
  located_in_tz  — actor → timezone

USAGE:
    from attackGraphBuilder import AttackGraphBuilder

    builder = AttackGraphBuilder()
    graph   = builder.build(correlation_report, actor_profiles)

    # Save interactive HTML
    builder.export_html(graph, "huntертrace_graph.html")

    # Save GraphML for Gephi / Maltego
    builder.export_graphml(graph, "huntертrace_graph.graphml")
"""

import json
import html as html_module
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# NODE / EDGE COLOUR SCHEME
# ─────────────────────────────────────────────────────────────────────────────

NODE_COLORS = {
    "actor":        "#E63946",   # Red — attacker
    "email":        "#F4A261",   # Orange — email
    "ip_vpn":       "#457B9D",   # Blue — VPN IP
    "ip_real":      "#E63946",   # Red — real IP (dangerous)
    "asn":          "#1D3557",   # Dark blue — ASN
    "vpn_provider": "#2A9D8F",   # Teal — VPN service
    "webmail":      "#E9C46A",   # Yellow — webmail
    "timezone":     "#6A4C93",   # Purple — timezone
}

NODE_SHAPES = {
    "actor":        "diamond",
    "email":        "rect",
    "ip_vpn":       "circle",
    "ip_real":      "circle",
    "asn":          "triangle",
    "vpn_provider": "circle",
    "webmail":      "circle",
    "timezone":     "ellipse",
}

EDGE_COLORS = {
    "sent_via":         "#F4A261",
    "used_vpn_ip":      "#457B9D",
    "leaked_real_ip":   "#E63946",
    "belongs_to_asn":   "#1D3557",
    "used_provider":    "#2A9D8F",
    "used_webmail":     "#E9C46A",
    "located_in_tz":    "#6A4C93",
    "same_actor":       "#E63946",
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    id:       str
    label:    str
    type:     str
    color:    str
    size:     int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source:       str
    target:       str
    relationship: str
    color:        str
    weight:       float = 1.0
    label:        str   = ""


@dataclass
class AttackGraph:
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any] = field(default_factory=dict)
    nx_graph: Any = None     # networkx DiGraph if available

    def node_count(self) -> int: return len(self.nodes)
    def edge_count(self) -> int: return len(self.edges)


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────

class AttackGraphBuilder:

    def build(self, correlation_report, actor_profiles: Dict = None) -> AttackGraph:
        """
        Build attack graph from CorrelationReport + optional ActorTTPProfile map.
        actor_profiles: {actor_id: ActorTTPProfile}
        """
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge]      = []
        profiles = actor_profiles or {}

        def add_node(node_id: str, label: str, ntype: str,
                     size: int = 20, meta: dict = None):
            if node_id not in nodes:
                nodes[node_id] = GraphNode(
                    id       = node_id,
                    label    = label,
                    type     = ntype,
                    color    = NODE_COLORS.get(ntype, "#888888"),
                    size     = size,
                    metadata = meta or {},
                )

        def add_edge(src: str, tgt: str, rel: str, weight: float = 1.0, lbl: str = ""):
            edges.append(GraphEdge(
                source       = src,
                target       = tgt,
                relationship = rel,
                color        = EDGE_COLORS.get(rel, "#999999"),
                weight       = weight,
                label        = lbl,
            ))

        # ── Actor nodes ───────────────────────────────────────────────────
        for cluster in correlation_report.actor_clusters:
            aid = cluster.actor_id
            prof = profiles.get(aid)

            actor_label = (prof.actor_label if prof else
                           f"{aid}\n{cluster.likely_country or '?'}")
            meta = {
                "campaign_count":  cluster.campaign_count,
                "confidence":      f"{cluster.confidence:.0%}",
                "likely_country":  cluster.likely_country,
                "first_seen":      cluster.first_seen,
                "last_seen":       cluster.last_seen,
            }
            if prof:
                meta["sophistication"] = prof.sophistication
                meta["motivation"]     = prof.likely_motivation
                meta["opsec_score"]    = prof.infrastructure.opsec_score

            add_node(aid, actor_label, "actor", size=45, meta=meta)

            # Timezone node
            if cluster.consensus_timezone:
                tz_id = f"TZ:{cluster.consensus_timezone}"
                add_node(tz_id, cluster.consensus_timezone, "timezone", size=18)
                add_edge(aid, tz_id, "located_in_tz", 0.8, "located in")

            # ── Email nodes ───────────────────────────────────────────────
            for fp in cluster.fingerprints:
                eid = f"email:{fp.email_file}"
                email_label = (fp.email_subject[:35] + "…"
                               if len(fp.email_subject) > 35 else fp.email_subject)
                add_node(eid, email_label, "email", size=22, meta={
                    "from":     fp.email_from,
                    "subject":  fp.email_subject,
                    "date":     str(fp.email_date or ""),
                    "tz":       fp.timezone_offset,
                })
                add_edge(aid, eid, "sent_via", 1.0, "sent")

                # VPN IP node
                if fp.origin_ip:
                    vpn_id = f"vpn:{fp.origin_ip}"
                    vpn_label = f"{fp.origin_ip}\n({fp.vpn_provider or 'VPN'})"
                    add_node(vpn_id, vpn_label, "ip_vpn", size=20, meta={
                        "vpn_provider": fp.vpn_provider,
                        "ip":           fp.origin_ip,
                    })
                    add_edge(eid, vpn_id, "used_vpn_ip", 0.9, "routed via")

                    # VPN provider node
                    if fp.vpn_provider:
                        prov_id = f"provider:{fp.vpn_provider}"
                        add_node(prov_id, fp.vpn_provider, "vpn_provider", size=28)
                        add_edge(vpn_id, prov_id, "used_provider", 0.8, "service")

                # Real IP node (highest value — webmail leaked)
                if fp.real_ip and fp.real_ip != fp.origin_ip:
                    rip_id = f"realip:{fp.real_ip}"
                    add_node(rip_id, f"REAL IP\n{fp.real_ip}", "ip_real", size=32, meta={
                        "ip":     fp.real_ip,
                        "source": fp.real_ip_source,
                    })
                    add_edge(eid, rip_id, "leaked_real_ip", 1.0, "LEAKED")
                    add_edge(aid, rip_id, "leaked_real_ip", 1.0, "true origin")

                # Webmail node
                if fp.webmail_provider:
                    wm_id = f"webmail:{fp.webmail_provider}"
                    add_node(wm_id, fp.webmail_provider, "webmail", size=24)
                    add_edge(eid, wm_id, "used_webmail", 0.85, "sent via")

        # ── Singleton emails ──────────────────────────────────────────────
        all_fps = {}
        for cluster in correlation_report.actor_clusters:
            for fp in cluster.fingerprints:
                all_fps[fp.email_file] = fp

        for singleton_file in correlation_report.singleton_emails:
            fp = all_fps.get(singleton_file)
            if not fp:
                continue
            eid = f"email:{singleton_file}"
            add_node(eid, fp.email_subject[:30], "email", size=16, meta={
                "note": "unattributed — no matching peer",
            })

        # ── Cross-actor shared infrastructure edges ───────────────────────
        # If two actors used the same VPN provider, show shared infra link
        vpn_prov_actors: Dict[str, List[str]] = {}
        for cluster in correlation_report.actor_clusters:
            for fp in cluster.fingerprints:
                if fp.vpn_provider:
                    vpn_prov_actors.setdefault(fp.vpn_provider, [])
                    if cluster.actor_id not in vpn_prov_actors[fp.vpn_provider]:
                        vpn_prov_actors[fp.vpn_provider].append(cluster.actor_id)

        for prov, actor_list in vpn_prov_actors.items():
            if len(actor_list) > 1:
                for i in range(len(actor_list) - 1):
                    add_edge(
                        actor_list[i], actor_list[i+1],
                        "same_actor", 0.3,
                        f"shared VPN: {prov}"
                    )

        # ── Build NetworkX graph ──────────────────────────────────────────
        nx_graph = None
        if NX_AVAILABLE:
            nx_graph = nx.DiGraph()
            for n in nodes.values():
                nx_graph.add_node(n.id, label=n.label, type=n.type,
                                  color=n.color, size=n.size, **n.metadata)
            for e in edges:
                nx_graph.add_edge(e.source, e.target,
                                  relationship=e.relationship,
                                  weight=e.weight, label=e.label)

        return AttackGraph(
            nodes    = list(nodes.values()),
            edges    = edges,
            metadata = {
                "generated_at":   datetime.now().isoformat(),
                "total_actors":   correlation_report.total_actors,
                "total_emails":   correlation_report.total_emails,
                "node_count":     len(nodes),
                "edge_count":     len(edges),
            },
            nx_graph = nx_graph,
        )

    # ─────────────────────────────────────────────────────────────────────
    # EXPORT: Self-contained HTML / D3.js
    # ─────────────────────────────────────────────────────────────────────
    def export_html(self, graph: AttackGraph, output_path: str) -> str:

      nodes_json = json.dumps([
          {
              "id": n.id,
              "label": n.label,
              "type": n.type,
              "color": n.color,
              "size": n.size,
              "meta": {k: str(v) for k, v in n.metadata.items()},
          }
          for n in graph.nodes
      ], indent=2)

      edges_json = json.dumps([
          {
              "source": e.source,
              "target": e.target,
              "rel": e.relationship,
              "color": e.color,
              "weight": e.weight,
              "label": e.label,
          }
          for e in graph.edges
      ], indent=2)

      meta = graph.metadata

      legend_html = "".join(
          f'<div class="legend-item">'
          f'<div class="legend-dot" style="background:{color}"></div>'
          f'<span class="legend-label">{ntype}</span>'
          f'</div>'
          for ntype, color in NODE_COLORS.items()
      )

      template = Path("./src/html/attackerGraph.html").read_text(encoding="utf-8")
      html = (
          template
          .replace("__NODES_JSON__", nodes_json)
          .replace("__EDGES_JSON__", edges_json)
          .replace("{{TOTAL_ACTORS}}", str(meta.get("total_actors", 0)))
          .replace("{{TOTAL_EMAILS}}", str(meta.get("total_emails", 0)))
          .replace("{{TOTAL_NODES}}", str(meta.get("node_count", 0)))
          .replace("{{TOTAL_EDGES}}", str(meta.get("edge_count", 0)))
          .replace("{{GENERATED_AT}}", meta.get("generated_at", "")[:16])
          .replace("{{LEGEND_ITEMS}}", legend_html)
      )
      
      Path(output_path).write_text(html, encoding="utf-8")
      return str(Path(output_path).resolve())
    # ─────────────────────────────────────────────────────────────────────
    # EXPORT: GraphML (Gephi / Maltego compatible)
    # ─────────────────────────────────────────────────────────────────────

    def export_graphml(self, graph: AttackGraph, output_path: str) -> str:
        """Export as GraphML for Gephi, Maltego, or other graph tools."""
        if not NX_AVAILABLE or graph.nx_graph is None:
            raise RuntimeError("networkx required for GraphML export")
        nx.write_graphml(graph.nx_graph, output_path)
        return output_path

    # ─────────────────────────────────────────────────────────────────────
    # EXPORT: JSON (for external tools / API)
    # ─────────────────────────────────────────────────────────────────────

    def export_json(self, graph: AttackGraph, output_path: str) -> str:
        data = {
            "metadata": graph.metadata,
            "nodes": [
                {"id": n.id, "label": n.label, "type": n.type,
                 "color": n.color, "size": n.size, "metadata": n.metadata}
                for n in graph.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target,
                 "relationship": e.relationship, "weight": e.weight, "label": e.label}
                for e in graph.edges
            ],
        }
        Path(output_path).write_text(json.dumps(data, indent=2))
        return output_path

    # ─────────────────────────────────────────────────────────────────────
    # STATS
    # ─────────────────────────────────────────────────────────────────────

    def print_stats(self, graph: AttackGraph):
        from collections import Counter
        type_counts = Counter(n.type for n in graph.nodes)
        rel_counts  = Counter(e.relationship for e in graph.edges)

        print("[v3] Attack Graph Statistics")
        print(f"  Total nodes: {graph.node_count()}")
        for t, c in type_counts.most_common():
            print(f"    {t:<18} {c}")
        print(f"  Total edges: {graph.edge_count()}")
        for r, c in rel_counts.most_common():
            print(f"    {r:<22} {c}")

        if NX_AVAILABLE and graph.nx_graph:
            G = graph.nx_graph
            print(f"  NetworkX: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
            if G.number_of_nodes() > 0:
                try:
                    # Most connected nodes
                    top = sorted(G.degree(), key=lambda x: x[1], reverse=True)[:3]
                    print(f"  Most connected: {', '.join(f'{n}({d})' for n, d in top)}")
                except Exception:
                    pass
