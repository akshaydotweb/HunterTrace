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
        """
        Export self-contained HTML with D3.js force-directed graph.
        No server, no dependencies — open directly in browser.
        """
        nodes_json = json.dumps([
            {
                "id":    n.id,
                "label": n.label,
                "type":  n.type,
                "color": n.color,
                "size":  n.size,
                "meta":  {k: str(v) for k, v in n.metadata.items()},
            }
            for n in graph.nodes
        ], indent=2)

        edges_json = json.dumps([
            {
                "source": e.source,
                "target": e.target,
                "rel":    e.relationship,
                "color":  e.color,
                "weight": e.weight,
                "label":  e.label,
            }
            for e in graph.edges
        ], indent=2)

        meta = graph.metadata
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HunterTrace v3 — Attack Infrastructure Graph</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', monospace; }}

  #header {{
    padding: 14px 24px;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    display: flex; align-items: center; gap: 16px;
  }}
  #header h1 {{ font-size: 16px; color: #58a6ff; font-weight: 600; }}
  #header .stats {{ font-size: 12px; color: #8b949e; }}
  #header .badge {{
    background: #21262d; border: 1px solid #30363d;
    border-radius: 4px; padding: 2px 8px; font-size: 11px; color: #c9d1d9;
  }}

  #main {{ display: flex; height: calc(100vh - 50px); }}

  #sidebar {{
    width: 280px; min-width: 220px;
    background: #161b22; border-right: 1px solid #30363d;
    padding: 16px; overflow-y: auto; font-size: 12px;
  }}
  #sidebar h3 {{ color: #58a6ff; font-size: 12px; text-transform: uppercase;
                 letter-spacing: 0.08em; margin-bottom: 10px; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; margin: 5px 0; }}
  .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
  #node-info {{
    margin-top: 20px; padding: 12px;
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    min-height: 100px;
  }}
  #node-info h4 {{ color: #f0f6fc; font-size: 12px; margin-bottom: 8px; }}
  #node-info .attr {{ color: #8b949e; font-size: 11px; margin: 3px 0; }}
  #node-info .attr span {{ color: #c9d1d9; }}

  #graph-area {{ flex: 1; position: relative; overflow: hidden; }}
  svg {{ width: 100%; height: 100%; }}

  .node circle, .node rect, .node polygon {{
    stroke: #30363d; stroke-width: 1.5px; cursor: pointer;
    transition: opacity 0.15s;
  }}
  .node:hover circle, .node:hover rect, .node:hover polygon {{ stroke: #fff; stroke-width: 2.5px; }}
  .node text {{
    font-size: 10px; fill: #c9d1d9; text-anchor: middle;
    pointer-events: none; dominant-baseline: middle;
  }}
  .node.highlighted circle, .node.highlighted rect {{ stroke: #f0f6fc; stroke-width: 3px; }}

  .link {{ fill: none; stroke-opacity: 0.55; }}
  .link:hover {{ stroke-opacity: 1; }}
  .link-label {{ font-size: 9px; fill: #8b949e; pointer-events: none; }}

  #controls {{
    position: absolute; bottom: 16px; right: 16px;
    display: flex; gap: 8px;
  }}
  .ctrl-btn {{
    background: #21262d; border: 1px solid #30363d; border-radius: 6px;
    color: #c9d1d9; padding: 6px 12px; cursor: pointer; font-size: 12px;
  }}
  .ctrl-btn:hover {{ background: #30363d; }}

  #search-box {{
    position: absolute; top: 12px; right: 16px;
    background: #21262d; border: 1px solid #30363d; border-radius: 6px;
    color: #c9d1d9; padding: 6px 10px; font-size: 12px; width: 200px;
    outline: none;
  }}
</style>
</head>
<body>

<div id="header">
  <h1>⚡ HunterTrace v3 — Attack Infrastructure Graph</h1>
  <span class="badge">{meta.get('total_actors', 0)} actor(s)</span>
  <span class="badge">{meta.get('total_emails', 0)} email(s)</span>
  <span class="badge">{meta.get('node_count', 0)} nodes</span>
  <span class="badge">{meta.get('edge_count', 0)} edges</span>
  <span class="stats">Generated: {meta.get('generated_at', '')[:19]}</span>
</div>

<div id="main">
  <div id="sidebar">
    <h3>Node Types</h3>
    {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{color}"></div>{ntype}</div>'
             for ntype, color in NODE_COLORS.items())}

    <div id="node-info">
      <h4>Click a node for details</h4>
    </div>
  </div>

  <div id="graph-area">
    <svg id="svg"></svg>
    <input id="search-box" placeholder="Search nodes…" autocomplete="off">
    <div id="controls">
      <button class="ctrl-btn" onclick="resetZoom()">⟳ Reset</button>
      <button class="ctrl-btn" onclick="toggleLabels()">🏷 Labels</button>
    </div>
  </div>
</div>

<script>
const RAW_NODES = {nodes_json};
const RAW_EDGES = {edges_json};

// ── D3 setup ──────────────────────────────────────────────────────────
const svg    = d3.select('#svg');
const width  = () => document.getElementById('graph-area').clientWidth;
const height = () => document.getElementById('graph-area').clientHeight;

const zoom = d3.zoom()
  .scaleExtent([0.15, 4])
  .on('zoom', e => container.attr('transform', e.transform));
svg.call(zoom);

const container = svg.append('g');
let showLabels  = true;

// Arrow markers
svg.append('defs').selectAll('marker')
  .data(['default', 'real'])
  .enter().append('marker')
    .attr('id', d => `arrow-${{d}}`)
    .attr('viewBox', '0 -4 8 8')
    .attr('refX', 18).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto')
  .append('path')
    .attr('d', 'M0,-4L8,0L0,4')
    .attr('fill', d => d === 'real' ? '#E63946' : '#555');

// ── Simulation ────────────────────────────────────────────────────────
const sim = d3.forceSimulation(RAW_NODES)
  .force('link', d3.forceLink(RAW_EDGES)
    .id(d => d.id)
    .distance(d => d.rel === 'sent_via' ? 80 : d.rel === 'leaked_real_ip' ? 60 : 120)
    .strength(0.4))
  .force('charge', d3.forceManyBody().strength(d => d.type === 'actor' ? -400 : -180))
  .force('center', d3.forceCenter(width() / 2, height() / 2))
  .force('collision', d3.forceCollide(d => d.size + 8));

// ── Edges ─────────────────────────────────────────────────────────────
const link = container.append('g').attr('class', 'links')
  .selectAll('line')
  .data(RAW_EDGES).enter().append('line')
    .attr('class', 'link')
    .attr('stroke', d => d.color)
    .attr('stroke-width', d => Math.max(1, d.weight * 2.5))
    .attr('marker-end', d => `url(#arrow-${{d.rel === 'leaked_real_ip' ? 'real' : 'default'}})`);

// Edge labels
const linkLabel = container.append('g')
  .selectAll('text')
  .data(RAW_EDGES.filter(e => e.label)).enter().append('text')
    .attr('class', 'link-label')
    .text(d => d.label);

// ── Nodes ─────────────────────────────────────────────────────────────
const node = container.append('g').attr('class', 'nodes')
  .selectAll('.node')
  .data(RAW_NODES).enter().append('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', (e, d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag',  (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
      .on('end',   (e, d) => {{ if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}))
    .on('click', showNodeInfo);

// Shapes per type
node.each(function(d) {{
  const g = d3.select(this);
  const r = d.size / 2;
  if (d.type === 'actor') {{
    // Diamond
    g.append('polygon')
      .attr('points', `0,${{-r*1.2}} ${{r}},0 0,${{r*1.2}} ${{-r}},0`)
      .attr('fill', d.color);
  }} else if (d.type === 'email') {{
    g.append('rect')
      .attr('x', -r).attr('y', -r/1.5).attr('width', r*2).attr('height', r*1.3)
      .attr('rx', 3).attr('fill', d.color);
  }} else if (d.type === 'asn') {{
    const pts = [0, -r*1.1, r*0.95, r*0.55, -r*0.95, r*0.55];
    g.append('polygon')
      .attr('points', `${{pts[0]}},${{pts[1]}} ${{pts[2]}},${{pts[3]}} ${{pts[4]}},${{pts[5]}}`)
      .attr('fill', d.color);
  }} else {{
    g.append('circle').attr('r', r).attr('fill', d.color);
  }}
}});

// Labels
const labels = node.append('text')
  .each(function(d) {{
    const lines = d.label.split('\\n');
    const el    = d3.select(this);
    lines.forEach((line, i) => {{
      el.append('tspan')
        .attr('x', 0)
        .attr('dy', i === 0 ? `${{-(lines.length - 1) * 0.55}}em` : '1.1em')
        .text(line);
    }});
  }});

// ── Tick ──────────────────────────────────────────────────────────────
sim.on('tick', () => {{
  link
    .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);

  linkLabel
    .attr('x', d => (d.source.x + d.target.x) / 2)
    .attr('y', d => (d.source.y + d.target.y) / 2);

  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});

// ── Node info panel ───────────────────────────────────────────────────
function showNodeInfo(e, d) {{
  const panel = document.getElementById('node-info');
  let html = `<h4>${{d.label.replace('\\n', ' ')}}</h4>`;
  html += `<div class="attr">Type: <span>${{d.type}}</span></div>`;
  Object.entries(d.meta || {{}}).forEach(([k, v]) => {{
    if (v) html += `<div class="attr">${{k}}: <span>${{v}}</span></div>`;
  }});
  panel.innerHTML = html;

  // Highlight connected
  const connectedIds = new Set([d.id]);
  RAW_EDGES.forEach(e => {{
    if (e.source.id === d.id || e.source === d.id) connectedIds.add(e.target.id || e.target);
    if (e.target.id === d.id || e.target === d.id) connectedIds.add(e.source.id || e.source);
  }});
  node.classed('highlighted', n => connectedIds.has(n.id));
  link.style('stroke-opacity', l =>
    (l.source.id === d.id || l.target.id === d.id ||
     l.source === d.id    || l.target === d.id) ? 1.0 : 0.15);
}}

// ── Controls ──────────────────────────────────────────────────────────
function resetZoom() {{
  svg.transition().duration(400)
    .call(zoom.transform, d3.zoomIdentity.translate(width()/2, height()/2).scale(0.8));
}}

function toggleLabels() {{
  showLabels = !showLabels;
  labels.style('display', showLabels ? null : 'none');
}}

// ── Search ────────────────────────────────────────────────────────────
document.getElementById('search-box').addEventListener('input', function() {{
  const q = this.value.toLowerCase();
  node.style('opacity', d =>
    !q || d.label.toLowerCase().includes(q) || d.id.toLowerCase().includes(q) ? 1 : 0.15);
}});

// Initial zoom
setTimeout(() => svg.call(zoom.transform,
  d3.zoomIdentity.translate(width()*0.5, height()*0.5).scale(0.75)), 200);
</script>
</body>
</html>"""

        path = Path(output_path)
        path.write_text(html, encoding='utf-8')
        return str(path.resolve())

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
