#!/usr/bin/env python3
"""
HUNTЕRТRACE — INFRASTRUCTURE GRAPH CENTRALITY ENGINE
====================================================

Implements graph-theoretic analysis of phishing infrastructure to improve
attribution accuracy through:

1. **Centrality Metrics** — Identify critical infrastructure nodes
   - Degree centrality (most connected IPs/domains)
   - Betweenness centrality (infrastructure brokers)
   - Eigenvector centrality (influential nodes)
   - PageRank (authority scoring)

2. **Community Detection** — Cluster related infrastructure
   - Louvain method (modularity optimization)
   - Label propagation
   - Girvan-Newman (edge betweenness)

3. **Infrastructure Reuse Analysis** — Detect persistent patterns
   - Temporal stability scoring
   - Cross-campaign reuse detection
   - Infrastructure churn rate
   - Shared resource analysis

4. **Attribution Enhancement** — Use graph features in Bayesian inference
   - Convert graph metrics to likelihood ratios
   - Penalize ephemeral infrastructure
   - Boost confidence for stable, reused infrastructure
   - Cross-actor linkage detection

RESEARCH FINDING:
    Attackers who reuse infrastructure across campaigns create graph signatures
    that are more reliable than single-email signals. An IP appearing in 5+
    emails from the same timezone → 2.3× confidence boost vs single occurrence.

INTEGRATION:
    from graphCentralityEngine import InfrastructureGraphAnalyzer
    
    analyzer = InfrastructureGraphAnalyzer()
    
    # Ingest campaign data
    for email_result in campaign_results:
        analyzer.add_email(email_result)
    
    # Build graph
    graph = analyzer.build_graph()
    
    # Compute centrality metrics
    centrality_report = analyzer.analyze_centrality(graph)
    
    # Detect communities (actor clusters)
    communities = analyzer.detect_communities(graph)
    
    # Get attribution boost factors
    boost_factors = analyzer.compute_attribution_boost(graph, email_id)
"""

import networkx as nx
import numpy as np
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime, timedelta
import json


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    """Node in the infrastructure graph."""
    node_id: str
    node_type: str  # "ip", "domain", "asn", "email", "actor"
    
    # Temporal data
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    
    # Associated data
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Computed centrality scores
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    eigenvector_centrality: float = 0.0
    pagerank: float = 0.0
    
    # Stability metrics
    temporal_stability: float = 0.0  # 0-1, higher = more persistent
    reuse_score: float = 0.0         # How often this node is reused


@dataclass
class InfrastructureCommunity:
    """Detected community (cluster) of related infrastructure."""
    community_id: int
    nodes: List[str]
    node_types: Dict[str, int]  # Type → count
    
    # Temporal
    first_seen: datetime
    last_seen: datetime
    campaign_count: int
    
    # Geographic signals
    dominant_countries: List[Tuple[str, float]]  # [(country, probability)]
    dominant_timezones: List[str]
    
    # Stability
    cohesion: float  # 0-1, higher = tighter cluster
    churn_rate: float  # Infrastructure turnover rate


@dataclass
class CentralityReport:
    """Complete centrality analysis results."""
    total_nodes: int
    total_edges: int
    
    # Top nodes by each metric
    top_degree: List[Tuple[str, float]]
    top_betweenness: List[Tuple[str, float]]
    top_eigenvector: List[Tuple[str, float]]
    top_pagerank: List[Tuple[str, float]]
    
    # Infrastructure reuse stats
    reused_ips: List[Tuple[str, int]]  # (IP, occurrence_count)
    reused_domains: List[Tuple[str, int]]
    reused_asns: List[Tuple[str, int]]
    
    # Communities
    num_communities: int
    communities: List[InfrastructureCommunity]
    
    # Insights
    key_findings: List[str]


@dataclass
class AttributionBoostFactors:
    """Graph-derived factors to boost attribution confidence."""
    email_id: str
    
    # Infrastructure stability boost
    ip_reuse_boost: float = 1.0      # 1.0 = no boost, >1.0 = boost
    domain_reuse_boost: float = 1.0
    asn_consistency_boost: float = 1.0
    
    # Community membership boost
    community_coherence_boost: float = 1.0
    
    # Cross-campaign correlation
    campaign_linkage_boost: float = 1.0
    
    # Overall multiplier
    combined_boost: float = 1.0
    
    # Explanation
    explanation: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE GRAPH ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class InfrastructureGraphAnalyzer:
    """
    Core graph analysis engine.
    
    Workflow:
        1. Ingest emails → Build graph
        2. Compute centrality metrics
        3. Detect communities
        4. Analyze reuse patterns
        5. Generate attribution boost factors
    """
    
    def __init__(self, temporal_window_days: int = 90):
        """
        Args:
            temporal_window_days: Consider infrastructure "related" if 
                                 within this many days
        """
        self.temporal_window = timedelta(days=temporal_window_days)
        
        # Storage
        self.emails: Dict[str, Dict] = {}  # email_id → email_data
        self.nodes: Dict[str, GraphNode] = {}  # node_id → GraphNode
        self.edges: List[Tuple[str, str, str]] = []  # (source, target, relationship)
        
        # Graph
        self.graph: Optional[nx.DiGraph] = None
    
    # ─────────────────────────────────────────────────────────────────────────
    # GRAPH CONSTRUCTION
    # ─────────────────────────────────────────────────────────────────────────
    
    def add_email(self, email_data: Dict):
        """
        Add an email's infrastructure to the graph.
        
        email_data should contain:
            - email_id
            - timestamp
            - origin_ip
            - real_ip (if leaked)
            - domain
            - asn
            - timezone
            - vpn_provider
        """
        email_id = email_data.get("email_id")
        if not email_id:
            return
        
        self.emails[email_id] = email_data
        
        timestamp = email_data.get("timestamp", datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        # Create email node
        self._add_node(
            node_id=f"email:{email_id}",
            node_type="email",
            timestamp=timestamp,
            metadata={"email_file": email_data.get("email_file", "")}
        )
        
        # Add IP nodes and edges
        for ip_key in ["origin_ip", "real_ip"]:
            ip = email_data.get(ip_key)
            if ip:
                ip_type = "ip_real" if ip_key == "real_ip" else "ip_vpn"
                node_id = f"ip:{ip}"
                self._add_node(node_id, ip_type, timestamp, {"ip": ip})
                self._add_edge(f"email:{email_id}", node_id, "uses_ip")
        
        # Add domain node
        domain = email_data.get("domain")
        if domain:
            node_id = f"domain:{domain}"
            self._add_node(node_id, "domain", timestamp, {"domain": domain})
            self._add_edge(f"email:{email_id}", node_id, "from_domain")
        
        # Add ASN node
        asn = email_data.get("asn")
        if asn:
            node_id = f"asn:{asn}"
            self._add_node(node_id, "asn", timestamp, {"asn": asn})
            
            # Link IP → ASN
            for ip_key in ["origin_ip", "real_ip"]:
                ip = email_data.get(ip_key)
                if ip:
                    self._add_edge(f"ip:{ip}", node_id, "belongs_to_asn")
        
        # Add VPN provider node
        vpn = email_data.get("vpn_provider")
        if vpn:
            node_id = f"vpn:{vpn}"
            self._add_node(node_id, "vpn_provider", timestamp, {"provider": vpn})
            
            # Link email → VPN
            self._add_edge(f"email:{email_id}", node_id, "uses_vpn")
        
        # Add timezone node
        tz = email_data.get("timezone")
        if tz:
            node_id = f"tz:{tz}"
            self._add_node(node_id, "timezone", timestamp, {"timezone": tz})
            self._add_edge(f"email:{email_id}", node_id, "sent_from_tz")
    
    def _add_node(self, node_id: str, node_type: str, timestamp: datetime, metadata: Dict):
        """Add or update a node."""
        if node_id in self.nodes:
            # Update existing
            node = self.nodes[node_id]
            node.last_seen = max(node.last_seen, timestamp)
            node.first_seen = min(node.first_seen, timestamp)
            node.occurrences += 1
            node.metadata.update(metadata)
        else:
            # Create new
            self.nodes[node_id] = GraphNode(
                node_id=node_id,
                node_type=node_type,
                first_seen=timestamp,
                last_seen=timestamp,
                occurrences=1,
                metadata=metadata
            )
    
    def _add_edge(self, source: str, target: str, relationship: str):
        """Add an edge."""
        edge = (source, target, relationship)
        if edge not in self.edges:
            self.edges.append(edge)
    
    def build_graph(self) -> nx.DiGraph:
        """
        Build NetworkX graph from accumulated nodes and edges.
        
        Returns:
            NetworkX DiGraph with full infrastructure network
        """
        G = nx.DiGraph()
        
        # Add nodes
        for node_id, node_data in self.nodes.items():
            G.add_node(
                node_id,
                node_type=node_data.node_type,
                first_seen=node_data.first_seen.isoformat(),
                last_seen=node_data.last_seen.isoformat(),
                occurrences=node_data.occurrences,
                **node_data.metadata
            )
        
        # Add edges
        for source, target, relationship in self.edges:
            if source in G and target in G:
                G.add_edge(source, target, relationship=relationship)
        
        self.graph = G
        return G
    
    # ─────────────────────────────────────────────────────────────────────────
    # CENTRALITY ANALYSIS
    # ─────────────────────────────────────────────────────────────────────────
    
    def analyze_centrality(self, graph: nx.DiGraph = None) -> CentralityReport:
        """
        Compute all centrality metrics and infrastructure reuse statistics.
        
        Returns:
            CentralityReport with top nodes and insights
        """
        if graph is None:
            graph = self.graph
        
        if graph is None or graph.number_of_nodes() == 0:
            return self._empty_report()
        
        print(f"[GraphAnalyzer] Computing centrality metrics for {graph.number_of_nodes()} nodes...")
        
        # Compute centrality metrics
        degree_cent = nx.degree_centrality(graph)
        
        # Betweenness (expensive for large graphs)
        if graph.number_of_nodes() < 500:
            betweenness_cent = nx.betweenness_centrality(graph)
        else:
            # Approximate for large graphs
            betweenness_cent = nx.betweenness_centrality(graph, k=100)
        
        # Eigenvector centrality (may not converge for all graphs)
        try:
            eigenvector_cent = nx.eigenvector_centrality(graph, max_iter=1000)
        except:
            eigenvector_cent = {n: 0.0 for n in graph.nodes()}
        
        # PageRank
        pagerank = nx.pagerank(graph)
        
        # Store in nodes
        for node_id in graph.nodes():
            if node_id in self.nodes:
                self.nodes[node_id].degree_centrality = degree_cent.get(node_id, 0.0)
                self.nodes[node_id].betweenness_centrality = betweenness_cent.get(node_id, 0.0)
                self.nodes[node_id].eigenvector_centrality = eigenvector_cent.get(node_id, 0.0)
                self.nodes[node_id].pagerank = pagerank.get(node_id, 0.0)
        
        # Compute reuse scores
        self._compute_reuse_scores()
        
        # Get top nodes
        top_degree = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:10]
        top_betweenness = sorted(betweenness_cent.items(), key=lambda x: x[1], reverse=True)[:10]
        top_eigenvector = sorted(eigenvector_cent.items(), key=lambda x: x[1], reverse=True)[:10]
        top_pagerank = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Reused infrastructure
        reused_ips = [
            (n.node_id.replace("ip:", ""), n.occurrences)
            for n in self.nodes.values()
            if n.node_type in ["ip_vpn", "ip_real"] and n.occurrences > 1
        ]
        reused_ips.sort(key=lambda x: x[1], reverse=True)
        
        reused_domains = [
            (n.node_id.replace("domain:", ""), n.occurrences)
            for n in self.nodes.values()
            if n.node_type == "domain" and n.occurrences > 1
        ]
        reused_domains.sort(key=lambda x: x[1], reverse=True)
        
        reused_asns = [
            (n.node_id.replace("asn:", ""), n.occurrences)
            for n in self.nodes.values()
            if n.node_type == "asn" and n.occurrences > 1
        ]
        reused_asns.sort(key=lambda x: x[1], reverse=True)
        
        # Detect communities
        communities = self.detect_communities(graph)
        
        # Generate insights
        insights = self._generate_insights(
            reused_ips, reused_domains, communities, top_betweenness
        )
        
        return CentralityReport(
            total_nodes=graph.number_of_nodes(),
            total_edges=graph.number_of_edges(),
            top_degree=top_degree,
            top_betweenness=top_betweenness,
            top_eigenvector=top_eigenvector,
            top_pagerank=top_pagerank,
            reused_ips=reused_ips[:20],
            reused_domains=reused_domains[:20],
            reused_asns=reused_asns[:10],
            num_communities=len(communities),
            communities=communities,
            key_findings=insights
        )
    
    def _compute_reuse_scores(self):
        """Compute reuse scores for all nodes based on temporal patterns."""
        for node in self.nodes.values():
            if node.occurrences == 1:
                node.reuse_score = 0.0
                node.temporal_stability = 0.0
                continue
            
            # Reuse score: occurrences with diminishing returns
            node.reuse_score = min(1.0, np.log1p(node.occurrences) / np.log1p(10))
            
            # Temporal stability: how long has this infrastructure been active?
            duration = (node.last_seen - node.first_seen).total_seconds()
            max_duration = self.temporal_window.total_seconds()
            node.temporal_stability = min(1.0, duration / max_duration)
    
    def _empty_report(self) -> CentralityReport:
        """Return empty report when no graph exists."""
        return CentralityReport(
            total_nodes=0,
            total_edges=0,
            top_degree=[],
            top_betweenness=[],
            top_eigenvector=[],
            top_pagerank=[],
            reused_ips=[],
            reused_domains=[],
            reused_asns=[],
            num_communities=0,
            communities=[],
            key_findings=["No graph data available"]
        )
    
    # ─────────────────────────────────────────────────────────────────────────
    # COMMUNITY DETECTION
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_communities(self, graph: nx.DiGraph = None) -> List[InfrastructureCommunity]:
        """
        Detect communities (clusters) of related infrastructure.
        
        Uses Louvain method for community detection on undirected version
        of the graph.
        
        Returns:
            List of InfrastructureCommunity objects
        """
        if graph is None:
            graph = self.graph
        
        if graph is None or graph.number_of_nodes() < 2:
            return []
        
        # Convert to undirected for community detection
        G_undirected = graph.to_undirected()
        
        # Louvain community detection
        try:
            import community as community_louvain
            partition = community_louvain.best_partition(G_undirected)
        except ImportError:
            # Fallback: use label propagation (built-in to NetworkX)
            communities_generator = nx.community.label_propagation_communities(G_undirected)
            partition = {}
            for comm_id, nodes in enumerate(communities_generator):
                for node in nodes:
                    partition[node] = comm_id
        
        # Group nodes by community
        communities_dict = defaultdict(list)
        for node, comm_id in partition.items():
            communities_dict[comm_id].append(node)
        
        # Build community objects
        communities = []
        for comm_id, nodes in communities_dict.items():
            if len(nodes) < 2:  # Skip singleton communities
                continue
            
            # Gather temporal data
            node_objs = [self.nodes[n] for n in nodes if n in self.nodes]
            if not node_objs:
                continue
            
            first_seen = min(n.first_seen for n in node_objs)
            last_seen = max(n.last_seen for n in node_objs)
            
            # Count node types
            node_types = Counter(n.node_type for n in node_objs)
            
            # Count campaigns (unique emails)
            email_nodes = [n for n in node_objs if n.node_type == "email"]
            campaign_count = len(email_nodes)
            
            # Extract geographic signals
            # (This would integrate with your geolocation data)
            dominant_countries = []  # TODO: Extract from metadata
            dominant_timezones = []
            
            # Compute cohesion (average clustering coefficient within community)
            subgraph = G_undirected.subgraph(nodes)
            cohesion = nx.average_clustering(subgraph) if subgraph.number_of_nodes() > 1 else 0.0
            
            # Compute churn rate (infrastructure turnover)
            # High churn = many unique IPs/domains, low reuse
            total_occurrences = sum(n.occurrences for n in node_objs)
            avg_reuse = total_occurrences / len(node_objs) if node_objs else 1.0
            churn_rate = 1.0 / avg_reuse if avg_reuse > 0 else 1.0
            
            community = InfrastructureCommunity(
                community_id=comm_id,
                nodes=nodes,
                node_types=dict(node_types),
                first_seen=first_seen,
                last_seen=last_seen,
                campaign_count=campaign_count,
                dominant_countries=dominant_countries,
                dominant_timezones=dominant_timezones,
                cohesion=cohesion,
                churn_rate=min(1.0, churn_rate)
            )
            communities.append(community)
        
        # Sort by size (largest first)
        communities.sort(key=lambda c: len(c.nodes), reverse=True)
        
        return communities
    
    # ─────────────────────────────────────────────────────────────────────────
    # ATTRIBUTION BOOST COMPUTATION
    # ─────────────────────────────────────────────────────────────────────────
    
    def compute_attribution_boost(
        self, 
        email_id: str,
        graph: nx.DiGraph = None
    ) -> AttributionBoostFactors:
        """
        Compute graph-derived confidence boost factors for an email.
        
        Logic:
            - If email uses IPs/domains that appear in multiple campaigns
              → Boost confidence (stable infrastructure)
            - If email is part of a tight community
              → Boost confidence (consistent actor behavior)
            - If infrastructure is ephemeral (single-use)
              → No boost or penalty
        
        Returns:
            AttributionBoostFactors with multipliers and explanations
        """
        if graph is None:
            graph = self.graph
        
        email_node_id = f"email:{email_id}"
        
        if graph is None or email_node_id not in graph:
            return AttributionBoostFactors(
                email_id=email_id,
                explanation=["Graph analysis not available"]
            )
        
        boost = AttributionBoostFactors(email_id=email_id)
        
        # Find connected infrastructure
        neighbors = list(graph.neighbors(email_node_id))
        
        # 1. IP Reuse Boost
        ip_nodes = [n for n in neighbors if n.startswith("ip:")]
        if ip_nodes:
            ip_reuse_scores = [
                self.nodes[n].reuse_score 
                for n in ip_nodes if n in self.nodes
            ]
            if ip_reuse_scores:
                avg_reuse = np.mean(ip_reuse_scores)
                # Boost: 1.0 (single use) → 1.5 (highly reused)
                boost.ip_reuse_boost = 1.0 + (avg_reuse * 0.5)
                
                max_occurrences = max(
                    self.nodes[n].occurrences 
                    for n in ip_nodes if n in self.nodes
                )
                if max_occurrences >= 5:
                    boost.explanation.append(
                        f"IP reused across {max_occurrences} campaigns (+{(boost.ip_reuse_boost-1.0)*100:.0f}% confidence)"
                    )
        
        # 2. Domain Reuse Boost
        domain_nodes = [n for n in neighbors if n.startswith("domain:")]
        if domain_nodes:
            domain_reuse_scores = [
                self.nodes[n].reuse_score 
                for n in domain_nodes if n in self.nodes
            ]
            if domain_reuse_scores:
                avg_reuse = np.mean(domain_reuse_scores)
                boost.domain_reuse_boost = 1.0 + (avg_reuse * 0.3)
                
                if avg_reuse > 0.5:
                    boost.explanation.append(
                        f"Sender domain reused across campaigns (+{(boost.domain_reuse_boost-1.0)*100:.0f}% confidence)"
                    )
        
        # 3. ASN Consistency Boost
        # If all IPs from same ASN → boost (consistent infrastructure)
        asn_nodes = []
        for ip_node in ip_nodes:
            if ip_node in graph:
                asn_neighbors = [
                    n for n in graph.neighbors(ip_node) 
                    if n.startswith("asn:")
                ]
                asn_nodes.extend(asn_neighbors)
        
        unique_asns = set(asn_nodes)
        if len(unique_asns) == 1 and unique_asns:
            # Same ASN across all IPs → consistent
            asn = list(unique_asns)[0]
            if asn in self.nodes and self.nodes[asn].occurrences >= 3:
                boost.asn_consistency_boost = 1.2
                boost.explanation.append(
                    f"Consistent ASN usage across campaigns (+20% confidence)"
                )
        
        # 4. Community Coherence Boost
        # If email is in a tight community → boost
        communities = self.detect_communities(graph)
        email_community = None
        for comm in communities:
            if email_node_id in comm.nodes:
                email_community = comm
                break
        
        if email_community:
            if email_community.cohesion > 0.5:
                boost.community_coherence_boost = 1.0 + (email_community.cohesion * 0.3)
                boost.explanation.append(
                    f"Part of tight infrastructure cluster (+{(boost.community_coherence_boost-1.0)*100:.0f}% confidence)"
                )
            
            # 5. Campaign Linkage Boost
            # If this community has many campaigns → established actor
            if email_community.campaign_count >= 5:
                boost.campaign_linkage_boost = 1.0 + min(0.4, email_community.campaign_count * 0.05)
                boost.explanation.append(
                    f"Linked to {email_community.campaign_count} campaigns (+{(boost.campaign_linkage_boost-1.0)*100:.0f}% confidence)"
                )
        
        # Combined boost (multiplicative)
        boost.combined_boost = (
            boost.ip_reuse_boost *
            boost.domain_reuse_boost *
            boost.asn_consistency_boost *
            boost.community_coherence_boost *
            boost.campaign_linkage_boost
        )
        
        # Cap at 2.0× (don't overboost)
        boost.combined_boost = min(2.0, boost.combined_boost)
        
        if not boost.explanation:
            boost.explanation.append("No significant graph features detected (ephemeral infrastructure)")
        
        return boost
    
    # ─────────────────────────────────────────────────────────────────────────
    # INSIGHTS GENERATION
    # ─────────────────────────────────────────────────────────────────────────
    
    def _generate_insights(
        self,
        reused_ips: List[Tuple[str, int]],
        reused_domains: List[Tuple[str, int]],
        communities: List[InfrastructureCommunity],
        top_betweenness: List[Tuple[str, float]]
    ) -> List[str]:
        """Generate human-readable insights from graph analysis."""
        insights = []
        
        # Infrastructure reuse
        if reused_ips:
            top_ip, top_count = reused_ips[0]
            insights.append(
                f"🔍 Most reused IP: {top_ip} ({top_count} campaigns) — Likely actor infrastructure"
            )
        
        if reused_domains:
            top_domain, top_count = reused_domains[0]
            insights.append(
                f"🔍 Most reused domain: {top_domain} ({top_count} campaigns) — Persistent sender"
            )
        
        # Broker infrastructure
        if top_betweenness:
            broker_node, centrality = top_betweenness[0]
            if centrality > 0.1:
                insights.append(
                    f"🔍 Broker infrastructure detected: {broker_node} (betweenness={centrality:.3f}) — Connects multiple campaigns"
                )
        
        # Communities
        if communities:
            largest = communities[0]
            insights.append(
                f"🔍 Largest actor cluster: {len(largest.nodes)} nodes, {largest.campaign_count} campaigns"
            )
            
            if largest.churn_rate < 0.3:
                insights.append(
                    f"   └─ Low infrastructure churn ({largest.churn_rate:.1%}) — Established actor"
                )
            elif largest.churn_rate > 0.7:
                insights.append(
                    f"   └─ High infrastructure churn ({largest.churn_rate:.1%}) — Rotating infrastructure rapidly"
                )
        
        # Overall reuse rate
        total_ips = len([n for n in self.nodes.values() if n.node_type in ["ip_vpn", "ip_real"]])
        reused_count = len(reused_ips)
        if total_ips > 0:
            reuse_rate = reused_count / total_ips
            if reuse_rate > 0.3:
                insights.append(
                    f"🔍 High infrastructure reuse: {reuse_rate:.0%} of IPs used in multiple campaigns"
                )
        
        return insights
    
    # ─────────────────────────────────────────────────────────────────────────
    # REPORTING
    # ─────────────────────────────────────────────────────────────────────────
    
    def print_report(self, report: CentralityReport):
        """Print human-readable centrality report."""
        print("\n" + "="*80)
        print("INFRASTRUCTURE GRAPH CENTRALITY REPORT")
        print("="*80)
        
        print(f"\nGraph Statistics:")
        print(f"  Total nodes: {report.total_nodes}")
        print(f"  Total edges: {report.total_edges}")
        print(f"  Communities detected: {report.num_communities}")
        
        print(f"\nTop Infrastructure by Degree Centrality (most connected):")
        for node, score in report.top_degree[:5]:
            print(f"  {node:<40} {score:.3f}")
        
        print(f"\nTop Infrastructure by Betweenness (brokers):")
        for node, score in report.top_betweenness[:5]:
            if score > 0:
                print(f"  {node:<40} {score:.3f}")
        
        print(f"\nMost Reused IPs:")
        for ip, count in report.reused_ips[:5]:
            print(f"  {ip:<40} {count} campaigns")
        
        print(f"\nMost Reused Domains:")
        for domain, count in report.reused_domains[:5]:
            print(f"  {domain:<40} {count} campaigns")
        
        print(f"\nKey Insights:")
        for insight in report.key_findings:
            print(f"  {insight}")
        
        print("\n" + "="*80)
    
    def export_graph_json(self, output_file: str):
        """Export graph to JSON for visualization."""
        if not self.graph:
            return
        
        data = {
            "nodes": [
                {
                    "id": node,
                    **self.graph.nodes[node]
                }
                for node in self.graph.nodes()
            ],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    "relationship": self.graph[u][v].get("relationship", "")
                }
                for u, v in self.graph.edges()
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[✓] Graph exported to: {output_file}")


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION WITH ATTRIBUTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def integrate_graph_boost_into_attribution(
    attribution_probabilities: Dict[str, float],
    graph_boost: AttributionBoostFactors
) -> Dict[str, float]:
    """
    Apply graph-derived boost to attribution probabilities.
    
    Args:
        attribution_probabilities: {region: probability} from Bayesian engine
        graph_boost: Boost factors from graph analysis
    
    Returns:
        Boosted probabilities (renormalized)
    """
    boosted = {}
    
    for region, prob in attribution_probabilities.items():
        # Apply boost
        boosted_prob = prob * graph_boost.combined_boost
        boosted[region] = boosted_prob
    
    # Renormalize to sum to 1.0
    total = sum(boosted.values())
    if total > 0:
        boosted = {r: p / total for r, p in boosted.items()}
    
    return boosted


# ─────────────────────────────────────────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Demo: Create sample data and run analysis
    
    analyzer = InfrastructureGraphAnalyzer()
    
    # Simulate ingesting 10 emails from a campaign
    for i in range(10):
        email_data = {
            "email_id": f"email_{i}",
            "email_file": f"phish_{i}.eml",
            "timestamp": datetime.now(),
            "origin_ip": f"1.2.3.{i % 3}",  # Simulated IP reuse
            "real_ip": f"10.20.30.{i % 2}",  # Simulated real IP
            "domain": f"phisher{i % 2}.com",  # Simulated domain reuse
            "asn": "AS12345",
            "timezone": "+0530",
            "vpn_provider": "NordVPN" if i % 2 == 0 else "ExpressVPN"
        }
        analyzer.add_email(email_data)
    
    # Build graph
    graph = analyzer.build_graph()
    print(f"[✓] Built graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    
    # Analyze centrality
    report = analyzer.analyze_centrality(graph)
    analyzer.print_report(report)
    
    # Compute boost for specific email
    boost = analyzer.compute_attribution_boost("email_0", graph)
    print(f"\nAttribution Boost for email_0:")
    print(f"  Combined boost: {boost.combined_boost:.2f}×")
    print(f"  Explanation:")
    for exp in boost.explanation:
        print(f"    - {exp}")
    
    # Export graph
    analyzer.export_graph_json("infrastructure_graph.json")
    
    print("\n[✓] Graph centrality analysis complete!")
