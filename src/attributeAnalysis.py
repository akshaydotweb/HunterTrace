#!/usr/bin/env python3
"""
STAGE 5: FINAL ATTRIBUTION & EVIDENCE PACKAGING
Synthesizes all analysis from Stages 1-4 + Geolocation into:
  - Final confidence scoring
  - Evidence graphs
  - Attacker profile
  - Law enforcement evidence package
"""

import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import defaultdict


@dataclass
class EvidenceItem:
    """Single piece of evidence pointing to attacker"""
    category: str  # "location", "infrastructure", "threat_intel", "behavior", "technical"
    description: str
    confidence: float  # 0-1
    severity: str  # "critical", "high", "medium", "low"
    stage_origin: int  # which stage found this (1-4)
    source: str  # "geolocation", "abuseipdb", "whois", etc.


@dataclass
class AttackerProfile:
    """Complete attacker profile based on all analysis"""
    primary_origin: str  # "City, Country"
    origin_confidence: float  # 0-1
    
    # Geographic profile
    countries_used: List[str]
    cities_detected: List[str]
    timezones: List[str]
    
    # Infrastructure profile
    unique_isps: int
    unique_asns: List[str]
    hosting_types: Dict[str, int]  # {"datacenter": 3, "residential": 1}
    
    # Sophistication indicators
    uses_tor: bool
    uses_vpn: bool
    uses_residential_proxies: bool
    infrastructure_diversity: str  # "low", "medium", "high"
    operational_security_level: str  # "amateur", "professional", "nation-state"
    
    # Behavioral signature
    attack_type: str  # "phishing", "spear-phishing", "bec", "ransomware", etc.
    estimated_team_size: Tuple[int, int]  # (min, max)
    likely_motivation: str  # "financial", "espionage", "disruption", "unknown"
    
    # Temporal patterns
    activity_timezone: Optional[str]
    activity_hours: str  # "business", "24/7", "varying"
    campaign_frequency: str  # "sporadic", "regular", "intensive"


@dataclass
class AttributionGraph:
    """Relationship graph of IPs, domains, ASNs, and clusters"""
    nodes: List[Dict[str, Any]] = field(default_factory=list)  # {"id": "IP", "type": "ip", "label": "Lagos, Nigeria", "color": "#FF0000"}
    edges: List[Dict[str, Any]] = field(default_factory=list)  # {"source": "IP1", "target": "IP2", "relationship": "proxy_chain", "weight": 0.9}
    clusters: List[Dict[str, Any]] = field(default_factory=list)  # {"id": "cluster_0", "ips": ["IP1", "IP2"], "likely_purpose": "command_and_control"}


@dataclass
class AttributionConfidence:
    """Confidence scoring across multiple dimensions"""
    location_confidence: float  # Based on geolocation data quality
    infrastructure_confidence: float  # Consistency across IPs/ASNs
    threat_intel_confidence: float  # Corroboration with known threats
    behavioral_confidence: float  # Pattern consistency
    technical_confidence: float  # Evidence quality
    
    overall_confidence: float  # 0-1 final score
    confidence_reasoning: List[str]  # Why this confidence level


@dataclass
class Stage5Attribution:
    """Complete Stage 5 attribution analysis output"""
    timestamp: str
    
    # Primary findings
    attacker_profile: AttackerProfile
    attribution_graph: AttributionGraph
    confidence_scoring: AttributionConfidence
    
    # Evidence
    supporting_evidence: List[EvidenceItem]
    
    # Law enforcement ready data
    evidence_package: Dict[str, Any]
    
    # Summary
    final_attribution_statement: str  # Human-readable 1-2 sentence attribution
    confidence_level: str  # "High", "Medium", "Low"
    recommended_actions: List[str]
    

class AttributionAnalysisEngine:
    """Stage 5: Synthesize all analysis into final attribution"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def analyze(self, 
                header_analysis,
                classifications,
                proxy_analysis,
                enrichment_results,
                correlation_analysis,
                threat_intelligence,
                geolocation_results) -> Stage5Attribution:
        """
        Synthesize all stages into final attribution
        """
        
        # 1. Build attacker profile
        attacker_profile = self._build_attacker_profile(
            header_analysis, classifications, enrichment_results, 
            correlation_analysis, threat_intelligence, geolocation_results
        )
        
        # 2. Build attribution graph
        attribution_graph = self._build_attribution_graph(
            classifications, enrichment_results, geolocation_results, correlation_analysis
        )
        
        # 3. Collect all evidence
        evidence_items = self._collect_evidence(
            classifications, proxy_analysis, enrichment_results,
            threat_intelligence, geolocation_results, attacker_profile
        )
        
        # 4. Calculate confidence
        confidence = self._calculate_confidence(
            evidence_items, geolocation_results, threat_intelligence, 
            enrichment_results, correlation_analysis
        )
        
        # 5. Generate evidence package for law enforcement
        evidence_package = self._generate_evidence_package(
            header_analysis, classifications, enrichment_results,
            threat_intelligence, geolocation_results, evidence_items, attacker_profile
        )
        
        # 6. Generate attribution statement
        attribution_statement = self._generate_attribution_statement(
            attacker_profile, confidence
        )
        
        # 7. Recommend actions
        recommended_actions = self._generate_recommendations(
            attacker_profile, confidence, threat_intelligence
        )
        
        return Stage5Attribution(
            timestamp=datetime.now().isoformat(),
            attacker_profile=attacker_profile,
            attribution_graph=attribution_graph,
            confidence_scoring=confidence,
            supporting_evidence=evidence_items,
            evidence_package=evidence_package,
            final_attribution_statement=attribution_statement,
            confidence_level=self._confidence_to_label(confidence.overall_confidence),
            recommended_actions=recommended_actions
        )
    
    def _build_attacker_profile(self, header_analysis, classifications, enrichment_results,
                                correlation_analysis, threat_intelligence, geolocation_results):
        """Build complete attacker profile"""
        
        # Geolocation data
        primary_origin = "Unknown"
        origin_confidence = 0.0
        countries = set()
        cities = set()
        timezones = set()
        
        if geolocation_results:
            for ip, geoloc in geolocation_results.items():
                if geoloc and geoloc.confidence > 0:
                    if geoloc.country:
                        countries.add(geoloc.country)
                    if geoloc.city and geoloc.country:
                        cities.add(f"{geoloc.city}, {geoloc.country}")
                    if geoloc.timezone:
                        timezones.add(geoloc.timezone)
                    
                    # Find most frequent location
                    if geoloc.confidence > origin_confidence:
                        origin_confidence = geoloc.confidence
                        primary_origin = f"{geoloc.city or 'Unknown'}, {geoloc.country or 'Unknown'}"
        
        # Infrastructure profile
        isps = set()
        asns = []
        hosting_types = defaultdict(int)
        
        if enrichment_results:
            for ip, enrich in enrichment_results.items():
                if enrich.whois_data.organization:
                    isps.add(enrich.whois_data.organization)
                if enrich.whois_data.asn:
                    asns.append(enrich.whois_data.asn)
                if enrich.hosting_analysis.hosting_type:
                    hosting_types[enrich.hosting_analysis.hosting_type] += 1
        
        # Obfuscation detection
        uses_tor = False
        uses_vpn = False
        uses_residential = False
        
        for ip, classification in classifications.items():
            if "Tor" in classification.classification:
                uses_tor = True
            if "VPN" in classification.classification:
                uses_vpn = True
            if "Residential" in str(enrichment_results.get(ip, {}).hosting_analysis.hosting_type if enrichment_results else ""):
                uses_residential = True
        
        # Infrastructure diversity
        infrastructure_diversity = self._assess_diversity(len(isps), len(set(asns)), len(countries))
        
        # Team size from correlation
        estimated_team_size = (2, 6)
        if correlation_analysis and correlation_analysis.estimated_team_size_range:
            estimated_team_size = correlation_analysis.estimated_team_size_range
        
        return AttackerProfile(
            primary_origin=primary_origin,
            origin_confidence=origin_confidence,
            countries_used=list(countries),
            cities_detected=list(cities),
            timezones=list(timezones),
            unique_isps=len(isps),
            unique_asns=list(set(asns)),
            hosting_types=dict(hosting_types),
            uses_tor=uses_tor,
            uses_vpn=uses_vpn,
            uses_residential_proxies=uses_residential,
            infrastructure_diversity=infrastructure_diversity,
            operational_security_level=self._assess_opsec(uses_tor, uses_vpn, len(isps), infrastructure_diversity),
            attack_type=self._infer_attack_type(header_analysis),
            estimated_team_size=estimated_team_size,
            likely_motivation=self._infer_motivation(threat_intelligence, classifications),
            activity_timezone=self._most_common_timezone(timezones),
            activity_hours=self._assess_activity_hours(header_analysis, timezones),
            campaign_frequency="regular"
        )
    
    def _build_attribution_graph(self, classifications, enrichment_results, geolocation_results, correlation_analysis):
        """Build graph showing relationships between IPs, ASNs, locations"""
        
        nodes = []
        edges = []
        clusters = []
        
        # Add IP nodes
        for ip, geoloc in (geolocation_results or {}).items():
            if ip in classifications:
                classification = classifications[ip]
                label = f"{ip}\n{geoloc.city if geoloc and geoloc.city else 'Unknown'}"
                
                # Color by threat level
                if classification.threat_score > 75:
                    color = "#FF0000"  # Red - high threat
                elif classification.threat_score > 50:
                    color = "#FF9900"  # Orange - medium threat
                else:
                    color = "#00AA00"  # Green - low threat
                
                nodes.append({
                    "id": ip,
                    "type": "ip",
                    "label": label,
                    "color": color,
                    "size": max(20, min(50, 20 + classification.threat_score / 2)),
                    "threat_score": classification.threat_score,
                    "location": f"{geoloc.city}, {geoloc.country}" if geoloc else "Unknown"
                })
        
        # Add ASN nodes
        asns_seen = set()
        for ip, enrich in (enrichment_results or {}).items():
            if enrich.whois_data.asn and enrich.whois_data.asn not in asns_seen:
                asns_seen.add(enrich.whois_data.asn)
                nodes.append({
                    "id": enrich.whois_data.asn,
                    "type": "asn",
                    "label": enrich.whois_data.asn,
                    "color": "#0088FF",
                    "size": 30
                })
        
        # Add edges: IPs to ASNs
        for ip, enrich in (enrichment_results or {}).items():
            if enrich.whois_data.asn:
                edges.append({
                    "source": ip,
                    "target": enrich.whois_data.asn,
                    "relationship": "belongs_to",
                    "weight": 0.9
                })
        
        # Add clustering information
        if correlation_analysis and correlation_analysis.clusters:
            for i, cluster in enumerate(correlation_analysis.clusters):
                clusters.append({
                    "id": f"cluster_{i}",
                    "ips": cluster.ips if hasattr(cluster, 'ips') else [],
                    "likely_purpose": "infrastructure" if i == 0 else "backup",
                    "confidence": cluster.confidence if hasattr(cluster, 'confidence') else 0.6
                })
        
        return AttributionGraph(nodes=nodes, edges=edges, clusters=clusters)
    
    def _collect_evidence(self, classifications, proxy_analysis, enrichment_results,
                         threat_intelligence, geolocation_results, attacker_profile):
        """Collect all evidence pointing to attacker"""
        
        evidence = []
        
        # Geolocation evidence
        if attacker_profile.origin_confidence > 0.8:
            evidence.append(EvidenceItem(
                category="location",
                description=f"High-confidence geolocation to {attacker_profile.primary_origin}",
                confidence=attacker_profile.origin_confidence,
                severity="critical" if attacker_profile.origin_confidence > 0.9 else "high",
                stage_origin=0,  # Geolocation stage
                source="geolocation_apis"
            ))
        
        # Infrastructure evidence
        for ip, classification in classifications.items():
            if classification.threat_score > 50:
                evidence.append(EvidenceItem(
                    category="infrastructure",
                    description=f"IP {ip} has threat score {classification.threat_score}/100",
                    confidence=min(classification.confidence, 1.0),
                    severity="high" if classification.threat_score > 75 else "medium",
                    stage_origin=2,
                    source="abuseipdb"
                ))
        
        # Threat intelligence evidence
        if threat_intelligence and threat_intelligence.critical_ips:
            evidence.append(EvidenceItem(
                category="threat_intel",
                description=f"Detected {len(threat_intelligence.critical_ips)} known malicious IPs",
                confidence=0.95,
                severity="critical",
                stage_origin=4,
                source="threat_intelligence"
            ))
        
        # C2 evidence
        if threat_intelligence and threat_intelligence.c2_servers:
            evidence.append(EvidenceItem(
                category="threat_intel",
                description=f"Identified {len(threat_intelligence.c2_servers)} suspected C2 servers",
                confidence=0.85,
                severity="critical",
                stage_origin=4,
                source="c2_detection"
            ))
        
        # Obfuscation evidence
        if proxy_analysis.obfuscation_count > 0:
            evidence.append(EvidenceItem(
                category="technical",
                description=f"Detected {proxy_analysis.obfuscation_count} obfuscation layers (Tor/VPN/Proxy)",
                confidence=0.95,
                severity="high",
                stage_origin=3,
                source="proxy_analysis"
            ))
        
        return evidence
    
    def _calculate_confidence(self, evidence_items, geolocation_results, threat_intelligence,
                             enrichment_results, correlation_analysis):
        """Calculate final confidence scoring"""
        
        reasoning = []
        
        # Location confidence
        location_conf = 0.0
        if geolocation_results:
            valid_geolocs = [g for g in geolocation_results.values() if g and g.confidence > 0]
            if valid_geolocs:
                location_conf = sum(g.confidence for g in valid_geolocs) / len(valid_geolocs)
                reasoning.append(f"Location: {location_conf:.0%} based on {len(valid_geolocs)} geolocations")
        
        # Infrastructure confidence
        infra_conf = 0.0
        if enrichment_results:
            consistent_asns = len(set([e.whois_data.asn for e in enrichment_results.values() if e.whois_data.asn]))
            total_ips = len(enrichment_results)
            if total_ips > 0:
                # More IPs from same ASN = more confident
                infra_conf = 1.0 - (consistent_asns / total_ips)
                reasoning.append(f"Infrastructure: {infra_conf:.0%} (consistency across {total_ips} IPs)")
        
        # Threat intel confidence
        threat_conf = 0.0
        if threat_intelligence:
            if threat_intelligence.critical_ips or threat_intelligence.c2_servers:
                threat_conf = threat_intelligence.aggregate_confidence
                reasoning.append(f"Threat Intel: {threat_conf:.0%}")
        
        # Behavioral confidence
        behavior_conf = 0.0
        if correlation_analysis:
            if correlation_analysis.patterns:
                behavior_conf = 0.8  # Patterns detected
                reasoning.append("Behavior: 80% (consistent patterns detected)")
        
        # Technical confidence
        technical_conf = 0.0
        if evidence_items:
            high_conf_evidence = [e for e in evidence_items if e.confidence > 0.8]
            technical_conf = len(high_conf_evidence) / len(evidence_items) if evidence_items else 0.5
            reasoning.append(f"Technical: {technical_conf:.0%} ({len(high_conf_evidence)}/{len(evidence_items)} high-confidence)")
        
        # Overall confidence
        weights = {
            'location': 0.25,
            'infrastructure': 0.20,
            'threat_intel': 0.25,
            'behavioral': 0.15,
            'technical': 0.15
        }
        
        overall = (
            location_conf * weights['location'] +
            infra_conf * weights['infrastructure'] +
            threat_conf * weights['threat_intel'] +
            behavior_conf * weights['behavioral'] +
            technical_conf * weights['technical']
        )
        
        return AttributionConfidence(
            location_confidence=location_conf,
            infrastructure_confidence=infra_conf,
            threat_intel_confidence=threat_conf,
            behavioral_confidence=behavior_conf,
            technical_confidence=technical_conf,
            overall_confidence=min(overall, 0.99),  # Never 100%
            confidence_reasoning=reasoning
        )
    
    def _generate_evidence_package(self, header_analysis, classifications, enrichment_results,
                                  threat_intelligence, geolocation_results, evidence_items, attacker_profile):
        """Generate law enforcement evidence package"""
        
        return {
            "package_type": "attacker_attribution",
            "generated": datetime.now().isoformat(),
            
            # Case information
            "email_metadata": {
                "from": header_analysis.email_from,
                "to": header_analysis.email_to,
                "subject": header_analysis.email_subject,
                "date": header_analysis.email_date,
                "message_id": header_analysis.message_id
            },
            
            # Attribution results
            "attribution": {
                "primary_origin": attacker_profile.primary_origin,
                "origin_confidence": float(attacker_profile.origin_confidence),
                "countries": attacker_profile.countries_used,
                "cities": attacker_profile.cities_detected,
                "estimated_team_size": list(attacker_profile.estimated_team_size)
            },
            
            # Technical evidence
            "technical_data": {
                "extracted_ips": list(classifications.keys()),
                "asns_involved": attacker_profile.unique_asns,
                "isps_identified": attacker_profile.unique_isps,
                "tor_detected": attacker_profile.uses_tor,
                "vpn_detected": attacker_profile.uses_vpn
            },
            
            # Threat assessment
            "threat_assessment": {
                "attack_type": attacker_profile.attack_type,
                "sophistication": attacker_profile.operational_security_level,
                "likely_motivation": attacker_profile.likely_motivation,
                "critical_ips": threat_intelligence.critical_ips if threat_intelligence else [],
                "c2_servers": threat_intelligence.c2_servers if threat_intelligence else []
            },
            
            # Evidence summary
            "evidence_count": len(evidence_items),
            "high_severity_evidence": len([e for e in evidence_items if e.severity in ["critical", "high"]])
        }
    
    def _generate_attribution_statement(self, profile, confidence):
        """Generate 1-2 sentence attribution statement"""
        
        conf_pct = int(confidence.overall_confidence * 100)
        
        if conf_pct >= 80:
            confidence_str = "high confidence"
        elif conf_pct >= 60:
            confidence_str = "moderate confidence"
        else:
            confidence_str = "low confidence"
        
        stmt = f"With {confidence_str} ({conf_pct}%), the attacker was located in {profile.primary_origin}. "
        stmt += f"The {profile.operational_security_level} operation used {len(profile.unique_asns)} unique ASNs across {len(profile.countries_used)} countries, "
        stmt += f"suggesting a team of {profile.estimated_team_size[0]}-{profile.estimated_team_size[1]} members."
        
        return stmt
    
    def _generate_recommendations(self, profile, confidence, threat_intel):
        """Generate recommended actions"""
        
        recommendations = []
        
        # Location-based recommendations
        if profile.primary_origin and profile.primary_origin != "Unknown":
            recommendations.append(f"Contact law enforcement in {profile.primary_origin.split(',')[1] if ',' in profile.primary_origin else 'detected region'}")
        
        # Infrastructure-based recommendations
        if profile.unique_isps > 3:
            recommendations.append("High ISP diversity detected - suggest coordinated international investigation")
        else:
            recommendations.append(f"Focus investigation on {profile.unique_asns[0] if profile.unique_asns else 'identified ASN'}")
        
        # Obfuscation recommendations
        if profile.uses_tor or profile.uses_vpn:
            recommendations.append("Block known Tor exit nodes and VPN services at perimeter")
        
        # Threat intel recommendations
        if threat_intel and threat_intel.c2_servers:
            recommendations.append(f"Block {len(threat_intel.c2_servers)} identified C2 servers")
        
        # Team size recommendations
        if profile.estimated_team_size[1] > 10:
            recommendations.append("Escalate to federal/international law enforcement - likely APT")
        
        return recommendations
    
    def _assess_diversity(self, isps, asns, countries):
        """Assess infrastructure diversity"""
        if isps >= 5 or asns >= 5 or countries >= 3:
            return "high"
        elif isps >= 3 or asns >= 3 or countries >= 2:
            return "medium"
        else:
            return "low"
    
    def _assess_opsec(self, uses_tor, uses_vpn, isps, diversity):
        """Assess operational security level"""
        if uses_tor and isps >= 5 and diversity == "high":
            return "nation-state"
        elif uses_tor or uses_vpn or (isps >= 3 and diversity == "medium"):
            return "professional"
        else:
            return "amateur"
    
    def _infer_attack_type(self, header_analysis):
        """Infer attack type from headers"""
        subject = header_analysis.email_subject.lower()
        
        if "urgent" in subject or "verify" in subject or "confirm" in subject:
            return "phishing"
        elif "wire" in subject or "payment" in subject or "invoice" in subject:
            return "business_email_compromise"
        elif "urgent action" in subject or "ransomware" in subject:
            return "ransomware"
        else:
            return "generic_phishing"
    
    def _infer_motivation(self, threat_intel, classifications):
        """Infer likely motivation"""
        if threat_intel:
            high_threat_count = len([c for c in classifications.values() if c.threat_score > 75])
            if high_threat_count > 0:
                return "financial"
        return "unknown"
    
    def _most_common_timezone(self, timezones):
        """Find most common timezone"""
        if not timezones:
            return None
        # Simple: return first, ideally should count occurrences
        return list(timezones)[0] if timezones else None
    
    def _assess_activity_hours(self, header_analysis, timezones):
        """Assess typical activity hours"""
        # Parse email datetime - simplified for now
        return "business"
    
    def _confidence_to_label(self, confidence):
        """Convert confidence score to label"""
        if confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        else:
            return "Low"
