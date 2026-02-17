#!/usr/bin/env python3
"""
HOSTING KEYWORDS INTEGRATION MODULE
Provides keywords for datacenter, residential ISP, and hosting provider classification
Fetches live data from online sources + known providers

Usage:
    from hosting_keywords_integration import get_hosting_keywords
    keywords = get_hosting_keywords()
    print(keywords['datacenter'])
"""

import json
import requests
from pathlib import Path
from typing import Dict, Set


# In-memory cache for keywords (avoid repeated fetches)
_keywords_cache = None


def _fetch_peeringdb_keywords() -> Dict[str, set]:
    """Fetch keywords directly from PeeringDB API"""
    result = {"datacenter": set(), "residential": set()}
    
    try:
        # Fetch organizations
        url = "https://api.peeringdb.com/api/org"
        params = {"depth": 1, "limit": 10000}
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if "data" in data:
            for org in data["data"]:
                if org.get("name"):
                    name = org["name"].lower().strip()
                    # Filter noise
                    if len(name) > 2 and not any(c in name for c in ['(', ')', '#', '"']):
                        result["datacenter"].add(name)
                        # Add individual words
                        for word in name.split():
                            if len(word) > 3 and word.isalpha():
                                result["datacenter"].add(word)
        
        print(f"[✓] PeeringDB: Fetched {len(data.get('data', []))} organizations")
    
    except Exception as e:
        print(f"[!] PeeringDB fetch failed: {e}")
    
    return result


def _fetch_peeringdb_networks() -> Dict[str, set]:
    """Fetch network keywords directly from PeeringDB"""
    result = {"datacenter": set(), "residential": set()}
    
    try:
        url = "https://api.peeringdb.com/api/net"
        params = {"depth": 1, "limit": 2000}  # Reduced from 5000 for speed
        
        response = requests.get(url, params=params, timeout=10)  # Reduced timeout
        response.raise_for_status()
        data = response.json()
        
        if "data" in data:
            count = 0
            for net in data["data"]:
                if net.get("name"):
                    name = net["name"].lower().strip()
                    if len(name) > 2 and not any(c in name for c in ['(', ')', '#', '"']):
                        if any(kw in name for kw in ["datacenter", "hosting", "aws", "azure", "cloud", "provider"]):
                            result["datacenter"].add(name)
                            count += 1
                        elif any(kw in name for kw in ["residential", "comcast", "verizon", "cox", "charter"]):
                            result["residential"].add(name)
            
            print(f"[✓] PeeringDB Networks: Classified {count} providers")
    
    except Exception as e:
        print(f"[!] PeeringDB Networks fetch failed (continuing): {e}")
    
    return result


def get_hosting_keywords(fetch_online: bool = True) -> dict:
    """
    Get hosting classification keywords
    
    Args:
        fetch_online: If True, fetch fresh data from online sources. If False, use hardcoded only.
    
    Returns:
        dict with 'datacenter', 'residential', 'hosting' keys containing keyword lists
    """
    
    global _keywords_cache
    
    # Hardcoded known providers (always available as fallback)
    known_providers = {
        "datacenter": {
            # Major cloud providers
            "amazon", "aws", "azure", "google", "google cloud", "digitalocean",
            "linode", "vultr", "scaleway", "hetzner", "ovh",
            
            # European datacenters
            "rackspace", "softlayer", "equinix", "zenlayer", "leaseweb",
            "infomaniak", "exoscale", "strato", "internap",
            
            # Asian/Chinese cloud
            "aliyun", "alibaba", "tencent", "baidu", "qcloud", "ksyun",
            
            # Russian/Eastern European
            "timeweb", "beget", "selectel", "firstvds", "fastvps",
            
            # Proxy/CDN
            "cloudflare", "akamai", "fastly", "cdn", "proxy", "vpn",
            
            # Generic datacenter terms
            "datacenter", "data center", "hosting", "colocation", "colo",
            "vps", "virtual private server", "managed hosting",
        },
        "residential": {
            # North American ISPs
            "comcast", "xfinity", "verizon", "fios", "at&t", "att",
            "cox", "charter", "spectrum", "century link", "centurylink",
            "frontier", "windstream", "mediacom", "megapath",
            
            # European ISPs
            "orange", "telefonica", "deutsche telekom", "vodafone",
            "swisscom", "telecom italia", "telia", "telenor",
            "bt", "btinternet", "virgin media", "talktalk", "plusnet", "sky",
            
            # Asian ISPs
            "ntt", "kddi", "softbank", "kt corp", "korea telecom",
            "telstra", "optus", "singnet", "starhub",
            
            # Russian/Eastern European ISPs
            "yandex", "rostelecom", "beeline", "megafon",
            
            # Generic residential terms
            "residential", "home internet", "consumer", "retail",
            "broadband", "adsl", "dsl", "cable", "fiber",
        },
        "hosting_provider": {
            # Web hosting companies
            "godaddy", "namecheap", "bluehost", "hostgator", "siteground",
            "kinsa", "wpengine", "flywheel", "pagely", "managed wordpress",
            
            # Hosting control panels
            "cpanel", "whm", "plesk", "directadmin", "ispconfig",
            
            # Generic hosting terms
            "hosting provider", "web host", "reseller", "managed service",
        }
    }
    
    # Initialize result with hardcoded providers
    result = {
        "datacenter": known_providers["datacenter"].copy(),
        "residential": known_providers["residential"].copy(),
        "hosting": known_providers["hosting_provider"].copy(),
    }
    
    # Fetch online if requested
    if fetch_online:
        try:
            print("[*] Fetching hosting keywords from online sources...")
            
            # Fetch from PeeringDB
            pdb_orgs = _fetch_peeringdb_keywords()
            result["datacenter"].update(pdb_orgs["datacenter"])
            result["residential"].update(pdb_orgs["residential"])
            
            # Fetch from PeeringDB Networks
            pdb_nets = _fetch_peeringdb_networks()
            result["datacenter"].update(pdb_nets["datacenter"])
            result["residential"].update(pdb_nets["residential"])
            
            print("[✓] Online keywords fetched successfully")
        
        except Exception as e:
            print(f"[!] Online fetch failed, using hardcoded keywords: {e}")
    
    # Convert sets to sorted lists for consistency
    return {
        "datacenter": sorted(list(result["datacenter"])),
        "residential": sorted(list(result["residential"])),
        "hosting": sorted(list(result["hosting"])),
    }


def classify_hosting_by_keywords(organization_name: str, keywords: dict = None) -> dict:
    """
    Classify hosting type based on keyword matching
    
    Args:
        organization_name: WHOIS organization name
        keywords: Keywords dict from get_hosting_keywords(). Fetches if None.
    
    Returns:
        dict with classification, confidence, and matching keywords
    """
    if not organization_name:
        return {"type": "UNKNOWN", "confidence": 0, "matches": []}
    
    if keywords is None:
        keywords = get_hosting_keywords()
    
    org_lower = organization_name.lower()
    results = {}
    
    for class_type in ["datacenter", "residential", "hosting"]:
        matches = [kw for kw in keywords[class_type] if kw in org_lower]
        if matches:
            results[class_type] = {
                "matches": matches,
                "confidence": min(100, len(matches) * 20),  # 20% per match
            }
    
    if not results:
        return {"type": "UNKNOWN", "confidence": 0, "matches": []}
    
    # Get best match
    best_match = max(results.items(), key=lambda x: x[1]["confidence"])
    return {
        "type": best_match[0].upper(),
        "confidence": best_match[1]["confidence"],
        "matches": best_match[1]["matches"],
        "all_results": results,
    }


if __name__ == "__main__":
    # Example usage
    print("=" * 80)
    print("HOSTING KEYWORDS INTEGRATION - LIVE ONLINE FETCH")
    print("=" * 80)
    
    keywords = get_hosting_keywords(fetch_online=True)
    
    print(f"\n✓ Datacenter keywords: {len(keywords['datacenter'])}")
    print(f"  Sample: {', '.join(keywords['datacenter'][:10])}")
    
    print(f"\n✓ Residential keywords: {len(keywords['residential'])}")
    print(f"  Sample: {', '.join(keywords['residential'][:10])}")
    
    print(f"\n✓ Hosting keywords: {len(keywords['hosting'])}")
    print(f"  Sample: {', '.join(keywords['hosting'][:5])}")
    
    # Test classification
    print("\n" + "=" * 80)
    print("CLASSIFICATION EXAMPLES")
    print("=" * 80)
    
    test_orgs = [
        "Amazon Web Services, Inc.",
        "Comcast Cable Communications, Inc.",
        "Google Cloud EMEA",
        "DigitalOcean",
        "Verizon Internet Services",
        "Hetzner Online GmbH",
        "Orange France",
    ]
    
    for org in test_orgs:
        result = classify_hosting_by_keywords(org, keywords)
        print(f"\nOrganization: {org}")
        print(f"  Type: {result['type']} ({result['confidence']}% confidence)")
        print(f"  Matches: {', '.join(result['matches'][:3]) if result['matches'] else 'None'}")
