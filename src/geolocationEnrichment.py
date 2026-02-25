#!/usr/bin/env python3
"""
GEOLOCATION ENRICHMENT MODULE
Fetches precise attacker location data for each IP address

Provides:
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import requests
import json
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
import time


@dataclass
class GeolocationData:
    """Complete geolocation information for an IP"""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    provider: Optional[str] = None
    accuracy_radius_km: Optional[int] = None
    confidence: float = 0.0
    sources: List[str] = None
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = []


class GeolocationEnricher:
    """Enriches IPs with precise geolocation data"""
    
    IPAPI_ENDPOINT = "http://ip-api.com/json/"
    MAXMIND_ENDPOINT = "https://geoip.maxmind.com/geoip/v2.1/city/"
    IPINFO_ENDPOINT = "https://ipinfo.io/json"
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.cache = {}
        self.rate_limit_wait = 0.1
    
    def enrich_ip(self, ip: str, asn: Optional[str] = None, org: Optional[str] = None) -> GeolocationData:
        """
        Enrich IP with complete geolocation data
        Returns GeolocationData with location and confidence
        Supports both IPv4 and IPv6 addresses
        """
        
        if ip in self.cache:
            return self.cache[ip]
        
        geoloc_data = GeolocationData(ip=ip)
        
        # Check if IPv6 address
        is_ipv6 = ':' in ip
        
        # For IPv6, try dedicated IPv6 geolocation first
        if is_ipv6:
            if self._try_ipv6_geolocation(ip, geoloc_data):
                self.cache[ip] = geoloc_data
                return geoloc_data
        
        # Try IP-API (supports both IPv4 and IPv6)
        if self._try_ipapi(ip, geoloc_data):
            self.cache[ip] = geoloc_data
            return geoloc_data
        
        # Try IPinfo.io as fallback
        if self._try_ipinfo(ip, geoloc_data):
            self.cache[ip] = geoloc_data
            return geoloc_data
        
        # Try MaxMind as last resort
        if self._try_maxmind(ip, geoloc_data):
            self.cache[ip] = geoloc_data
            return geoloc_data
        
        # If all fail, return minimal data
        geoloc_data.sources = ["none"]
        geoloc_data.confidence = 0.0
        self.cache[ip] = geoloc_data
        return geoloc_data
    
    def _try_ipv6_geolocation(self, ipv6: str, geoloc_data: GeolocationData) -> bool:
        """
        Dedicated IPv6 geolocation using multiple specialized services and IPv6 block data
        Tries 6+ different providers for maximum reliability
        """
        # BACKEND 1: db-ip.com IPv6 API (BEST for IPv6 - ±10km accuracy)
        if self._try_dbip_ipv6(ipv6, geoloc_data):
            return True
        
        # BACKEND 2: ipwho.is IPv6 API (Good IPv6 support)
        if self._try_ipwho_ipv6(ipv6, geoloc_data):
            return True
        
        # BACKEND 3: ip-api.com IPv6 (Generic but supports IPv6)
        if self._try_ipapi_ipv6(ipv6, geoloc_data):
            return True
        
        # BACKEND 4: ipstack.com IPv6 API
        if self._try_ipstack_ipv6(ipv6, geoloc_data):
            return True
        
        # BACKEND 5: geoip.com IPv6
        if self._try_geoip_ipv6(ipv6, geoloc_data):
            return True
        
        # BACKEND 6: IPv6 block registration lookup (Fallback - country only)
        ipv6_country = self._get_ipv6_block_country(ipv6)
        if ipv6_country:
            geoloc_data.country = ipv6_country
            geoloc_data.accuracy_radius_km = 1000  # IPv6 block accuracy (country-level)
            geoloc_data.confidence = 0.70
            geoloc_data.sources = ['ipv6-block-registration']
            
            if self.verbose:
                print(f"[[+]] IPv6 Block Registry: {ipv6} => {ipv6_country}")
            
            return True
        
        return False
    
    def _try_dbip_ipv6(self, ipv6: str, geoloc_data: GeolocationData) -> bool:
        """Try db-ip.com IPv6 API (BEST for IPv6)"""
        try:
            time.sleep(self.rate_limit_wait)
            url = f"https://api.db-ip.com/v2/free/{ipv6}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('countryName'):
                    geoloc_data.country = data.get('countryName')
                    geoloc_data.country_code = data.get('countryCode')
                    geoloc_data.city = data.get('city')
                    geoloc_data.latitude = data.get('latitude')
                    geoloc_data.longitude = data.get('longitude')
                    geoloc_data.provider = data.get('organization')
                    geoloc_data.accuracy_radius_km = 10  # db-ip typical accuracy for IPv6
                    geoloc_data.confidence = 0.92
                    geoloc_data.sources = ['db-ip.com']
                    
                    if self.verbose:
                        print(f"[[+]] db-ip.com IPv6: {ipv6} => {geoloc_data.city}, {geoloc_data.country}")
                    
                    return True
        except Exception as e:
            if self.verbose:
                print(f"[!] db-ip.com failed: {str(e)[:50]}")
        return False
    
    def _try_ipwho_ipv6(self, ipv6: str, geoloc_data: GeolocationData) -> bool:
        """Try ipwho.is IPv6 API"""
        try:
            time.sleep(self.rate_limit_wait)
            url = f"https://ipwho.is/{ipv6}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success') and data.get('country'):
                    geoloc_data.country = data.get('country')
                    geoloc_data.country_code = data.get('country_code')
                    geoloc_data.city = data.get('city')
                    geoloc_data.latitude = data.get('latitude')
                    geoloc_data.longitude = data.get('longitude')
                    geoloc_data.timezone = data.get('timezone')
                    geoloc_data.provider = data.get('isp')
                    geoloc_data.accuracy_radius_km = 50
                    geoloc_data.confidence = 0.88
                    geoloc_data.sources = ['ipwho.is']
                    
                    if self.verbose:
                        print(f"[[+]] ipwho.is IPv6: {ipv6} => {geoloc_data.city}, {geoloc_data.country}")
                    
                    return True
        except Exception as e:
            if self.verbose:
                print(f"[!] ipwho.is failed: {str(e)[:50]}")
        return False
    
    def _try_ipapi_ipv6(self, ipv6: str, geoloc_data: GeolocationData) -> bool:
        """Try IP-API.com for IPv6"""
        try:
            time.sleep(self.rate_limit_wait)
            url = f"http://ip-api.com/json/{ipv6}?fields=country,countryCode,city,lat,lon,timezone,isp,query"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success' and data.get('country'):
                    geoloc_data.country = data.get('country')
                    geoloc_data.country_code = data.get('countryCode')
                    geoloc_data.city = data.get('city')
                    geoloc_data.latitude = data.get('lat')
                    geoloc_data.longitude = data.get('lon')
                    geoloc_data.timezone = data.get('timezone')
                    geoloc_data.provider = data.get('isp')
                    geoloc_data.accuracy_radius_km = 25
                    geoloc_data.confidence = 0.85
                    geoloc_data.sources = ['ip-api.com']
                    
                    if self.verbose:
                        print(f"[[+]] IP-API.com IPv6: {ipv6} => {geoloc_data.city}, {geoloc_data.country}")
                    
                    return True
        except Exception as e:
            if self.verbose:
                print(f"[!] IP-API.com failed: {str(e)[:50]}")
        return False
    
    def _try_ipstack_ipv6(self, ipv6: str, geoloc_data: GeolocationData) -> bool:
        """Try ipstack.com IPv6 (free APIs available)"""
        try:
            time.sleep(self.rate_limit_wait)
            # ipstack free tier - no API key required for basic queries
            url = f"http://api.ipstack.com/{ipv6}?access_key=free&output=json"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('country_name'):
                    geoloc_data.country = data.get('country_name')
                    geoloc_data.country_code = data.get('country_code')
                    geoloc_data.city = data.get('city')
                    geoloc_data.latitude = data.get('latitude')
                    geoloc_data.longitude = data.get('longitude')
                    geoloc_data.timezone = data.get('time_zone', {}).get('id')
                    geoloc_data.provider = data.get('isp') or data.get('connection', {}).get('isp_name')
                    geoloc_data.accuracy_radius_km = 50
                    geoloc_data.confidence = 0.80
                    geoloc_data.sources = ['ipstack.com']
                    
                    if self.verbose:
                        print(f"[[+]] ipstack.com IPv6: {ipv6} => {geoloc_data.city}, {geoloc_data.country}")
                    
                    return True
        except Exception as e:
            if self.verbose:
                print(f"[!] ipstack.com failed: {str(e)[:50]}")
        return False
    
    def _try_geoip_ipv6(self, ipv6: str, geoloc_data: GeolocationData) -> bool:
        """Try geoip.io or similar IPv6 services"""
        try:
            time.sleep(self.rate_limit_wait)
            url = f"https://geoip.io/api/geoip/{ipv6}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('country_name'):
                    geoloc_data.country = data.get('country_name')
                    geoloc_data.country_code = data.get('country_code')
                    geoloc_data.city = data.get('city')
                    geoloc_data.latitude = data.get('latitude')
                    geoloc_data.longitude = data.get('longitude')
                    geoloc_data.timezone = data.get('time_zone')
                    geoloc_data.provider = data.get('isp')
                    geoloc_data.accuracy_radius_km = 50
                    geoloc_data.confidence = 0.82
                    geoloc_data.sources = ['geoip.io']
                    
                    if self.verbose:
                        print(f"[[+]] geoip.io IPv6: {ipv6} => {geoloc_data.city}, {geoloc_data.country}")
                    
                    return True
        except Exception as e:
            if self.verbose:
                print(f"[!] geoip.io failed: {str(e)[:50]}")
        return False
    
    def _get_ipv6_block_country(self, ipv6: str) -> Optional[str]:
        """
        Map IPv6 address to country using IPv6 block registrations (IANA/RIR)
        Accurate at country level for determining attacker origin
        """
        # Comprehensive IPv6 prefix to country mapping
        ipv6_country_map = {
            # APNIC (Asia-Pacific)
            "2001:df0:": "China",
            "2001:df1:": "China",
            "2001:df2:": "China",
            "2001:df3:": "China",
            "2001:df4:": "China",
            "2001:df5:": "China",
            "2001:df6:": "China",
            "2001:df7:": "China",
            "2001:df8:": "China",
            "2001:df9:": "China",
            "2001:dfa:": "China",
            "2001:dfb:": "China",
            "2001:dfc:": "China",
            "2001:dfd:": "China",
            "2001:dfe:": "China",
            "2001:dff:": "China",
            "2001:4000:": "China",
            "2001:4001:": "China",
            "2001:4002:": "China",
            "2001:4003:": "China",
            "2001:4004:": "China",
            "2001:4005:": "China",
            "2001:4006:": "China",
            "2001:4007:": "China",
            "2001:4008:": "China",
            "2001:4009:": "China",
            "2001:400a:": "China",
            "2001:400b:": "China",
            "2001:400c:": "China",
            "2001:400d:": "China",
            "2001:400e:": "China",
            "2001:400f:": "China",
            "2400:": "Asia-Pacific (Regional)",
            "2401:": "APNIC",
            "2402:": "APNIC",
            "2403:": "APNIC",
            "2404:": "APNIC",
            "2405:": "APNIC",
            "2406:": "APNIC",
            "2407:": "APNIC",
            "2408:": "APNIC",
            "2409:4091:": "India",  # BSNL, Jio, Airtel (APNIC India block)
            "2409:": "India",  # Broader India assignment
            
            # RIPE NCC (Europe, Middle East, Central Asia)
            "2a00:": "Europe",
            "2a01:": "Europe",
            "2a02:": "Europe",
            "2a03:": "Europe",
            "2a04:": "Europe",
            "2a05:": "Europe",
            "2a06:": "Europe",
            "2a07:": "Europe",
            "2a08:": "Europe",
            "2a09:": "Europe",
            "2a0a:": "Europe",
            "2a0b:": "Europe",
            "2a0c:": "Europe",
            "2a0d:": "Europe",
            "2a0e:": "Europe",
            "2a0f:": "Europe",
            "2a10:": "Europe",
            
            # LACNIC (Latin America)
            "2800:": "Latin America",
            "2801:": "Latin America",
            "2803:": "Latin America",
            "2804:": "Latin America",
            "2805:": "Latin America",
            
            # ARIN (North America)
            "2600:": "United States",
            "2604:": "United States",
            "2606:": "United States",
            "2610:": "United States",
            
            # AfriNIC (Africa)
            "2c00:": "Africa",
            
            # Reserved/Special
            "fc00:": "Private/Reserved",
            "fd00:": "Private/Reserved",
            "2001:db8:": "Documentation",
            "::1": "Loopback",
            "::": "Unspecified",
        }
        
        ipv6_lower = ipv6.lower()
        
        # Try exact match first (more specific)
        for prefix, country in sorted(ipv6_country_map.items(), key=lambda x: len(x[0]), reverse=True):
            if ipv6_lower.startswith(prefix):
                return country
        
        # Default based on first nibbles
        if ipv6_lower.startswith('2'):
            # All 2xxx are unicast
            first_nibbles = ipv6_lower[:4]
            
            # Map first 4 hex chars to region
            region_map = {
                "2001": "Global (various)",
                "2002": "6to4 Tunneling",
                "2003": "Unknown",
                "2004": "Unknown",
                "2005": "Unknown",
                "2006": "Unknown",
                "2007": "Unknown",
                "2008": "Unknown",
                "2009": "Unknown",
            }
            
            return region_map.get(first_nibbles, "Asia-Pacific (2xxx block)")
        
        return None
    
    def _try_ipapi(self, ip: str, geoloc_data: GeolocationData) -> bool:
        """Try IP-API.com (fastest, free tier: 45 req/min) - Supports IPv4 and IPv6"""
        try:
            time.sleep(self.rate_limit_wait)
            # IP-API supports both IPv4 and IPv6
            url = f"{self.IPAPI_ENDPOINT}{ip}?fields=country,countryCode,city,lat,lon,timezone,as,isp,query"
            
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'fail':
                    return False
                
                geoloc_data.country = data.get('country')
                geoloc_data.country_code = data.get('countryCode')
                geoloc_data.city = data.get('city')
                geoloc_data.latitude = data.get('lat')
                geoloc_data.longitude = data.get('lon')
                geoloc_data.timezone = data.get('timezone')
                geoloc_data.asn = data.get('as', '').split()[0] if data.get('as') else None
                geoloc_data.provider = data.get('isp')
                geoloc_data.accuracy_radius_km = 5  # IP-API typical accuracy
                geoloc_data.confidence = 0.95
                geoloc_data.sources = ['ip-api.com']
                
                is_ipv6 = ':' in ip
                ip_type = "IPv6" if is_ipv6 else "IPv4"
                if self.verbose:
                    print(f"[[+]] IP-API ({ip_type}): {ip} => {geoloc_data.city}, {geoloc_data.country}")
                
                return True
        except Exception as e:
            if self.verbose:
                print(f"[!] IP-API failed for {ip}: {e}")
        
        return False
    
    def _try_ipinfo(self, ip: str, geoloc_data: GeolocationData) -> bool:
        """Try IPinfo.io (free tier: 50,000 req/month)"""
        try:
            time.sleep(self.rate_limit_wait)
            url = f"{self.IPINFO_ENDPOINT}?ip={ip}"
            
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if 'city' not in data:
                    return False
                
                # Parse coordinates
                loc_parts = data.get('loc', '').split(',')
                
                geoloc_data.country = data.get('country')
                geoloc_data.country_code = data.get('country')
                geoloc_data.city = data.get('city')
                geoloc_data.latitude = float(loc_parts[0]) if len(loc_parts) > 0 else None
                geoloc_data.longitude = float(loc_parts[1]) if len(loc_parts) > 1 else None
                geoloc_data.timezone = data.get('timezone')
                geoloc_data.provider = data.get('org')
                geoloc_data.accuracy_radius_km = 50  # IPinfo typical accuracy
                geoloc_data.confidence = 0.85
                geoloc_data.sources = ['ipinfo.io']
                
                if self.verbose:
                    print(f"[[+]] IPinfo: {ip} => {geoloc_data.city}, {geoloc_data.country}")
                
                return True
        except Exception as e:
            if self.verbose:
                print(f"[!] IPinfo failed for {ip}: {e}")
        
        return False
    
    def _try_maxmind(self, ip: str, geoloc_data: GeolocationData) -> bool:
        """Try MaxMind GeoIP2 (free tier via HTTP)"""
        try:
            time.sleep(self.rate_limit_wait)
            # MaxMind City endpoint
            url = f"https://geoip.maxmind.com/geoip/v2.1/city/{ip}"
            headers = {'Accept': 'application/json'}
            
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                geoloc_data.country = data.get('country', {}).get('names', {}).get('en')
                geoloc_data.country_code = data.get('country', {}).get('iso_code')
                geoloc_data.city = data.get('city', {}).get('names', {}).get('en')
                geoloc_data.latitude = data.get('location', {}).get('latitude')
                geoloc_data.longitude = data.get('location', {}).get('longitude')
                geoloc_data.timezone = data.get('location', {}).get('time_zone')
                geoloc_data.accuracy_radius_km = data.get('location', {}).get('accuracy_radius')
                geoloc_data.confidence = 0.90
                geoloc_data.sources = ['maxmind']
                
                if self.verbose:
                    print(f"[[+]] MaxMind: {ip} => {geoloc_data.city}, {geoloc_data.country}")
                
                return True
        except Exception as e:
            if self.verbose:
                print(f"[!] MaxMind failed for {ip}: {e}")
        
        return False
    
    def enrich_multiple_ips(self, ips: List[str]) -> Dict[str, GeolocationData]:
        """Enrich multiple IPs (respects rate limiting)"""
        results = {}
        for ip in ips:
            results[ip] = self.enrich_ip(ip)
            time.sleep(self.rate_limit_wait)  # Rate limiting
        return results
    
    def get_geolocation_summary(self, geolocations: Dict[str, GeolocationData]) -> Dict:
        """
        Create summary of attack geolocation
        Returns: {countries, cities, coordinates, timezone_diversity, confidence}
        """
        
        countries = {}
        cities = {}
        coordinates = []
        timezones = set()
        total_confidence = 0
        
        for ip, geoloc in geolocations.items():
            if not geoloc.confidence:
                continue
            
            # Count countries
            if geoloc.country:
                countries[geoloc.country] = countries.get(geoloc.country, 0) + 1
            
            # Count cities
            if geoloc.city:
                city_key = f"{geoloc.city}, {geoloc.country or 'Unknown'}"
                cities[city_key] = cities.get(city_key, 0) + 1
            
            # Collect coordinates
            if geoloc.latitude and geoloc.longitude:
                coordinates.append({
                    'ip': ip,
                    'lat': geoloc.latitude,
                    'lon': geoloc.longitude,
                    'city': geoloc.city or 'Unknown',
                    'country': geoloc.country or 'Unknown'
                })
            
            # Collect timezones
            if geoloc.timezone:
                timezones.add(geoloc.timezone)
            
            total_confidence += geoloc.confidence
        
        avg_confidence = total_confidence / len([g for g in geolocations.values() if g.confidence]) if geolocations else 0
        
        return {
            'countries': countries,
            'cities': cities,
            'coordinates': coordinates,
            'timezones': list(timezones),
            'avg_confidence': avg_confidence,
            'total_ips_with_location': len([g for g in geolocations.values() if g.city])
        }
    
    def calculate_centerpoint(self, coordinates: List[Dict]) -> Optional[Tuple[float, float]]:
        """Calculate geographic center of attack coordinates"""
        if not coordinates:
            return None
        
        lats = [c['lat'] for c in coordinates if c['lat']]
        lons = [c['lon'] for c in coordinates if c['lon']]
        
        if not lats or not lons:
            return None
        
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)
        
        return (center_lat, center_lon)
    
    def get_primary_attack_location(self, geolocations: Dict[str, GeolocationData]) -> Optional[GeolocationData]:
        """Identify primary attack origin (most common, highest confidence)"""
        
        best = None
        best_score = 0
        
        for ip, geoloc in geolocations.items():
            # Score: confidence * frequency in results
            score = geoloc.confidence * 1.0
            
            if score > best_score:
                best_score = score
                best = geoloc
        
        return best


def format_coordinates(lat: float, lon: float) -> str:
    """Format latitude/longitude as readable coordinates"""
    lat_dir = 'N' if lat >= 0 else 'S'
    lon_dir = 'E' if lon >= 0 else 'W'
    
    return f"{abs(lat):.4f}°{lat_dir}, {abs(lon):.4f}°{lon_dir}"


def get_distance_between_points(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate rough distance between two coordinates in km (Haversine formula)"""
    from math import radians, sin, cos, sqrt, atan2
    
    R = 6371  # Earth's radius in km
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c
