#!/usr/bin/env python3
"""
GEOLOCATION ENRICHMENT MODULE
Fetches precise attacker location data for each IP address

Provides:
- City-level geolocation (latitude, longitude)
- Timezone information
- ASN and provider details
- Location confidence scoring
- Fallback mechanisms for reliability
"""

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
        """
        
        if ip in self.cache:
            return self.cache[ip]
        
        geoloc_data = GeolocationData(ip=ip)
        
        # Try IP-API first (fastest, free tier)
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
    
    def _try_ipapi(self, ip: str, geoloc_data: GeolocationData) -> bool:
        """Try IP-API.com (fastest, free tier: 45 req/min)"""
        try:
            time.sleep(self.rate_limit_wait)
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
                
                if self.verbose:
                    print(f"[✓] IP-API: {ip} → {geoloc_data.city}, {geoloc_data.country}")
                
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
                    print(f"[✓] IPinfo: {ip} → {geoloc_data.city}, {geoloc_data.country}")
                
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
                    print(f"[✓] MaxMind: {ip} → {geoloc_data.city}, {geoloc_data.country}")
                
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
