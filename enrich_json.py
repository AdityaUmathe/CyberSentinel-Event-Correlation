#!/usr/bin/env python3
"""
Enhanced Log Enrichment Pipeline with Network Intelligence
Adds ASN, cloud provider detection, IP reputation, Tor detection, and QUIC detection.

All enrichment uses FREE, OFFLINE data sources only - no external APIs.

Requirements:
    pip install geoip2 --break-system-packages

Databases needed:
    - GeoLite2-City.mmdb (for GeoIP)
    - GeoLite2-ASN.mmdb (for ASN lookup)
    - tor-exit-nodes.txt (Tor exit node list)
    - malicious-ips.txt (IP reputation data)

Usage:
    python3 enrich_logs_network.py --input normalized.jsonl --output enriched.jsonl
"""

import argparse
import hashlib
import ipaddress
import json
import sys
import math
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class NetworkIntelligence:
    """Offline network intelligence using local databases."""
    
    # Cloud provider ASN mapping (major providers only)
    CLOUD_PROVIDERS = {
        # Google Cloud / Google
        15169: "google", 16550: "google", 36040: "google", 36384: "google", 36385: "google",
        43515: "google", 139190: "google", 36492: "google", 19527: "google", 395973: "google",
        
        # AWS
        16509: "aws", 14618: "aws", 8987: "aws", 10124: "aws", 17493: "aws",
        38895: "aws", 58588: "aws", 62785: "aws", 133788: "aws", 135971: "aws",
        
        # Microsoft Azure
        8075: "azure", 12076: "azure", 8068: "azure", 3598: "azure", 6584: "azure",
        
        # Cloudflare
        13335: "cloudflare", 209242: "cloudflare",
        
        # DigitalOcean
        14061: "digitalocean", 393406: "digitalocean",
        
        # OVH
        16276: "ovh",
        
        # Linode/Akamai
        63949: "linode", 20473: "linode",
        
        # Vultr
        20473: "vultr", 64515: "vultr",
        
        # Hetzner
        24940: "hetzner", 213230: "hetzner",
    }
    
    def __init__(self, 
                 asn_db_path: Optional[str] = None,
                 tor_list_path: Optional[str] = None,
                 reputation_db_path: Optional[str] = None):
        
        # ASN database
        self.asn_reader = None
        if asn_db_path and GEOIP_AVAILABLE:
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                print(f"✓ ASN database loaded: {asn_db_path}", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load ASN database: {e}", file=sys.stderr)
        
        # Tor exit nodes
        self.tor_exits: Set[str] = set()
        if tor_list_path and os.path.exists(tor_list_path):
            try:
                with open(tor_list_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.tor_exits.add(line)
                print(f"✓ Tor exit nodes loaded: {len(self.tor_exits)} nodes", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load Tor list: {e}", file=sys.stderr)
        
        # IP reputation database
        self.malicious_ips: Dict[str, float] = {}  # ip -> confidence
        if reputation_db_path and os.path.exists(reputation_db_path):
            try:
                with open(reputation_db_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',')
                            if len(parts) >= 2:
                                ip = parts[0].strip()
                                confidence = float(parts[1].strip())
                                self.malicious_ips[ip] = confidence
                            elif len(parts) == 1:
                                # Default confidence if not specified
                                self.malicious_ips[parts[0].strip()] = 0.8
                print(f"✓ IP reputation loaded: {len(self.malicious_ips)} malicious IPs", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load reputation database: {e}", file=sys.stderr)
    
    def lookup_asn(self, ip: str, ip_type: str) -> Optional[Dict[str, Any]]:
        """Lookup ASN information for an IP."""
        if not self.asn_reader or not ip or ip_type != "public":
            return None
        
        try:
            response = self.asn_reader.asn(ip)
            return {
                "number": response.autonomous_system_number,
                "org": response.autonomous_system_organization
            }
        except (geoip2.errors.AddressNotFoundError, AttributeError):
            return None
        except Exception as e:
            return None
    
    def get_provider(self, asn_number: Optional[int]) -> Optional[str]:
        """Get cloud provider from ASN."""
        if asn_number is None:
            return None
        return self.CLOUD_PROVIDERS.get(asn_number)
    
    def check_tor_exit(self, ip: str) -> bool:
        """Check if IP is a Tor exit node."""
        return ip in self.tor_exits
    
    def check_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation."""
        if ip in self.malicious_ips:
            return {
                "status": "malicious",
                "confidence": self.malicious_ips[ip]
            }
        return None
    
    def detect_quic(self, protocol: Optional[str], port: Optional[int], asn_number: Optional[int]) -> Optional[Dict[str, Any]]:
        """Detect QUIC protocol based on UDP + port 443."""
        if not protocol or not port:
            return None
        
        # QUIC detection: UDP + port 443
        if protocol.upper() in ["UDP", "17"] and port == 443:
            quic_data = {
                "is_quic": True,
                "quic_hint": "likely_http3"
            }
            
            # Google QUIC specific detection
            if asn_number == 15169:  # Google ASN
                quic_data["quic_provider"] = "google"
            
            return quic_data
        
        return None
    
    def close(self):
        """Close database readers."""
        if self.asn_reader:
            self.asn_reader.close()


class RollingCounter:
    """Bounded rolling counter with time-based eviction."""
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.events = defaultdict(deque)
    
    def increment(self, key: str, timestamp: datetime) -> int:
        if key not in self.events:
            self.events[key] = deque()
        
        self.events[key].append(timestamp)
        
        cutoff = timestamp - timedelta(seconds=self.window_seconds)
        while self.events[key] and self.events[key][0] < cutoff:
            self.events[key].popleft()
        
        count = len(self.events[key])
        if count == 0:
            del self.events[key]
        
        return count


class GeoTracker:
    """Track geographic patterns for impossible travel detection."""
    
    def __init__(self):
        self.last_location = {}
    
    def update_location(self, key: str, country: str, city: str, lat: float, lon: float, timestamp: datetime) -> Optional[Dict]:
        if key in self.last_location:
            last = self.last_location[key]
            time_diff = (timestamp - last["time"]).total_seconds() / 3600
            distance_km = self._calculate_distance(last["lat"], last["lon"], lat, lon)
            
            if time_diff > 0 and distance_km > 0:
                max_speed_kmh = distance_km / time_diff
                is_impossible = max_speed_kmh > 1000
                
                result = {
                    "is_impossible_travel": is_impossible,
                    "previous_location": f"{last['city']}, {last['country']}",
                    "current_location": f"{city}, {country}",
                    "distance_km": round(distance_km, 2),
                    "time_diff_hours": round(time_diff, 2),
                    "required_speed_kmh": round(max_speed_kmh, 2) if time_diff > 0 else 0
                }
            else:
                result = None
        else:
            result = None
        
        self.last_location[key] = {
            "country": country, "city": city,
            "lat": lat, "lon": lon, "time": timestamp
        }
        
        cutoff = timestamp - timedelta(hours=24)
        to_remove = [k for k, v in self.last_location.items() if v["time"] < cutoff]
        for k in to_remove:
            del self.last_location[k]
        
        return result
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371.0
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c


class BehaviorTracker:
    """Track behavioral patterns for anomaly detection."""
    
    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds
        self.src_destinations = defaultdict(lambda: {"ips": set(), "ports": set(), "last_seen": None})
        self.failures = defaultdict(deque)
    
    def update_destination_diversity(self, src_ip: str, dest_ip: str, dest_port: int, timestamp: datetime) -> Dict[str, int]:
        if src_ip:
            self.src_destinations[src_ip]["ips"].add(dest_ip if dest_ip else "unknown")
            self.src_destinations[src_ip]["ports"].add(dest_port if dest_port else 0)
            self.src_destinations[src_ip]["last_seen"] = timestamp
        
        cutoff = timestamp - timedelta(seconds=self.window_seconds)
        to_remove = [k for k, v in self.src_destinations.items() 
                     if v["last_seen"] and v["last_seen"] < cutoff]
        for k in to_remove:
            del self.src_destinations[k]
        
        if src_ip and src_ip in self.src_destinations:
            return {
                "unique_dest_ips": len(self.src_destinations[src_ip]["ips"]),
                "unique_dest_ports": len(self.src_destinations[src_ip]["ports"])
            }
        return {"unique_dest_ips": 0, "unique_dest_ports": 0}
    
    def track_failure(self, entity_key: str, timestamp: datetime) -> int:
        if entity_key not in self.failures:
            self.failures[entity_key] = deque()
        
        self.failures[entity_key].append(timestamp)
        
        cutoff = timestamp - timedelta(seconds=300)
        while self.failures[entity_key] and self.failures[entity_key][0] < cutoff:
            self.failures[entity_key].popleft()
        
        return len(self.failures[entity_key])


class LogEnricher:
    """Enhanced log enrichment engine with network intelligence."""
    
    def __init__(self, 
                 counter_window_seconds: int = 300, 
                 overwrite: bool = False,
                 geoip_db_path: Optional[str] = None,
                 asn_db_path: Optional[str] = None,
                 tor_list_path: Optional[str] = None,
                 reputation_db_path: Optional[str] = None):
        
        self.overwrite = overwrite
        self.counter_window = counter_window_seconds
        
        # Rolling counters
        self.src_ip_counter = RollingCounter(counter_window_seconds)
        self.user_counter = RollingCounter(counter_window_seconds)
        self.host_counter = RollingCounter(counter_window_seconds)
        self.signature_counter = RollingCounter(counter_window_seconds)
        self.dest_ip_counter = RollingCounter(counter_window_seconds)
        self.dest_port_counter = RollingCounter(counter_window_seconds)
        
        # Behavioral tracking
        self.behavior_tracker = BehaviorTracker(window_seconds=3600)
        self.geo_tracker = GeoTracker()
        
        # GeoIP database
        self.geoip_reader = None
        self.geo_cache = {}
        
        if geoip_db_path and GEOIP_AVAILABLE:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                print(f"✓ GeoIP database loaded: {geoip_db_path}", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load GeoIP database: {e}", file=sys.stderr)
        
        # Network intelligence
        self.network_intel = NetworkIntelligence(
            asn_db_path=asn_db_path,
            tor_list_path=tor_list_path,
            reputation_db_path=reputation_db_path
        )
    
    def lookup_geo(self, ip: str, ip_type: str) -> Optional[Dict[str, Any]]:
        if not self.geoip_reader or not ip or ip_type != "public":
            return None
        
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        try:
            response = self.geoip_reader.city(ip)
            
            geo_data = {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name if response.city.name else "Unknown",
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
                "is_in_eu": response.country.is_in_european_union,
            }
            
            self.geo_cache[ip] = geo_data
            
            if len(self.geo_cache) > 10000:
                for _ in range(1000):
                    self.geo_cache.pop(next(iter(self.geo_cache)))
            
            return geo_data
            
        except (geoip2.errors.AddressNotFoundError, AttributeError):
            return None
        except Exception:
            return None
    
    def classify_ip(self, ip_str: Optional[str]) -> str:
        if not ip_str:
            return "unknown"
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if ip.is_loopback:
                return "loopback"
            elif ip.is_private:
                return "private"
            elif ip.is_multicast:
                return "multicast"
            elif ip.is_link_local:
                return "linklocal"
            elif not ip.is_reserved:
                return "public"
            else:
                return "unknown"
        except (ValueError, AttributeError):
            return "unknown"
    
    def extract_temporal_context(self, timestamp: datetime) -> Dict[str, Any]:
        return {
            "hour_of_day": timestamp.hour,
            "day_of_week": timestamp.strftime("%A"),
            "day_of_month": timestamp.day,
            "is_business_hours": 9 <= timestamp.hour < 17 and timestamp.weekday() < 5,
            "is_weekend": timestamp.weekday() >= 5,
            "is_night": timestamp.hour < 6 or timestamp.hour >= 22,
        }
    
    def normalize_protocol(self, protocol: Optional[str]) -> str:
        if not protocol:
            return "unknown"
        
        protocol = protocol.upper()
        protocol_map = {
            "TCP": "tcp", "UDP": "udp", "ICMP": "icmp",
            "HTTP": "http", "HTTPS": "https", "DNS": "dns",
            "SSH": "ssh", "FTP": "ftp", "SMTP": "smtp",
            "6": "tcp", "17": "udp", "1": "icmp",
        }
        return protocol_map.get(protocol, protocol.lower())
    
    def normalize_action(self, event: Dict[str, Any]) -> str:
        outcome = event.get("event_outcome", "").lower()
        action = event.get("event_action", "").lower()
        raw_action = event.get("context", {}).get("raw_event", {}).get("data", {}).get("action", "").lower()
        
        if outcome == "success" or raw_action in ["pass", "allow", "accept", "permit"]:
            return "allowed"
        elif outcome == "failure" or raw_action in ["deny", "drop", "reject"]:
            return "denied"
        elif "block" in action or "block" in raw_action:
            return "blocked"
        else:
            return "unknown"
    
    def infer_host_role(self, event: Dict[str, Any]) -> Optional[str]:
        host = event.get("host", {})
        existing_type = host.get("type", "")
        os_family = host.get("os", {}).get("family", "")
        
        known_types = ["firewall", "router", "switch", "server", "workstation", "endpoint", "domain_controller"]
        if existing_type and any(kt in existing_type.lower() for kt in known_types):
            return None
        
        event_category = event.get("event_category", "")
        subject = event.get("subject", {})
        
        if os_family == "network_os" and event_category == "network":
            if not existing_type or existing_type == "unknown":
                return "network_device"
        
        if event_category == "auth" and subject.get("name"):
            if not existing_type or existing_type == "unknown":
                return "endpoint"
        
        return None
    
    def compute_fingerprint(self, event: Dict[str, Any]) -> str:
        subject = event.get("subject", {})
        obj = event.get("object", {})
        host = event.get("host", {})
        security = event.get("security", {})
        
        components = [
            event.get("event_category", ""),
            event.get("event_action", ""),
            event.get("event_outcome", ""),
            subject.get("name", ""),
            subject.get("ip", ""),
            obj.get("name", ""),
            obj.get("ip", ""),
            host.get("id", ""),
            security.get("signature_id", ""),
        ]
        
        fingerprint_input = "|".join(str(c) for c in components)
        return hashlib.sha1(fingerprint_input.encode("utf-8")).hexdigest()
    
    def detect_anomalies(
        self,
        counters: Dict[str, int],
        diversity: Dict[str, int],
        normalized_action: str,
        src_ip_type: str,
        dest_ip_type: str,
        temporal: Dict[str, Any],
        geo_data: Optional[Dict[str, Any]] = None,
        impossible_travel: Optional[Dict[str, Any]] = None,
        network_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        anomalies = {
            "is_high_frequency": counters.get("src_ip_5m", 0) > 50,
            "is_port_scan": diversity.get("unique_dest_ports", 0) > 15,
            "is_lateral_movement": diversity.get("unique_dest_ips", 0) > 20,
            "is_brute_force": counters.get("user_5m", 0) > 15 and normalized_action in ["denied", "blocked"],
            "is_data_exfil": (
                src_ip_type == "private" and 
                dest_ip_type == "public" and 
                counters.get("src_ip_5m", 0) > 30
            ),
            "is_after_hours": not temporal.get("is_business_hours", True),
        }
        
        if geo_data:
            anomalies["cross_continent"] = geo_data.get("cross_continent", False)
            anomalies["cross_border"] = geo_data.get("cross_border", False)
        
        if impossible_travel:
            anomalies["is_impossible_travel"] = impossible_travel.get("is_impossible_travel", False)
        
        # Network intelligence anomalies
        if network_intel:
            if network_intel.get("tor_detected"):
                anomalies["is_tor_traffic"] = True
            if network_intel.get("threat_detected"):
                anomalies["is_malicious_ip"] = True
        
        anomalies["anomaly_count"] = sum(1 for k, v in anomalies.items() if k != "anomaly_count" and v)
        
        return anomalies
    
    def compute_risk_score(
        self,
        event: Dict[str, Any],
        src_ip_type: str,
        dest_ip_type: str,
        counters: Dict[str, int],
        normalized_action: str,
        diversity: Dict[str, int],
        anomalies: Dict[str, Any],
        failure_count: int,
        geo_data: Optional[Dict[str, Any]] = None,
        network_intel: Optional[Dict[str, Any]] = None
    ) -> int:
        security = event.get("security", {})
        severity = security.get("severity")
        
        score = 0
        if severity is not None:
            try:
                score = min(int(severity) * 10, 50)
            except (ValueError, TypeError):
                score = 0
        
        if normalized_action in ["denied", "blocked"]:
            score += 15
        
        if failure_count > 10:
            score += 20
        elif failure_count > 5:
            score += 10
        
        if src_ip_type == "public":
            score += 15
        if dest_ip_type == "public" and src_ip_type == "private":
            score += 10
        
        if anomalies.get("is_port_scan"):
            score += 20
        if anomalies.get("is_lateral_movement"):
            score += 20
        if anomalies.get("is_high_frequency"):
            score += 15
        if anomalies.get("is_brute_force"):
            score += 25
        if anomalies.get("is_data_exfil"):
            score += 20
        if anomalies.get("is_after_hours") and anomalies.get("anomaly_count", 0) > 1:
            score += 10
        
        if geo_data:
            if geo_data.get("cross_border"):
                score += 10
            if geo_data.get("distance_km", 0) > 5000:
                score += 5
        
        if anomalies.get("is_impossible_travel"):
            score += 25
        
        # Network intelligence scoring
        if network_intel:
            if network_intel.get("tor_detected"):
                score += 15
            if network_intel.get("threat_detected"):
                threat_confidence = network_intel.get("threat_confidence", 0.0)
                score += int(30 * threat_confidence)
        
        return min(score, 100)
    
    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    
    def update_counters(self, event: Dict[str, Any], timestamp: datetime) -> Dict[str, int]:
        subject = event.get("subject", {})
        obj = event.get("object", {})
        host = event.get("host", {})
        security = event.get("security", {})
        
        counters = {}
        
        src_ip = subject.get("ip")
        if src_ip:
            counters["src_ip_5m"] = self.src_ip_counter.increment(src_ip, timestamp)
        
        dest_ip = obj.get("ip")
        if dest_ip:
            counters["dest_ip_5m"] = self.dest_ip_counter.increment(dest_ip, timestamp)
        
        dest_port = obj.get("port")
        if dest_port:
            counters["dest_port_5m"] = self.dest_port_counter.increment(str(dest_port), timestamp)
        
        user = subject.get("name")
        if user:
            counters["user_5m"] = self.user_counter.increment(user, timestamp)
        
        host_id = host.get("id")
        if host_id:
            counters["host_5m"] = self.host_counter.increment(host_id, timestamp)
        
        sig_id = security.get("signature_id")
        if sig_id:
            counters["signature_5m"] = self.signature_counter.increment(str(sig_id), timestamp)
        
        return counters
    
    def build_enrichment_section(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event_time_str = event.get("event_time", "")
        event_time = self.parse_timestamp(event_time_str)
        if not event_time:
            event_time = datetime.utcnow()
        
        subject = event.get("subject", {})
        obj = event.get("object", {})
        security = event.get("security", {})
        network = event.get("network", {})
        event_category = event.get("event_category", "")
        
        src_ip = subject.get("ip")
        dest_ip = obj.get("ip")
        dest_port = obj.get("port")
        protocol = network.get("protocol")
        
        # Handle missing protocol - default to "unknown" to prevent None errors
        if not protocol:
            protocol = "unknown"
        
        # Temporal
        temporal = self.extract_temporal_context(event_time)
        
        # Flags
        flags = {
            "is_auth_event": event_category == "auth",
            "is_network_event": event_category == "network",
            "is_process_event": event_category == "process",
            "is_file_event": event_category == "file",
            "is_alert": security.get("signature_id") is not None,
        }
        
        # IP classification
        src_ip_type = self.classify_ip(src_ip)
        dest_ip_type = self.classify_ip(dest_ip)
        
        ip_classification = {
            "src_ip_type": src_ip_type,
            "dest_ip_type": dest_ip_type,
            "is_internal_traffic": (
                src_ip and dest_ip and
                src_ip_type == "private" and dest_ip_type == "private"
            ),
            "is_external_inbound": src_ip_type == "public" and dest_ip_type == "private",
            "is_external_outbound": src_ip_type == "private" and dest_ip_type == "public",
        }
        
        # Network intelligence enrichment
        network_intel_data = {}
        
        # ASN lookup for source IP
        src_asn = self.network_intel.lookup_asn(src_ip, src_ip_type)
        if src_asn:
            network_intel_data["src_asn"] = src_asn
            
            # Cloud provider detection
            provider = self.network_intel.get_provider(src_asn.get("number"))
            if provider:
                network_intel_data["src_provider"] = provider
        
        # ASN lookup for dest IP
        dest_asn = self.network_intel.lookup_asn(dest_ip, dest_ip_type)
        if dest_asn:
            network_intel_data["dest_asn"] = dest_asn
            
            provider = self.network_intel.get_provider(dest_asn.get("number"))
            if provider:
                network_intel_data["dest_provider"] = provider
        
        # Tor detection for source IP - ALWAYS include
        if src_ip and src_ip_type == "public":
            is_tor = self.network_intel.check_tor_exit(src_ip)
            network_intel_data["src_tor"] = {"is_exit_node": is_tor}
            if is_tor:
                network_intel_data["tor_detected"] = True
        
        # Tor detection for dest IP - ALWAYS include
        if dest_ip and dest_ip_type == "public":
            is_tor = self.network_intel.check_tor_exit(dest_ip)
            network_intel_data["dest_tor"] = {"is_exit_node": is_tor}
            if is_tor:
                network_intel_data["tor_detected"] = True
        
        # IP reputation for source IP - ALWAYS include
        if src_ip and src_ip_type == "public":
            src_reputation = self.network_intel.check_reputation(src_ip)
            if src_reputation:
                network_intel_data["src_reputation"] = {
                    "ip_reputation": src_reputation["status"],
                    "confidence": src_reputation["confidence"]
                }
                network_intel_data["threat_detected"] = True
                network_intel_data["threat_confidence"] = src_reputation["confidence"]
            else:
                network_intel_data["src_reputation"] = {
                    "ip_reputation": "clean",
                    "confidence": 0.0
                }
        
        # IP reputation for dest IP - ALWAYS include
        if dest_ip and dest_ip_type == "public":
            dest_reputation = self.network_intel.check_reputation(dest_ip)
            if dest_reputation:
                network_intel_data["dest_reputation"] = {
                    "ip_reputation": dest_reputation["status"],
                    "confidence": dest_reputation["confidence"]
                }
                network_intel_data["threat_detected"] = True
                network_intel_data["threat_confidence"] = max(
                    network_intel_data.get("threat_confidence", 0.0),
                    dest_reputation["confidence"]
                )
            else:
                network_intel_data["dest_reputation"] = {
                    "ip_reputation": "clean",
                    "confidence": 0.0
                }
        
        # QUIC detection - ALWAYS include
        src_asn_number = src_asn.get("number") if src_asn else None
        dest_asn_number = dest_asn.get("number") if dest_asn else None
        
        quic_data = self.network_intel.detect_quic(protocol, dest_port, dest_asn_number)
        if quic_data:
            network_intel_data["quic"] = quic_data
        else:
            # Explicitly show QUIC was checked but not detected
            if not protocol or protocol == "unknown":
                quic_reason = "no_protocol"
            elif protocol.upper() not in ["UDP", "17"] or dest_port != 443:
                quic_reason = "not_udp_443"
            else:
                quic_reason = "criteria_not_met"
            network_intel_data["quic"] = {
                "is_quic": False,
                "reason": quic_reason
            }
        
        # GeoIP lookup
        geo_section = None
        impossible_travel_data = None
        
        if self.geoip_reader:
            src_geo = self.lookup_geo(src_ip, src_ip_type)
            dest_geo = self.lookup_geo(dest_ip, dest_ip_type)
            
            if src_geo or dest_geo:
                geo_section = {}
                
                if src_geo:
                    geo_section["src"] = src_geo
                
                if dest_geo:
                    geo_section["dest"] = dest_geo
                
                if src_geo and dest_geo:
                    # Only calculate distance if both locations have coordinates
                    if (src_geo.get("latitude") is not None and src_geo.get("longitude") is not None and
                        dest_geo.get("latitude") is not None and dest_geo.get("longitude") is not None):
                        distance = self.geo_tracker._calculate_distance(
                            src_geo["latitude"], src_geo["longitude"],
                            dest_geo["latitude"], dest_geo["longitude"]
                        )
                        geo_section["distance_km"] = round(distance, 2)
                        geo_section["cross_continent"] = distance > 3000
                    
                    # Country comparison can be done even without coordinates
                    geo_section["same_country"] = src_geo.get("country_code") == dest_geo.get("country_code")
                    geo_section["cross_border"] = src_geo.get("country_code") != dest_geo.get("country_code")
                
                tracking_key = subject.get("name") or src_ip
                if tracking_key and src_geo and src_geo.get("latitude") is not None and src_geo.get("longitude") is not None:
                    impossible_travel_data = self.geo_tracker.update_location(
                        tracking_key,
                        src_geo["country"],
                        src_geo["city"],
                        src_geo["latitude"],
                        src_geo["longitude"],
                        event_time
                    )
        
        # Normalization
        normalized_proto = self.normalize_protocol(protocol)
        normalized_action = self.normalize_action(event)
        
        normalization = {
            "protocol": normalized_proto,
            "action": normalized_action,
        }
        
        # Counters
        counters = self.update_counters(event, event_time)
        
        # Behavioral
        diversity = self.behavior_tracker.update_destination_diversity(
            src_ip, dest_ip, dest_port, event_time
        )
        
        failure_count = 0
        if normalized_action in ["denied", "blocked"]:
            entity_key = f"{src_ip}:{dest_ip}:{dest_port}" if src_ip else "unknown"
            failure_count = self.behavior_tracker.track_failure(entity_key, event_time)
        
        behavioral = {
            "unique_destinations_1h": diversity.get("unique_dest_ips", 0),
            "unique_ports_1h": diversity.get("unique_dest_ports", 0),
            "recent_failures_5m": failure_count,
        }
        
        # Anomalies
        anomalies = self.detect_anomalies(
            counters, diversity, normalized_action, src_ip_type, dest_ip_type, 
            temporal, geo_section, impossible_travel_data, network_intel_data
        )
        
        # Fingerprint
        fingerprint = self.compute_fingerprint(event)
        
        # Host role
        host_role = self.infer_host_role(event)
        
        # Risk score
        risk_score = self.compute_risk_score(
            event, src_ip_type, dest_ip_type, counters, normalized_action,
            diversity, anomalies, failure_count, geo_section, network_intel_data
        )
        
        # Build enrichment section
        enrich_section = {
            "timestamp_processed": datetime.utcnow().isoformat() + "Z",
            "fingerprint": fingerprint,
            "temporal": temporal,
            "flags": flags,
            "classification": ip_classification,
            "normalization": normalization,
            "counters": counters,
            "behavioral": behavioral,
            "anomalies": anomalies,
            "risk_score": risk_score,
        }
        
        # Add network intelligence if available
        if network_intel_data:
            enrich_section["network_intel"] = network_intel_data
        
        # Add geo section if available
        if geo_section:
            enrich_section["geo"] = geo_section
        
        # Add impossible travel if detected
        if impossible_travel_data:
            enrich_section["impossible_travel"] = impossible_travel_data
        
        # Add host role if valuable
        if host_role:
            enrich_section["inferred_host_role"] = host_role
        
        return enrich_section
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        enrich_section = self.build_enrichment_section(event)
        enriched = event.copy()
        
        if self.overwrite or "enrich" not in enriched:
            enriched["enrich"] = enrich_section
        
        return enriched
    
    def process_line(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        
        try:
            event = json.loads(line)
            enriched = self.enrich_event(event)
            return json.dumps(enriched, separators=(",", ":"), ensure_ascii=False)
        except json.JSONDecodeError:
            minimal_event = {
                "schema_version": "1.0",
                "event_id": "",
                "event_time": "",
                "ingest_time": "",
                "event_category": "",
                "event_action": "",
                "event_outcome": "",
                "subject": {"type": None, "id": None, "name": None, "ip": None, "port": None},
                "object": {"type": None, "id": None, "name": None, "ip": None, "port": None},
                "host": {"id": None, "name": None, "ip": None, "os": {"name": None, "version": None, "family": None}, "type": None},
                "network": {"protocol": None, "direction": None},
                "security": {"signature_id": None, "signature": None, "severity": None, "tags": []},
                "context": {"source": "", "environment": None, "message": "unparsed_input", "raw_event": {"unparsed_line": line}},
                "enrich": {
                    "timestamp_processed": datetime.utcnow().isoformat() + "Z",
                    "fingerprint": "",
                    "flags": {"is_alert": False},
                    "risk_score": 0,
                }
            }
            return json.dumps(minimal_event, separators=(",", ":"), ensure_ascii=False)
    
    def close(self):
        """Close all database readers."""
        if self.geoip_reader:
            self.geoip_reader.close()
        self.network_intel.close()


def main():
    parser = argparse.ArgumentParser(description="Enhanced log enrichment with network intelligence")
    parser.add_argument("--input", default="normalized.jsonl", help="Input JSONL file")
    parser.add_argument("--output", default="enriched.jsonl", help="Output JSONL file")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing enrichment")
    parser.add_argument("--counter-window-seconds", type=int, default=300, help="Rolling counter window")
    parser.add_argument("--geoip-db", help="Path to GeoLite2-City.mmdb")
    parser.add_argument("--asn-db", help="Path to GeoLite2-ASN.mmdb")
    parser.add_argument("--tor-list", help="Path to tor-exit-nodes.txt")
    parser.add_argument("--reputation-db", help="Path to malicious-ips.txt")
    parser.add_argument("--follow", action="store_true",
                        help="Continuously tail input file for new data")
    parser.add_argument("--state-file", default=".state/enricher.state",
                        help="State file for follow mode position tracking")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="Poll interval in seconds for follow mode")
    
    args = parser.parse_args()
    
    if (args.geoip_db or args.asn_db) and not GEOIP_AVAILABLE:
        print("✗ Error: geoip2 library not installed", file=sys.stderr)
        print("  Run: pip install geoip2 --break-system-packages", file=sys.stderr)
        sys.exit(1)
    
    enricher = LogEnricher(
        counter_window_seconds=args.counter_window_seconds,
        overwrite=args.overwrite,
        geoip_db_path=args.geoip_db,
        asn_db_path=args.asn_db,
        tor_list_path=args.tor_list,
        reputation_db_path=args.reputation_db
    )
    
    if args.follow:
        # --- Streaming / follow mode ---
        from file_tailer import JSONLTailer, append_jsonl

        tailer = JSONLTailer(
            args.input,
            state_file=args.state_file,
            poll_interval=args.poll_interval,
        )
        line_count = 0
        try:
            outfile = open(args.output, "a", encoding="utf-8")
            print(f"Following {args.input} -> {args.output} ...", file=sys.stderr)

            for event in tailer.follow():
                enriched = enricher.enrich_event(event)
                if enriched:
                    append_jsonl(outfile, enriched)
                    line_count += 1
                    if line_count % 500 == 0:
                        print(f"  Enriched {line_count} events...", file=sys.stderr)

        except KeyboardInterrupt:
            print("\nShutting down enricher...", file=sys.stderr)
        finally:
            tailer.close()
            outfile.close()
            enricher.close()
            print(f"✓ Enriched {line_count} events (follow mode)", file=sys.stderr)
    else:
        # --- Batch mode (original behaviour) ---
        try:
            with open(args.input, "r", encoding="utf-8") as infile, \
                 open(args.output, "w", encoding="utf-8") as outfile:

                line_count = 0
                for line in infile:
                    enriched_line = enricher.process_line(line)
                    if enriched_line:
                        outfile.write(enriched_line + "\n")
                        line_count += 1

            print(f"\n✓ Network enrichment complete: {line_count} events processed", file=sys.stderr)
            print(f"  Input:  {args.input}", file=sys.stderr)
            print(f"  Output: {args.output}", file=sys.stderr)

            features = []
            if args.geoip_db:
                features.append("GeoIP")
            if args.asn_db:
                features.append("ASN")
            if args.tor_list:
                features.append("Tor Detection")
            if args.reputation_db:
                features.append("IP Reputation")

            if features:
                print(f"  Features: {', '.join(features)}", file=sys.stderr)

        except FileNotFoundError as e:
            print(f"✗ Error: File not found: {e}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            enricher.close()


if __name__ == "__main__":
    main()
