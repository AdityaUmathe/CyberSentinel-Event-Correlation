#!/usr/bin/env python3
"""
Unified Event Correlation Engine
Processes enriched logs and directly generates correlated security incidents.

Single-step correlation: Enriched Logs → Correlated Incidents

Features:
- Rule-based alert detection
- Automatic incident correlation by attack type
- Time-window grouping
- Entity-based correlation (IP, host, user)
- Attack pattern identification
- Incident severity scoring
- MITRE ATT&CK mapping

Usage:
    python3 unified_correlation_engine.py --input enriched.jsonl --output incidents.jsonl --rules correlation_rules.yaml
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import yaml
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set


class TimeWindow:
    """Sliding time window for event aggregation."""
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.events = deque()
    
    def add_event(self, event: Dict[str, Any], timestamp: datetime):
        """Add event to window."""
        self.events.append({
            "event": event,
            "timestamp": timestamp
        })
        self._cleanup(timestamp)
    
    def _cleanup(self, current_time: datetime):
        """Remove events outside the time window."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()
    
    def get_events(self) -> List[Dict[str, Any]]:
        """Get all events in current window."""
        return [e["event"] for e in self.events]
    
    def count(self, filter_func=None) -> int:
        """Count events matching filter."""
        if filter_func is None:
            return len(self.events)
        return sum(1 for e in self.events if filter_func(e["event"]))


class Rule:
    """Detection rule."""
    
    def __init__(self, rule_config: Dict[str, Any]):
        self.id = rule_config.get("id", "unknown")
        self.name = rule_config.get("name", "Unknown Rule")
        self.description = rule_config.get("description", "")
        self.severity = rule_config.get("severity", "medium")
        self.category = rule_config.get("category", "other")
        self.conditions = rule_config.get("conditions", {})
        self.enabled = rule_config.get("enabled", True)
        self.false_positive_rate = rule_config.get("false_positive_rate", "low")
        self.mitre_tactics = rule_config.get("mitre_tactics", [])
        self.response = rule_config.get("response", [])
        self.rule_type = rule_config.get("type", "single")
        
        # For aggregation rules
        self.time_window = rule_config.get("time_window", 300)
        self.group_by = rule_config.get("group_by", [])
        self.threshold = rule_config.get("threshold", {})
    
    def evaluate(self, event: Dict[str, Any]) -> bool:
        """Evaluate if event matches rule conditions."""
        if not self.enabled:
            return False
        
        return self._check_conditions(event, self.conditions)
    
    def _check_conditions(self, event: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Recursively check conditions."""
        if not conditions:
            return True
        
        # Handle logical operators
        if "AND" in conditions:
            return all(self._check_conditions(event, cond) for cond in conditions["AND"])
        
        if "OR" in conditions:
            return any(self._check_conditions(event, cond) for cond in conditions["OR"])
        
        if "NOT" in conditions:
            return not self._check_conditions(event, conditions["NOT"])
        
        # Handle field comparisons
        for field, condition in conditions.items():
            if field in ["AND", "OR", "NOT"]:
                continue
            
            value = self._get_nested_value(event, field)
            
            if not self._compare_value(value, condition):
                return False
        
        return True
    
    def _get_nested_value(self, obj: Dict[str, Any], path: str) -> Any:
        """Get nested value using dot notation."""
        keys = path.split(".")
        current = obj
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def _compare_value(self, value: Any, condition: Any) -> bool:
        """Compare value against condition."""
        if value is None:
            return False
        
        # Direct equality
        if not isinstance(condition, dict):
            return value == condition
        
        # Comparison operators
        if "eq" in condition:
            return value == condition["eq"]
        if "ne" in condition:
            return value != condition["ne"]
        if "gt" in condition:
            return value > condition["gt"]
        if "gte" in condition:
            return value >= condition["gte"]
        if "lt" in condition:
            return value < condition["lt"]
        if "lte" in condition:
            return value <= condition["lte"]
        if "in" in condition:
            return value in condition["in"]
        if "not_in" in condition:
            return value not in condition["not_in"]
        if "contains" in condition:
            return condition["contains"] in str(value)
        if "regex" in condition:
            import re
            return re.search(condition["regex"], str(value)) is not None
        
        return False


class Alert:
    """Security alert from rule match."""
    
    def __init__(self, rule: Rule, event: Dict[str, Any], context: Dict[str, Any] = None):
        self.rule = rule
        self.event = event
        self.context = context or {}
        self.alert_id = self._generate_alert_id()
        self.timestamp = event.get("event_time", datetime.utcnow().isoformat() + "Z")
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        components = [
            self.rule.id,
            self.event.get("event_id", ""),
            str(datetime.utcnow().timestamp())
        ]
        id_string = "|".join(components)
        return hashlib.sha256(id_string.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule": {
                "id": self.rule.id,
                "name": self.rule.name,
                "severity": self.rule.severity,
                "category": self.rule.category,
                "description": self.rule.description,
                "mitre_tactics": self.rule.mitre_tactics,
                "false_positive_rate": self.rule.false_positive_rate
            },
            "event": self.event,
            "context": self.context,
            "recommended_response": self.rule.response
        }


class UnifiedCorrelationEngine:
    """
    Unified correlation engine that generates correlated incidents directly.
    Combines alert generation and incident correlation in one pass.
    """
    
    def __init__(self, rules_config: Dict[str, Any], time_window_minutes: int = 60):
        self.rules = []
        self.time_window = timedelta(minutes=time_window_minutes)
        self.time_window_minutes = time_window_minutes
        self.incident_id_counter = 1

        # Load rules
        for rule_config in rules_config.get("rules", []):
            self.rules.append(Rule(rule_config))

        # Alert buffering for correlation
        self.alert_buffer = []

        # Time windows for aggregation rules
        self.windows = {}

        # --- Streaming state ---
        # Open incidents keyed by correlation group key
        self.open_incidents = {}
        # Track which aggregation rule+group has already fired to avoid re-firing
        self._aggregation_fired = {}  # (rule_id, group_key) -> datetime (fired time)
        # Counter for streaming mode (avoids growing alert_buffer)
        self._streaming_alert_count = 0
        
    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process all events and generate correlated incidents.
        
        Args:
            events: List of enriched log events
            
        Returns:
            List of correlated incident dictionaries
        """
        # Step 1: Generate alerts from events
        print(f"Generating alerts from {len(events)} events...", file=sys.stderr)
        
        for event in events:
            self._process_single_event(event)
        
        print(f"✓ Generated {len(self.alert_buffer)} alerts", file=sys.stderr)
        
        # Step 2: Correlate alerts into incidents
        print(f"Correlating alerts into incidents...", file=sys.stderr)
        incidents = self._correlate_alerts()
        print(f"✓ Created {len(incidents)} incident(s)", file=sys.stderr)
        
        return incidents
    
    def _process_single_event(self, event: Dict[str, Any]):
        """Process single event through all rules."""
        event_time = self._parse_timestamp(event.get("event_time"))
        if not event_time:
            event_time = datetime.utcnow()
        
        # Check single-event rules
        for rule in self.rules:
            if rule.rule_type == "single" and rule.evaluate(event):
                alert = Alert(rule, event)
                self.alert_buffer.append(alert.to_dict())
            
            # Check aggregation rules
            elif rule.rule_type == "aggregation":
                # Initialize window if needed
                if rule.id not in self.windows:
                    self.windows[rule.id] = TimeWindow(rule.time_window)
                
                # Add to window
                self.windows[rule.id].add_event(event, event_time)
                
                # Check if threshold met
                window_events = self.windows[rule.id].get_events()
                if self._check_aggregation_threshold(rule, window_events):
                    # Create alert for aggregation match
                    alert = Alert(
                        rule, 
                        event,
                        context={
                            "aggregation": {
                                "event_count": len(window_events),
                                "time_window_seconds": rule.time_window
                            }
                        }
                    )
                    self.alert_buffer.append(alert.to_dict())
    
    def _check_aggregation_threshold(self, rule: Rule, events: List[Dict[str, Any]]) -> bool:
        """Check if aggregation threshold is met."""
        if not events:
            return False
        
        # Group by specified fields
        groups = defaultdict(list)
        for event in events:
            if rule.evaluate(event):
                group_key = self._get_group_key(event, rule.group_by)
                groups[group_key].append(event)
        
        # Check threshold for each group
        threshold_config = rule.threshold.get("count", {})
        min_count = threshold_config.get("gte", 1)
        
        for group_events in groups.values():
            if len(group_events) >= min_count:
                return True
        
        return False
    
    # ==================================================================
    # Streaming methods
    # ==================================================================

    def process_single_event_streaming(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process one event in streaming mode.

        Returns a list of incident dicts that were created or updated.
        Each incident is emitted as a new JSONL line (append-only);
        downstream consumers should take the latest by incident_id.
        """
        emitted = []
        event_time = self._parse_timestamp(event.get("event_time"))
        if not event_time:
            event_time = datetime.utcnow()

        for rule in self.rules:
            if rule.rule_type == "single" and rule.evaluate(event):
                alert = Alert(rule, event).to_dict()
                self._streaming_alert_count += 1
                incident = self._correlate_single_alert(alert)
                if incident is not None:
                    emitted.append(incident)

            elif rule.rule_type == "aggregation":
                if rule.id not in self.windows:
                    self.windows[rule.id] = TimeWindow(rule.time_window)

                self.windows[rule.id].add_event(event, event_time)

                if rule.evaluate(event):
                    group_key = self._get_group_key(event, rule.group_by)
                    fire_key = (rule.id, group_key)

                    window_events = self.windows[rule.id].get_events()
                    groups = defaultdict(list)
                    for we in window_events:
                        if rule.evaluate(we):
                            gk = self._get_group_key(we, rule.group_by)
                            groups[gk].append(we)

                    threshold_config = rule.threshold.get("count", {})
                    min_count = threshold_config.get("gte", 1)

                    if len(groups.get(group_key, [])) >= min_count:
                        if fire_key not in self._aggregation_fired:
                            self._aggregation_fired[fire_key] = datetime.utcnow()
                            alert = Alert(
                                rule, event,
                                context={
                                    "aggregation": {
                                        "event_count": len(groups[group_key]),
                                        "time_window_seconds": rule.time_window,
                                    }
                                },
                            ).to_dict()
                            self._streaming_alert_count += 1
                            incident = self._correlate_single_alert(alert)
                            if incident is not None:
                                emitted.append(incident)

        return emitted

    # Emit thresholds: re-emit incident when alert count crosses these values
    _EMIT_THRESHOLDS = {1, 2, 3, 5, 10, 20, 50, 100, 200, 500, 1000}

    def _should_emit(self, prev_count: int, new_count: int) -> bool:
        """Decide whether to re-emit an updated incident.

        Re-emit on the first alert, when a threshold is crossed, or
        every 50 alerts above 100 to keep output manageable.
        """
        if new_count in self._EMIT_THRESHOLDS:
            return True
        if new_count > 100 and new_count % 50 == 0:
            return True
        return False

    def _correlate_single_alert(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Try to merge alert into an existing open incident.
        If no match, create a new incident.
        Returns the (new or updated) incident dict, or None if throttled.
        """
        for group_key, incident in self.open_incidents.items():
            group_alerts = incident.get("_alerts", [])
            if self._should_correlate_alert(alert, group_alerts):
                prev_count = len(group_alerts)
                original_id = incident.get("incident_id")
                # Merge into existing incident
                group_alerts.append(alert)
                updated = self._rebuild_incident(group_alerts, group_key, existing_id=original_id)
                updated["_alerts"] = group_alerts
                self.open_incidents[group_key] = updated

                # Throttle: only re-emit at meaningful thresholds
                if not self._should_emit(prev_count, len(group_alerts)):
                    return None

                # Return a clean copy (without internal _alerts list)
                clean = {k: v for k, v in updated.items() if not k.startswith("_")}
                return clean

        # No match – always emit new incidents
        new_key = self._generate_group_key(alert)
        new_incident = self._create_incident([alert], new_key)
        new_incident["_alerts"] = [alert]
        self.open_incidents[new_key] = new_incident
        clean = {k: v for k, v in new_incident.items() if not k.startswith("_")}
        return clean

    def _rebuild_incident(self, alerts: List[Dict[str, Any]], group_key: str,
                          existing_id: Optional[str] = None) -> Dict[str, Any]:
        """Rebuild incident dict from its alert list (for updates)."""
        return self._create_incident(alerts, group_key, existing_id=existing_id)

    def flush_expired_windows(self):
        """
        Clean up stale aggregation windows and evict expired open incidents.
        Should be called periodically in the streaming loop.
        """
        now = datetime.utcnow().replace(tzinfo=None)
        stale_cutoff = now - timedelta(minutes=self.time_window_minutes * 2)

        # Evict old open incidents
        expired_keys = []
        for key, incident in self.open_incidents.items():
            last_seen_str = incident.get("last_seen")
            if last_seen_str:
                last_seen = self._parse_timestamp(last_seen_str)
                if last_seen:
                    last_seen_naive = last_seen.replace(tzinfo=None)
                    if last_seen_naive < stale_cutoff:
                        expired_keys.append(key)

        for key in expired_keys:
            del self.open_incidents[key]

        # Clean up aggregation fired keys — evict by age or empty window
        stale_fire_keys = []
        for fire_key, fired_at in self._aggregation_fired.items():
            rule_id = fire_key[0]
            # Evict if the window is empty
            if rule_id in self.windows:
                window = self.windows[rule_id]
                if window.count() == 0:
                    stale_fire_keys.append(fire_key)
            # Evict if fired_at is older than stale_cutoff (handles orphaned keys)
            elif isinstance(fired_at, datetime) and fired_at.replace(tzinfo=None) < stale_cutoff:
                stale_fire_keys.append(fire_key)
            # Legacy True values without timestamp — evict if no window exists
            elif not isinstance(fired_at, datetime) and rule_id not in self.windows:
                stale_fire_keys.append(fire_key)

        for fk in stale_fire_keys:
            del self._aggregation_fired[fk]

    def _get_group_key(self, event: Dict[str, Any], group_fields: List[str]) -> str:
        """Generate grouping key from event fields."""
        key_parts = []
        for field in group_fields:
            value = self._get_nested_value(event, field)
            key_parts.append(str(value) if value else "null")
        return "|".join(key_parts)
    
    def _get_nested_value(self, obj: Dict[str, Any], path: str) -> Any:
        """Get nested value using dot notation."""
        keys = path.split(".")
        current = obj
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def _correlate_alerts(self) -> List[Dict[str, Any]]:
        """Correlate alerts into incidents by attack type and entities."""
        if not self.alert_buffer:
            return []
        
        # Sort alerts by timestamp
        sorted_alerts = sorted(self.alert_buffer, key=lambda x: x.get('timestamp', ''))
        
        # Group alerts by correlation criteria
        incident_groups = self._group_alerts_by_attack_type(sorted_alerts)
        
        # Create incident objects
        incidents = []
        for group_key, group_alerts in incident_groups.items():
            incident = self._create_incident(group_alerts, group_key)
            incidents.append(incident)
        
        # Sort incidents by severity and time
        incidents.sort(key=lambda x: (
            self._severity_rank(x['severity']),
            x['first_seen']
        ), reverse=True)
        
        return incidents
    
    def _group_alerts_by_attack_type(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group alerts into incidents based on attack type and entities.
        
        Correlation logic:
        1. Same attack category (brute force, lateral movement, etc.)
        2. Within time window
        3. Shared entities (target IP, source IP, or host)
        """
        groups = {}
        
        for alert in alerts:
            # Try to find matching group
            matched = False
            
            for group_key, group_alerts in groups.items():
                if self._should_correlate_alert(alert, group_alerts):
                    groups[group_key].append(alert)
                    matched = True
                    break
            
            # Create new group if no match
            if not matched:
                new_key = self._generate_group_key(alert)
                groups[new_key] = [alert]
        
        return groups
    
    def _should_correlate_alert(self, alert: Dict[str, Any], group_alerts: List[Dict[str, Any]]) -> bool:
        """Determine if alert belongs to existing incident group."""
        if not group_alerts:
            return False
        
        first_alert = group_alerts[0]
        
        # 1. Check attack category - must match
        alert_category = alert.get('rule', {}).get('category')
        group_category = first_alert.get('rule', {}).get('category')
        
        if alert_category != group_category:
            return False
        
        # 2. Check time window
        alert_time = self._parse_timestamp(alert.get('timestamp'))
        first_time = self._parse_timestamp(first_alert.get('timestamp'))
        
        if alert_time and first_time:
            if abs(alert_time - first_time) > self.time_window:
                return False
        
        # 3. Check entity overlap (same target, source, or host)
        alert_entities = self._extract_alert_entities(alert)
        
        for group_alert in group_alerts:
            group_entities = self._extract_alert_entities(group_alert)
            
            # Same target being attacked
            if alert_entities['target_ip'] and alert_entities['target_ip'] == group_entities['target_ip']:
                return True
            
            # Same source attacking
            if alert_entities['source_ip'] and alert_entities['source_ip'] == group_entities['source_ip']:
                return True
            
            # Same host involved
            if alert_entities['host_id'] and alert_entities['host_id'] == group_entities['host_id']:
                return True
            
            # Same target host (by hostname)
            if alert_entities['host_name'] and alert_entities['host_name'] == group_entities['host_name']:
                return True
        
        return False
    
    _NOT_A_USER = frozenset({
        '/', '-', '.', '*', 'none', 'null', 'n/a', 'unknown', '',
        'system', 'local service', 'network service',
        # Windows service accounts
        'nt authority\\system', 'nt authority\\local service',
        'nt authority\\network service', 'nt authority\\anonymous logon',
        'nt authority\\iusr', 'nt authority\\system',
        # Protocol names that obj.name may contain
        'http', 'https', 'ssh', 'ftp', 'sftp', 'smtp', 'dns', 'dhcp',
        'rdp', 'smb', 'telnet', 'pop3', 'imap', 'ntp', 'snmp',
        'ldap', 'kerberos', 'tcp', 'udp', 'icmp', 'tls', 'ssl',
    })

    @staticmethod
    def _clean_user(val: Optional[str]) -> Optional[str]:
        """Clean username: strip quotes, reject garbage values."""
        if not val or not isinstance(val, str):
            return None
        # Normalize escaped backslashes (e.g. "NT AUTHORITY\\\\SYSTEM" -> "NT AUTHORITY\\SYSTEM")
        cleaned = val.replace('\\\\', '\\')
        cleaned = cleaned.strip().strip('"').strip("'").strip()
        if not cleaned:
            return None
        # Reject known non-user strings (check with normalized backslash)
        if cleaned.lower() in UnifiedCorrelationEngine._NOT_A_USER:
            return None
        # Reject URLs, file paths, and query strings
        if cleaned.startswith(('/', 'http://', 'https://', '\\')) or '?' in cleaned:
            return None
        # Reject if it looks like an IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cleaned):
            return None
        return cleaned

    def _extract_alert_entities(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract entity information from alert."""
        event = alert.get('event', {})
        subject = event.get('subject', {})
        obj = event.get('object', {})
        host = event.get('host', {})

        src_ip = subject.get('ip')
        target_ip = obj.get('ip') or host.get('ip')
        # Don't let target_ip be the same as source_ip
        if target_ip and target_ip == src_ip:
            target_ip = host.get('ip') if obj.get('ip') == src_ip else target_ip
            if target_ip == src_ip:
                target_ip = None

        return {
            'source_ip': src_ip,
            'target_ip': target_ip,
            'host_id': host.get('id'),
            'host_ip': host.get('ip'),
            'host_name': host.get('name'),
            'user': self._clean_user(subject.get('name')) or self._clean_user(obj.get('name'))
        }
    
    def _generate_group_key(self, alert: Dict[str, Any]) -> str:
        """Generate unique group key for new incident."""
        entities = self._extract_alert_entities(alert)
        category = alert.get('rule', {}).get('category', 'unknown')
        timestamp = alert.get('timestamp', '')[:16]  # Date+hour
        
        key_parts = [
            category,
            str(entities.get('target_ip', '')),
            str(entities.get('host_id', '')),
            timestamp
        ]
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()[:16]
    
    def _create_incident(
        self,
        alerts: List[Dict[str, Any]],
        group_key: str,
        existing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create incident from grouped alerts.

        Args:
            existing_id: If set, reuse this incident_id (for rebuilds).
                         Otherwise generate a new one.
        """
        # Extract timeline — filter out None timestamps
        timestamps = [a.get('timestamp') for a in alerts if a.get('timestamp')]
        if not timestamps:
            now_str = datetime.utcnow().isoformat() + "Z"
            timestamps = [now_str]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        # Calculate incident severity (highest alert severity)
        severities = [a.get('rule', {}).get('severity') for a in alerts]
        incident_severity = self._calculate_incident_severity(severities)

        # Extract all affected entities
        entities = self._extract_incident_entities(alerts)

        # Get attack patterns and tactics
        attack_info = self._analyze_attack_patterns(alerts)

        # Combine recommendations
        recommendations = self._combine_recommendations(alerts)

        # Incident ID: reuse existing or generate new
        if existing_id:
            incident_id = existing_id
        else:
            incident_id = f"INC-{self.incident_id_counter:06d}"
            self.incident_id_counter += 1

        # Create incident summary
        incident = {
            "incident_id": incident_id,
            "severity": incident_severity,
            "status": "open",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": self._calculate_duration(first_seen, last_seen),
            "alert_count": len(alerts),
            "title": self._generate_incident_title(alerts, attack_info),
            "description": self._generate_incident_description(alerts, entities, attack_info),
            "attack_chain": {
                "tactics": attack_info['tactics'],
                "techniques": attack_info['techniques'],
                "attack_pattern": attack_info['pattern'],
                "campaign_confidence": attack_info['confidence']
            },
            "affected_entities": entities,
            "alerts": [self._summarize_alert(a) for a in alerts],
            "indicators_of_compromise": self._extract_iocs(alerts),
            "enrichment_summary": self._aggregate_enrichment(alerts),
            "recommended_actions": recommendations,
            "metadata": {
                "correlation_key": group_key,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "correlated_by": "Unified Correlation Engine v2.0"
            }
        }

        return incident
    
    def _calculate_incident_severity(self, severities: List[str]) -> str:
        """Calculate overall incident severity (highest wins)."""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            if severity in severities:
                return severity
        
        return 'medium'
    
    def _extract_incident_entities(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract all affected entities from alerts."""
        source_ips = set()
        target_ips = set()
        hosts = set()
        users = set()

        for alert in alerts:
            entities = self._extract_alert_entities(alert)

            if entities['source_ip']:
                source_ips.add(entities['source_ip'])
            if entities['target_ip']:
                target_ips.add(entities['target_ip'])
            if entities['host_name']:
                hosts.add(entities['host_name'])
            elif entities['host_id']:
                hosts.add(entities['host_id'])
            if entities['host_ip']:
                hosts.add(entities['host_ip'])
            if entities['user']:
                users.add(entities['user'])
            # Also collect target/object user (e.g., targeted account in brute force)
            target_user = self._extract_target_user(alert)
            if target_user:
                users.add(target_user)

        # Remove source IPs from target set to avoid misleading src==dst
        target_ips -= source_ips

        return {
            "source_ips": sorted(list(source_ips)),
            "target_ips": sorted(list(target_ips)),
            "affected_hosts": sorted(list(hosts)),
            "affected_users": sorted(list(users)),
            "total_sources": len(source_ips),
            "total_targets": len(target_ips)
        }

    def _extract_target_user(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract target user from alert's object entity."""
        event = alert.get('event', {})
        obj = event.get('object', {})
        return self._clean_user(obj.get('name'))
    
    def _analyze_attack_patterns(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze alerts to determine attack pattern."""
        
        # Collect all MITRE tactics
        all_tactics = []
        categories = []
        
        for alert in alerts:
            rule = alert.get('rule', {})
            all_tactics.extend(rule.get('mitre_tactics', []))
            categories.append(rule.get('category'))
        
        tactics = sorted(list(set(all_tactics)))
        primary_category = max(set(categories), key=categories.count) if categories else 'unknown'
        
        # Determine attack pattern based on category and alert count
        pattern, confidence = self._identify_attack_pattern(primary_category, len(alerts), categories)
        
        return {
            'tactics': tactics,
            'techniques': [],  # Could be enhanced with technique extraction
            'pattern': pattern,
            'confidence': confidence
        }
    
    def _identify_attack_pattern(self, category: str, alert_count: int, categories: List[str]) -> tuple:
        """Identify attack pattern based on alerts."""
        
        # Count categories
        category_counts = defaultdict(int)
        for cat in categories:
            category_counts[cat] += 1
        
        # Determine confidence based on alert count
        if alert_count >= 5:
            confidence = "high"
        elif alert_count >= 3:
            confidence = "medium"
        else:
            confidence = "low"
        
        # Pattern identification
        patterns = {
            'authentication': {
                'pattern': 'Brute Force Attack Campaign',
                'multi_source_pattern': 'Distributed Brute Force Attack'
            },
            'threat_intelligence': {
                'pattern': 'Coordinated Attack from Malicious Infrastructure',
                'single_pattern': 'Malicious Infrastructure Communication'
            },
            'lateral_movement': {
                'pattern': 'Internal Lateral Movement Campaign',
                'single_pattern': 'Lateral Movement Detected'
            },
            'data_exfiltration': {
                'pattern': 'Data Exfiltration Attempt',
                'single_pattern': 'Suspicious Data Transfer'
            },
            'reconnaissance': {
                'pattern': 'Network Reconnaissance Campaign',
                'single_pattern': 'Scanning Activity Detected'
            },
            'high_risk': {
                'pattern': 'High-Risk Activity Pattern',
                'single_pattern': 'High-Risk Event'
            },
            'account_compromise': {
                'pattern': 'Account Compromise Indicators',
                'single_pattern': 'Suspicious Account Activity'
            }
        }
        
        if category in patterns:
            # Use multi-source pattern if multiple alerts
            if alert_count >= 3 and 'multi_source_pattern' in patterns[category]:
                return patterns[category]['multi_source_pattern'], confidence
            elif 'pattern' in patterns[category]:
                return patterns[category]['pattern'], confidence
            elif 'single_pattern' in patterns[category]:
                return patterns[category]['single_pattern'], confidence
        
        # Default pattern
        return f"Multi-Stage Security Incident ({category})", confidence
    
    def _combine_recommendations(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Combine and deduplicate recommendations from all alerts."""
        all_recs = []
        seen = set()
        
        # Add incident-level recommendations first
        incident_recs = [
            "Initiate incident response procedure",
            "Document all findings and timeline",
            "Preserve logs and forensic evidence",
            "Notify security stakeholders"
        ]
        
        for rec in incident_recs:
            if rec not in seen:
                all_recs.append(rec)
                seen.add(rec)
        
        # Add alert-specific recommendations
        for alert in alerts:
            for rec in alert.get('recommended_response', []):
                if rec not in seen:
                    all_recs.append(rec)
                    seen.add(rec)
        
        return all_recs
    
    def _extract_iocs(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract indicators of compromise from all alerts."""
        iocs = {
            "malicious_ips": [],
            "suspicious_ips": [],
            "affected_ports": [],
            "attack_signatures": [],
            "compromised_accounts": []
        }
        
        for alert in alerts:
            event = alert.get('event', {})
            enrich = event.get('enrich', {})
            network_intel = enrich.get('network_intel', {})
            
            # Extract malicious IPs
            src_rep = network_intel.get('src_reputation', {})
            if src_rep.get('ip_reputation') == 'malicious':
                src_ip = event.get('subject', {}).get('ip')
                if src_ip and src_ip not in iocs['malicious_ips']:
                    iocs['malicious_ips'].append(src_ip)
            elif src_rep.get('ip_reputation') == 'suspicious':
                src_ip = event.get('subject', {}).get('ip')
                if src_ip and src_ip not in iocs['suspicious_ips']:
                    iocs['suspicious_ips'].append(src_ip)
            
            # Extract ports
            dest_port = event.get('object', {}).get('port')
            if dest_port and dest_port not in iocs['affected_ports']:
                iocs['affected_ports'].append(dest_port)
            
            # Extract compromised accounts (from auth failures/success patterns)
            if alert.get('rule', {}).get('category') == 'authentication':
                user = event.get('subject', {}).get('name')
                if user and user not in iocs['compromised_accounts']:
                    iocs['compromised_accounts'].append(user)
        
        return iocs
    
    def _generate_incident_title(self, alerts: List[Dict[str, Any]], attack_info: Dict[str, Any]) -> str:
        """Generate descriptive incident title."""
        pattern = attack_info['pattern']
        alert_count = len(alerts)
        
        return f"{pattern} - {alert_count} Related Alert{'s' if alert_count != 1 else ''}"
    
    def _generate_incident_description(self, alerts: List[Dict[str, Any]], 
                                      entities: Dict[str, Any], 
                                      attack_info: Dict[str, Any]) -> str:
        """Generate detailed incident description."""
        
        desc_parts = [
            f"Security incident involving {len(alerts)} correlated alerts.",
            f"Attack Pattern: {attack_info['pattern']}",
            f"Confidence: {attack_info['confidence']}",
            f"\nAffected Infrastructure:"
        ]
        
        if entities['source_ips']:
            sources_preview = ', '.join(entities['source_ips'][:3])
            if len(entities['source_ips']) > 3:
                sources_preview += '...'
            desc_parts.append(f"  - {entities['total_sources']} source IP(s): {sources_preview}")
        
        if entities['target_ips']:
            targets_preview = ', '.join(entities['target_ips'][:3])
            if len(entities['target_ips']) > 3:
                targets_preview += '...'
            desc_parts.append(f"  - {entities['total_targets']} target IP(s): {targets_preview}")
        
        if entities['affected_hosts']:
            desc_parts.append(f"  - Affected Hosts: {', '.join(entities['affected_hosts'][:5])}")
        
        if entities['affected_users']:
            desc_parts.append(f"  - Affected Users: {', '.join(entities['affected_users'][:5])}")
        
        if attack_info['tactics']:
            desc_parts.append(f"\nMITRE ATT&CK Tactics: {', '.join(attack_info['tactics'])}")
        
        return '\n'.join(desc_parts)
    
    def _summarize_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of individual alert for incident."""
        event = alert.get('event', {})
        subject = event.get('subject', {})
        obj = event.get('object', {})

        src_ip = subject.get('ip')
        tgt_ip = obj.get('ip')
        # Guard: don't propagate same IP as both source and target
        if tgt_ip and tgt_ip == src_ip:
            tgt_ip = None

        return {
            "alert_id": alert.get('alert_id'),
            "timestamp": alert.get('timestamp'),
            "rule_id": alert.get('rule', {}).get('id'),
            "rule_name": alert.get('rule', {}).get('name'),
            "severity": alert.get('rule', {}).get('severity'),
            "category": alert.get('rule', {}).get('category'),
            "source_ip": src_ip,
            "target_ip": tgt_ip,
            "target_port": obj.get('port'),
            "user": self._clean_user(subject.get('name')) or self._clean_user(obj.get('name')),
            "enrichment": self._extract_enrichment_summary(alert)
        }

    def _extract_enrichment_summary(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract compact enrichment data from an alert's event."""
        enrich = alert.get('event', {}).get('enrich', {})
        if not enrich:
            return {}

        summary = {}

        # GeoIP
        geo = enrich.get('geo', {})
        if geo:
            geo_out = {}
            src_geo = geo.get('src', {})
            dest_geo = geo.get('dest', {})
            if src_geo:
                geo_out["src_country"] = src_geo.get("country")
                geo_out["src_country_code"] = src_geo.get("country_code")
                geo_out["src_city"] = src_geo.get("city")
            if dest_geo:
                geo_out["dest_country"] = dest_geo.get("country")
                geo_out["dest_country_code"] = dest_geo.get("country_code")
                geo_out["dest_city"] = dest_geo.get("city")
            if geo.get("distance_km") is not None:
                geo_out["distance_km"] = geo["distance_km"]
            if geo.get("cross_border") is not None:
                geo_out["cross_border"] = geo["cross_border"]
            if geo_out:
                summary["geo"] = geo_out

        # Network intelligence
        ni = enrich.get('network_intel', {})
        if ni:
            ni_out = {}
            for key in ('src_asn', 'dest_asn', 'src_provider', 'dest_provider',
                        'tor_detected', 'threat_detected', 'threat_confidence',
                        'src_reputation', 'dest_reputation'):
                if key in ni:
                    ni_out[key] = ni[key]
            if ni_out:
                summary["network_intel"] = ni_out

        # Impossible travel
        it = enrich.get('impossible_travel')
        if it and it.get('is_impossible_travel'):
            summary["impossible_travel"] = it

        # Anomalies — only include active flags
        anomalies = enrich.get('anomalies', {})
        active = {k: v for k, v in anomalies.items() if v}
        if active:
            summary["anomalies"] = active

        # Risk score
        if enrich.get('risk_score') is not None:
            summary["risk_score"] = enrich['risk_score']

        return summary

    def _aggregate_enrichment(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate enrichment data across all alerts in an incident."""
        countries = set()
        country_codes = set()
        cities = set()
        asn_orgs = set()
        providers = set()
        tor_detected = False
        threat_detected = False
        max_threat_confidence = 0.0
        max_risk_score = 0.0
        impossible_travel = None
        all_anomalies = set()
        max_distance_km = None
        cross_border = False
        reputations = {"malicious": [], "suspicious": []}

        for alert in alerts:
            enrich = alert.get('event', {}).get('enrich', {})
            if not enrich:
                continue

            # Geo
            geo = enrich.get('geo', {})
            for prefix in ('src', 'dest'):
                g = geo.get(prefix, {})
                if g.get('country'):
                    countries.add(g['country'])
                if g.get('country_code'):
                    country_codes.add(g['country_code'])
                if g.get('city'):
                    cities.add(g['city'])
            if geo.get('distance_km') is not None:
                if max_distance_km is None or geo['distance_km'] > max_distance_km:
                    max_distance_km = geo['distance_km']
            if geo.get('cross_border'):
                cross_border = True

            # Network intel
            ni = enrich.get('network_intel', {})
            for key in ('src_asn', 'dest_asn'):
                asn = ni.get(key, {})
                if asn.get('org'):
                    asn_orgs.add(asn['org'])
            for key in ('src_provider', 'dest_provider'):
                if ni.get(key):
                    providers.add(ni[key])
            if ni.get('tor_detected'):
                tor_detected = True
            if ni.get('threat_detected'):
                threat_detected = True
            tc = ni.get('threat_confidence', 0.0)
            if tc and tc > max_threat_confidence:
                max_threat_confidence = tc

            # Reputation
            for rep_key, ip_key in [('src_reputation', 'subject'), ('dest_reputation', 'object')]:
                rep = ni.get(rep_key, {})
                status = rep.get('ip_reputation')
                if status in ('malicious', 'suspicious'):
                    ip = alert.get('event', {}).get(ip_key, {}).get('ip')
                    if ip and ip not in reputations[status]:
                        reputations[status].append(ip)

            # Impossible travel
            it = enrich.get('impossible_travel')
            if it and it.get('is_impossible_travel'):
                impossible_travel = it

            # Anomalies
            anomalies = enrich.get('anomalies', {})
            for k, v in anomalies.items():
                if v:
                    all_anomalies.add(k)

            # Risk score
            rs = enrich.get('risk_score', 0)
            if rs and rs > max_risk_score:
                max_risk_score = rs

        result = {}

        # Derive cross_border from collected country codes if per-event flag missed it
        if not cross_border and len(country_codes) > 1:
            cross_border = True

        if countries or max_distance_km is not None:
            geo_agg = {}
            if countries:
                geo_agg["countries"] = sorted(countries)
            if cities:
                geo_agg["cities"] = sorted(cities)
            if max_distance_km is not None:
                geo_agg["max_distance_km"] = max_distance_km
            geo_agg["cross_border"] = cross_border
            result["geo"] = geo_agg

        if asn_orgs or providers or tor_detected or threat_detected:
            ni_agg = {}
            if asn_orgs:
                ni_agg["asn_orgs"] = sorted(asn_orgs)
            if providers:
                ni_agg["cloud_providers"] = sorted(providers)
            ni_agg["tor_detected"] = tor_detected
            ni_agg["threat_detected"] = threat_detected
            if max_threat_confidence > 0:
                ni_agg["max_threat_confidence"] = max_threat_confidence
            if reputations["malicious"]:
                ni_agg["malicious_ips"] = reputations["malicious"]
            if reputations["suspicious"]:
                ni_agg["suspicious_ips"] = reputations["suspicious"]
            result["network_intel"] = ni_agg

        if impossible_travel:
            result["impossible_travel"] = impossible_travel

        if all_anomalies:
            result["anomaly_flags"] = sorted(all_anomalies)

        if max_risk_score > 0:
            result["max_enrichment_risk_score"] = max_risk_score

        return result

    def _calculate_duration(self, first_seen: str, last_seen: str) -> int:
        """Calculate incident duration in seconds."""
        try:
            first = self._parse_timestamp(first_seen)
            last = self._parse_timestamp(last_seen)
            if first and last:
                return int((last - first).total_seconds())
        except (ValueError, TypeError, OverflowError):
            pass
        return 0
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse ISO8601 timestamp."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    
    def _severity_rank(self, severity: str) -> int:
        """Rank severity for sorting."""
        ranks = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        return ranks.get(severity, 0)


def main():
    parser = argparse.ArgumentParser(
        description="Unified Event Correlation Engine - Enriched Logs → Correlated Incidents"
    )
    parser.add_argument("--input", required=True, help="Input enriched logs file (JSONL)")
    parser.add_argument("--output", default="incidents.jsonl", help="Output incidents file (JSONL)")
    parser.add_argument("--rules", required=True, help="Rules configuration (YAML)")
    parser.add_argument("--time-window", type=int, default=60,
                       help="Incident correlation time window in minutes (default: 60)")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON output")
    parser.add_argument("--stats", action="store_true", help="Print detailed statistics")
    parser.add_argument("--follow", action="store_true",
                        help="Continuously tail input file for new data")
    parser.add_argument("--state-file", default=".state/correlation.state",
                        help="State file for follow mode position tracking")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="Poll interval in seconds for follow mode")
    parser.add_argument("--flush-interval", type=int, default=60,
                        help="Seconds between flushing expired windows in follow mode")
    
    args = parser.parse_args()
    
    # Load rules
    print(f"\n{'='*70}", file=sys.stderr)
    print("UNIFIED CORRELATION ENGINE", file=sys.stderr)
    print(f"{'='*70}\n", file=sys.stderr)
    
    print(f"[1/4] Loading rules from {args.rules}...", file=sys.stderr)
    try:
        with open(args.rules, 'r', encoding='utf-8') as f:
            rules_config = yaml.safe_load(f)
        print(f"      ✓ Loaded {len(rules_config.get('rules', []))} rules\n", file=sys.stderr)
    except FileNotFoundError:
        print(f"      ✗ Error: Rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"      ✗ Error parsing YAML: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Initialize engine
    engine = UnifiedCorrelationEngine(rules_config, time_window_minutes=args.time_window)

    if args.follow:
        # --- Streaming / follow mode ---
        from file_tailer import JSONLTailer, append_jsonl

        tailer = JSONLTailer(
            args.input,
            state_file=args.state_file,
            poll_interval=args.poll_interval,
        )
        event_count = 0
        incident_count = 0
        last_flush = time.time()

        try:
            outfile = open(args.output, "a", encoding="utf-8")
            print(f"[streaming] Following {args.input} -> {args.output} ...", file=sys.stderr)
            print(f"      Time window: {args.time_window} minutes", file=sys.stderr)
            print(f"      Flush interval: {args.flush_interval}s\n", file=sys.stderr)

            for event in tailer.follow():
                emitted = engine.process_single_event_streaming(event)
                event_count += 1

                for incident in emitted:
                    append_jsonl(outfile, incident)
                    incident_count += 1

                # Periodic flush of expired windows
                now = time.time()
                if now - last_flush >= args.flush_interval:
                    engine.flush_expired_windows()
                    last_flush = now

                if event_count % 500 == 0:
                    print(f"  Events: {event_count}, Incidents: {incident_count}, "
                          f"Alerts: {engine._streaming_alert_count}, "
                          f"Open: {len(engine.open_incidents)}", file=sys.stderr)

        except KeyboardInterrupt:
            print("\nShutting down correlation engine...", file=sys.stderr)
        finally:
            tailer.close()
            outfile.close()
            print(f"✓ {event_count} events -> {engine._streaming_alert_count} alerts -> "
                  f"{incident_count} incident emissions (follow mode)", file=sys.stderr)
    else:
        # --- Batch mode (original behaviour) ---
        # Load events
        print(f"[2/4] Loading enriched events from {args.input}...", file=sys.stderr)
        events = []

        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError:
                        print(f"      ⚠ Line {line_num}: JSON decode error", file=sys.stderr)
                        continue

            print(f"      ✓ Loaded {len(events)} events\n", file=sys.stderr)

        except FileNotFoundError:
            print(f"      ✗ Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        if not events:
            print("      ✗ No events to process", file=sys.stderr)
            sys.exit(1)

        # Process
        print(f"[3/4] Processing events and correlating incidents...", file=sys.stderr)
        print(f"      Time window: {args.time_window} minutes\n", file=sys.stderr)

        incidents = engine.process_events(events)

        if not incidents:
            print("\n      ⚠ No incidents generated (no matching rules or correlation)", file=sys.stderr)
            print(f"\n{'='*70}\n", file=sys.stderr)
            sys.exit(0)

        # Write incidents
        print(f"\n[4/4] Writing incidents to {args.output}...", file=sys.stderr)
        with open(args.output, 'w', encoding='utf-8') as f:
            for incident in incidents:
                if args.pretty:
                    f.write(json.dumps(incident, indent=2, ensure_ascii=False) + "\n")
                else:
                    f.write(json.dumps(incident, separators=(",", ":"), ensure_ascii=False) + "\n")

        print(f"      ✓ Done!\n", file=sys.stderr)

        # Print summary
        print(f"{'='*70}", file=sys.stderr)
        print("INCIDENT SUMMARY", file=sys.stderr)
        print(f"{'='*70}", file=sys.stderr)

        for i, incident in enumerate(incidents, 1):
            print(f"\n[{i}] {incident['incident_id']}: {incident['title']}", file=sys.stderr)
            print(f"    Severity: {incident['severity'].upper()}", file=sys.stderr)
            print(f"    Alerts Correlated: {incident['alert_count']}", file=sys.stderr)
            print(f"    Attack Pattern: {incident['attack_chain']['attack_pattern']}", file=sys.stderr)
            print(f"    Confidence: {incident['attack_chain']['campaign_confidence']}", file=sys.stderr)
            print(f"    Duration: {incident['duration_seconds']}s", file=sys.stderr)

            entities = incident['affected_entities']
            if entities['source_ips']:
                print(f"    Attacking IPs: {', '.join(entities['source_ips'][:3])}", file=sys.stderr)
            if entities['target_ips']:
                print(f"    Target IPs: {', '.join(entities['target_ips'][:3])}", file=sys.stderr)
            if entities['affected_hosts']:
                print(f"    Hosts: {', '.join(entities['affected_hosts'][:3])}", file=sys.stderr)

        print(f"\n{'='*70}", file=sys.stderr)
        print(f"Total: {len(incidents)} incident(s) from {len(engine.alert_buffer)} alerts", file=sys.stderr)
        print(f"{'='*70}\n", file=sys.stderr)

        # Detailed stats if requested
        if args.stats:
            print("\nDETAILED STATISTICS", file=sys.stderr)
            print("="*70, file=sys.stderr)

            # Count by severity
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)

            for incident in incidents:
                severity_counts[incident['severity']] += 1
                category = incident.get('attack_chain', {}).get('attack_pattern', 'Unknown')
                category_counts[category] += 1

            print("\nIncidents by Severity:", file=sys.stderr)
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_counts:
                    print(f"  {severity}: {severity_counts[severity]}", file=sys.stderr)

            print("\nIncidents by Attack Pattern:", file=sys.stderr)
            for pattern, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {pattern}: {count}", file=sys.stderr)

            print(f"\n{'='*70}\n", file=sys.stderr)


if __name__ == "__main__":
    main()
