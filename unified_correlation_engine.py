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
import json
import sys
import yaml
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
import hashlib


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
        self.incident_id_counter = 1
        
        # Load rules
        for rule_config in rules_config.get("rules", []):
            self.rules.append(Rule(rule_config))
        
        # Alert buffering for correlation
        self.alert_buffer = []
        
        # Time windows for aggregation rules
        self.windows = {}
        
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
    
    def _extract_alert_entities(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract entity information from alert."""
        event = alert.get('event', {})
        subject = event.get('subject', {})
        obj = event.get('object', {})
        host = event.get('host', {})
        
        return {
            'source_ip': subject.get('ip'),
            'target_ip': obj.get('ip'),
            'host_id': host.get('id'),
            'host_ip': host.get('ip'),
            'host_name': host.get('name'),
            'user': subject.get('name')
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
    
    def _create_incident(self, alerts: List[Dict[str, Any]], group_key: str) -> Dict[str, Any]:
        """Create incident from grouped alerts."""
        
        # Extract timeline
        timestamps = [a.get('timestamp') for a in alerts]
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
        
        # Create incident summary
        incident = {
            "incident_id": f"INC-{self.incident_id_counter:06d}",
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
            "recommended_actions": recommendations,
            "metadata": {
                "correlation_key": group_key,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "correlated_by": "Unified Correlation Engine v2.0"
            }
        }
        
        self.incident_id_counter += 1
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
            if entities['user']:
                users.add(entities['user'])
        
        return {
            "source_ips": sorted(list(source_ips)),
            "target_ips": sorted(list(target_ips)),
            "affected_hosts": sorted(list(hosts)),
            "affected_users": sorted(list(users)),
            "total_sources": len(source_ips),
            "total_targets": len(target_ips)
        }
    
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
        
        return {
            "alert_id": alert.get('alert_id'),
            "timestamp": alert.get('timestamp'),
            "rule_id": alert.get('rule', {}).get('id'),
            "rule_name": alert.get('rule', {}).get('name'),
            "severity": alert.get('rule', {}).get('severity'),
            "category": alert.get('rule', {}).get('category'),
            "source_ip": event.get('subject', {}).get('ip'),
            "target_ip": event.get('object', {}).get('ip'),
            "target_port": event.get('object', {}).get('port'),
            "user": event.get('subject', {}).get('name')
        }
    
    def _calculate_duration(self, first_seen: str, last_seen: str) -> int:
        """Calculate incident duration in seconds."""
        try:
            first = self._parse_timestamp(first_seen)
            last = self._parse_timestamp(last_seen)
            if first and last:
                return int((last - first).total_seconds())
        except:
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
                except json.JSONDecodeError as e:
                    print(f"      ⚠ Line {line_num}: JSON decode error", file=sys.stderr)
                    continue
        
        print(f"      ✓ Loaded {len(events)} events\n", file=sys.stderr)
    
    except FileNotFoundError:
        print(f"      ✗ Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    if not events:
        print("      ✗ No events to process", file=sys.stderr)
        sys.exit(1)
    
    # Initialize engine and process
    print(f"[3/4] Processing events and correlating incidents...", file=sys.stderr)
    print(f"      Time window: {args.time_window} minutes\n", file=sys.stderr)
    
    engine = UnifiedCorrelationEngine(rules_config, time_window_minutes=args.time_window)
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
