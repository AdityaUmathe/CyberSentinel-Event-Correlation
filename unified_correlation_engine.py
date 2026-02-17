#!/usr/bin/env python3
"""
Unified Event Correlation Engine
Processes enriched logs and directly generates correlated security incidents.

Single-step correlation: Enriched Logs → Correlated Incidents

Features:
- Rule-based alert detection
- Trigger-point based per-source-IP correlation
- Three fixed trigger offsets: 5min, 30min, 24hr (cumulative)
- Dual-firing: event-driven + timer-driven
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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


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


class TriggerPointTracker:
    """Per-source-IP tracker with recurring trigger intervals.

    Fires every 5min, 30min, and 24hr continuously.  Each firing covers
    only the alerts accumulated since the previous firing of that same
    interval.  Trackers are cleaned up when no new alerts arrive for
    longer than STALE_TIMEOUT.
    """

    TRIGGER_INTERVALS: List[Tuple[str, timedelta]] = [
        ("5min",  timedelta(minutes=5)),
        ("30min", timedelta(minutes=30)),
        ("24hr",  timedelta(hours=24)),
    ]
    STALE_TIMEOUT = timedelta(hours=25)

    def __init__(self, source_ip: str, first_seen: datetime):
        self.source_ip = source_ip
        self.first_seen = first_seen
        self.alerts: List[Dict[str, Any]] = []
        self.last_alert_time = first_seen
        # Per-label: when last fired and how far into self.alerts was emitted
        self.last_fired: Dict[str, datetime] = {}
        self.emitted_up_to: Dict[str, int] = {}

    def add_alert(self, alert: Dict[str, Any], alert_time: datetime):
        """Add an alert to this tracker."""
        self.alerts.append(alert)
        if alert_time > self.last_alert_time:
            self.last_alert_time = alert_time

    def check_triggers(self, current_time: datetime) -> List[Tuple[str, timedelta]]:
        """Return labels whose interval has elapsed and have new alerts."""
        due = []
        for label, interval in self.TRIGGER_INTERVALS:
            ref = self.last_fired.get(label, self.first_seen)
            if current_time >= ref + interval:
                idx = self.emitted_up_to.get(label, 0)
                if len(self.alerts) > idx:
                    due.append((label, interval))
        return due

    def get_new_alerts(self, label: str) -> List[Dict[str, Any]]:
        """Alerts accumulated since the last firing of *label*."""
        idx = self.emitted_up_to.get(label, 0)
        return self.alerts[idx:]

    def mark_fired(self, label: str, current_time: datetime):
        """Record that *label* just fired at *current_time*."""
        self.last_fired[label] = current_time
        self.emitted_up_to[label] = len(self.alerts)

    def is_stale(self, current_time: datetime) -> bool:
        """True when no new alerts for longer than STALE_TIMEOUT."""
        return current_time - self.last_alert_time > self.STALE_TIMEOUT


class UnifiedCorrelationEngine:
    """
    Unified correlation engine using trigger-point based per-source-IP correlation.
    Alerts are routed to IP trackers; triggers fire at 5min, 30min, 24hr offsets.
    """

    def __init__(self, rules_config: Dict[str, Any], time_window_minutes: int = 60):
        self.rules = []
        self.time_window = timedelta(minutes=time_window_minutes)
        self.time_window_minutes = time_window_minutes
        self.incident_id_counter = 1

        # Load rules
        for rule_config in rules_config.get("rules", []):
            self.rules.append(Rule(rule_config))

        # Alert buffering for batch mode
        self.alert_buffer = []

        # Time windows for aggregation rules
        self.windows = {}

        # --- Trigger-point state ---
        self.ip_trackers: Dict[str, TriggerPointTracker] = {}

        # Track which aggregation rule+group has already fired to avoid re-firing
        self._aggregation_fired = {}
        # Counter for streaming mode
        self._streaming_alert_count = 0

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process all events and generate correlated incidents (batch mode).

        Routes alerts to IP trackers, then fires all triggers at a synthetic
        end-time so every IP produces 3 trigger records (5min, 30min, 24hr).
        """
        # Step 1: Generate alerts from events
        print(f"Generating alerts from {len(events)} events...", file=sys.stderr)

        for event in events:
            self._process_single_event(event)

        print(f"Generated {len(self.alert_buffer)} alerts", file=sys.stderr)

        if not self.alert_buffer:
            return []

        # Step 2: Route all buffered alerts to IP trackers
        # Collect any immediate emissions (standalone alerts with no source IP)
        print(f"Routing alerts to trigger-point trackers...", file=sys.stderr)
        incidents = []
        for alert in sorted(self.alert_buffer, key=lambda a: a.get('timestamp', '')):
            alert_time = self._parse_timestamp(alert.get('timestamp'))
            if not alert_time:
                alert_time = datetime.now(timezone.utc)
            emissions = self._route_alert_to_tracker(alert, alert_time)
            incidents.extend(emissions)

        # Step 3: Fire all triggers at synthetic end-time
        # Find the max event time and add 24hr+1s so all 3 triggers fire
        max_time = None
        for alert in self.alert_buffer:
            t = self._parse_timestamp(alert.get('timestamp'))
            if t and (max_time is None or t > max_time):
                max_time = t
        if max_time is None:
            max_time = datetime.now(timezone.utc)
        synthetic_end = max_time + timedelta(hours=24, seconds=1)

        for tracker in list(self.ip_trackers.values()):
            emissions = self._check_and_fire_triggers(tracker, synthetic_end)
            incidents.extend(emissions)

        # In batch mode, all trackers are done — clean them up
        self.ip_trackers.clear()

        # Sort incidents by severity and time
        incidents.sort(key=lambda x: (
            self._severity_rank(x['severity']),
            x['first_seen']
        ), reverse=True)

        print(f"Created {len(incidents)} incident(s)", file=sys.stderr)
        return incidents

    def _process_single_event(self, event: Dict[str, Any]):
        """Process single event through all rules (batch mode alert generation)."""
        event_time = self._parse_timestamp(event.get("event_time"))
        if not event_time:
            event_time = datetime.now(timezone.utc)

        for rule in self.rules:
            if rule.rule_type == "single" and rule.evaluate(event):
                alert = Alert(rule, event)
                self.alert_buffer.append(alert.to_dict())

            elif rule.rule_type == "aggregation":
                if rule.id not in self.windows:
                    self.windows[rule.id] = TimeWindow(rule.time_window)

                self.windows[rule.id].add_event(event, event_time)

                window_events = self.windows[rule.id].get_events()
                if self._check_aggregation_threshold(rule, window_events):
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

        groups = defaultdict(list)
        for event in events:
            if rule.evaluate(event):
                group_key = self._get_group_key(event, rule.group_by)
                groups[group_key].append(event)

        threshold_config = rule.threshold.get("count", {})
        min_count = threshold_config.get("gte", 1)
        unique_field = threshold_config.get("unique_field")

        for group_events in groups.values():
            count = self._count_for_threshold(group_events, unique_field)
            if count >= min_count:
                return True

        return False

    def _count_for_threshold(self, events: List[Dict[str, Any]], unique_field: Optional[str] = None) -> int:
        """Count events or unique field values for threshold comparison."""
        if not unique_field:
            return len(events)
        values = set()
        for event in events:
            val = self._get_nested_value(event, unique_field)
            if val is not None:
                values.add(val)
        return len(values)

    # ==================================================================
    # Trigger-point routing and emission
    # ==================================================================

    @staticmethod
    def _extract_source_ip(alert: Dict[str, Any]) -> Optional[str]:
        """Extract source IP from alert's event.subject.ip."""
        return alert.get('event', {}).get('subject', {}).get('ip')

    def _route_alert_to_tracker(self, alert: Dict[str, Any], alert_time: datetime) -> List[Dict[str, Any]]:
        """
        Route an alert to the appropriate IP tracker.
        Creates tracker if needed, adds alert, checks triggers.
        Returns any trigger emissions.
        """
        source_ip = self._extract_source_ip(alert)
        if not source_ip:
            return [self._create_standalone_incident(alert)]

        # Create tracker if this is first alert for this IP
        if source_ip not in self.ip_trackers:
            self.ip_trackers[source_ip] = TriggerPointTracker(source_ip, alert_time)

        tracker = self.ip_trackers[source_ip]
        tracker.add_alert(alert, alert_time)

        # Check for event-driven trigger fires
        return self._check_and_fire_triggers(tracker, alert_time)

    def _check_and_fire_triggers(self, tracker: TriggerPointTracker, current_time: datetime) -> List[Dict[str, Any]]:
        """Check tracker for due triggers and fire them."""
        emissions = []
        for label, interval in tracker.check_triggers(current_time):
            incident = self._emit_trigger_point(tracker, label, current_time)
            if incident:
                tracker.mark_fired(label, current_time)
                emissions.append(incident)
        return emissions

    def _emit_trigger_point(self, tracker: TriggerPointTracker, trigger_label: str, current_time: datetime) -> Optional[Dict[str, Any]]:
        """Build incident dict for a trigger point emission.

        Uses only the alerts accumulated since the previous firing of this
        label (not cumulative across all time).
        """
        new_alerts = tracker.get_new_alerts(trigger_label)
        if not new_alerts:
            return None

        group_key = f"trigger_{tracker.source_ip}_{trigger_label}"
        incident = self._create_incident(new_alerts, group_key)

        ref_time = tracker.last_fired.get(trigger_label, tracker.first_seen)

        def _fmt(dt):
            return dt.isoformat() + ("Z" if dt.tzinfo is None else "")

        incident["trigger_point"] = {
            "label": trigger_label,
            "source_ip": tracker.source_ip,
            "window_start": _fmt(ref_time),
            "window_end": _fmt(current_time),
            "alerts_in_window": len(new_alerts),
        }

        incident["trigger_summary"] = self._generate_trigger_summary(
            tracker, trigger_label, new_alerts, ref_time, current_time
        )

        return incident

    def _generate_trigger_summary(self, tracker: TriggerPointTracker, trigger_label: str,
                                  alerts: List[Dict[str, Any]],
                                  window_start: datetime, window_end: datetime) -> str:
        """Build a multi-line trigger summary string."""
        categories = defaultdict(int)
        severities = defaultdict(int)
        target_ips = set()
        users = set()

        for alert in alerts:
            rule = alert.get('rule', {})
            categories[rule.get('category', 'unknown')] += 1
            severities[rule.get('severity', 'unknown')] += 1
            entities = self._extract_alert_entities(alert)
            if entities['target_ip']:
                target_ips.add(entities['target_ip'])
            if entities['user']:
                users.add(entities['user'])

        attack_info = self._analyze_attack_patterns(alerts)

        def _fmt(dt):
            return dt.isoformat() + ("Z" if dt.tzinfo is None else "")

        lines = [
            f"Trigger: {trigger_label} | Source IP: {tracker.source_ip}",
            f"Window: {_fmt(window_start)} to {_fmt(window_end)}",
            f"Alerts: {len(alerts)}",
            f"Categories: {', '.join(f'{k}: {v}' for k, v in sorted(categories.items(), key=lambda x: -x[1]))}",
            f"Severities: {', '.join(f'{k}: {v}' for k, v in sorted(severities.items(), key=lambda x: -x[1]))}",
        ]
        if target_ips:
            lines.append(f"Targets: {', '.join(sorted(target_ips)[:5])}")
        if users:
            lines.append(f"Users: {', '.join(sorted(users)[:5])}")
        lines.append(f"Pattern: {attack_info['pattern']}")

        return '\n'.join(lines)

    def _create_standalone_incident(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Create an immediate incident for alerts with no source IP."""
        group_key = f"standalone_{alert.get('alert_id', 'unknown')}"
        incident = self._create_incident([alert], group_key)

        alert_time_str = alert.get('timestamp', datetime.utcnow().isoformat() + "Z")

        incident["trigger_point"] = {
            "label": "immediate",
            "source_ip": None,
            "window_start": alert_time_str,
            "window_end": alert_time_str,
            "alerts_in_window": 1,
        }
        incident["trigger_summary"] = (
            f"Trigger Point: immediate (no source IP)\n"
            f"Alert: {alert.get('rule', {}).get('name', 'Unknown')}\n"
            f"Severity: {alert.get('rule', {}).get('severity', 'unknown')}"
        )
        return incident

    # ==================================================================
    # Streaming methods
    # ==================================================================

    def process_single_event_streaming(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process one event in streaming mode.

        Returns a list of incident dicts emitted by trigger-point firing.
        """
        emitted = []
        event_time = self._parse_timestamp(event.get("event_time"))
        if not event_time:
            event_time = datetime.now(timezone.utc)

        for rule in self.rules:
            if rule.rule_type == "single" and rule.evaluate(event):
                alert = Alert(rule, event).to_dict()
                self._streaming_alert_count += 1
                emissions = self._route_alert_to_tracker(alert, event_time)
                emitted.extend(emissions)

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
                    unique_field = threshold_config.get("unique_field")

                    group_events = groups.get(group_key, [])
                    count = self._count_for_threshold(group_events, unique_field)
                    if count >= min_count:
                        if fire_key not in self._aggregation_fired:
                            self._aggregation_fired[fire_key] = datetime.now(timezone.utc)
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
                            emissions = self._route_alert_to_tracker(alert, event_time)
                            emitted.extend(emissions)

        return emitted

    def flush_trackers(self) -> List[Dict[str, Any]]:
        """
        Timer-driven flush: fire any overdue recurring triggers, remove
        stale trackers (no alerts for >25 hours), clean aggregation state.
        """
        now = datetime.now(timezone.utc)
        emissions = []

        for ip, tracker in list(self.ip_trackers.items()):
            fired = self._check_and_fire_triggers(tracker, now)
            emissions.extend(fired)

        # Remove stale trackers (no new alerts for >25 hours)
        stale = [ip for ip, t in self.ip_trackers.items() if t.is_stale(now)]
        for ip in stale:
            del self.ip_trackers[ip]

        # Clean up aggregation fired keys
        stale_cutoff = now.replace(tzinfo=None) - timedelta(minutes=self.time_window_minutes * 2)
        stale_fire_keys = []
        for fire_key, fired_at in self._aggregation_fired.items():
            rule_id = fire_key[0]
            if rule_id in self.windows:
                window = self.windows[rule_id]
                if window.count() == 0:
                    stale_fire_keys.append(fire_key)
            elif isinstance(fired_at, datetime) and fired_at.replace(tzinfo=None) < stale_cutoff:
                stale_fire_keys.append(fire_key)
            elif not isinstance(fired_at, datetime) and rule_id not in self.windows:
                stale_fire_keys.append(fire_key)

        for fk in stale_fire_keys:
            del self._aggregation_fired[fk]

        return emissions

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

    def _compact_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group alerts by target IP, producing compact summaries instead of listing every alert.

        Returns a list of dicts, one per target IP (or "unknown"), each containing:
        target_ip, alert_count, rules triggered, severity breakdown, users, time range.
        """
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for alert in alerts:
            entities = self._extract_alert_entities(alert)
            target = entities['target_ip'] or "unknown"
            groups[target].append(alert)

        compact = []
        for target_ip, group_alerts in sorted(groups.items(), key=lambda x: -len(x[1])):
            rules = {}
            severities = defaultdict(int)
            users = set()
            timestamps = []
            original_event_ids_seen: set = set()
            original_event_ids: list = []

            for a in group_alerts:
                rule = a.get('rule', {})
                rule_name = rule.get('name', 'Unknown')
                rules[rule_name] = rules.get(rule_name, 0) + 1
                severities[rule.get('severity', 'unknown')] += 1
                entities = self._extract_alert_entities(a)
                if entities['user']:
                    users.add(entities['user'])
                ts = a.get('timestamp')
                if ts:
                    timestamps.append(ts)
                eid = a.get('event', {}).get('event_id')
                if eid and eid not in original_event_ids_seen:
                    original_event_ids_seen.add(eid)
                    original_event_ids.append(eid)

            entry = {
                "target_ip": target_ip if target_ip != "unknown" else None,
                "alert_count": len(group_alerts),
                "rules": rules,
                "severities": dict(severities),
            }
            if users:
                entry["users"] = sorted(users)
            if timestamps:
                entry["first_seen"] = min(timestamps)
                entry["last_seen"] = max(timestamps)
            if original_event_ids:
                entry["original_event_ids"] = original_event_ids
            compact.append(entry)

        return compact

    def _create_incident(
        self,
        alerts: List[Dict[str, Any]],
        group_key: str,
        existing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create incident from grouped alerts."""
        # Extract timeline
        timestamps = [a.get('timestamp') for a in alerts if a.get('timestamp')]
        if not timestamps:
            now_str = datetime.utcnow().isoformat() + "Z"
            timestamps = [now_str]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        severities = [a.get('rule', {}).get('severity') for a in alerts]
        incident_severity = self._calculate_incident_severity(severities)

        entities = self._extract_incident_entities(alerts)
        attack_info = self._analyze_attack_patterns(alerts)
        recommendations = self._combine_recommendations(alerts)

        if existing_id:
            incident_id = existing_id
        else:
            incident_id = f"INC-{self.incident_id_counter:06d}"
            self.incident_id_counter += 1

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
            "alert_summary": self._compact_alerts(alerts),
            "alerts": [self._summarize_alert(alerts[0])] if alerts else [],
            "enrichment_summary": self._aggregate_enrichment(alerts),
            "recommended_actions": recommendations,
            "metadata": {
                "correlation_key": group_key,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "correlated_by": "Unified Correlation Engine v2.0"
            }
        }

        # Only include IOCs when there is actual data
        iocs = self._extract_iocs(alerts)
        if iocs:
            incident["indicators_of_compromise"] = iocs

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
        all_tactics = []
        categories = []
        source_ips = set()

        for alert in alerts:
            rule = alert.get('rule', {})
            all_tactics.extend(rule.get('mitre_tactics', []))
            categories.append(rule.get('category'))
            src_ip = self._extract_source_ip(alert)
            if src_ip:
                source_ips.add(src_ip)

        tactics = sorted(list(set(all_tactics)))
        primary_category = max(set(categories), key=categories.count) if categories else 'unknown'

        pattern, confidence = self._identify_attack_pattern(
            primary_category, len(alerts), categories, len(source_ips)
        )

        return {
            'tactics': tactics,
            'techniques': [],
            'pattern': pattern,
            'confidence': confidence
        }

    def _identify_attack_pattern(self, category: str, alert_count: int,
                                 categories: List[str], source_count: int = 1) -> tuple:
        """Identify attack pattern based on alerts."""
        category_counts = defaultdict(int)
        for cat in categories:
            category_counts[cat] += 1

        if alert_count >= 5:
            confidence = "high"
        elif alert_count >= 3:
            confidence = "medium"
        else:
            confidence = "low"

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
            if source_count > 1 and 'multi_source_pattern' in patterns[category]:
                return patterns[category]['multi_source_pattern'], confidence
            elif 'pattern' in patterns[category]:
                return patterns[category]['pattern'], confidence
            elif 'single_pattern' in patterns[category]:
                return patterns[category]['single_pattern'], confidence

        return f"Multi-Stage Security Incident ({category})", confidence

    def _combine_recommendations(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Combine and deduplicate recommendations from all alerts."""
        all_recs = []
        seen = set()

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

        for alert in alerts:
            for rec in alert.get('recommended_response', []):
                if rec not in seen:
                    all_recs.append(rec)
                    seen.add(rec)

        return all_recs

    def _extract_iocs(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract indicators of compromise from all alerts.

        Only returns categories that actually have data — no empty arrays.
        Does NOT auto-populate fields (e.g. auth target users are not
        treated as "compromised accounts").
        """
        malicious_ips: List[str] = []
        suspicious_ips: List[str] = []
        affected_ports: List[Any] = []

        for alert in alerts:
            event = alert.get('event', {})
            enrich = event.get('enrich', {})
            network_intel = enrich.get('network_intel', {})

            src_rep = network_intel.get('src_reputation', {})
            if src_rep.get('ip_reputation') == 'malicious':
                src_ip = event.get('subject', {}).get('ip')
                if src_ip and src_ip not in malicious_ips:
                    malicious_ips.append(src_ip)
            elif src_rep.get('ip_reputation') == 'suspicious':
                src_ip = event.get('subject', {}).get('ip')
                if src_ip and src_ip not in suspicious_ips:
                    suspicious_ips.append(src_ip)

            dest_port = event.get('object', {}).get('port')
            if dest_port and dest_port not in affected_ports:
                affected_ports.append(dest_port)

        # Only include categories with actual data
        iocs: Dict[str, List] = {}
        if malicious_ips:
            iocs["malicious_ips"] = malicious_ips
        if suspicious_ips:
            iocs["suspicious_ips"] = suspicious_ips
        if affected_ports:
            iocs["affected_ports"] = affected_ports
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
        """Create summary of individual alert for incident.

        Omits null/empty fields and per-alert enrichment (enrichment is
        aggregated at the incident level instead).
        """
        entities = self._extract_alert_entities(alert)
        event = alert.get('event', {})
        obj = event.get('object', {})
        host = event.get('host', {})

        summary: Dict[str, Any] = {}
        # Only include fields that have actual values
        _maybe = [
            ("alert_id", alert.get('alert_id')),
            ("timestamp", alert.get('timestamp')),
            ("rule_id", alert.get('rule', {}).get('id')),
            ("rule_name", alert.get('rule', {}).get('name')),
            ("severity", alert.get('rule', {}).get('severity')),
            ("category", alert.get('rule', {}).get('category')),
            ("source_ip", entities['source_ip']),
            ("target_ip", entities['target_ip']),
            ("target_port", obj.get('port') or host.get('port')),
            ("user", entities['user']),
            ("original_event_id", event.get('event_id')),
            ("original_signature_id", event.get('security', {}).get('signature_id')),
            ("original_signature", event.get('security', {}).get('signature')),
            ("original_action", event.get('enrich', {}).get('normalization', {}).get('action')),
        ]
        for key, val in _maybe:
            if val is not None:
                summary[key] = val
        return summary

    def _extract_enrichment_summary(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract compact enrichment data with separate source/destination sections.

        Skips the destination section when it is identical to source (happens
        when L2 enriched both sides with the same IP).
        """
        enrich = alert.get('event', {}).get('enrich', {})
        if not enrich:
            return {}

        summary = {}
        source = {}
        destination = {}

        # GeoIP — separated by src/dest
        geo = enrich.get('geo', {})
        if geo:
            src_geo = geo.get('src', {})
            dest_geo = geo.get('dest', {})
            if src_geo:
                source["geo"] = {
                    "country": src_geo.get("country"),
                    "country_code": src_geo.get("country_code"),
                    "city": src_geo.get("city"),
                }
            if dest_geo:
                destination["geo"] = {
                    "country": dest_geo.get("country"),
                    "country_code": dest_geo.get("country_code"),
                    "city": dest_geo.get("city"),
                }
            if geo.get("distance_km") is not None:
                summary["distance_km"] = geo["distance_km"]
            if geo.get("cross_border") is not None:
                summary["cross_border"] = geo["cross_border"]

        # Network intelligence — separated by src/dest
        ni = enrich.get('network_intel', {})
        if ni:
            src_asn = ni.get('src_asn', {})
            dest_asn = ni.get('dest_asn', {})
            src_rep = ni.get('src_reputation', {})
            dest_rep = ni.get('dest_reputation', {})

            if src_asn:
                source["asn"] = src_asn
            if src_rep:
                source["reputation"] = src_rep.get('ip_reputation', 'unknown')
            source["tor_exit_node"] = bool(ni.get('tor_detected', False))

            if dest_asn:
                destination["asn"] = dest_asn
            if dest_rep:
                destination["reputation"] = dest_rep.get('ip_reputation', 'unknown')
            destination["tor_exit_node"] = False

        if source:
            summary["source"] = source
        # Only include destination if it differs from source (avoid mirrored data)
        if destination and destination != source:
            summary["destination"] = destination

        # Impossible travel
        it = enrich.get('impossible_travel')
        if it and it.get('is_impossible_travel'):
            summary["impossible_travel"] = it
        else:
            summary["impossible_travel"] = None

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
        """Aggregate enrichment data across all alerts, separated by source/destination."""
        # Source aggregation
        src_countries = set()
        src_cities = set()
        src_asn_orgs = set()
        src_tor_detected = False
        src_threat_detected = False
        src_malicious_ips = []
        src_suspicious_ips = []

        # Destination aggregation
        dest_countries = set()
        dest_cities = set()
        dest_asn_orgs = set()
        dest_tor_detected = False
        dest_threat_detected = False
        dest_malicious_ips = []
        dest_suspicious_ips = []

        # Shared
        cross_border = False
        max_distance_km = None
        impossible_travel = None
        all_anomalies = set()
        max_risk_score = 0.0
        country_codes = set()

        for alert in alerts:
            enrich = alert.get('event', {}).get('enrich', {})
            if not enrich:
                continue

            # Geo
            geo = enrich.get('geo', {})
            src_g = geo.get('src', {})
            dest_g = geo.get('dest', {})

            if src_g.get('country'):
                src_countries.add(src_g['country'])
            if src_g.get('country_code'):
                country_codes.add(src_g['country_code'])
            if src_g.get('city'):
                src_cities.add(src_g['city'])

            if dest_g.get('country'):
                dest_countries.add(dest_g['country'])
            if dest_g.get('country_code'):
                country_codes.add(dest_g['country_code'])
            if dest_g.get('city'):
                dest_cities.add(dest_g['city'])

            if geo.get('distance_km') is not None:
                if max_distance_km is None or geo['distance_km'] > max_distance_km:
                    max_distance_km = geo['distance_km']
            if geo.get('cross_border'):
                cross_border = True

            # Network intel
            ni = enrich.get('network_intel', {})
            src_asn = ni.get('src_asn', {})
            dest_asn = ni.get('dest_asn', {})

            if src_asn.get('org'):
                src_asn_orgs.add(src_asn['org'])
            if dest_asn.get('org'):
                dest_asn_orgs.add(dest_asn['org'])

            if ni.get('tor_detected'):
                src_tor_detected = True
            if ni.get('threat_detected'):
                src_threat_detected = True

            # Reputation — source
            src_rep = ni.get('src_reputation', {})
            src_status = src_rep.get('ip_reputation')
            if src_status in ('malicious', 'suspicious'):
                src_ip = alert.get('event', {}).get('subject', {}).get('ip')
                if src_ip:
                    if src_status == 'malicious' and src_ip not in src_malicious_ips:
                        src_malicious_ips.append(src_ip)
                    elif src_status == 'suspicious' and src_ip not in src_suspicious_ips:
                        src_suspicious_ips.append(src_ip)

            # Reputation — destination
            dest_rep = ni.get('dest_reputation', {})
            dest_status = dest_rep.get('ip_reputation')
            if dest_status in ('malicious', 'suspicious'):
                dest_ip = alert.get('event', {}).get('object', {}).get('ip')
                if dest_ip:
                    if dest_status == 'malicious' and dest_ip not in dest_malicious_ips:
                        dest_malicious_ips.append(dest_ip)
                    elif dest_status == 'suspicious' and dest_ip not in dest_suspicious_ips:
                        dest_suspicious_ips.append(dest_ip)

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

        # Derive cross_border from collected country codes if per-event flag missed it
        if not cross_border and len(country_codes) > 1:
            cross_border = True

        # Add cross_border to anomaly flags if true
        if cross_border:
            all_anomalies.add("cross_border")
        # Check for cross-continent (simplified: >1 unique country)
        all_countries = src_countries | dest_countries
        if len(all_countries) > 1:
            all_anomalies.add("cross_continent")

        result = {}

        # Source section
        source_section = {
            "countries": sorted(src_countries),
            "cities": sorted(src_cities),
            "asn_orgs": sorted(src_asn_orgs),
            "tor_detected": src_tor_detected,
            "threat_detected": src_threat_detected,
            "malicious_ips": src_malicious_ips,
            "suspicious_ips": src_suspicious_ips,
        }
        result["source"] = source_section

        # Destination section — only include if it differs from source
        destination_section = {
            "countries": sorted(dest_countries),
            "cities": sorted(dest_cities),
            "asn_orgs": sorted(dest_asn_orgs),
            "tor_detected": dest_tor_detected,
            "threat_detected": dest_threat_detected,
            "malicious_ips": dest_malicious_ips,
            "suspicious_ips": dest_suspicious_ips,
        }
        if destination_section != source_section:
            result["destination"] = destination_section

        result["cross_border"] = cross_border
        if max_distance_km is not None:
            result["max_distance_km"] = max_distance_km
        result["impossible_travel"] = impossible_travel
        if all_anomalies:
            result["anomaly_flags"] = sorted(all_anomalies)
        if max_risk_score > 0:
            result["max_risk_score"] = max_risk_score

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
        description="Unified Event Correlation Engine - Enriched Logs -> Correlated Incidents"
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
        print(f"      Loaded {len(rules_config.get('rules', []))} rules\n", file=sys.stderr)
    except FileNotFoundError:
        print(f"      Error: Rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"      Error parsing YAML: {e}", file=sys.stderr)
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

                # Periodic flush: fire timer-driven triggers
                now = time.time()
                if now - last_flush >= args.flush_interval:
                    timer_emissions = engine.flush_trackers()
                    for incident in timer_emissions:
                        append_jsonl(outfile, incident)
                        incident_count += 1
                    last_flush = now

                if event_count % 500 == 0:
                    print(f"  Events: {event_count}, Incidents: {incident_count}, "
                          f"Alerts: {engine._streaming_alert_count}, "
                          f"Active IPs: {len(engine.ip_trackers)}", file=sys.stderr)

        except KeyboardInterrupt:
            print("\nShutting down correlation engine...", file=sys.stderr)
        finally:
            tailer.close()
            outfile.close()
            print(f"{event_count} events -> {engine._streaming_alert_count} alerts -> "
                  f"{incident_count} incident emissions (follow mode)", file=sys.stderr)
    else:
        # --- Batch mode ---
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
                        print(f"      Line {line_num}: JSON decode error", file=sys.stderr)
                        continue

            print(f"      Loaded {len(events)} events\n", file=sys.stderr)

        except FileNotFoundError:
            print(f"      Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        if not events:
            print("      No events to process", file=sys.stderr)
            sys.exit(1)

        # Process
        print(f"[3/4] Processing events and correlating incidents...", file=sys.stderr)
        print(f"      Time window: {args.time_window} minutes\n", file=sys.stderr)

        incidents = engine.process_events(events)

        if not incidents:
            print("\n      No incidents generated (no matching rules or correlation)", file=sys.stderr)
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

        print(f"      Done!\n", file=sys.stderr)

        # Print summary
        print(f"{'='*70}", file=sys.stderr)
        print("INCIDENT SUMMARY", file=sys.stderr)
        print(f"{'='*70}", file=sys.stderr)

        for i, incident in enumerate(incidents, 1):
            trigger = incident.get('trigger_point', {})
            trigger_label = trigger.get('label', 'N/A')
            print(f"\n[{i}] {incident['incident_id']}: {incident['title']}", file=sys.stderr)
            print(f"    Severity: {incident['severity'].upper()}", file=sys.stderr)
            print(f"    Trigger: {trigger_label} | Source IP: {trigger.get('source_ip', 'N/A')}", file=sys.stderr)
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

            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            trigger_counts = defaultdict(int)

            for incident in incidents:
                severity_counts[incident['severity']] += 1
                category = incident.get('attack_chain', {}).get('attack_pattern', 'Unknown')
                category_counts[category] += 1
                trigger_label = incident.get('trigger_point', {}).get('label', 'unknown')
                trigger_counts[trigger_label] += 1

            print("\nIncidents by Severity:", file=sys.stderr)
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_counts:
                    print(f"  {severity}: {severity_counts[severity]}", file=sys.stderr)

            print("\nIncidents by Attack Pattern:", file=sys.stderr)
            for pattern, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {pattern}: {count}", file=sys.stderr)

            print("\nIncidents by Trigger Point:", file=sys.stderr)
            for label, count in sorted(trigger_counts.items()):
                print(f"  {label}: {count}", file=sys.stderr)

            print(f"\n{'='*70}\n", file=sys.stderr)


if __name__ == "__main__":
    main()
