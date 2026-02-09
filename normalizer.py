#!/usr/bin/env python3
"""
Wazuh Log Normalization Pipeline
Production-grade streaming normalizer with robust parsing and OS/device enrichment.
Handles partial JSON, embedded newlines, log rotation, and diverse alert types.
"""

import argparse
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# ROBUST JSON PARSING (Handles partial writes, embedded newlines)
# ============================================================================

class IncrementalJSONParser:
    """
    Incrementally parse JSON objects from a stream that may contain:
    - Partial objects
    - Embedded newlines
    - Interrupted writes
    """
    
    def __init__(self, max_buffer_size: int = 10 * 1024 * 1024):
        self.buffer = ""
        self.max_buffer_size = max_buffer_size
        self.decoder = json.JSONDecoder()
    
    def feed(self, chunk: str) -> List[Dict[str, Any]]:
        """
        Feed new data and extract complete JSON objects.
        Returns list of successfully parsed objects.
        """
        self.buffer += chunk
        objects = []
        
        while self.buffer:
            # Skip whitespace and junk until we find a '{'
            self.buffer = self.buffer.lstrip()
            if not self.buffer:
                break
            
            # If buffer doesn't start with '{', discard until next '{'
            if not self.buffer.startswith('{'):
                next_brace = self.buffer.find('{')
                if next_brace == -1:
                    # No valid JSON start found, clear buffer
                    print(f"Warning: Discarding junk data: {self.buffer[:100]}...", file=sys.stderr)
                    self.buffer = ""
                    break
                else:
                    discarded = self.buffer[:next_brace]
                    print(f"Warning: Discarding junk before JSON: {discarded[:100]}...", file=sys.stderr)
                    self.buffer = self.buffer[next_brace:]
                    continue
            
            # Try to decode a JSON object
            try:
                obj, end_idx = self.decoder.raw_decode(self.buffer)
                objects.append(obj)
                self.buffer = self.buffer[end_idx:]
            except json.JSONDecodeError as e:
                # Incomplete JSON - need more data
                # But if buffer is too large, we may have corrupted data
                if len(self.buffer) > self.max_buffer_size:
                    # Try to recover by finding next '{'
                    next_brace = self.buffer.find('{', 1)
                    if next_brace == -1:
                        # No recovery possible, emit error record
                        fragment = self.buffer[:1000]
                        print(f"Error: Buffer overflow, emitting error record: {fragment}...", file=sys.stderr)
                        objects.append(self._create_error_record(fragment))
                        self.buffer = ""
                    else:
                        # Skip to next potential object
                        discarded = self.buffer[:next_brace]
                        print(f"Warning: Skipping corrupted data: {discarded[:200]}...", file=sys.stderr)
                        self.buffer = self.buffer[next_brace:]
                else:
                    # Wait for more data
                    break
        
        return objects
    
    def _create_error_record(self, fragment: str) -> Dict[str, Any]:
        """Create a minimal alert for unparseable data."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "id": str(uuid.uuid4()),
            "rule": {
                "id": "0",
                "description": "Unparseable alert fragment",
                "level": 0,
                "groups": ["parse_error"]
            },
            "full_log": fragment,
            "_parse_error": True
        }


# ============================================================================
# TIMESTAMP PARSING
# ============================================================================

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse various timestamp formats to timezone-aware datetime."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    
    # Normalize timezone format
    normalized = ts_str.strip()
    if normalized.endswith('Z'):
        normalized = normalized[:-1] + '+0000'
    
    # Remove colon from timezone offset (e.g., +05:30 -> +0530)
    if len(normalized) > 6:
        tz_match = re.search(r'([+-]\d{2}):(\d{2})$', normalized)
        if tz_match:
            normalized = normalized[:tz_match.start()] + tz_match.group(1) + tz_match.group(2)
    
    # Try multiple formats
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%b %d %H:%M:%S',  # Syslog format
        '%Y-%m-%d',
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(normalized, fmt)
            if dt.tzinfo is None:
                # Assume local timezone
                dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            return dt
        except ValueError:
            continue
    
    # Try Unix timestamp
    try:
        ts = float(normalized)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError):
        pass
    
    return None


def extract_event_time(alert: Dict[str, Any]) -> datetime:
    """Extract most specific event timestamp."""
    # Search common locations in order of preference
    search_paths = [
        ['data', 'timestamp'],
        ['data', '@timestamp'],
        ['data', 'event_time'],
        ['data', 'EventTime'],
        ['data', 'time'],
        ['data', 'datetime'],
        ['data', 'UtcTime'],
        ['data', 'TimeGenerated'],
        ['data', 'win', 'system', 'systemTime'],
        ['timestamp'],
        ['@timestamp'],
    ]
    
    for path in search_paths:
        val = alert
        for key in path:
            if isinstance(val, dict) and key in val:
                val = val[key]
            else:
                val = None
                break
        
        if val:
            ts = parse_timestamp(str(val))
            if ts:
                return ts
    
    # Fallback to current time
    return datetime.now(timezone.utc)


def extract_ingest_time(alert: Dict[str, Any]) -> datetime:
    """Extract Wazuh ingest timestamp."""
    ts = parse_timestamp(alert.get('timestamp', ''))
    return ts if ts else datetime.now(timezone.utc)


# ============================================================================
# FIELD EXTRACTION UTILITIES
# ============================================================================

def safe_get(obj: Any, *keys: str, default=None) -> Any:
    """Safely traverse nested dictionary."""
    if not isinstance(obj, dict):
        return default
    for key in keys:
        if key in obj and obj[key] not in (None, ''):
            return obj[key]
    return default


def deep_search(obj: Dict[str, Any], *key_patterns: str) -> Optional[Any]:
    """
    Recursively search for keys matching patterns (case-insensitive).
    Returns first match found.
    """
    if not isinstance(obj, dict):
        return None
    
    # Check current level
    for pattern in key_patterns:
        pattern_lower = pattern.lower()
        for key, val in obj.items():
            if key.lower() == pattern_lower and val not in (None, ''):
                return val
    
    # Recurse into nested dicts
    for val in obj.values():
        if isinstance(val, dict):
            result = deep_search(val, *key_patterns)
            if result is not None:
                return result
    
    return None


def extract_ip(data: Dict[str, Any], *key_patterns: str) -> Optional[str]:
    """Extract IP address from candidate keys."""
    for pattern in key_patterns:
        val = deep_search(data, pattern)
        if val and isinstance(val, str):
            # Simple IPv4 validation
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
                return val
    return None


def extract_port(data: Dict[str, Any], *key_patterns: str) -> Optional[int]:
    """Extract port number from candidate keys."""
    for pattern in key_patterns:
        val = deep_search(data, pattern)
        if val is not None:
            try:
                port = int(val)
                if 0 <= port <= 65535:
                    return port
            except (ValueError, TypeError):
                continue
    return None


def extract_user(data: Dict[str, Any], *key_patterns: str) -> Optional[str]:
    """Extract username from candidate keys."""
    for pattern in key_patterns:
        val = deep_search(data, pattern)
        if val and isinstance(val, str) and val.strip():
            return val.strip()
    return None


# ============================================================================
# OS / DEVICE TYPE DETECTION
# ============================================================================

def detect_os_and_type(alert: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """
    Detect OS family/version and host type using heuristics.
    Returns (os_dict, host_type)
    """
    # Gather hints
    data = alert.get('data', {})
    decoder = alert.get('decoder', {})
    rule_groups = alert.get('rule', {}).get('groups', [])
    location = (alert.get('location') or '').lower()
    full_log = (alert.get('full_log') or '').lower()
    
    all_text = ' '.join([
        str(decoder.get('name', '')).lower(),
        str(decoder.get('parent', '')).lower(),
        location,
        full_log[:500],
        ' '.join(str(g).lower() for g in rule_groups)
    ])
    
    os_info = {'name': None, 'version': None, 'family': None}
    host_type = 'unknown'
    
    # Windows detection
    if any(key in data for key in ['EventID', 'Channel', 'Provider', 'EventData', 'win']):
        os_info['family'] = 'windows'
        # Try to extract version
        if 'windows' in all_text:
            version_match = re.search(r'windows\s*(server\s*)?([\d.]+|xp|vista|7|8|10|11|2008|2012|2016|2019|2022)', all_text)
            if version_match:
                os_info['version'] = version_match.group(0)
        host_type = 'workstation' if any(x in all_text for x in ['workstation', 'desktop', 'win10', 'win11']) else 'server'
    
    elif any(keyword in all_text for keyword in ['windows', 'win32', 'sysmon', 'eventlog', 'microsoft-windows']):
        os_info['family'] = 'windows'
        host_type = 'workstation' if 'desktop' in all_text else 'server'
    
    # Linux detection
    elif any(keyword in all_text for keyword in ['sshd', 'pam', 'auditd', 'journald', 'systemd', '/var/log/', 'linux', 'ubuntu', 'debian', 'centos', 'rhel', 'fedora']):
        os_info['family'] = 'linux'
        # Try to detect distro
        for distro in ['ubuntu', 'debian', 'centos', 'rhel', 'fedora', 'amazon linux', 'alpine']:
            if distro in all_text:
                os_info['name'] = distro
                break
        host_type = 'server'
    
    # macOS detection
    elif any(keyword in all_text for keyword in ['darwin', 'macos', 'osx', 'launchd', 'endpointsecurity', 'apple']):
        os_info['family'] = 'macos'
        host_type = 'workstation'
    
    # Network device detection
    elif any(keyword in all_text for keyword in ['fortigate', 'fortinet', 'cisco', 'paloalto', 'palo alto', 'juniper', 'checkpoint', 'netscaler', 'f5', 'arista']):
        os_info['family'] = 'network_os'
        
        # Specific vendor
        if 'fortigate' in all_text or 'fortinet' in all_text:
            os_info['name'] = 'fortios'
        elif 'cisco' in all_text:
            os_info['name'] = 'cisco_ios'
        elif 'palo' in all_text:
            os_info['name'] = 'pan-os'
        elif 'juniper' in all_text:
            os_info['name'] = 'junos'
        
        # Device type
        if any(x in all_text for x in ['firewall', 'utm', 'ngfw']):
            host_type = 'firewall'
        elif any(x in all_text for x in ['ids', 'ips', 'intrusion']):
            host_type = 'ids'
        elif 'router' in all_text:
            host_type = 'router'
        elif 'switch' in all_text:
            host_type = 'switch'
        else:
            host_type = 'network_device'
    
    # Cloud/container detection
    elif any(keyword in all_text for keyword in ['cloudtrail', 'azure', 'gcp', 'aws', 'kubernetes', 'docker', 'k8s']):
        host_type = 'cloud'
        if 'container' in all_text or 'docker' in all_text or 'k8s' in all_text:
            host_type = 'container'
    
    return os_info, host_type


# ============================================================================
# HOST EXTRACTION
# ============================================================================

def extract_host(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract comprehensive host information with OS enrichment."""
    agent = alert.get('agent', {})
    manager = alert.get('manager', {})
    predecoder = alert.get('predecoder', {})
    
    # Host name priority
    host_name = (
        agent.get('name') or
        predecoder.get('hostname') or
        manager.get('name')
    )
    
    # Detect OS and type
    os_info, host_type = detect_os_and_type(alert)
    
    return {
        'id': agent.get('id'),
        'name': host_name,
        'ip': agent.get('ip'),
        'os': os_info,
        'type': host_type
    }


# ============================================================================
# ENTITY EXTRACTION
# ============================================================================

def extract_entities(alert: Dict[str, Any]) -> Tuple[Dict, Dict]:
    """Extract subject (initiator) and object (target) entities."""
    data = alert.get('data', {})
    
    # Source/Subject
    src_ip = extract_ip(data, 'src_ip', 'srcip', 'source_ip', 'client_ip', 'saddr', 'src', 'srcaddr', 'SourceAddress', 'ClientIP')
    src_port = extract_port(data, 'src_port', 'srcport', 'sport', 'source_port', 'SourcePort')
    src_user = extract_user(data, 'user', 'username', 'srcuser', 'SubjectUserName', 'UserName', 'Account', 'SourceUserName')
    
    # Destination/Object
    dst_ip = extract_ip(data, 'dest_ip', 'dstip', 'destination_ip', 'server_ip', 'daddr', 'dst', 'dstaddr', 'DestinationAddress', 'TargetIP')
    dst_port = extract_port(data, 'dest_port', 'dstport', 'dport', 'destination_port', 'DestinationPort')
    dst_user = extract_user(data, 'dstuser', 'targetUserName', 'TargetUserName', 'DestinationUserName')
    
    # Object name (file, process, service, etc.)
    obj_name = safe_get(data,
        'file', 'filepath', 'file_path', 'path', 'TargetFilename', 'ObjectName',
        'url', 'domain', 'query', 'dns_query', 'QueryName',
        'process', 'process_name', 'Image', 'ProcessName',
        'service', 'ServiceName', 'registry', 'resource'
    )
    
    # Subject
    subject = {
        'type': 'user' if src_user else ('ip' if src_ip else None),
        'id': src_user or src_ip,
        'name': src_user,
        'ip': src_ip,
        'port': src_port
    }
    
    # Object
    obj_type = None
    if obj_name:
        obj_lower = str(obj_name).lower()
        if any(ext in obj_lower for ext in ['.exe', '.dll', '.sys', '.bin', 'process']):
            obj_type = 'process'
        elif any(x in obj_lower for x in ['http', 'www', 'url']):
            obj_type = 'url'
        elif '/' in obj_lower or '\\' in obj_lower:
            obj_type = 'file'
        else:
            obj_type = 'resource'
    elif dst_ip:
        obj_type = 'ip'
    elif dst_user:
        obj_type = 'user'
    
    obj = {
        'type': obj_type,
        'id': dst_user or obj_name or dst_ip,
        'name': obj_name or dst_user,
        'ip': dst_ip,
        'port': dst_port
    }
    
    return subject, obj


# ============================================================================
# NETWORK EXTRACTION
# ============================================================================

def extract_network(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract network protocol and direction."""
    data = alert.get('data', {})
    
    # Protocol
    proto = safe_get(data, 'proto', 'protocol', 'transport', 'Protocol', 'IPProtocol')
    if proto:
        proto_str = str(proto).upper()
        # Map numeric to name
        proto_map = {
            '6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6',
            '41': 'IPv6', '47': 'GRE', '50': 'ESP', '51': 'AH'
        }
        proto = proto_map.get(proto_str, proto_str)
    
    # Direction
    direction = safe_get(data, 'direction', 'Direction', 'flow_direction')
    if direction:
        direction = str(direction).lower()
    
    return {
        'protocol': proto,
        'direction': direction
    }


# ============================================================================
# SECURITY EXTRACTION
# ============================================================================

def extract_security(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract security metadata."""
    rule = alert.get('rule', {})
    data = alert.get('data', {})
    
    sig_id = (
        rule.get('id') or
        deep_search(data, 'signature_id', 'SignatureId', 'EventID', 'event_id')
    )
    
    sig_name = (
        rule.get('description') or
        deep_search(data, 'signature', 'message', 'Message', 'EventName', 'alert.signature')
    )
    
    severity = rule.get('level') or deep_search(data, 'severity', 'Severity', 'Level')
    if severity is not None:
        try:
            severity = int(severity)
        except (ValueError, TypeError):
            pass
    
    # Tags from rule groups
    tags = rule.get('groups', [])
    if not isinstance(tags, list):
        tags = [tags] if tags else []
    
    # Add decoder hints
    decoder = alert.get('decoder', {})
    if decoder.get('name'):
        tags.append(f"decoder:{decoder['name']}")
    if decoder.get('parent'):
        tags.append(f"parent:{decoder['parent']}")
    
    return {
        'signature_id': sig_id,
        'signature': sig_name,
        'severity': severity,
        'tags': tags
    }


# ============================================================================
# EVENT CATEGORIZATION
# ============================================================================

def categorize_event(alert: Dict[str, Any], security: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Infer event_category, event_action, event_outcome.
    Returns (category, action, outcome)
    """
    data = alert.get('data', {})
    tags = security.get('tags', [])
    description = (security.get('signature') or '').lower()
    decoder_name = alert.get('decoder', {}).get('name', '').lower()
    location = (alert.get('location') or '').lower()
    
    all_text = ' '.join([
        description,
        decoder_name,
        location,
        ' '.join(str(t).lower() for t in tags)
    ])
    
    # Category inference
    category = 'other'
    
    # Auth
    if any(kw in all_text for kw in [
        'ssh', 'pam', 'radius', 'kerberos', 'ldap', 'login', 'logon', 'auth',
        'password', 'credential', 'session', 'sudo', 'logoff', 'logout'
    ]):
        category = 'auth'
    
    # Network
    elif any(kw in all_text for kw in [
        'firewall', 'fortigate', 'utm', 'ids', 'ips', 'suricata', 'zeek',
        'netflow', 'network', 'connection', 'traffic', 'packet', 'flow',
        'iptables', 'cisco', 'juniper', 'palo alto'
    ]) or (data.get('src_ip') and data.get('dest_ip')):
        category = 'network'
    
    # Process
    elif any(kw in all_text for kw in [
        'process', 'commandline', 'cmdline', 'execve', 'sysmon', 'execution',
        'spawn', 'fork', 'exec', '4688', 'process creation'
    ]) or deep_search(data, 'process', 'Image', 'ProcessName'):
        category = 'process'
    
    # File
    elif any(kw in all_text for kw in [
        'syscheck', 'fim', 'file', 'integrity', 'registry', 'filesystem'
    ]) or deep_search(data, 'file', 'path', 'TargetFilename'):
        category = 'file'
    
    # DNS
    elif any(kw in all_text for kw in ['dns', 'query', 'domain', 'resolve']) or deep_search(data, 'dns_query', 'QueryName'):
        category = 'dns'
    
    # Web
    elif any(kw in all_text for kw in ['http', 'https', 'web', 'apache', 'nginx', 'iis', 'url']):
        category = 'web'
    
    # Malware
    elif any(kw in all_text for kw in ['malware', 'virus', 'trojan', 'ransomware', 'defender', 'antivirus']):
        category = 'malware'
    
    # Cloud
    elif any(kw in all_text for kw in ['cloudtrail', 'azure', 'gcp', 'aws', 'cloud', 'o365', 'kubernetes']):
        category = 'cloud'
    
    # Policy
    elif any(kw in all_text for kw in ['policy', 'compliance', 'audit', 'violation', 'cis']):
        category = 'policy'
    
    # System
    elif any(kw in all_text for kw in ['system', 'kernel', 'syslog', 'systemd', 'service', 'boot']):
        category = 'system'
    
    # Action inference
    action = 'event'
    
    if category == 'auth':
        if any(kw in all_text for kw in ['login', 'logon', 'sign in', 'opened']):
            action = 'login'
        elif any(kw in all_text for kw in ['logout', 'logoff', 'sign out', 'closed']):
            action = 'logout'
        elif 'session' in all_text:
            action = 'session_open' if 'open' in all_text else 'session_close'
    
    elif category == 'network':
        if any(kw in all_text for kw in ['connect', 'establish']):
            action = 'connect'
        elif 'flow' in all_text:
            action = 'flow'
        elif any(kw in all_text for kw in ['allow', 'accept', 'permit']):
            action = 'allow'
        elif any(kw in all_text for kw in ['deny', 'block', 'drop', 'reject']):
            action = 'deny'
    
    elif category == 'file':
        if any(kw in all_text for kw in ['creat', 'add', 'new']):
            action = 'create'
        elif any(kw in all_text for kw in ['modif', 'change', 'edit', 'write']):
            action = 'modify'
        elif any(kw in all_text for kw in ['delet', 'remov']):
            action = 'delete'
    
    elif category == 'process':
        if any(kw in all_text for kw in ['start', 'creat', 'spawn', 'launch']):
            action = 'start'
        elif any(kw in all_text for kw in ['stop', 'kill', 'terminate']):
            action = 'stop'
    
    elif category == 'dns':
        action = 'query'
    
    elif category == 'web':
        if 'request' in all_text:
            action = 'request'
        elif 'download' in all_text:
            action = 'download'
        elif 'upload' in all_text:
            action = 'upload'
    
    # Outcome inference
    outcome = 'unknown'
    
    if any(kw in all_text for kw in ['success', 'successful', 'accepted', 'allowed', 'granted', 'opened', 'permitted']):
        outcome = 'success'
    elif any(kw in all_text for kw in ['fail', 'failed', 'invalid', 'denied', 'reject', 'block', 'drop', 'refused']):
        outcome = 'failure'
    elif action in ['allow', 'permit']:
        outcome = 'allow'
    elif action in ['deny', 'block', 'drop']:
        outcome = 'deny'
    
    return category, action, outcome


# ============================================================================
# CONTEXT EXTRACTION
# ============================================================================

def infer_source(alert: Dict[str, Any]) -> str:
    """Infer source identifier."""
    decoder = alert.get('decoder', {})
    location = alert.get('location', '')
    
    parts = []
    
    if decoder.get('parent'):
        parts.append(decoder['parent'])
    elif decoder.get('name'):
        parts.append(decoder['name'])
    
    # Add hints from location
    if 'windows' in location.lower():
        if 'windows' not in ' '.join(parts).lower():
            parts.append('windows')
    elif 'linux' in location.lower() or '/var/log' in location:
        if 'linux' not in ' '.join(parts).lower():
            parts.append('linux')
    
    return '-'.join(parts).lower() if parts else 'wazuh'


def extract_message(alert: Dict[str, Any], security: Dict[str, Any]) -> str:
    """Extract best available message."""
    msg = alert.get('full_log')
    if msg:
        return str(msg).strip()
    
    if security.get('signature'):
        return security['signature']
    
    data = alert.get('data', {})
    msg = deep_search(data, 'message', 'Message', 'msg')
    return str(msg).strip() if msg else ''


# ============================================================================
# NORMALIZATION
# ============================================================================

def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize alert to standard schema."""
    # Handle parse errors
    if alert.get('_parse_error'):
        return {
            'schema_version': '1.0',
            'event_id': str(uuid.uuid4()),
            'event_time': datetime.now(timezone.utc).isoformat(),
            'ingest_time': datetime.now(timezone.utc).isoformat(),
            'event_category': 'other',
            'event_action': 'event',
            'event_outcome': 'unknown',
            'subject': {'type': None, 'id': None, 'name': None, 'ip': None, 'port': None},
            'object': {'type': None, 'id': None, 'name': None, 'ip': None, 'port': None},
            'host': {'id': None, 'name': None, 'ip': None, 'os': {'name': None, 'version': None, 'family': None}, 'type': None},
            'network': {'protocol': None, 'direction': None},
            'security': {'signature_id': '0', 'signature': 'Parse error', 'severity': 0, 'tags': ['parse_error']},
            'context': {
                'source': 'wazuh',
                'environment': None,
                'message': alert.get('full_log', 'Unparseable fragment'),
                'raw_event': {'unparsed_fragment': alert.get('full_log', '')}
            }
        }
    
    # Extract components
    event_time = extract_event_time(alert)
    ingest_time = extract_ingest_time(alert)
    subject, obj = extract_entities(alert)
    host = extract_host(alert)
    network = extract_network(alert)
    security = extract_security(alert)
    
    # Categorize
    category, action, outcome = categorize_event(alert, security)
    
    # Context
    source = infer_source(alert)
    message = extract_message(alert, security)
    
    # Event ID
    event_id = alert.get('id') or alert.get('event_id') or str(uuid.uuid4())
    
    return {
        'schema_version': '1.0',
        'event_id': event_id,
        'event_time': event_time.isoformat(),
        'ingest_time': ingest_time.isoformat(),
        'event_category': category,
        'event_action': action,
        'event_outcome': outcome,
        'subject': subject,
        'object': obj,
        'host': host,
        'network': network,
        'security': security,
        'context': {
            'source': source,
            'environment': None,
            'message': message,
            'raw_event': alert
        }
    }


# ============================================================================
# FILE FOLLOWING
# ============================================================================

class FileTailer:
    """Follow file with rotation support."""
    
    def __init__(self, filepath: str, poll_interval: float):
        self.filepath = filepath
        self.poll_interval = poll_interval
        self.file = None
        self.inode = None
        self.position = 0
        self.parser = IncrementalJSONParser()
    
    def open(self):
        """Open or reopen file."""
        try:
            if self.file:
                self.file.close()
            
            self.file = open(self.filepath, 'r', encoding='utf-8', errors='replace')
            stat = os.stat(self.filepath)
            self.inode = stat.st_ino
            self.position = 0
        except FileNotFoundError:
            self.file = None
            self.inode = None
    
    def check_rotation(self) -> bool:
        """Check if file rotated."""
        try:
            stat = os.stat(self.filepath)
            if stat.st_ino != self.inode or stat.st_size < self.position:
                return True
        except FileNotFoundError:
            return True
        return False
    
    def read_chunk(self, size: int = 65536) -> List[Dict[str, Any]]:
        """Read chunk and parse objects."""
        if not self.file:
            self.open()
            if not self.file:
                time.sleep(self.poll_interval)
                return []
        
        if self.check_rotation():
            self.parser = IncrementalJSONParser()  # Reset parser
            self.open()
            if not self.file:
                time.sleep(self.poll_interval)
                return []
        
        chunk = self.file.read(size)
        if chunk:
            self.position = self.file.tell()
            return self.parser.feed(chunk)
        else:
            time.sleep(self.poll_interval)
            return []
    
    def close(self):
        """Close file."""
        if self.file:
            self.file.close()


# ============================================================================
# STATE PERSISTENCE
# ============================================================================

def load_state(state_file: str) -> Tuple[Optional[int], Optional[int]]:
    """Load last position and inode."""
    if not os.path.exists(state_file):
        return None, None
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
            return state.get('position'), state.get('inode')
    except Exception:
        return None, None


def save_state(state_file: str, position: int, inode: int):
    """Save position and inode."""
    try:
        with open(state_file, 'w') as f:
            json.dump({'position': position, 'inode': inode}, f)
    except Exception as e:
        print(f"Warning: Could not save state: {e}", file=sys.stderr)


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Wazuh Log Normalization Pipeline')
    parser.add_argument('--input', default='/var/ossec/logs/alerts/alerts.json')
    parser.add_argument('--output', default='./normalized.jsonl')
    parser.add_argument('--window-minutes', type=int, default=5)
    parser.add_argument('--poll-interval', type=float, default=0.5)
    parser.add_argument('--state-file', default='./wazuh_normalizer.state')
    
    args = parser.parse_args()
    
    print(f"Wazuh Normalization Pipeline")
    print(f"  Input: {args.input}")
    print(f"  Output: {args.output}")
    print(f"  Window: {args.window_minutes} minutes")
    
    # Time window
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=args.window_minutes)
    print(f"  Processing from: {window_start.isoformat()}")
    
    # Wait for input
    while not os.path.exists(args.input):
        print(f"Waiting for {args.input}...", file=sys.stderr)
        time.sleep(5)
    
    # Open output
    output_file = open(args.output, 'a', encoding='utf-8')
    
    print("Scanning existing alerts...")
    processed = 0
    tailer = FileTailer(args.input, args.poll_interval)
    
    try:
        # Phase 1: Scan existing
        tailer.open()
        if tailer.file:
            while True:
                alerts = tailer.read_chunk()
                if not alerts:
                    # Check if we've reached EOF
                    current_pos = tailer.file.tell()
                    tailer.file.seek(0, 2)  # Seek to end
                    end_pos = tailer.file.tell()
                    tailer.file.seek(current_pos)  # Seek back
                    
                    if current_pos >= end_pos:
                        break  # EOF reached
                
                for alert in alerts:
                    event_time = extract_event_time(alert)
                    if event_time >= window_start:
                        normalized = normalize_alert(alert)
                        output_file.write(json.dumps(normalized, separators=(',', ':'), ensure_ascii=False) + '\n')
                        output_file.flush()
                        processed += 1
                        if processed % 100 == 0:
                            print(f"  Processed {processed}...")
        
        print(f"Scan complete: {processed} events")
        print("Following new alerts...")
        
        # Phase 2: Follow mode
        follow_count = 0
        save_counter = 0
        
        while True:
            alerts = tailer.read_chunk()
            for alert in alerts:
                event_time = extract_event_time(alert)
                if event_time >= window_start:
                    normalized = normalize_alert(alert)
                    output_file.write(json.dumps(normalized, separators=(',', ':'), ensure_ascii=False) + '\n')
                    output_file.flush()
                    follow_count += 1
                    save_counter += 1
                    
                    if save_counter >= 10:
                        save_state(args.state_file, tailer.position, tailer.inode)
                        save_counter = 0
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if tailer.inode:
            save_state(args.state_file, tailer.position, tailer.inode)
        tailer.close()
        output_file.close()
        print(f"Total: {processed + follow_count} events")


if __name__ == '__main__':
    main()