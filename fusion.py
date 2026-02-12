#!/usr/bin/env python3
"""
Fusion Engine - Final Layer
Combines scored incidents (Layer 4) with UEBA scores (Layer 5) to generate final alerts.

Input:
    - scored_incidents.jsonl (from Layer 4)
    - ueba_scores.jsonl (from Layer 5)
    
Output:
    - correlated_UEBA_alerts.jsonl (final output)

Usage:
    python3 fusion.py \
        --incidents scored_incidents.jsonl \
        --ueba ueba_scores.jsonl \
        --output correlated_UEBA_alerts.jsonl
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class FusionEngine:
    """Fuses incident correlation with UEBA analysis."""
    
    def __init__(self):
        self.incidents = []
        self.ueba_scores = []
        self.fused_alerts = []
    
    def load_incidents(self, filepath: str):
        """Load scored incidents from Layer 4."""
        print(f"Loading incidents from {filepath}...", file=sys.stderr)
        count = 0
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        incident = json.loads(line)
                        self.incidents.append(incident)
                        count += 1
                    except json.JSONDecodeError:
                        continue
            
            print(f"✓ Loaded {count} incidents", file=sys.stderr)
        
        except FileNotFoundError:
            print(f"✗ Error: Incidents file not found: {filepath}", file=sys.stderr)
            sys.exit(1)
    
    def load_ueba_scores(self, filepath: str):
        """Load UEBA scores from Layer 5."""
        print(f"Loading UEBA scores from {filepath}...", file=sys.stderr)
        count = 0
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        score = json.loads(line)
                        self.ueba_scores.append(score)
                        count += 1
                    except json.JSONDecodeError:
                        continue
            
            print(f"✓ Loaded {count} UEBA scores", file=sys.stderr)
        
        except FileNotFoundError:
            print(f"⚠ Warning: UEBA file not found: {filepath}", file=sys.stderr)
            print(f"  Continuing with incidents only...", file=sys.stderr)
    
    def correlate(self):
        """Correlate incidents with UEBA scores."""
        print(f"Correlating incidents with UEBA...", file=sys.stderr)
        
        # Build UEBA lookup by user and time
        ueba_by_user = defaultdict(list)
        for score in self.ueba_scores:
            user = score.get("entity", {}).get("user")
            if user:
                ueba_by_user[user].append(score)
        
        # Process each incident
        for incident in self.incidents:
            original = incident.get("original_incident", {})
            # Try single-event path first, fall back to correlation incident structure
            event = original.get("event", {})
            user = event.get("subject", {}).get("name")
            if not user:
                # Correlation incident: extract from affected_entities or first alert
                affected_users = original.get("affected_entities", {}).get("affected_users", [])
                alerts_list = original.get("alerts", [])
                user = (affected_users[0] if affected_users
                        else alerts_list[0].get("user") if alerts_list else None)
            event_time_str = event.get("event_time") or original.get("first_seen")
            
            # Find matching UEBA scores
            matching_ueba = []
            if user and user in ueba_by_user:
                event_time = self._parse_timestamp(event_time_str)
                
                for ueba_score in ueba_by_user[user]:
                    ueba_time = self._parse_timestamp(ueba_score.get("event_context", {}).get("event_time"))
                    
                    # Match if within 5 minutes
                    if event_time and ueba_time:
                        time_diff = abs((event_time - ueba_time).total_seconds())
                        if time_diff <= 300:  # 5 minutes
                            matching_ueba.append(ueba_score)
            
            # Create fused alert
            fused_alert = self._create_fused_alert(incident, matching_ueba)
            self.fused_alerts.append(fused_alert)
        
        print(f"✓ Generated {len(self.fused_alerts)} fused alerts", file=sys.stderr)
    
    def _create_fused_alert(
        self,
        incident: Dict[str, Any],
        ueba_scores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create final fused alert."""
        
        # Extract key components
        priority = incident.get("priority", {})
        impact = incident.get("impact_analysis", {})
        context = incident.get("context", {})
        original_incident = incident.get("original_incident", {})

        # The original_incident is a *correlation incident* with:
        #   alerts[], affected_entities, attack_chain, title, severity, ...
        # Extract the first alert for rule-level details
        alerts_list = original_incident.get("alerts", [])
        first_alert = alerts_list[0] if alerts_list else {}
        entities = original_incident.get("affected_entities", {})

        # Calculate final risk score
        incident_priority_score = priority.get("priority_score", 50)
        ueba_score = max([u.get("ueba", {}).get("score", 0) for u in ueba_scores]) if ueba_scores else 0

        # Alert volume boost: many correlated alerts increase confidence
        alert_count = original_incident.get("alert_count", len(alerts_list))
        if alert_count >= 20:
            volume_boost = 15
        elif alert_count >= 10:
            volume_boost = 10
        elif alert_count >= 5:
            volume_boost = 5
        else:
            volume_boost = 0

        # Weighted combination: incident priority is the floor, UEBA can raise it
        if ueba_scores:
            # 60% incident, 40% UEBA, plus volume boost
            final_risk_score = int(incident_priority_score * 0.6 + ueba_score * 0.4) + volume_boost
        else:
            # Without UEBA, use full incident priority (not penalized for missing data)
            final_risk_score = incident_priority_score + volume_boost

        final_risk_score = min(final_risk_score, 100)

        # Determine final severity
        final_severity = self._calculate_final_severity(
            priority.get("priority_level", "P4"),
            ueba_score
        )

        # Aggregate UEBA anomalies
        ueba_anomalies = []
        for ueba in ueba_scores:
            ueba_anomalies.extend(ueba.get("ueba", {}).get("anomalies", []))
        ueba_anomalies = list(set(ueba_anomalies))  # Deduplicate

        # Build fused alert
        fused_alert = {
            "alert_id": incident.get("alert_id") or original_incident.get("incident_id"),
            "generated_at": datetime.utcnow().isoformat() + "Z",

            # Final assessment
            "final_assessment": {
                "risk_score": final_risk_score,
                "severity": final_severity,
                "confidence": self._calculate_confidence(incident, ueba_scores),
                "threat_level": self._get_threat_level(final_risk_score)
            },

            # Incident details (extracted from correlation incident + first alert)
            "incident": {
                "incident_id": original_incident.get("incident_id"),
                "title": original_incident.get("title"),
                "rule_name": first_alert.get("rule_name") or original_incident.get("rule", {}).get("name"),
                "rule_category": first_alert.get("category") or original_incident.get("rule", {}).get("category"),
                "rule_severity": first_alert.get("severity") or original_incident.get("rule", {}).get("severity") or original_incident.get("severity"),
                "alert_count": original_incident.get("alert_count", len(alerts_list)),
                "alert_timestamp": first_alert.get("timestamp") or original_incident.get("first_seen"),
                "priority_level": priority.get("priority_level"),
                "priority_score": incident_priority_score
            },

            # UEBA contribution
            "ueba_contribution": {
                "ueba_score": ueba_score,
                "anomalies_detected": ueba_anomalies,
                "behavioral_risk": self._assess_behavioral_risk(ueba_scores)
            } if ueba_scores else {
                "ueba_score": 0,
                "anomalies_detected": [],
                "behavioral_risk": "no_ueba_data"
            },

            # Business context
            "business_context": {
                "impact_score": impact.get("impact_score", 0),
                "impact_level": impact.get("impact_level", "unknown"),
                "asset_criticality": context.get("asset", {}).get("criticality", "unknown"),
                "user_privilege": context.get("user", {}).get("privilege_level", "unknown"),
                "is_privileged_user": context.get("user", {}).get("is_privileged", False)
            },

            # Event details (from affected_entities + first alert)
            "event_details": self._build_event_details(
                original_incident, first_alert, entities
            ),

            # Response guidance
            "response": {
                "sla": priority.get("sla", {}),
                "recommended_actions": incident.get("recommended_actions", []) or original_incident.get("recommended_actions", []),
                "escalation_required": final_severity in ["P1", "P2"],
                "investigation_priority": self._get_investigation_priority(final_risk_score)
            },

            # MITRE ATT&CK mapping
            "mitre_attack": {
                "tactics": original_incident.get("attack_chain", {}).get("tactics", []) or original_incident.get("rule", {}).get("mitre_tactics", [])
            },

            # Network intelligence (propagated from L2 enrichment)
            "network_intelligence": self._build_network_intelligence(
                original_incident
            )
        }

        return fused_alert

    def _build_network_intelligence(self, original_incident: Dict[str, Any]) -> Dict[str, Any]:
        """Build network intelligence section from incident enrichment summary."""
        enrichment = original_incident.get("enrichment_summary", {})
        iocs = original_incident.get("indicators_of_compromise", {})
        if not enrichment and not iocs:
            return {}

        result = {}

        # Geographic context
        geo = enrichment.get("geo", {})
        if geo:
            result["geo"] = {
                "countries": geo.get("countries", []),
                "cities": geo.get("cities", []),
                "max_distance_km": geo.get("max_distance_km"),
                "cross_border": geo.get("cross_border", False)
            }

        # ASN & cloud providers
        ni = enrichment.get("network_intel", {})
        if ni:
            if ni.get("asn_orgs"):
                result["asn_organizations"] = ni["asn_orgs"]
            if ni.get("cloud_providers"):
                result["cloud_providers"] = ni["cloud_providers"]
            result["tor_traffic_detected"] = ni.get("tor_detected", False)

        # Threat intelligence
        threat = {}
        if ni.get("threat_detected"):
            threat["threat_detected"] = True
            threat["max_confidence"] = ni.get("max_threat_confidence", 0.0)
        if iocs.get("malicious_ips"):
            threat["malicious_ips"] = iocs["malicious_ips"]
        if iocs.get("suspicious_ips"):
            threat["suspicious_ips"] = iocs["suspicious_ips"]
        if threat:
            result["threat_intel"] = threat

        # Impossible travel
        it = enrichment.get("impossible_travel")
        if it:
            result["impossible_travel"] = it

        # Risk indicators
        risk = {}
        if enrichment.get("anomaly_flags"):
            risk["anomaly_flags"] = enrichment["anomaly_flags"]
        if enrichment.get("max_enrichment_risk_score"):
            risk["enrichment_risk_score"] = enrichment["max_enrichment_risk_score"]
        if risk:
            result["risk_indicators"] = risk

        return result
    
    _NOT_A_USER = frozenset({
        '/', '-', '.', '*', 'none', 'null', 'n/a', 'unknown', '',
        'system', 'local service', 'network service',
        # Windows service accounts
        'nt authority\\system', 'nt authority\\local service',
        'nt authority\\network service', 'nt authority\\anonymous logon',
        'nt authority\\iusr',
        'http', 'https', 'ssh', 'ftp', 'sftp', 'smtp', 'dns', 'dhcp',
        'rdp', 'smb', 'telnet', 'pop3', 'imap', 'ntp', 'snmp',
        'ldap', 'kerberos', 'tcp', 'udp', 'icmp', 'tls', 'ssl',
    })

    @staticmethod
    def _clean_user(val: Optional[str]) -> Optional[str]:
        """Strip quotes and reject garbage usernames."""
        if not val or not isinstance(val, str):
            return None
        # Normalize escaped backslashes
        cleaned = val.replace('\\\\', '\\')
        cleaned = cleaned.strip().strip('"').strip("'").strip()
        if not cleaned:
            return None
        if cleaned.lower() in FusionEngine._NOT_A_USER:
            return None
        if cleaned.startswith(('/', 'http://', 'https://', '\\')) or '?' in cleaned:
            return None
        return cleaned

    def _build_event_details(
        self,
        original_incident: Dict[str, Any],
        first_alert: Dict[str, Any],
        entities: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build event_details with deduplication guards."""
        source_ip = (
            first_alert.get("source_ip")
            or (entities.get("source_ips", [None])[0] if entities.get("source_ips") else None)
        )
        destination_ip = (
            first_alert.get("target_ip")
            or (entities.get("target_ips", [None])[0] if entities.get("target_ips") else None)
        )
        # Guard: source and destination should not be the same IP
        if destination_ip and destination_ip == source_ip:
            destination_ip = None

        user = self._clean_user(first_alert.get("user"))
        if not user:
            users = entities.get("affected_users", [])
            for u in users:
                user = self._clean_user(u)
                if user:
                    break

        # Extract geo context from first alert's enrichment
        alert_enrichment = first_alert.get("enrichment", {})
        alert_geo = alert_enrichment.get("geo", {})

        details = {
            "event_id": original_incident.get("incident_id") or original_incident.get("event", {}).get("event_id"),
            "event_time": original_incident.get("first_seen") or original_incident.get("event", {}).get("event_time"),
            "event_category": first_alert.get("category") or original_incident.get("event", {}).get("event_category"),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "user": user,
            "host": (
                (entities.get("affected_hosts", [None])[0] if entities.get("affected_hosts") else None)
                or original_incident.get("event", {}).get("host", {}).get("id")
            ),
        }

        # Add per-IP geo context if available
        if alert_geo.get("src_country"):
            details["source_geo"] = {
                "country": alert_geo.get("src_country"),
                "country_code": alert_geo.get("src_country_code"),
                "city": alert_geo.get("src_city"),
            }
        if alert_geo.get("dest_country"):
            details["destination_geo"] = {
                "country": alert_geo.get("dest_country"),
                "country_code": alert_geo.get("dest_country_code"),
                "city": alert_geo.get("dest_city"),
            }

        return details

    def _calculate_final_severity(self, incident_priority: str, ueba_score: int) -> str:
        """Calculate final severity combining incident and UEBA."""
        priority_values = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
        incident_value = priority_values.get(incident_priority, 1)
        
        # UEBA can escalate severity
        if ueba_score >= 80:
            ueba_boost = 2
        elif ueba_score >= 60:
            ueba_boost = 1
        else:
            ueba_boost = 0
        
        final_value = min(incident_value + ueba_boost, 4)
        
        reverse_map = {4: "P1", 3: "P2", 2: "P3", 1: "P4"}
        return reverse_map[final_value]
    
    def _calculate_confidence(
        self,
        incident: Dict[str, Any],
        ueba_scores: List[Dict[str, Any]]
    ) -> float:
        """Calculate confidence in the alert."""
        # Base confidence from false positive rate
        fp_rate = incident.get("original_incident", {}).get("rule", {}).get("false_positive_rate", "medium")
        
        fp_confidence = {
            "very_low": 0.95,
            "low": 0.85,
            "medium": 0.70,
            "high": 0.50
        }.get(fp_rate, 0.70)
        
        # Boost confidence if UEBA confirms
        if ueba_scores:
            ueba_boost = 0.15
        else:
            ueba_boost = 0
        
        return min(fp_confidence + ueba_boost, 1.0)
    
    def _get_threat_level(self, risk_score: int) -> str:
        """Convert risk score to threat level."""
        if risk_score >= 90:
            return "imminent"
        elif risk_score >= 70:
            return "severe"
        elif risk_score >= 50:
            return "elevated"
        elif risk_score >= 30:
            return "moderate"
        else:
            return "low"
    
    def _assess_behavioral_risk(self, ueba_scores: List[Dict[str, Any]]) -> str:
        """Assess behavioral risk from UEBA scores."""
        if not ueba_scores:
            return "no_data"
        
        max_ueba = max(u.get("ueba", {}).get("score", 0) for u in ueba_scores)
        
        if max_ueba >= 80:
            return "critical_behavior_change"
        elif max_ueba >= 60:
            return "significant_anomaly"
        elif max_ueba >= 40:
            return "moderate_deviation"
        else:
            return "minor_deviation"
    
    def _get_investigation_priority(self, risk_score: int) -> str:
        """Get investigation priority."""
        if risk_score >= 80:
            return "immediate"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse ISO8601 timestamp."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get all fused alerts."""
        return self.fused_alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fusion statistics."""
        if not self.fused_alerts:
            return {
                "total_alerts": 0,
                "incidents_processed": len(self.incidents),
                "ueba_scores_used": len(self.ueba_scores)
            }
        
        from collections import Counter
        
        severities = [a["final_assessment"]["severity"] for a in self.fused_alerts]
        threat_levels = [a["final_assessment"]["threat_level"] for a in self.fused_alerts]
        
        return {
            "total_alerts": len(self.fused_alerts),
            "incidents_processed": len(self.incidents),
            "ueba_scores_used": len(self.ueba_scores),
            "by_severity": dict(Counter(severities)),
            "by_threat_level": dict(Counter(threat_levels)),
            "with_ueba_correlation": sum(1 for a in self.fused_alerts if a["ueba_contribution"]["ueba_score"] > 0),
            "escalated_by_ueba": sum(1 for a in self.fused_alerts if a["incident"]["priority_level"] != a["final_assessment"]["severity"])
        }


class StreamingFusionEngine:
    """
    Streaming fusion: tails two input files (scored_incidents + ueba_scores),
    correlates them on the fly, and writes fused alerts immediately.
    """

    UEBA_EVICTION_SECONDS = 600  # 10 minutes

    def __init__(self):
        self.batch_engine = FusionEngine()
        # user -> list of (timestamp_dt, score_dict)
        self.ueba_index = defaultdict(list)

    def ingest_ueba_score(self, score: Dict[str, Any]):
        """Index a UEBA score by user for later correlation."""
        user = score.get("entity", {}).get("user")
        if not user:
            return
        ts = self.batch_engine._parse_timestamp(
            score.get("event_context", {}).get("event_time")
        )
        self.ueba_index[user].append((ts, score))

    def process_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate a single scored incident with buffered UEBA scores."""
        original = incident.get("original_incident", {})
        event = original.get("event", {})
        user = event.get("subject", {}).get("name")
        if not user:
            affected_users = original.get("affected_entities", {}).get("affected_users", [])
            alerts_list = original.get("alerts", [])
            user = (affected_users[0] if affected_users
                    else alerts_list[0].get("user") if alerts_list else None)
        event_time_str = event.get("event_time") or original.get("first_seen")

        matching_ueba = []
        if user and user in self.ueba_index:
            event_time = self.batch_engine._parse_timestamp(event_time_str)
            for ueba_ts, ueba_score in self.ueba_index[user]:
                if event_time and ueba_ts:
                    time_diff = abs((event_time - ueba_ts).total_seconds())
                    if time_diff <= 300:
                        matching_ueba.append(ueba_score)

        fused = self.batch_engine._create_fused_alert(incident, matching_ueba)
        # Don't accumulate in memory — already written to disk by caller
        return fused

    def evict_stale_ueba(self):
        """Remove UEBA scores older than eviction window."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.UEBA_EVICTION_SECONDS)

        for user in list(self.ueba_index.keys()):
            self.ueba_index[user] = [
                (ts, s) for ts, s in self.ueba_index[user]
                if ts is None or ts.replace(tzinfo=None) >= cutoff
            ]
            if not self.ueba_index[user]:
                del self.ueba_index[user]


def main():
    parser = argparse.ArgumentParser(description="Fusion Engine - Final Correlation")
    parser.add_argument("--incidents", default="scored_incidents.jsonl", help="Scored incidents from Layer 4")
    parser.add_argument("--ueba", default="ueba_scores.jsonl", help="UEBA scores from Layer 5")
    parser.add_argument("--output", default="correlated_UEBA_alerts.jsonl", help="Final output")
    parser.add_argument("--stats", action="store_true", help="Print statistics")
    parser.add_argument("--follow", action="store_true",
                        help="Continuously tail input files for new data")
    parser.add_argument("--state-file-prefix", default=".state/fusion",
                        help="Prefix for state files in follow mode")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="Poll interval in seconds for follow mode")
    
    args = parser.parse_args()
    
    if args.follow:
        # --- Streaming / follow mode ---
        from file_tailer import JSONLTailer, append_jsonl

        incident_tailer = JSONLTailer(
            args.incidents,
            state_file=f"{args.state_file_prefix}_incidents.state",
            poll_interval=args.poll_interval,
        )
        ueba_tailer = JSONLTailer(
            args.ueba,
            state_file=f"{args.state_file_prefix}_ueba.state",
            poll_interval=args.poll_interval,
        )

        streaming_engine = StreamingFusionEngine()
        alert_count = 0
        evict_counter = 0

        try:
            outfile = open(args.output, "a", encoding="utf-8")
            print(f"Following {args.incidents} + {args.ueba} -> {args.output} ...",
                  file=sys.stderr)

            while True:
                did_work = False

                # Drain UEBA scores first (to index them before incidents arrive)
                while True:
                    ueba_score = ueba_tailer.read_one()
                    if ueba_score is None:
                        break
                    streaming_engine.ingest_ueba_score(ueba_score)
                    did_work = True

                # Process incidents
                while True:
                    incident = incident_tailer.read_one()
                    if incident is None:
                        break
                    fused = streaming_engine.process_incident(incident)
                    append_jsonl(outfile, fused)
                    alert_count += 1
                    did_work = True

                    if alert_count % 100 == 0:
                        print(f"  Fused alerts: {alert_count}", file=sys.stderr)

                if not did_work:
                    time.sleep(args.poll_interval)

                # Periodically evict stale UEBA data
                evict_counter += 1
                if evict_counter >= 200:
                    streaming_engine.evict_stale_ueba()
                    evict_counter = 0

        except KeyboardInterrupt:
            print("\nShutting down fusion...", file=sys.stderr)
        finally:
            incident_tailer.close()
            ueba_tailer.close()
            outfile.close()
            print(f"✓ Generated {alert_count} fused alerts (follow mode)", file=sys.stderr)
    else:
        # --- Batch mode (original behaviour) ---
        engine = FusionEngine()

        engine.load_incidents(args.incidents)
        engine.load_ueba_scores(args.ueba)

        engine.correlate()

        alerts = engine.get_alerts()

        print(f"Writing final alerts to {args.output}...", file=sys.stderr)
        with open(args.output, 'w') as f:
            for alert in alerts:
                f.write(json.dumps(alert, separators=(",", ":"), ensure_ascii=False) + "\n")

        print(f"✓ Generated {len(alerts)} final alerts", file=sys.stderr)

        if args.stats:
            stats = engine.get_stats()
            print("\n" + "="*60, file=sys.stderr)
            print("FUSION ENGINE STATISTICS", file=sys.stderr)
            print("="*60, file=sys.stderr)
            print(f"Incidents Processed: {stats['incidents_processed']}", file=sys.stderr)
            print(f"UEBA Scores Used: {stats['ueba_scores_used']}", file=sys.stderr)
            print(f"Total Final Alerts: {stats['total_alerts']}", file=sys.stderr)
            print(f"\nBy Severity:", file=sys.stderr)
            for severity, count in sorted(stats['by_severity'].items()):
                print(f"  {severity}: {count}", file=sys.stderr)
            print(f"\nBy Threat Level:", file=sys.stderr)
            for level, count in sorted(stats['by_threat_level'].items()):
                print(f"  {level}: {count}", file=sys.stderr)
            print(f"\nWith UEBA Correlation: {stats['with_ueba_correlation']}", file=sys.stderr)
            print(f"Escalated by UEBA: {stats['escalated_by_ueba']}", file=sys.stderr)
            print("="*60, file=sys.stderr)


if __name__ == "__main__":
    main()
