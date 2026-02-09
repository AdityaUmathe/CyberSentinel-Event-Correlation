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
            event = incident.get("original_incident", {}).get("event", {})
            user = event.get("subject", {}).get("name")
            event_time_str = event.get("event_time")
            
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
        
        # Calculate final risk score
        incident_priority_score = priority.get("priority_score", 50)
        ueba_score = max([u.get("ueba", {}).get("score", 0) for u in ueba_scores]) if ueba_scores else 0
        
        # Weighted combination: 60% incident, 40% UEBA
        final_risk_score = int(incident_priority_score * 0.6 + ueba_score * 0.4)
        
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
            "alert_id": incident.get("alert_id"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            
            # Final assessment
            "final_assessment": {
                "risk_score": final_risk_score,
                "severity": final_severity,
                "confidence": self._calculate_confidence(incident, ueba_scores),
                "threat_level": self._get_threat_level(final_risk_score)
            },
            
            # Original incident details
            "incident": {
                "rule_name": original_incident.get("rule", {}).get("name"),
                "rule_category": original_incident.get("rule", {}).get("category"),
                "rule_severity": original_incident.get("rule", {}).get("severity"),
                "alert_timestamp": original_incident.get("timestamp"),
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
            
            # Event details
            "event_details": {
                "event_id": original_incident.get("event", {}).get("event_id"),
                "event_time": original_incident.get("event", {}).get("event_time"),
                "event_category": original_incident.get("event", {}).get("event_category"),
                "source_ip": original_incident.get("event", {}).get("subject", {}).get("ip"),
                "destination_ip": original_incident.get("event", {}).get("object", {}).get("ip"),
                "user": original_incident.get("event", {}).get("subject", {}).get("name"),
                "host": original_incident.get("event", {}).get("host", {}).get("id")
            },
            
            # Response guidance
            "response": {
                "sla": priority.get("sla", {}),
                "recommended_actions": incident.get("recommended_actions", []),
                "escalation_required": final_severity in ["P1", "P2"],
                "investigation_priority": self._get_investigation_priority(final_risk_score)
            },
            
            # MITRE ATT&CK mapping
            "mitre_attack": {
                "tactics": original_incident.get("rule", {}).get("mitre_tactics", [])
            }
        }
        
        return fused_alert
    
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


def main():
    parser = argparse.ArgumentParser(description="Fusion Engine - Final Correlation")
    parser.add_argument("--incidents", default="scored_incidents.jsonl", help="Scored incidents from Layer 4")
    parser.add_argument("--ueba", default="ueba_scores.jsonl", help="UEBA scores from Layer 5")
    parser.add_argument("--output", default="correlated_UEBA_alerts.jsonl", help="Final output")
    parser.add_argument("--stats", action="store_true", help="Print statistics")
    
    args = parser.parse_args()
    
    # Initialize fusion engine
    engine = FusionEngine()
    
    # Load inputs
    engine.load_incidents(args.incidents)
    engine.load_ueba_scores(args.ueba)
    
    # Perform fusion
    engine.correlate()
    
    # Get fused alerts
    alerts = engine.get_alerts()
    
    # Write output
    print(f"Writing final alerts to {args.output}...", file=sys.stderr)
    with open(args.output, 'w') as f:
        for alert in alerts:
            f.write(json.dumps(alert, separators=(",", ":"), ensure_ascii=False) + "\n")
    
    print(f"✓ Generated {len(alerts)} final alerts", file=sys.stderr)
    
    # Print statistics
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
