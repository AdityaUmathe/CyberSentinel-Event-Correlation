#!/usr/bin/env python3
"""
UEBA (User and Entity Behavior Analytics) Engine - Layer 5
Analyzes enriched logs to detect behavioral anomalies.

Input: enriched.jsonl (from Layer 2)
Output: ueba_scores.jsonl

Usage:
    python3 ueba.py --input enriched.jsonl --output ueba_scores.jsonl --config ueba_config.yaml
"""

import argparse
import json
import sys
import yaml
from collections import defaultdict, Counter
from datetime import datetime
from typing import Any, Dict, List
import statistics


class BaselineProfile:
    """Build behavioral baselines for users."""
    
    def __init__(self):
        self.user_hours = defaultdict(list)
        self.user_countries = defaultdict(set)
        self.user_ips = defaultdict(set)
        self.user_days = defaultdict(list)
        self.events_processed = 0
        self.learning_complete = False
    
    def update(self, event: Dict[str, Any]):
        """Update baseline with event."""
        self.events_processed += 1
        
        user = event.get("subject", {}).get("name")
        if not user:
            return
        
        enrich = event.get("enrich", {})
        temporal = enrich.get("temporal", {})
        geo = enrich.get("geo", {})
        
        hour = temporal.get("hour_of_day")
        day = temporal.get("day_of_week")
        country = geo.get("src", {}).get("country_code") if geo else None
        src_ip = event.get("subject", {}).get("ip")
        
        if hour is not None:
            self.user_hours[user].append(hour)
        if day:
            self.user_days[user].append(day)
        if country:
            self.user_countries[user].add(country)
        if src_ip:
            self.user_ips[user].add(src_ip)
        
        if self.events_processed >= 1000 and not self.learning_complete:
            self.learning_complete = True
            print(f"✓ Baseline learning complete: {self.events_processed} events", file=sys.stderr)
    
    def get_baseline(self, user: str) -> Dict[str, Any]:
        """Get user baseline."""
        if user not in self.user_hours:
            return {}
        
        return {
            "typical_hours": list(set(self.user_hours[user])),
            "countries_seen": list(self.user_countries[user]),
            "ips_used": len(self.user_ips[user]),
            "typical_days": list(set(self.user_days[user])),
            "total_events": len(self.user_hours[user])
        }


class AnomalyDetector:
    """Detect behavioral anomalies."""
    
    def __init__(self, baseline: BaselineProfile):
        self.baseline = baseline
    
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in event."""
        user = event.get("subject", {}).get("name")
        if not user:
            return {"anomalies": [], "scores": {}, "total_score": 0}
        
        baseline = self.baseline.get_baseline(user)
        if not baseline or baseline.get("total_events", 0) < 10:
            return {"anomalies": [], "scores": {}, "total_score": 0, "reason": "insufficient_baseline"}
        
        anomalies = []
        scores = {}
        
        enrich = event.get("enrich", {})
        temporal = enrich.get("temporal", {})
        geo = enrich.get("geo", {})
        
        hour = temporal.get("hour_of_day")
        country = geo.get("src", {}).get("country_code") if geo else None
        src_ip = event.get("subject", {}).get("ip")
        
        # First-time country
        if country and country not in baseline["countries_seen"]:
            anomalies.append("first_time_country")
            scores["first_time_country"] = 35
        
        # First-time IP
        if src_ip and src_ip not in self.baseline.user_ips[user]:
            anomalies.append("first_time_ip")
            scores["first_time_ip"] = 20
        
        # Unusual hour
        if hour is not None and hour not in baseline["typical_hours"]:
            anomalies.append("unusual_hour")
            scores["unusual_hour"] = 25
        
        # After-hours activity
        if temporal.get("is_after_hours") and hour is not None:
            if hour not in baseline["typical_hours"]:
                anomalies.append("after_hours_anomaly")
                scores["after_hours_anomaly"] = 20
        
        # Weekend activity for weekday users
        if temporal.get("is_weekend"):
            if "Saturday" not in baseline["typical_days"] and "Sunday" not in baseline["typical_days"]:
                anomalies.append("unusual_weekend")
                scores["unusual_weekend"] = 15
        
        # High-risk indicators from enrichment
        network_intel = enrich.get("network_intel", {})
        if network_intel.get("src_tor", {}).get("is_exit_node"):
            anomalies.append("tor_usage")
            scores["tor_usage"] = 40
        
        if network_intel.get("src_reputation", {}).get("ip_reputation") == "malicious":
            anomalies.append("malicious_ip")
            scores["malicious_ip"] = 50
        
        if enrich.get("anomalies", {}).get("is_impossible_travel"):
            anomalies.append("impossible_travel")
            scores["impossible_travel"] = 45
        
        total_score = min(sum(scores.values()), 100)
        
        return {
            "anomalies": anomalies,
            "scores": scores,
            "total_score": total_score,
            "baseline": baseline
        }


class UEBAEngine:
    """Main UEBA engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.baseline = BaselineProfile()
        self.detector = None
        self.scores = []
        self.min_score_threshold = config.get("min_score_threshold", 20)
    
    def process_event(self, event: Dict[str, Any]):
        """Process event through UEBA."""
        self.baseline.update(event)
        
        if self.baseline.learning_complete and self.detector is None:
            self.detector = AnomalyDetector(self.baseline)
        
        if not self.baseline.learning_complete:
            return
        
        user = event.get("subject", {}).get("name")
        if not user:
            return
        
        result = self.detector.detect(event)
        
        if result.get("anomalies") or result.get("total_score", 0) >= self.min_score_threshold:
            score = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "entity": {
                    "user": user,
                    "source_ip": event.get("subject", {}).get("ip")
                },
                "ueba": {
                    "score": result["total_score"],
                    "risk_level": self._get_risk_level(result["total_score"]),
                    "anomalies": result["anomalies"],
                    "anomaly_breakdown": result["scores"],
                    "baseline": result.get("baseline", {})
                },
                "event_context": {
                    "event_id": event.get("event_id"),
                    "event_time": event.get("event_time"),
                    "event_category": event.get("event_category"),
                    "enrichment_risk": event.get("enrich", {}).get("risk_score", 0)
                }
            }
            self.scores.append(score)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"
    
    def get_scores(self) -> List[Dict[str, Any]]:
        """Get all scores."""
        return self.scores
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics."""
        if not self.scores:
            return {
                "total_scores": 0,
                "events_processed": self.baseline.events_processed,
                "learning_complete": self.baseline.learning_complete
            }
        
        score_values = [s["ueba"]["score"] for s in self.scores]
        risk_levels = [s["ueba"]["risk_level"] for s in self.scores]
        
        return {
            "total_scores": len(self.scores),
            "events_processed": self.baseline.events_processed,
            "learning_complete": self.baseline.learning_complete,
            "score_stats": {
                "min": min(score_values),
                "max": max(score_values),
                "avg": statistics.mean(score_values)
            },
            "by_risk_level": dict(Counter(risk_levels)),
            "unique_users": len(set(s["entity"]["user"] for s in self.scores))
        }


def main():
    parser = argparse.ArgumentParser(description="UEBA Engine - Layer 5")
    parser.add_argument("--input", default="enriched.jsonl", help="Input enriched logs")
    parser.add_argument("--output", default="ueba_scores.jsonl", help="Output UEBA scores")
    parser.add_argument("--config", default="ueba_config.yaml", help="Configuration")
    parser.add_argument("--stats", action="store_true", help="Print statistics")
    
    args = parser.parse_args()
    
    print(f"Loading UEBA configuration...", file=sys.stderr)
    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"⚠ Config not found, using defaults", file=sys.stderr)
        config = {"min_score_threshold": 20}
    
    engine = UEBAEngine(config)
    
    print(f"Processing events from {args.input}...", file=sys.stderr)
    event_count = 0
    
    try:
        with open(args.input, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    engine.process_event(event)
                    event_count += 1
                    
                    if event_count % 1000 == 0:
                        print(f"  Processed {event_count} events...", file=sys.stderr)
                
                except json.JSONDecodeError:
                    continue
        
        print(f"✓ Processed {event_count} events", file=sys.stderr)
    
    except FileNotFoundError:
        print(f"✗ Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    scores = engine.get_scores()
    
    print(f"Writing UEBA scores to {args.output}...", file=sys.stderr)
    with open(args.output, 'w') as f:
        for score in scores:
            f.write(json.dumps(score, separators=(",", ":"), ensure_ascii=False) + "\n")
    
    print(f"✓ Generated {len(scores)} UEBA scores", file=sys.stderr)
    
    if args.stats:
        stats = engine.get_stats()
        print("\n" + "="*60, file=sys.stderr)
        print("UEBA STATISTICS", file=sys.stderr)
        print("="*60, file=sys.stderr)
        print(f"Events Processed: {stats['events_processed']}", file=sys.stderr)
        print(f"Learning Complete: {stats['learning_complete']}", file=sys.stderr)
        print(f"Total Scores: {stats['total_scores']}", file=sys.stderr)
        
        if stats['total_scores'] > 0:
            print(f"\nScore Stats:", file=sys.stderr)
            print(f"  Min: {stats['score_stats']['min']}", file=sys.stderr)
            print(f"  Max: {stats['score_stats']['max']}", file=sys.stderr)
            print(f"  Avg: {stats['score_stats']['avg']:.2f}", file=sys.stderr)
            
            print(f"\nBy Risk Level:", file=sys.stderr)
            for level, count in sorted(stats['by_risk_level'].items()):
                print(f"  {level}: {count}", file=sys.stderr)
            
            print(f"\nUnique Users: {stats['unique_users']}", file=sys.stderr)
        
        print("="*60, file=sys.stderr)


if __name__ == "__main__":
    main()
