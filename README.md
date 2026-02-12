# CyberSentinel Event Correlation Engine

A production-grade SIEM event correlation pipeline that ingests raw Wazuh security alerts and produces prioritized, context-enriched, UEBA-correlated security incidents.

## Architecture

The pipeline processes events through 6 layers connected by JSONL intermediate files:

```
Raw Wazuh Alerts (alerts.json)
         |
   [L1: Normalizer]  --->  normalized.jsonl
         |
   [L2: Enricher]    --->  enriched.jsonl
         |
    +----+----+
    |         |
   [L3]      [L5]
 Correlation  UEBA
    |         |
   [L4]       |
  Scoring     |
    |         |
    +----+----+
         |
     [FUSION]         --->  correlated_UEBA_alerts.jsonl
```

| Layer | Script | Purpose |
|-------|--------|---------|
| L1 | `normalizer.py` | Parses raw Wazuh JSON alerts into a unified event schema |
| L2 | `enrich_json.py` | Adds GeoIP, ASN, Tor detection, IP reputation, anomaly flags, risk scores |
| L3 | `unified_correlation_engine.py` | Rule-based detection (24 rules) and incident grouping |
| L4 | `context_scorer.py` | Business impact scoring with asset criticality and user privilege context |
| L5 | `ueba.py` | User & Entity Behavior Analytics - baseline learning and anomaly detection |
| Fusion | `fusion.py` | Combines scored incidents with UEBA scores into final prioritized alerts |

Shared module `file_tailer.py` provides JSONL tailing with state persistence for streaming mode.

## Requirements

**Python 3.8+**

```
pip install pyyaml geoip2
```

`geoip2` is optional - only needed if you want GeoIP/ASN enrichment.

### Databases (optional, for full enrichment)

Place these in a `databases/` directory:

| File | Source | Purpose |
|------|--------|---------|
| `GeoLite2-City.mmdb` | [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | IP geolocation |
| `GeoLite2-ASN.mmdb` | [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | ASN / cloud provider lookup |
| `tor-exit-nodes.txt` | [Tor Project](https://check.torproject.org/torbulkexitlist) | Tor exit node detection |
| `malicious-ips.txt` | Threat intelligence feeds | Known malicious IP list |

The pipeline runs without these databases - enrichment fields will simply be absent.

## Usage

### Full pipeline (batch mode)

```bash
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all
```

### Full pipeline (continuous streaming)

```bash
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all --follow
```

### Start from a specific layer

```bash
# If you already have normalized.jsonl
python3 pipeline.py --input normalized.jsonl --from L2

# If you already have enriched.jsonl
python3 pipeline.py --input enriched.jsonl --from L3
```

### Run individual scripts

```bash
# Normalize raw alerts
python3 normalizer.py --input /var/ossec/logs/alerts/alerts.json --output normalized.jsonl

# Enrich with GeoIP and threat intel
python3 enrich_json.py --input normalized.jsonl --output enriched.jsonl \
    --geoip-db databases/GeoLite2-City.mmdb \
    --asn-db databases/GeoLite2-ASN.mmdb \
    --tor-list databases/tor-exit-nodes.txt \
    --reputation-db databases/malicious-ips.txt

# Correlate into incidents
python3 unified_correlation_engine.py --input enriched.jsonl --output incidents.jsonl \
    --rules correlation_rules.yaml

# Score with business context
python3 context_scorer.py --input incidents.jsonl --output scored_incidents.jsonl \
    --config context_config.yaml

# UEBA behavioral analysis
python3 ueba.py --input enriched.jsonl --output ueba_scores.jsonl

# Final fusion
python3 fusion.py --incidents scored_incidents.jsonl --ueba ueba_scores.jsonl \
    --output correlated_UEBA_alerts.jsonl
```

All scripts support `--follow` for continuous streaming mode.

## Pipeline Modes

### Batch Mode (default)

Each layer runs sequentially - reads entire input, processes, writes output, exits. Suitable for replaying historical logs or testing.

### Streaming Mode (`--follow`)

All layers run as parallel processes. Each tails its input file for new data using `JSONLTailer`. State is persisted to `.state/` so processes can resume after restart.

- Graceful shutdown on SIGINT/SIGTERM
- Automatic crash detection and reporting
- State persistence every 10 events

## Detection Rules

24 detection rules across 10 categories defined in `correlation_rules.yaml`:

| Category | Rules | MITRE Tactics |
|----------|-------|---------------|
| Threat Intelligence | Malicious IP, Tor traffic, high-risk country | TA0011 |
| Authentication | Brute force (single/distributed), login after failures | TA0006 |
| Reconnaissance | Port scan, network sweep, high-frequency scanning | TA0043 |
| Lateral Movement | Internal movement, rapid host hopping | TA0008 |
| Data Exfiltration | High-volume transfer, after-hours exfil, cloud upload | TA0010 |
| Account Compromise | Impossible travel, cross-continent auth | TA0001, TA0006 |
| High-Risk Events | Critical risk score, sustained high-risk activity | TA0001 |
| Protocol Anomalies | Suspicious protocol usage | TA0011 |
| After-Hours Activity | Admin activity outside business hours | TA0003 |
| Compliance | Cross-border data transfer | TA0010 |

Rules support two types:
- **Single** - fires when one event matches all conditions
- **Aggregation** - fires when count threshold is met within a time window

## Enrichment Data

L2 enrichment adds to each event:

- **GeoIP** - country, city, coordinates, timezone, impossible travel detection
- **ASN** - organization, cloud provider identification (AWS, Azure, GCP, Cloudflare)
- **Tor Detection** - source/destination Tor exit node check
- **IP Reputation** - malicious/suspicious/clean classification
- **Temporal Context** - business hours, weekend, night shift flags
- **Behavioral Counters** - 5-minute rolling counts per source, destination, user
- **Anomaly Flags** - brute force, port scan, lateral movement, data exfiltration
- **Risk Score** - composite 0-100 score

All enrichment data propagates through to the final output in the `network_intelligence` section.

## Output Format

Final alerts in `correlated_UEBA_alerts.jsonl`:

```json
{
  "alert_id": "INC-000001",
  "final_assessment": {
    "risk_score": 81,
    "severity": "P1",
    "confidence": 0.85,
    "threat_level": "severe"
  },
  "incident": {
    "title": "Distributed Brute Force Attack - 100 Related Alerts",
    "rule_category": "authentication",
    "alert_count": 100,
    "priority_level": "P1"
  },
  "ueba_contribution": {
    "ueba_score": 45,
    "anomalies_detected": ["impossible_travel"],
    "behavioral_risk": "moderate_deviation"
  },
  "business_context": {
    "impact_score": 75,
    "asset_criticality": "medium",
    "user_privilege": "domain_admin"
  },
  "event_details": {
    "source_ip": "206.123.144.8",
    "destination_ip": "123.63.177.49",
    "user": "admin",
    "source_geo": { "country": "United States", "city": "Unknown" },
    "destination_geo": { "country": "United States", "city": "Unknown" }
  },
  "network_intelligence": {
    "geo": {
      "countries": ["India", "Iran", "United Kingdom", "United States"],
      "max_distance_km": 13697.55,
      "cross_border": true
    },
    "asn_organizations": ["888 Ventures LLC", "PebbleHost Ltd", "Vodafone Idea Ltd"],
    "tor_traffic_detected": false,
    "impossible_travel": {
      "is_impossible_travel": true,
      "distance_km": 11256.37,
      "required_speed_kmh": 2216791.28
    },
    "risk_indicators": {
      "anomaly_flags": ["cross_border", "cross_continent", "is_impossible_travel"],
      "enrichment_risk_score": 100
    }
  },
  "response": {
    "sla": { "response_time_minutes": 15, "resolution_time_hours": 4 },
    "recommended_actions": ["Begin incident response procedure", "..."],
    "escalation_required": true
  },
  "mitre_attack": { "tactics": ["TA0006"] }
}
```

## Priority Levels

| Priority | Score Range | Response SLA | Resolution SLA |
|----------|-----------|--------------|----------------|
| P1 Critical | >= 80 | 15 minutes | 4 hours |
| P2 High | 60-79 | 1 hour | 24 hours |
| P3 Medium | 40-59 | 4 hours | 72 hours |
| P4 Low | < 40 | 24 hours | 168 hours |

## Configuration

| File | Purpose |
|------|---------|
| `correlation_rules.yaml` | Detection rules with conditions, thresholds, MITRE mapping |
| `context_config.yaml` | Asset criticality, user privileges, IP ranges, impact matrix, SLA definitions |
| `ueba_config.yaml` | Baseline learning parameters, anomaly types, risk weights, thresholds |

## Project Structure

```
CyberSentinel-Event-Correlation/
    pipeline.py                       # Main orchestrator
    normalizer.py                     # L1 - Log normalization
    enrich_json.py                    # L2 - Network intelligence enrichment
    unified_correlation_engine.py     # L3 - Rule-based detection & correlation
    context_scorer.py                 # L4 - Business context & priority scoring
    ueba.py                           # L5 - User & Entity Behavior Analytics
    fusion.py                         # Final - Incident + UEBA fusion
    file_tailer.py                    # Shared JSONL tailing module
    correlation_rules.yaml            # 24 detection rules
    context_config.yaml               # Asset & user context config
    ueba_config.yaml                  # UEBA configuration
    ARCHITECTURE.md                   # Technical architecture documentation
    databases/                        # GeoIP, ASN, Tor, reputation databases
    .state/                           # Runtime state files (auto-created)
```
