# CyberSentinel Event Correlation Engine - Architecture

## Overview

CyberSentinel is a 6-stage SIEM pipeline that ingests raw Wazuh alerts and produces prioritized, UEBA-enriched security incidents. It supports two modes:

- **Batch mode** -- sequential execution, processes a file and exits
- **Streaming mode (`--follow`)** -- all stages run in parallel, continuously tailing their input files for new data

```
Raw Wazuh Alerts
       |
       v
 [L1: Normalizer]  ------>  normalized.jsonl
       |
       v
 [L2: Enricher]  --------->  enriched.jsonl
       |
       +--------------------------+
       |                          |
       v                          v
 [L3: Correlation]          [L5: UEBA]
       |                          |
       v                          |
  incidents.jsonl                 |
       |                          |
       v                          |
 [L4: Context Scorer]             |
       |                          |
       v                          v
  scored_incidents.jsonl    ueba_scores.jsonl
       |                          |
       +-----------+--------------+
                   |
                   v
            [FUSION Engine]
                   |
                   v
       correlated_UEBA_alerts.jsonl   (final output)
```

L3 (Correlation) and L5 (UEBA) both read from `enriched.jsonl` independently and in parallel.

---

## Pipeline Stages

### L1 -- Normalizer (`normalizer.py`)

Converts raw Wazuh JSON alerts into a standardized event schema.

**Key components:**

| Component | Purpose |
|-----------|---------|
| `IncrementalJSONParser` | Handles partial JSON, embedded newlines, and buffer recovery (max 10 MB) |
| `FileTailer` | Follows the alert file with inode-based rotation detection |
| `normalize_alert()` | Maps Wazuh fields to the unified schema |

**Normalized schema:**

```json
{
  "schema_version": "1.0",
  "event_id":       "unique-id",
  "event_time":     "2026-02-09T08:30:00Z",
  "ingest_time":    "2026-02-09T08:30:01Z",
  "event_category": "authentication",
  "event_action":   "logon",
  "event_outcome":  "failure",
  "subject":  { "type": "user", "name": "admin", "ip": "10.0.0.5", "port": 52341 },
  "object":   { "type": "host", "name": "dc01",  "ip": "10.0.0.1", "port": 3389  },
  "host":     { "id": "agent-001", "name": "dc01", "ip": "10.0.0.1",
                "os": { "family": "windows", "version": "10.0", "name": "Windows Server 2019" },
                "type": "server" },
  "network":  { "protocol": "rdp", "direction": "inbound" },
  "security": { "signature_id": "4625", "severity": "high", "tags": ["authentication"] },
  "context":  { "source": "windows-eventlog", "environment": "production", "message": "..." }
}
```

**Categorization:** authentication, network, process, file, dns, web, malware, cloud, policy, system.

**OS/device detection:** Windows, Linux, macOS, Cisco, Palo Alto, Fortinet, and others.

---

### L2 -- Enricher (`enrich_json.py`)

Adds network intelligence, geolocation, behavioral counters, anomaly flags, and a composite risk score to each event. All lookups are **offline** -- no external API calls.

**Enrichment sections added under the `enrich` key:**

| Section | Fields |
|---------|--------|
| `temporal` | `hour_of_day`, `day_of_week`, `is_business_hours`, `is_weekend`, `is_night` |
| `classification` | `src_ip_type`, `dest_ip_type`, `is_internal_traffic`, `is_external_inbound` |
| `network_intel` | ASN, cloud provider (AWS/GCP/Azure/CloudFlare/...), Tor exit node, IP reputation |
| `geo` | Country, city, region, coordinates, timezone per IP; impossible travel detection |
| `counters` | Rolling 5-minute counts: `src_ip_5m`, `dest_ip_5m`, `user_5m`, `host_5m` |
| `behavioral` | `unique_destinations_1h`, `unique_ports_1h`, `recent_failures_5m` |
| `anomalies` | Boolean flags: `is_port_scan`, `is_brute_force`, `is_lateral_movement`, `is_data_exfil`, `is_impossible_travel` |
| `risk_score` | 0-100 composite score combining severity, failure rate, anomaly flags, traffic type |
| `fingerprint` | SHA-1 hash of the event signature for deduplication |

**Databases required (in `databases/` directory):**

- `GeoLite2-City.mmdb` -- GeoIP lookup
- `GeoLite2-ASN.mmdb` -- ASN/provider lookup
- `tor-exit-nodes.txt` -- Tor exit node list
- `malicious-ips.txt` -- IP reputation data

**Anomaly detection thresholds:**

| Anomaly | Trigger |
|---------|---------|
| Brute force | > 15 failures from same source in 5 min |
| Port scan | > 15 unique destination ports in 5 min |
| Lateral movement | > 20 unique internal destination IPs |
| Impossible travel | Speed > 1000 km/h between consecutive logins |

---

### L3 -- Correlation Engine (`unified_correlation_engine.py`)

Evaluates enriched events against detection rules and groups matching alerts into correlated incidents.

**Rule types:**

| Type | Behavior |
|------|----------|
| `single` | Fires immediately when one event matches all conditions |
| `aggregation` | Accumulates events in a sliding time window; fires when a group-by threshold is met |

**Condition operators:** `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `contains`, `regex`. Logical: `AND`, `OR`, `NOT`.

**Correlation grouping logic:**

1. Alerts must share the same **attack category** (e.g. `authentication`, `lateral_movement`)
2. Alerts must fall within the configured **time window** (default 60 minutes)
3. Alerts must share at least one **entity**: same target IP, same source IP, same host, or same hostname

**Incident output:**

```json
{
  "incident_id":      "INC-000001",
  "severity":         "high",
  "status":           "open",
  "first_seen":       "2026-02-09T08:00:00Z",
  "last_seen":        "2026-02-09T08:15:00Z",
  "duration_seconds": 900,
  "alert_count":      5,
  "title":            "Brute Force Attack Campaign - 5 Related Alerts",
  "description":      "...",
  "attack_chain": {
    "tactics":              ["TA0006"],
    "techniques":           [],
    "attack_pattern":       "Brute Force Attack Campaign",
    "campaign_confidence":  "high"
  },
  "affected_entities": {
    "source_ips":      ["203.0.113.50"],
    "target_ips":      ["10.0.0.1"],
    "affected_hosts":  ["dc01"],
    "affected_users":  ["admin"]
  },
  "alerts": [ { "alert_id": "...", "rule_name": "...", "severity": "...", ... } ],
  "indicators_of_compromise": {
    "malicious_ips": [], "suspicious_ips": [], "affected_ports": [],
    "attack_signatures": [], "compromised_accounts": []
  },
  "recommended_actions": ["Initiate incident response procedure", "..."],
  "metadata": { "correlation_key": "abc123", "created_at": "...", "correlated_by": "..." }
}
```

**Attack pattern identification:**

| Category | Pattern name |
|----------|-------------|
| `authentication` | Brute Force Attack Campaign / Distributed Brute Force Attack |
| `threat_intelligence` | Coordinated Attack from Malicious Infrastructure |
| `lateral_movement` | Internal Lateral Movement Campaign |
| `data_exfiltration` | Data Exfiltration Attempt |
| `reconnaissance` | Network Reconnaissance Campaign |
| `account_compromise` | Account Compromise Indicators |

**Streaming mode:** each event is evaluated immediately. Alerts are merged into `open_incidents` (keyed by category + entity + time). When a new alert is absorbed, the updated incident is re-emitted as a new JSONL line (append-only). Expired incidents (> 2x time window) are evicted.

---

### L4 -- Context Scorer (`context_scorer.py`)

Adds business context to incidents: asset criticality, user privilege level, business impact, and priority with SLA.

**Business impact formula:**

```
base_score = category_impact[category]              (auth=60, lateral=80, exfil=90, ...)
base_score *= asset_criticality_multiplier           (critical=1.3, high=1.1, medium=1.0, low=0.8)
base_score += 20 if privileged_user
base_score += 15 if data_classification in [confidential, restricted]
base_score += 10 if business_unit in [finance, hr, executive]
base_score += 10 if mitre_tactic_count > 2
impact_score = min(base_score, 100)
```

**Priority scoring and SLA tiers:**

```
priority_score = rule_severity_score * 0.4 + impact_score * 0.6
```

| Priority | Score range | Response time | Resolution time |
|----------|-----------|---------------|-----------------|
| **P1** Critical | >= 80 | 15 minutes | 4 hours |
| **P2** High | 60 -- 79 | 1 hour | 24 hours |
| **P3** Medium | 40 -- 59 | 4 hours | 72 hours |
| **P4** Low | < 40 | 24 hours | 168 hours |

---

### L5 -- UEBA Engine (`ueba.py`)

Detects behavioral anomalies by comparing each event against learned user baselines.

**Baseline learning:**

- First **1000 events** are used to build baselines (no anomaly output during this phase)
- Tracks per user: typical hours, countries seen, IPs used, days of week
- Baseline is persisted to `.state/ueba_baseline.json` on shutdown and loaded on restart

**Anomaly types and scores:**

| Anomaly | Score | Trigger |
|---------|-------|---------|
| `first_time_country` | 35 | Country code not in user's baseline |
| `unusual_hour` | 25 | Hour not in user's typical hours |
| `first_time_ip` | 20 | Source IP never seen for this user |
| `after_hours_anomaly` | 20 | After-hours activity at an unusual hour |
| `unusual_weekend` | 15 | Weekend activity for a weekday-only user |
| `impossible_travel` | 45 | Flagged by enricher (> 1000 km/h) |
| `tor_usage` | 40 | Source is a Tor exit node |
| `malicious_ip` | 50 | Source is a known malicious IP |

Total score is capped at 100.

**Risk levels:**

| Level | Score range |
|-------|-----------|
| Critical | >= 80 |
| High | 60 -- 79 |
| Medium | 40 -- 59 |
| Low | < 40 |

Only events with anomalies or score >= threshold (default 20) are emitted.

---

### FUSION -- Final Fusion (`fusion.py`)

Combines scored incidents (L4) with UEBA scores (L5) to produce final actionable alerts.

**Correlation logic:**

1. For each scored incident, find UEBA scores matching the same **user** within **5 minutes**
2. Calculate final risk score: `60% * incident_priority_score + 40% * max_ueba_score`
3. UEBA can **escalate** severity: score >= 80 boosts by 2 levels, >= 60 by 1 level (max P1)

**Confidence calculation:**

```
base_confidence = {very_low: 0.95, low: 0.85, medium: 0.70, high: 0.50}[false_positive_rate]
if ueba_data_present: base_confidence += 0.15
confidence = min(base_confidence, 1.0)
```

**Threat level mapping:**

| Risk score | Threat level |
|-----------|-------------|
| >= 90 | Imminent |
| 70 -- 89 | Severe |
| 50 -- 69 | Elevated |
| 30 -- 49 | Moderate |
| < 30 | Low |

**Final output schema:**

```json
{
  "alert_id": "INC-000001",
  "generated_at": "2026-02-09T08:47:52Z",
  "final_assessment": {
    "risk_score": 78,
    "severity": "P2",
    "confidence": 0.85,
    "threat_level": "severe"
  },
  "incident": {
    "incident_id": "INC-000001",
    "title": "Brute Force Attack Campaign - 5 Related Alerts",
    "rule_name": "Multiple Failed Logins",
    "rule_category": "authentication",
    "rule_severity": "high",
    "alert_count": 5,
    "priority_level": "P2",
    "priority_score": 72
  },
  "ueba_contribution": {
    "ueba_score": 55,
    "anomalies_detected": ["first_time_country", "unusual_hour"],
    "behavioral_risk": "moderate_deviation"
  },
  "business_context": {
    "impact_score": 65,
    "impact_level": "high",
    "asset_criticality": "critical",
    "user_privilege": "domain_admin",
    "is_privileged_user": true
  },
  "event_details": {
    "event_id": "INC-000001",
    "event_time": "2026-02-09T08:00:00Z",
    "event_category": "authentication",
    "source_ip": "203.0.113.50",
    "destination_ip": "10.0.0.1",
    "user": "admin",
    "host": "dc01"
  },
  "response": {
    "sla": { "response_time_minutes": 60, "resolution_time_hours": 24 },
    "recommended_actions": ["Escalate to senior analyst", "Block source IP"],
    "escalation_required": true,
    "investigation_priority": "high"
  },
  "mitre_attack": {
    "tactics": ["TA0006"]
  }
}
```

---

## MITRE ATT&CK Coverage

Rules in `correlation_rules.yaml` map to the following tactics:

| Tactic | ID | Example rules |
|--------|-----|--------------|
| Initial Access | TA0001 | Impossible travel, account compromise indicators |
| Persistence | TA0003 | After-hours admin activity |
| Credential Access | TA0006 | Brute force, password spray, multiple failed logins |
| Reconnaissance | TA0043 | Port scans, network sweeps, service enumeration |
| Lateral Movement | TA0008 | Internal host hopping, multi-hop connections |
| Exfiltration | TA0010 | Large data transfer, cloud upload, DNS tunneling |
| Command & Control | TA0011 | Malicious IP communication, Tor usage, protocol anomalies |

**24 detection rules** across 10 categories: threat intelligence, authentication, scanning, lateral movement, data exfiltration, impossible travel, high-risk score, protocol anomalies, after-hours activity, and compliance/policy.

---

## Streaming Architecture

### How it works

When `--follow` is passed:

1. `pipeline.py` launches **all 6 processes simultaneously** via `subprocess.Popen`
2. Each process uses a `JSONLTailer` to tail its input file
3. If the input file doesn't exist yet, the tailer **waits** until it appears -- this provides natural ordering without explicit sequencing
4. Each event flows through the pipeline as soon as it's written to the intermediate file

### Shared module: `file_tailer.py`

**`JSONLTailer`** -- tails a JSONL file, yielding parsed JSON objects:

- `follow()` generator -- scans existing data, then polls for new lines
- `read_one()` -- non-blocking single read (used by fusion's dual-input loop)
- State persistence: saves `{position, inode}` to a state file every N events
- File rotation detection: compares inode and file size
- Resumes from saved position on restart

**`append_jsonl(fileobj, obj)`** -- writes one compact JSON line and flushes.

### State persistence

All state files are stored in the `.state/` directory:

| Process | State file | What's persisted | On loss |
|---------|-----------|-----------------|---------|
| Normalizer | `normalizer.state` | file position + inode | Reprocess from start |
| Enricher | `enricher.state` | file position + inode | Reprocess; counters rebuild from stream |
| Correlation | `correlation.state` | file position + inode | Reprocess; incidents rebuilt |
| Scorer | `scorer.state` | file position + inode | Reprocess; scoring is stateless |
| UEBA | `ueba.state` + `ueba_baseline.json` | position + inode + full baseline | Reprocess; re-learn baseline (1000 events) |
| Fusion | `fusion_incidents.state` + `fusion_ueba.state` | two positions + inodes | Reprocess; UEBA index rebuilt |

### Signal handling

- `SIGINT` / `SIGTERM` -> sends `SIGINT` to all children
- Waits 10 seconds for graceful shutdown
- `SIGKILL` any processes still running after the deadline

### Streaming correlation details

- The correlation engine maintains an `open_incidents` dict keyed by correlation group
- When a new alert matches an existing incident, the incident is **updated and re-emitted** as a new JSONL line (append-only)
- Downstream consumers should take the **latest entry per `incident_id`**
- Expired incidents (older than 2x the time window) are evicted from memory
- Aggregation rules track a `_aggregation_fired` dict to avoid re-firing after the threshold is crossed

### Fusion dual-input polling

Fusion tails two files (`scored_incidents.jsonl` and `ueba_scores.jsonl`) using a round-robin loop:

1. **Drain all UEBA scores first** (indexes them by user for fast lookup)
2. **Process incidents** (correlates each with matching UEBA scores)
3. Sleep if both inputs are idle

UEBA index entries older than 10 minutes are evicted.

---

## Usage

**Batch mode (testing / replay):**

```bash
# Full pipeline
python3 pipeline.py --input raw_logs.jsonl --all

# From a specific stage
python3 pipeline.py --input normalized.jsonl --from L2
```

**Continuous streaming mode (production):**

```bash
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all --follow
```

**Individual script in follow mode:**

```bash
python3 enrich_json.py --input normalized.jsonl --output enriched.jsonl \
    --follow --geoip-db databases/GeoLite2-City.mmdb
```

**View final output as it streams:**

```bash
tail -f correlated_UEBA_alerts.jsonl | jq .
```

**Filter P1 alerts:**

```bash
tail -f correlated_UEBA_alerts.jsonl | jq 'select(.final_assessment.severity == "P1")'
```

---

## File Index

| File | Lines | Purpose |
|------|-------|---------|
| `normalizer.py` | ~975 | L1: Wazuh alert normalization |
| `enrich_json.py` | ~1020 | L2: Network intel, geo, behavioral enrichment |
| `unified_correlation_engine.py` | ~1100 | L3: Rule evaluation + incident correlation |
| `context_scorer.py` | ~500 | L4: Business impact + priority scoring |
| `ueba.py` | ~400 | L5: User behavior baseline + anomaly detection |
| `fusion.py` | ~530 | Final: UEBA + incident fusion |
| `pipeline.py` | ~490 | Orchestrator (batch + streaming) |
| `file_tailer.py` | ~230 | Shared JSONL tailing module |
| `correlation_rules.yaml` | ~520 | 24 detection rules with MITRE mapping |
| `context_config.yaml` | -- | Asset criticality + user context config |
| `ueba_config.yaml` | -- | UEBA thresholds config |
