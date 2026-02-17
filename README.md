# CyberSentinel Event Correlation Engine

A multi-stage SIEM event correlation pipeline that ingests raw Wazuh security alerts and produces prioritized, UEBA-enriched security incidents with full traceability back to the original log events.

Built for SOC teams that need correlated, deduplicated, and business-context-aware incident output from high-volume Wazuh deployments.

## Architecture

```
Raw Wazuh Alerts (alerts.json)
         |
   [L1: Normalizer]           -->  normalized.jsonl
         |
   [L2: Enricher]             -->  enriched.jsonl
         |
         +--------------------------+
         |                          |
   [L3: Correlation Engine]   [L5: UEBA Engine]
         |                          |
   incidents.jsonl             ueba_scores.jsonl
         |                          |
   [L4: Context Scorer]            |
         |                          |
   scored_incidents.jsonl           |
         |                          |
         +------------+-------------+
                      |
               [FUSION Engine]
                      |
            correlated_UEBA_alerts.jsonl   (final output)
```

| Layer | Script | Purpose |
|-------|--------|---------|
| L1 | `normalizer.py` | Parses raw Wazuh JSON alerts into a unified event schema |
| L2 | `enrich_json.py` | Adds GeoIP, ASN, Tor detection, IP reputation, behavioral counters, anomaly flags, risk scores |
| L3 | `unified_correlation_engine.py` | Rule-based detection with trigger-point correlation per source IP |
| L4 | `context_scorer.py` | Business impact scoring with asset criticality and SLA assignment |
| L5 | `ueba.py` | User and Entity Behavior Analytics with baseline learning |
| FUSION | `fusion.py` | Combines L4 scored incidents with L5 UEBA scores into final actionable alerts |

L3 and L5 read from `enriched.jsonl` independently and run in parallel. Shared module `file_tailer.py` provides JSONL tailing with state persistence for streaming mode.

## Features

- **Dual operation modes** -- batch (sequential, process-and-exit) and streaming (`--follow`, all stages run in parallel)
- **16 detection rules** across 8 categories with MITRE ATT&CK mapping
- **Trigger-point correlation** -- recurring 5min / 30min / 24hr intervals per source IP, grouping related alerts into incidents
- **Offline enrichment** -- GeoIP, ASN, cloud provider detection, Tor exit nodes, IP reputation using free local databases only (no external API calls)
- **Impossible travel detection** -- Haversine-based geographic analysis with VPN/proxy false-positive filtering
- **UEBA behavioral baselines** -- per-user learning of typical hours, countries, IPs, and activity patterns
- **Business context scoring** -- asset criticality, user privilege levels, impact matrices, and SLA assignment (P1-P4)
- **Fusion layer** -- combines rule-based correlation with behavioral analytics for final risk assessment
- **State persistence** -- all streaming processes resume from last position after restart
- **Wazuh traceability** -- correlated incidents include `original_event_id`, `original_signature_id`, `original_signature`, and `original_action` fields linking back to raw Wazuh events
- **Graceful shutdown** -- SIGINT/SIGTERM handling with phased process termination

## Requirements

**Python 3.8+**

```bash
pip install pyyaml geoip2
```

- `pyyaml` -- required by L3, L4, L5, and FUSION for reading YAML configuration
- `geoip2` -- optional, only needed for GeoIP/ASN enrichment in L2

### Databases (optional, for full enrichment)

Place these in a `databases/` directory:

| File | Source | Purpose |
|------|--------|---------|
| `GeoLite2-City.mmdb` | [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | IP geolocation (country, city, coordinates) |
| `GeoLite2-ASN.mmdb` | [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | ASN / organization / cloud provider lookup |
| `tor-exit-nodes.txt` | [Tor Project](https://check.torproject.org/torbulkexitlist) | Tor exit node IP list (one IP per line) |
| `malicious-ips.txt` | Threat intelligence feeds | Known malicious IPs (CSV: `ip,confidence`) |

The pipeline runs without these databases -- enrichment fields will simply be absent.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/<your-org>/CyberSentinel-Event-Correlation.git
cd CyberSentinel-Event-Correlation

# Install dependencies
pip install pyyaml geoip2

# Run the full pipeline on Wazuh alerts (batch mode)
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all

# Or run in continuous streaming mode
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all --follow
```

The pipeline orchestrator runs L1 through L4. For the full 6-stage pipeline including UEBA and Fusion, run L5 and FUSION separately (see below).

## Usage

### Full pipeline (batch mode)

```bash
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all
```

Runs L1 -> L2 -> L3 -> L4 sequentially. Each layer reads its input file, processes all events, writes output, and exits. Final output: `scored_incidents.jsonl`.

### Full pipeline (continuous streaming)

```bash
python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all --follow
```

Launches all four layers as parallel processes. Each tails its input file for new data. State is persisted to `.state/` so processes resume after restart. Press `Ctrl+C` for graceful shutdown.

### Start from a specific layer

```bash
# Already have normalized.jsonl -- start from enrichment
python3 pipeline.py --input normalized.jsonl --from L2

# Already have enriched.jsonl -- start from correlation
python3 pipeline.py --input enriched.jsonl --from L3
```

### Run individual scripts

```bash
# L1 -- Normalize raw alerts
python3 normalizer.py --input /var/ossec/logs/alerts/alerts.json --output normalized.jsonl

# L2 -- Enrich with GeoIP and threat intel
python3 enrich_json.py --input normalized.jsonl --output enriched.jsonl \
    --geoip-db databases/GeoLite2-City.mmdb \
    --asn-db databases/GeoLite2-ASN.mmdb \
    --tor-list databases/tor-exit-nodes.txt \
    --reputation-db databases/malicious-ips.txt

# L3 -- Correlate into incidents
python3 unified_correlation_engine.py --input enriched.jsonl --output incidents.jsonl \
    --rules correlation_rules.yaml --stats

# L4 -- Score with business context
python3 context_scorer.py --input incidents.jsonl --output scored_incidents.jsonl \
    --config context_config.yaml

# L5 -- UEBA behavioral analysis (runs independently from enriched.jsonl)
python3 ueba.py --input enriched.jsonl --output ueba_scores.jsonl \
    --config ueba_config.yaml

# FUSION -- Combine scored incidents with UEBA scores
python3 fusion.py --incidents scored_incidents.jsonl --ueba ueba_scores.jsonl \
    --output correlated_UEBA_alerts.jsonl
```

All scripts support `--follow` for continuous streaming mode, and `--stats` for statistics output (where applicable).

## Pipeline Stages

### L1: Normalizer (`normalizer.py`)

Converts raw Wazuh JSON alerts into a standardized event schema. Handles:

- Partial JSON objects and embedded newlines from the Wazuh alerts file
- 11+ timestamp formats (ISO 8601, syslog, Unix timestamps)
- Multi-level IP extraction: structured data fields -> alert root fields -> raw log text regex -> `location` field fallback
- Entity extraction for subject (initiator) and object (target) with IPs, ports, and usernames
- Event categorization (auth, network, process, file, DNS, web, malware, cloud, policy, system)
- OS/device heuristic detection (Windows, Linux, macOS, network devices, cloud/containers)

**Normalized schema fields:** `schema_version`, `event_id`, `event_time`, `ingest_time`, `event_category`, `event_action`, `event_outcome`, `subject`, `object`, `host`, `network`, `security`, `context`.

### L2: Enricher (`enrich_json.py`)

Adds offline network intelligence and behavioral analysis to each normalized event. All enrichment uses free local databases -- no external API calls.

**Enrichment data (added under `event.enrich`):**

| Section | Fields |
|---------|--------|
| `temporal` | Hour, day of week, business hours, weekend, night shift flags |
| `flags` | `is_auth_event`, `is_network_event`, `is_process_event`, `is_file_event`, `is_alert` |
| `classification` | IP type (public/private/loopback), traffic direction, internal/external classification |
| `network_intel` | ASN (src/dest), cloud provider (AWS/Azure/GCP/Cloudflare/etc.), Tor detection, IP reputation, QUIC detection |
| `geo` | Country, city, coordinates (src/dest), distance, cross-border flag, cross-continent flag |
| `impossible_travel` | Previous/current location, distance, time difference, required speed (flags >1000 km/h with 5+ minute gap) |
| `counters` | Rolling 5-minute counts per source IP, destination IP, user, host, signature, port |
| `behavioral` | Unique destinations (1h), unique ports (1h), recent auth failures (5m) |
| `anomalies` | Boolean flags: port scan, brute force, lateral movement, data exfiltration, after hours, high frequency, Tor, malicious IP, impossible travel |
| `risk_score` | Composite 0-100 score based on Wazuh level, anomaly flags, geo data, network intel, behavioral counters |

**Risk score adjustments:**
- Blocked/denied traffic receives a -30 penalty (firewall-handled traffic is lower risk)
- Impossible travel adds +25
- Malicious IP reputation adds +20
- Cross-border + cross-continent adds +5 each

### L3: Correlation Engine (`unified_correlation_engine.py`)

Processes enriched events through detection rules and groups related alerts into incidents using a trigger-point model.

**Correlation model:**
- Each source IP gets a `TriggerPointTracker` with three recurring trigger intervals: 5 minutes, 30 minutes, and 24 hours
- Triggers fire both event-driven (when a new alert arrives after the interval) and timer-driven (periodic flush)
- Each trigger covers only alerts accumulated since its last firing
- `_compact_alerts()` groups alerts by target IP with counts, rules, severities, and deduplicated `original_event_ids`
- Attack pattern identification classifies incidents as campaigns, distributed attacks, reconnaissance, etc.

**Rule types:**
- **Single** -- fires immediately when one event matches all conditions
- **Aggregation** -- fires when a threshold count is met within a time window, with optional `unique_field` for counting distinct values instead of raw events

**Incident output fields:** `incident_id`, `severity`, `status`, `first_seen`, `last_seen`, `duration_seconds`, `alert_count`, `title`, `description`, `attack_chain` (MITRE tactics, attack pattern, campaign confidence), `affected_entities`, `alert_summary`, `enrichment_summary`, `recommended_actions`, `trigger_point`, `indicators_of_compromise`.

### L4: Context Scorer (`context_scorer.py`)

Enriches incidents with business context and calculates final priority scores.

- **Asset context** -- looks up criticality by asset name or IP range prefix
- **User context** -- privilege level, department, is_privileged flag
- **Impact scoring** -- category-specific impact matrix with modifiers for privileged users (+20), sensitive data (+15), critical business unit (+10), multi-tactic attack (+10)
- **Priority formula:** `priority_score = severity_score * 0.4 + impact_score * 0.6`

### L5: UEBA Engine (`ueba.py`)

Builds per-user behavioral baselines and detects deviations.

- **Baseline learning** -- tracks typical hours, countries, source IPs, and days of week per user
- **Anomaly detection** with weighted scores:

| Anomaly Type | Score |
|-------------|-------|
| Malicious IP contact | 50 |
| Impossible travel | 45 |
| Tor usage | 40 |
| First-time country | 35 |
| Unusual hour | 25 |
| First-time IP | 20 |
| After-hours anomaly | 20 |
| Unusual weekend activity | 15 |

- **Baseline persistence** -- saves/loads baseline profiles to `.state/ueba_baseline.json` for instant startup

### FUSION Engine (`fusion.py`)

Combines L4 scored incidents with L5 UEBA scores into final actionable alerts.

- **Risk calculation:** `60% * incident_priority + 40% * max_ueba_score + volume_boost`
- **Volume boost:** +5 (5+ alerts), +10 (10+ alerts), +15 (20+ alerts)
- **UEBA escalation** -- behavioral anomalies can escalate incident severity by up to 2 levels
- **Dual-input streaming** -- round-robin polling of incidents and UEBA scores with 10-minute correlation window
- **Threat levels:** imminent (>=90), severe (70-89), elevated (50-69), moderate (30-49), low (<30)

## Detection Rules

16 detection rules across 8 categories defined in `correlation_rules.yaml`:

| ID | Rule Name | Type | Category | Severity | MITRE |
|----|-----------|------|----------|----------|-------|
| AUTH-001 | Brute Force Attack - Single Source | single | Authentication | high | TA0006 |
| AUTH-002 | Distributed Brute Force Attack | aggregation | Authentication | critical | TA0006 |
| AUTH-003 | Successful Login After Failed Attempts | single | Authentication | critical | TA0006 |
| TI-001 | Malicious IP Communication | single | Threat Intelligence | critical | TA0011 |
| TI-002 | Tor Exit Node Communication | single | Threat Intelligence | high | TA0011 |
| RECON-001 | Port Scan from External Source | single | Reconnaissance | high | TA0043 |
| RECON-002 | Network Sweep Detected | single | Reconnaissance | high | TA0043 |
| LATERAL-001 | Internal Lateral Movement | single | Lateral Movement | critical | TA0008 |
| LATERAL-002 | Rapid Internal Host Hopping | aggregation | Lateral Movement | critical | TA0008 |
| EXFIL-001 | High-Volume Outbound Transfer | single | Data Exfiltration | high | TA0010 |
| EXFIL-002 | After-Hours Data Exfiltration | single | Data Exfiltration | high | TA0010 |
| TRAVEL-001 | Impossible Geographic Travel | single | Account Compromise | critical | TA0001, TA0006 |
| TRAVEL-002 | Cross-Continent Authentication | single | Account Compromise | high | TA0001 |
| EVASION-001 | Log/Audit Tampering | single | Defense Evasion | critical | TA0005 |
| RISK-001 | Critical Risk Score Event | single | High Risk | critical | TA0001 |
| RISK-002 | Sustained High-Risk Activity | aggregation | High Risk | high | TA0001 |

Rules are **source-agnostic** -- they match on enrichment fields computed uniformly for all Wazuh event types rather than on specific Wazuh rule IDs. Blocked/denied traffic is excluded from exfiltration rules to prevent false positives from routine firewall blocks.

Rules support nested `AND`/`OR`/`NOT` conditions with operators: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `contains`, `regex`. Aggregation rules support `group_by` fields and `unique_field` for counting distinct values (e.g., unique source IPs instead of raw event count).

## Output Format

### Scored Incidents (`scored_incidents.jsonl`)

```json
{
  "scored_at": "2026-02-17T11:30:00.000000Z",
  "alert_id": "INC-000001",
  "severity": "critical",
  "title": "Distributed Brute Force Attack - 100 Related Alerts",
  "first_seen": "2026-02-17T11:24:24+05:30",
  "last_seen": "2026-02-17T11:29:32+05:30",
  "alert_count": 100,
  "attack_chain": {
    "tactics": ["TA0006"],
    "attack_pattern": "Brute Force Attack Campaign",
    "campaign_confidence": "high"
  },
  "affected_entities": {
    "source_ips": ["206.123.144.8", "103.76.143.84"],
    "target_ips": ["192.168.1.10"],
    "affected_users": ["admin"]
  },
  "alert_summary": [
    {
      "target_ip": "192.168.1.10",
      "alert_count": 95,
      "rules_triggered": ["Brute Force Attack - Single Source"],
      "severities": ["high"],
      "original_event_ids": ["1771307738.395077895", "1771307858.397037991"]
    }
  ],
  "enrichment_summary": {
    "source": {
      "countries": ["United States", "Iran"],
      "asn_orgs": ["888 Ventures LLC"],
      "max_risk_score": 90,
      "anomaly_flags": ["cross_border", "is_impossible_travel", "is_brute_force"]
    }
  },
  "context": {
    "asset": { "criticality": "critical", "business_unit": "it_infrastructure" },
    "user": { "privilege_level": "domain_admin", "is_privileged": true }
  },
  "impact_analysis": {
    "impact_score": 85,
    "impact_level": "critical",
    "category": "authentication"
  },
  "priority": {
    "priority_level": "P1",
    "priority_score": 86,
    "sla": { "response_time_minutes": 15, "resolution_time_hours": 4 }
  },
  "recommended_actions": [
    "Lock target account immediately",
    "Block all attacking source IPs at perimeter",
    "Force password reset on targeted account"
  ]
}
```

### Fused Alerts (`correlated_UEBA_alerts.jsonl`)

The fusion layer adds UEBA behavioral analysis, network intelligence summary, final threat level assessment, and SLA/response guidance on top of the scored incident.

## Priority Levels

| Priority | Score Range | Response SLA | Resolution SLA | Escalation |
|----------|-----------|--------------|----------------|------------|
| P1 Critical | >= 80 | 15 minutes | 4 hours | Immediate |
| P2 High | 60-79 | 1 hour | 24 hours | Within 1 hour |
| P3 Medium | 40-59 | 4 hours | 72 hours | Within 4 hours |
| P4 Low | < 40 | 24 hours | 168 hours | Next business day |

## Configuration

| File | Purpose |
|------|---------|
| `correlation_rules.yaml` | 16 detection rules with conditions, thresholds, MITRE ATT&CK mapping |
| `context_config.yaml` | Asset criticality, user privileges, IP range context, impact matrix, SLA definitions |
| `ueba_config.yaml` | UEBA thresholds, risk weights, anomaly type configuration, baseline learning parameters |

### `context_config.yaml` structure

```yaml
assets:          # Named assets with criticality, business unit, data classification
ip_ranges:       # IP prefix -> criticality mapping (e.g., "192.168.1." -> critical)
users:           # Named users with privilege level, department, is_privileged flag
impact_matrix:   # category -> criticality -> base impact score (0-100)
sla_definitions: # P1-P4 with response/resolution times and escalation policy
```

### `correlation_rules.yaml` structure

```yaml
rules:
  - id: AUTH-001
    name: "Brute Force Attack - Single Source"
    type: single              # or "aggregation"
    category: authentication
    severity: high
    enabled: true
    mitre_tactics: [TA0006]
    conditions:               # Nested AND/OR/NOT with field comparisons
      AND:
        - enrich.flags.is_auth_event: true
        - enrich.normalization.action: denied
        - enrich.behavioral.recent_failures_5m:
            gte: 10
    # Aggregation rules add:
    time_window: 600          # seconds
    group_by: [subject.name]
    threshold:
      count:
        gte: 5
        unique_field: subject.ip   # count distinct values, not events
    response:
      - "Block source IP temporarily"
```

## Streaming Architecture

In `--follow` mode, all pipeline processes run simultaneously:

```
[normalizer.py --follow]  writes to -->  normalized.jsonl
[enrich_json.py --follow] tails    -->  normalized.jsonl  writes to -->  enriched.jsonl
[unified_correlation_engine.py --follow] tails --> enriched.jsonl writes to --> incidents.jsonl
[context_scorer.py --follow] tails --> incidents.jsonl writes to --> scored_incidents.jsonl
[ueba.py --follow] tails --> enriched.jsonl writes to --> ueba_scores.jsonl
[fusion.py --follow] tails --> scored_incidents.jsonl + ueba_scores.jsonl
```

Each `JSONLTailer` (from `file_tailer.py`):
- Waits for its input file to appear if it doesn't exist yet
- Reads existing data (catch-up phase), then polls for new lines
- Persists `{position, inode}` to a state file every 10 events
- Detects file rotation via inode comparison and size shrink
- Caps partial line buffer at 1 MB to prevent OOM
- Resumes from saved position on restart

State files are stored in `.state/`:

| File | Script |
|------|--------|
| `normalizer.state` | `normalizer.py` |
| `enricher.state` | `enrich_json.py` |
| `correlation.state` | `unified_correlation_engine.py` |
| `scorer.state` | `context_scorer.py` |
| `ueba.state` | `ueba.py` |
| `ueba_baseline.json` | `ueba.py` (behavioral baselines) |
| `fusion_incidents.state` | `fusion.py` |
| `fusion_ueba.state` | `fusion.py` |

Shutdown sequence: `SIGINT` -> wait 10 seconds for graceful exit -> `SIGKILL` stragglers.

## Project Structure

```
CyberSentinel-Event-Correlation/
    pipeline.py                       # Pipeline orchestrator (batch + streaming)
    normalizer.py                     # L1 - Wazuh alert normalization
    enrich_json.py                    # L2 - Network intelligence enrichment
    unified_correlation_engine.py     # L3 - Rule-based detection & correlation
    context_scorer.py                 # L4 - Business context & priority scoring
    ueba.py                           # L5 - User & Entity Behavior Analytics
    fusion.py                         # FUSION - Combines L4 + L5 into final alerts
    file_tailer.py                    # Shared JSONL tailing module
    correlation_rules.yaml            # 16 detection rules (8 categories)
    context_config.yaml               # Asset criticality, users, impact matrix, SLA
    ueba_config.yaml                  # UEBA thresholds and baseline config
    ARCHITECTURE.md                   # Technical architecture documentation
    databases/                        # GeoIP, ASN, Tor, reputation databases
    rules/                            # Reference Wazuh XML rule definitions
    .state/                           # Runtime state files (auto-created)
```

## License

This project was developed as part of a SOC internship research initiative.
