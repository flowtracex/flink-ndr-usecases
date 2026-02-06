# UC-07: Large Volume Data Exfiltration Detection

Multi-signal detection of data theft through high-volume outbound transfers.

---

## Detection Logic

**Layer 1 (Flink SQL):**
1. Data Staging: >500MB internal file transfers (SMB, SCP, FTP)
2. Outbound Spike: >1GB upload OR >3σ anomaly OR upload ratio >10x
3. Destination Diversity: 5+ unique external IPs with >50MB total

**Layer 2 (Python):**
All 3 signals within 15 minutes → LARGE_VOLUME_EXFILTRATION

---

## Run

```bash
./RUN_ME.sh
```

---

## Expected Output

```
[DETECTION] LARGE_VOLUME_EXFILTRATION
Source: 10.100.50.25
Severity: CRITICAL
Signals: 3
Data Exfiltrated: 2.20 GB
Unique Destinations: 6
```

---

## Files

```
layer1-signals/      # Flink SQL
layer2-correlation/  # Python correlation
sample-data.json     # Demo input
```

---

## Detection Signals

### Signal 1: Data Staging
- **What:** Internal file transfers accumulating data
- **Threshold:** >500MB in 5 minutes
- **Protocols:** SMB (445), SCP (22), FTP (21), NFS (2049)

### Signal 2: Outbound Spike
- **What:** Sudden increase in outbound data transfer
- **Thresholds:**
  - Absolute: >1GB in 5 minutes
  - Statistical: >3 standard deviations
  - Ratio: Upload/download >10:1

### Signal 3: Destination Diversity
- **What:** Multiple external destinations (redundancy)
- **Threshold:** 5+ unique external IPs with >50MB total
- **Purpose:** Detect multi-drop exfiltration patterns

---

## MITRE ATT&CK

- **Tactic:** TA0010 (Exfiltration)
- **Techniques:**
  - T1567 (Exfiltration Over Web Service)
  - T1048 (Exfiltration Over Alternative Protocol)
  - T1074 (Data Staged)

