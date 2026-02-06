# How Large Volume Data Exfiltration Detection Works

**Plain English explanation**

---

## The Problem

Attackers steal sensitive data by:
- Staging files internally (copying to staging location)
- Uploading large volumes to external servers
- Using multiple destinations for redundancy

**Exfiltration looks normal** because it uses legitimate protocols (HTTPS, SMB).

---

## Our Approach: Multi-Signal Correlation

### Signal 1: Data Staging
A computer copies large amounts of data from internal servers.

**Normal:** Occasional file access (50-200MB)  
**Attack:** 500MB+ in 5 minutes from multiple sources

### Signal 2: Outbound Spike
Sudden increase in data uploaded to external servers.

**Normal:** 10-50MB uploads (web browsing, emails)  
**Attack:** 1GB+ uploads in 5 minutes, or upload >> download

### Signal 3: Destination Diversity
Connecting to many different external IPs.

**Normal:** 1-3 consistent destinations (cloud services)  
**Attack:** 5+ unique external IPs (redundancy strategy)

---

## Detection Logic

```
Data Staging (weak signal)
    +
Outbound Spike (weak signal)
    +
Destination Diversity (weak signal)
    =
LARGE VOLUME EXFILTRATION (high confidence)
```

**Time window:** All signals within 15 minutes

---

## Why This Works

**Single signal:** Could be normal (backup, cloud sync, software update)  
**All three together:** Almost always malicious data theft

**Result:** Catch exfiltration attacks, reduce false positives

---

## Technology

**Layer 1 (Flink):** Fast signal generation from network logs  
**Layer 2 (Python):** Correlate signals, make detection decision

---

## Example Attack Timeline

1. **10:15-10:20** - Attacker stages 1.1GB from internal servers (Signal 1)
2. **10:20-10:25** - Uploads 2.2GB to external cloud storage (Signal 2)
3. **10:20-10:30** - Uses 6 different external IPs for redundancy (Signal 3)
4. **Detection:** All 3 signals correlated → LARGE_VOLUME_EXFILTRATION

---

**Run the demo to see it in action:**
```bash
./RUN_ME.sh
```

