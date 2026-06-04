# UC-11: DNS-Based Exfiltration Detection

Multi-signal detection of data theft hidden inside DNS queries.

---

## Detection Logic

**Layer 1 (Flink SQL):**
1. DNS Query Burst: 25+ DNS queries with 20+ unique names
2. High-Entropy DNS: 10+ long, random-looking DNS labels
3. Encoded Tunneling Pattern: 12+ encoded chunks to the same domain

**Layer 2 (Python):**
All 3 signals within 10 minutes for the same source IP -> DNS_BASED_EXFILTRATION

---

## Run

```bash
./RUN_ME.sh
```

---

## Expected Output

```text
[DETECTION] DNS_BASED_EXFILTRATION
Source: 10.100.80.44
Tunnel Domain: tunnel-drop.example
Severity: CRITICAL
Signals: 3
Encoded Chunks: 18
```

---

## Files

```text
layer1-signals/      # Flink SQL
layer2-correlation/  # Python correlation
sample-data.json     # Demo DNS events
```

---

## Detection Signals

### Signal 1: DNS Query Burst
- **What:** A host sends unusually many DNS queries in a short time.
- **Threshold:** 25+ queries and 20+ unique query names.
- **Why it matters:** DNS tunnels split data into many small requests.

### Signal 2: High-Entropy DNS
- **What:** DNS labels look random or encoded.
- **Threshold:** 10+ long labels with entropy >= 3.5.
- **Why it matters:** Encoded data does not look like normal human-readable names.

### Signal 3: Encoded Tunneling Pattern
- **What:** Many unique encoded chunks go to the same registered domain.
- **Threshold:** 12+ chunks.
- **Why it matters:** This is the actual tunnel shape, not just noisy DNS.

---

## MITRE ATT&CK

- **Tactic:** TA0010 (Exfiltration)
- **Techniques:**
  - T1048 (Exfiltration Over Alternative Protocol)
  - T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)
  - T1071.004 (Application Layer Protocol: DNS)
