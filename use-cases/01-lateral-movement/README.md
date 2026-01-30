# UC-01: Lateral Movement Detection

Multi-signal detection of internal network reconnaissance.

---

## Detection Logic

**Layer 1 (Flink SQL):**
1. Port Scan: >20 unique ports in 60s
2. Connection Spike: >3σ above baseline
3. Privileged Access: SMB, RDP, SSH

**Layer 2 (Python):**
All 3 signals within 15 minutes → LATERAL_MOVEMENT

---

## Run

```bash
./RUN_ME.sh
```

---

## Expected Output

```
[DETECTION] LATERAL_MOVEMENT
Source: 10.0.0.5
Severity: CRITICAL
Signals: 3
```

---

## Files

```
layer1-signals/      # Flink SQL
layer2-correlation/  # Python correlation
sample-data.json     # Demo input
```
