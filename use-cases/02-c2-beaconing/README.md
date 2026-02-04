# UC-02: Command-and-Control (C2) Beaconing Detection

Multi-signal detection of infected hosts communicating with external C2 servers.

---

## Detection Logic

**Layer 1 (Flink SQL):**
1. Periodic Beacon: Regular interval connections (3+ with CV < 0.3)
2. Persistent Destination: Repeated connections to rare external endpoint (5+ connections, <5 internal hosts)
3. Command Exchange: Request/response patterns (3+ pairs, 3:1 response ratio)

**Layer 2 (Python):**
All 3 signals within 15 minutes for same source-destination pair → Active C2 Communication

---

## Run

```bash
./RUN_ME.sh
```

---

## Expected Output

```
[DETECTION] Active C2 Communication
Source: 192.168.1.45 → 203.0.113.99
Severity: CRITICAL
Signals: 3
```

---

## Files

```
layer1-signals/      # Flink SQL signal definitions
layer2-correlation/  # Python correlation engine
shared/              # Sample data (pre-generated signals)
```

---

## Notes

- This use case uses pre-generated signals in `shared/sample-data.json`
- For production, Layer 1 would generate signals from raw network events
- Detections are saved to `../../output/c2-detections.db`
