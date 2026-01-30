# Quick Start

Run your first detection in 5 minutes.

---

## Install

```bash
pip install -r requirements.txt
```

---

## Run Demo

```bash
cd use-cases/01-lateral-movement
./RUN_ME.sh
```

---

## Expected Output

```
[LAYER 1] Flink Signal Generation
  ✓ Port scan: 10.0.0.5 → 23 ports
  ✓ Connection spike: 10.0.0.5 (+10σ)
  ✓ Privileged access: SMB, RDP, SSH

[LAYER 2] Multi-Signal Correlation
  ✓ Stage 1: PORT_SCAN
  ✓ Stage 2: CONNECTION_SPIKE
  ✓ Stage 3: PRIVILEGED_ACCESS

[DETECTION] 🚨 LATERAL_MOVEMENT
  Source: 10.0.0.5
  Severity: CRITICAL
```

---

## Next Steps

- Read [HOW_IT_WORKS.md](use-cases/01-lateral-movement/HOW_IT_WORKS.md)
- View [Architecture](architecture/README.md)
- Modify thresholds in SQL files
