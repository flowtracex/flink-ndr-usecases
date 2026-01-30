# Flink NDR Use Cases

**Real-time network threat detection using Apache Flink + Python**

Production-style multi-signal detection demonstrating how real Network Detection & Response systems work.

---

## Architecture

```
Network Events (100K EPS)
        ↓
Layer 1: Flink SQL Signal Generation
        ↓
Signals (~5K/sec)
        ↓
Layer 2: Python Correlation
        ↓
SQLite Detections
```

**Key Principle:** Multi-signal correlation. Individual signals are weak. Combined = high confidence.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run first use case
cd use-cases/01-lateral-movement
./RUN_ME.sh
```

---

## Technology Stack

| Component | Purpose |
|-----------|---------|
| **Apache Flink** | Signal generation (stateful SQL) |
| **Python** | Multi-signal correlation |
| **SQLite** | Detection storage |

**Production:** Add Kafka + Redis for scale

---

## Use Cases

- **UC-01:** Lateral Movement Detection

Coming: SMB Spread, Privilege Escalation, Data Exfiltration (300 total)

---

## Learn More

- [Architecture](architecture/README.md)
- [Quick Start](QUICK_START.md)

---

**MIT License - Learn openly, build responsibly**
