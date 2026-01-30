# 2-Layer Detection Architecture

How production NDR systems detect threats.

---

## Architecture

```
Layer 1: Signal Generation (Flink)
  • Processes 100K events/sec
  • Generates behavioral signals
  • Output: ~5K signals/sec

Layer 2: Correlation (Python)
  • Multi-signal correlation
  • Time-window validation
  • Output: High-confidence detections
```

---

## Why 2 Layers?

**Layer 1 (Flink):** Fast aggregation at scale  
**Layer 2 (Python):** Complex correlation + ML

**Separation:** Independent scaling, easier debugging

---

## Demo vs Production

| Component | Demo | Production |
|-----------|------|------------|
| Data Source | sample-data.json | Live Zeek sensors |
| Layer 1 → 2 | In-memory | Kafka |
| State | In-memory dict | Redis (TTL keys) |
| Storage | SQLite | PostgreSQL |

**Same detection logic. Different infrastructure.**

---

## Read More

- [Layer 1: Flink Signals](layer1-signals.md)
- [Layer 2: Python Correlation](layer2-correlation.md)
