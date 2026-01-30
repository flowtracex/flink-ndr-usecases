# Layer 2: Python Correlation

Multi-signal correlation for high-confidence detection.

---

## Purpose

Correlate weak signals into strong detections.

**Input:** Signals from Flink (~5K/sec)  
**Output:** Detections (10-50/hour)

---

## Multi-Stage Correlation

```python
# Stage 1
if signal == 'PORT_SCAN':
    state[actor]['stage1'] = True

# Stage 2  
if signal == 'CONNECTION_SPIKE' and state[actor]['stage1']:
    state[actor]['stage2'] = True

# Stage 3
if signal == 'PRIV_ACCESS' and all_stages(actor):
    fire_detection(actor)
```

---

## State Management

**Demo:** In-memory dict  
**Production:** Redis with TTL keys

```python
# Production
redis.setex(f"stage1:{actor}", 1800, "true")  # 30min TTL

# Demo
state[actor] = {'stage1': True, 'timestamp': now()}
```

---

## Time Windows

Validate signals arrive within time window:

```python
delta = current_time - first_signal_time
if delta > 15 * 60:  # 15 minutes
    # Too late, ignore
    return
```

---

## Detection Output

Final detections saved to SQLite:

```sql
CREATE TABLE detections (
    detection_id TEXT PRIMARY KEY,
    src_ip TEXT,
    detection_type TEXT,
    severity TEXT,
    signals_json TEXT
);
```

---

## Why Python (Not Flink)

- ✅ Flexible correlation logic
- ✅ Easy debugging
- ✅ Simple for 300 use cases
- ✅ SQLite = no dependencies
