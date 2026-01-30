# Layer 1: Flink Signal Generation

Fast behavioral signal extraction using SQL.

---

## Purpose

Extract behavioral signals from 100K events/sec using Apache Flink SQL.

**Input:** Network events  
**Output:** Behavioral signals (20x reduction)

---

## Flink SQL Windows

**Tumbling (discrete):**
```sql
TUMBLE(event_time, INTERVAL '60' SECOND)
```

**Hop (sliding):**
```sql
HOP(event_time, INTERVAL '10' SECOND, INTERVAL '60' SECOND)
```

---

## Signal Examples

### Port Scan
```sql
SELECT src_ip, COUNT(DISTINCT dest_port) as ports
FROM events
GROUP BY src_ip, HOP(...)
HAVING ports > 20;
```

### Connection Spike
```sql
SELECT src_ip, COUNT(*) as conns
FROM events  
GROUP BY src_ip, TUMBLE(...)
HAVING (conns - baseline) / stddev > 3.0;
```

---

## State Management

- **Backend:** RocksDB (production)
- **State per key:** Port sets, counters
- **Checkpointing:** Every 5 minutes

---

## Execution

**Production:** `flink run signal-job.jar`  
**Demo:** `python ../../shared/run-signals.py`
