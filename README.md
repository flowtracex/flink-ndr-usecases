# 🔒 Flink NDR Use Cases
**Real-time network threat detection using Apache Flink + Python**

Welcome! 👋 This repository shows you how modern Network Detection & Response (NDR/XDR) platforms detect threats in real-time.

We've simplified a production-grade detection architecture so you can learn how it actually works—without getting lost in infrastructure complexity.

---

## 🎯 What You'll Learn

This is a **learning and reference implementation**, not a production deployment. Our goal is to help you understand the *detection logic* that powers modern security platforms.

---

## ⚠️ Demo vs. Production: What's the Difference?

### 🧪 This Demo Environment

- Small sample data (JSON files)
- Runs on your laptop
- In-memory correlation
- SQLite for storing detections

### 🏭 Real Production Environment

- Live network sensors processing 100K+ events per second
- Kafka for streaming and buffering
- Noise reduction and deduplication
- Whitelisting and alert suppression
- Data enrichment and normalization
- Distributed Flink clusters
- Redis for correlation state (with TTL)
- PostgreSQL / Elasticsearch for detections

**The detection logic is the same.**  
**The infrastructure and scale are different.**

---

## 🏗️ How Production Detection Works

Here's the typical flow in a real NDR/XDR platform:
```
Network Sensors (Zeek, etc.)
        ↓
Kafka (Streaming Backbone)
        ↓
Flink Jobs (Signal Generation)
        ↓
Correlation Engine + ML
        ↓
Detections & Alerts
```

This repository focuses on the **detection stages**—assuming data is already clean and enriched.

---

## 🧠 Architecture (Simplified)
```
Network Events (High Volume)
        ↓
📊 Layer 1: Flink SQL – Signal Generation
        • Stateful stream processing
        • Time-windowed aggregations
        • Extract behavioral signals
        ↓
Signals (Reduced Volume)
        • Port scanning detected
        • Connection fan-out detected
        • Privileged access detected
        ↓
🐍 Layer 2: Python – Correlation Engine
        • Combine multiple signals
        • Validate time windows
        • Apply ML-based baselining
        ↓
✅ Detections
        • Low volume
        • High confidence
```

### 💡 Key Principle

**Individual signals are weak.**  
**Correlated signals create reliable detections.**

---

## 🚀 Why the "Signal-First" Design?

When processing 100K+ events per second, complex joins inside Flink cause problems:

❌ Massive state size  
❌ Slow checkpointing  
❌ System backpressure  
❌ Operational headaches  

### Our Solution ✅

- Generate each signal **independently**
- Make signals **reusable** across multiple use cases
- Do correlation **outside Flink**

**Result:** Flink handles throughput. Python handles intelligence.

---

## 🐍 Why Correlation in Python (Not Flink)?

Correlation logic changes frequently and often includes:

- ML-based scoring
- Dynamic thresholds
- Whitelisting rules
- Business-specific logic

**Python gives us:**

✅ Faster iteration  
✅ Easier debugging  
✅ Native ML libraries  
✅ Cleaner detection code  

---

## ⚡ Quick Start

Get up and running in 3 steps:
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Navigate to a use case
cd use-cases/01-lateral-movement

# 3. Run it!
./RUN_ME.sh
```

### Expected Output
```
[LAYER 1] Signals generated ✓
[LAYER 2] Signals correlated ✓
[DETECTION] LATERAL_MOVEMENT detected 🚨
```

---

## 🛠️ Technology Stack

| Component | Purpose | Production Alternative |
|-----------|---------|----------------------|
| **Apache Flink** | Signal generation (stateful SQL) | Same, but distributed |
| **Python** | Multi-signal correlation + ML | Same |
| **SQLite** | Demo detection storage | PostgreSQL / Elasticsearch |
| | | **+ Kafka, Redis, monitoring** |

---

## 🎓 Use Cases

### ✅ Available Now

**UC-01: Lateral Movement Detection**
- Internal port scanning
- Connection fan-out
- Privileged access patterns

**UC-02: Command-and-Control (C2) Beaconing Detection**
- Periodic beaconing to rare external endpoints
- Persistent communication with suspicious C2 servers
- Request/response command patterns

**UC-07: Large Volume Data Exfiltration Detection**
- Internal data staging from multiple internal sources
- Large outbound upload spike
- Multiple external destinations (multi-drop exfiltration)

### 🔜 Coming Soon

- SMB lateral spread
- Privilege escalation
- DNS tunneling
- *...and more core use cases*

---

## 📚 Final Note

This repository teaches you **detection thinking**, not infrastructure plumbing.

We've intentionally simplified the production pipeline so you can focus on understanding how threat detection actually works.

**Ready to dive in? Start with UC-01!** 🚀

---

## 🤝 Contributing

Found a bug? Have a use case idea? Contributions welcome!

## 📄 License

[Add your license here]

## 🔗 Learn More

- [Apache Flink Documentation](https://flink.apache.org/)
- [Zeek Network Security Monitor](https://zeek.org/)
- Blog post: [Detecting Lateral Movement with Flink](https://github.com/flowtracex/flink-ndr-usecases/)

---

**Happy threat hunting! 🔍**