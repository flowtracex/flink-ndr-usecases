# How Lateral Movement Detection Works

**Plain English explanation**

---

## The Problem

Hackers move sideways through networks to:
- Find valuable targets
- Steal credentials  
- Deploy ransomware

**Lateral movement looks normal** because attackers use legitimate tools.

---

## Our Approach: Multi-Signal Correlation

### Signal 1: Port Scan
One computer connects to many different network ports.

**Normal:** 2-5 ports  
**Attack:** 20+ ports in 60 seconds

### Signal 2: Connection Spike
Sudden increase in network connections.

**Normal:** 10 connections/minute  
**Attack:** 40+ connections/minute

### Signal 3: Privileged Services
Access to admin tools (SMB, RDP, SSH).

**Normal:** Occasional use  
**Attack:** Multiple services in short time

---

## Detection Logic

```
Port Scan (weak signal)
    +
Connection Spike (weak signal)
    +
Privileged Access (weak signal)
    =
LATERAL MOVEMENT (high confidence)
```

**Time window:** All signals within 15 minutes

---

## Why This Works

**Single signal:** Could be normal (IT admin, vulnerability scanner)  
**All three together:** Almost always malicious

**Result:** Catch attacks, reduce false positives

---

## Technology

**Layer 1 (Flink):** Fast signal generation from network logs  
**Layer 2 (Python):** Correlate signals, make detection decision

---

**Run the demo to see it in action:**
```bash
./RUN_ME.sh
```
