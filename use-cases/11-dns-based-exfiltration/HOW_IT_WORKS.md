# How DNS-Based Exfiltration Detection Works

**Plain English explanation**

---

## The Problem

DNS is usually allowed out of most networks. Attackers abuse that trust by encoding stolen data into DNS subdomains.

Example shape:

```text
m9x4qz7p2v8k3n6r5t1y0abx.tunnel-drop.example
```

That left-most label can be a small chunk of stolen data.

---

## Our Approach: Multi-Signal Correlation

### Signal 1: DNS Query Burst
A host sends many DNS lookups quickly.

**Normal:** A few queries for web browsing or application startup  
**Attack:** Dozens of unique queries in a short window

### Signal 2: High-Entropy DNS
The query labels look random.

**Normal:** `login`, `api`, `cdn`, `mail`  
**Attack:** `m9x4qz7p2v8k3n6r5t1y0abx`

### Signal 3: Encoded Tunneling Pattern
Many unique encoded chunks go to the same domain.

**Normal:** Repeated lookups to known domains  
**Attack:** Many unique chunks to one attacker-controlled domain

---

## Detection Logic

```text
DNS Query Burst
    +
High-Entropy DNS Labels
    +
Repeated Encoded Chunks to Same Domain
    =
DNS_BASED_EXFILTRATION
```

**Time window:** All signals within 10 minutes

---

## Why This Works

One noisy DNS signal can be benign. All three together show intent:

- the host is sending many DNS requests,
- the names look encoded,
- and the chunks are consistently going to one tunnel domain.

That combination is a strong indicator of covert data movement.

---

## Example Attack Timeline

1. **02:10** - Host begins sending encoded TXT queries.
2. **02:10-02:12** - Query volume crosses the burst threshold.
3. **02:11** - Entropy and encoded chunk thresholds are met.
4. **Detection:** Signals correlate -> DNS_BASED_EXFILTRATION.

---

Run the demo:

```bash
./RUN_ME.sh
```
