# UC-04: Backup / Snapshot Targeting Detection

Multi-signal detection of ransomware preparation against backup and snapshot infrastructure.

---

## Detection Logic

**Layer 1 (Flink SQL):**
1. Backup Server Contact: 2+ backup or snapshot targets contacted
2. Admin Management Protocol: 2+ admin protocols used against backup assets
3. Destructive Recovery Action: 2+ backup or snapshot disruption actions

**Layer 2 (Python):**
All 3 signals within 10 minutes for the same source IP -> BACKUP_SNAPSHOT_TARGETING

---

## Run

```bash
./RUN_ME.sh
```

---

## Expected Output

```text
[DETECTION] BACKUP_SNAPSHOT_TARGETING
Source: 10.100.40.77
Severity: CRITICAL
Signals: 3
Backup Targets: 3
Destructive Actions: 4
```

---

## Files

```text
layer1-signals/      # Flink SQL
layer2-correlation/  # Python correlation
sample-data.json     # Demo backup/recovery events
```

---

## Detection Signals

### Signal 1: Backup Server Contact
- **What:** A host contacts multiple backup or snapshot systems.
- **Threshold:** 2+ backup targets.
- **Why it matters:** Attackers often discover recovery infrastructure before encryption.

### Signal 2: Admin Management Protocol
- **What:** Admin protocols are used against backup assets.
- **Threshold:** 2+ admin protocols.
- **Why it matters:** Ransomware operators often use RDP, WinRM, SMB, SSH, or RPC to control backup systems.

### Signal 3: Destructive Recovery Action
- **What:** Backup jobs, backup data, snapshots, or restore points are disabled or deleted.
- **Threshold:** 2+ destructive actions.
- **Why it matters:** Recovery impairment is a strong ransomware precursor.

---

## MITRE ATT&CK

- **Tactic:** TA0040 (Impact)
- **Techniques:**
  - T1490 (Inhibit System Recovery)
  - T1486 (Data Encrypted for Impact)
  - T1021 (Remote Services)
