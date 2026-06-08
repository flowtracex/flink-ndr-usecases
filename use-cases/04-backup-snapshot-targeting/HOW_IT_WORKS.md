# How Backup / Snapshot Targeting Detection Works

**Plain English explanation**

---

## The Problem

Ransomware attackers do not only encrypt files.

Before encryption, they often try to remove the victim's recovery path:

- Find backup servers
- Access backup consoles or repositories
- Disable backup jobs
- Delete backups or snapshots
- Stop recovery services

If recovery is impaired, the victim is more likely to pay.

---

## Our Approach: Multi-Signal Correlation

### Signal 1: Backup Server Contact
A suspicious workstation contacts multiple backup assets.

**Normal:** Backup admins or backup proxies contact these systems.  
**Attack:** A non-backup host suddenly touches backup servers and repositories.

### Signal 2: Admin Management Protocol
The same host uses admin protocols against backup infrastructure.

**Normal:** Managed access from known admin jump hosts.  
**Attack:** RDP, WinRM, SMB, SSH, or RPC from an unusual source.

### Signal 3: Destructive Recovery Action
The same host attempts to disable or delete recovery artifacts.

**Normal:** Planned maintenance or lifecycle cleanup.  
**Attack:** Backup jobs, snapshots, or restore points are removed before encryption.

---

## Detection Logic

```text
Backup Server Contact
    +
Admin Management Protocol Use
    +
Destructive Recovery Action
    =
BACKUP_SNAPSHOT_TARGETING
```

**Time window:** All signals within 10 minutes

---

## Why This Works

Contacting a backup server alone may be normal.

Using admin protocols may also be normal for the right administrator.

But when the same host contacts backup infrastructure, uses admin access paths, and performs destructive recovery actions in the same time window, the behavior becomes high confidence.

---

## Example Attack Timeline

1. **01:05** - Host contacts backup server and repository.
2. **01:06** - Host uses RDP and WinRM against backup assets.
3. **01:07** - Backup job is disabled and backup data deletion starts.
4. **Detection:** Signals correlate -> BACKUP_SNAPSHOT_TARGETING.

---

Run the demo:

```bash
./RUN_ME.sh
```
