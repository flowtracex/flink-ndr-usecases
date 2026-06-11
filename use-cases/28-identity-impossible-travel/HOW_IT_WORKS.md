# How UC-28 Works

This demo has two steps.

## 1. Normalize

Run:

```bash
python3 normalize.py
```

The script reads vendor-specific files from `raw-events/` and writes `normalized-events.json`.

Each vendor has different field names, but the output has one common schema. That is the detection contract.

## 2. Detect

Run:

```bash
python3 detect-impossible-travel.py
```

The detector groups successful authentication events by `user_id`, sorts them by time, and compares consecutive logins.

It alerts when:

```text
distance >= 750 km
speed >= 900 km/h
```

The example user logs in from London at `09:00`, then from Singapore at `09:45`.

That requires roughly `14463.8 km/h`, and the second login also has risky context:

```text
MFA: not_challenged
Device: unknown
ASN: hosting_provider
Risk score: 88
```

So the final severity is `CRITICAL`.
