Most SOC teams collect logs from 5+ identity sources.

But they end up writing 20+ separate detection rules, one per vendor.

Here's a better approach:

-> OpenTelemetry Collector ingests everything: Entra ID, AD, Okta, VPN
-> Normalize to one schema at the pipeline layer
-> Write your detection once; it covers all sources

Real example: Impossible Travel detection.

User logs in from London at 09:00.
Same user logs in from Singapore at 09:45.

Without normalization: two silos, weak correlation.
With an OTel pipeline: same schema, alert fires in seconds.

Storage tier:

Kafka -> real-time detection
ClickHouse -> fast investigation queries
S3 -> compliance archive

I pushed a runnable implementation here:
[GitHub link]
