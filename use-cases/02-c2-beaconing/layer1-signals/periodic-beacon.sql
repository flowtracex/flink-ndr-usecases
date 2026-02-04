-- Signal: Periodic Beacon Timing Detection
-- Detects regular interval outbound connections (malware heartbeat)

-- Purpose:
-- Identifies beaconing behavior typical of C2 malware
-- Detects time-based patterns in outbound connections

-- Logic:
-- Calculate time deltas between consecutive connections to same destination
-- Identify regular intervals (coefficient of variation < 0.3)
-- Window: 5 minutes (captures multiple beacons)
-- Threshold: 3+ connections with consistent timing

-- Window Type: HOP (sliding window)
-- Updates every 30 seconds, looks back 5 minutes

INSERT INTO signals
SELECT
    'PERIODIC_BEACON' AS signal_type,
    src_ip,
    dest_ip,
    dest_port,
    COUNT(*) AS connection_count,
    -- Calculate interval regularity (simplified)
    -- Production: Use STDDEV_POP / AVG for coefficient of variation
    AVG(
        CAST(TIMESTAMPDIFF(SECOND, 
            LAG(event_time) OVER (PARTITION BY src_ip, dest_ip ORDER BY event_time),
            event_time
        ) AS DOUBLE)
    ) AS avg_interval_seconds,
    STDDEV_POP(
        CAST(TIMESTAMPDIFF(SECOND,
            LAG(event_time) OVER (PARTITION BY src_ip, dest_ip ORDER BY event_time),
            event_time
        ) AS DOUBLE)
    ) AS interval_stddev,
    HOP_END(event_time, INTERVAL '30' SECOND, INTERVAL '5' MINUTE) AS window_end,
    CASE
        WHEN COUNT(*) >= 10 THEN 'CRITICAL'
        WHEN COUNT(*) >= 5 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    -- Only outbound connections (internal src to external dest)
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
    AND NOT (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
    -- Exclude known CDNs and cloud services (production: use reputation DB)
    AND dest_ip NOT LIKE '151.101.%' -- Fastly CDN example
GROUP BY
    src_ip,
    dest_ip,
    dest_port,
    HOP(event_time, INTERVAL '30' SECOND, INTERVAL '5' MINUTE)
HAVING
    COUNT(*) >= 3
    AND
    -- Regularity check: coefficient of variation < 0.3 (consistent timing)
    (STDDEV_POP(
        CAST(TIMESTAMPDIFF(SECOND,
            LAG(event_time) OVER (PARTITION BY src_ip, dest_ip ORDER BY event_time),
            event_time
        ) AS DOUBLE)
    ) / AVG(
        CAST(TIMESTAMPDIFF(SECOND, 
            LAG(event_time) OVER (PARTITION BY src_ip, dest_ip ORDER BY event_time),
            event_time
        ) AS DOUBLE)
    )) < 0.3;

-- Production Notes:
-- 1. Use coefficient of variation (CV) = stddev / mean for regularity
-- 2. Whitelist legitimate services (NTP, monitoring, cloud sync)
-- 3. Adjust window size based on known malware beacon intervals
-- 4. Consider JA3/JA3S TLS fingerprints for added confidence
-- 5. Correlate with threat intel feeds for known C2 IPs
