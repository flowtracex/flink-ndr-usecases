-- Signal: Connection Rate Spike Detection
-- Detects sudden increase in connection attempts

-- Purpose:
-- Identifies anomalous connection behavior
-- Indicates scanning, spreading, or data exfiltration prep

-- Logic:
-- Count connections per source IP
-- Compare against baseline (mean + stddev)
-- Window: 60 seconds (discrete buckets)
-- Threshold: >3 standard deviations above baseline

-- Window Type: TUMBLE (discrete time buckets)
-- Non-overlapping 60-second windows

INSERT INTO signals
SELECT
    'CONNECTION_SPIKE' AS signal_type,
    src_ip,
    COUNT(*) AS connection_count,
    -- Simplified baseline (production: learn from history)
    10.0 AS baseline_mean,
    3.0 AS baseline_stddev,
    (COUNT(*) - 10.0) / 3.0 AS deviation_score,
    TUMBLE_END(event_time, INTERVAL '60' SECOND) AS window_end,
    CASE
        WHEN (COUNT(*) - 10.0) / 3.0 > 5.0 THEN 'CRITICAL'
        WHEN (COUNT(*) - 10.0) / 3.0 > 4.0 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    -- Only internal source IPs
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
GROUP BY
    src_ip,
    TUMBLE(event_time, INTERVAL '60' SECOND)
HAVING
    -- Trigger when >3 standard deviations above baseline
    (COUNT(*) - 10.0) / 3.0 > 3.0;

-- Production Notes:
-- 1. Baseline should be learned per IP from historical data
-- 2. Update baselines periodically (daily/weekly)
-- 3. Account for time-of-day and day-of-week patterns
-- 4. Use Z-score or IQR methods for better accuracy
-- 5. In production, baselines stored in state or external DB
