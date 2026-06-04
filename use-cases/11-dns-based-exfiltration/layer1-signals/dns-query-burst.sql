-- Signal: DNS Query Burst Detection (S1)
-- Detects sudden high-volume DNS activity from one internal host.
--
-- Purpose:
--   DNS tunneling often breaks data into many small DNS lookups.
--   A query burst is weak alone, but useful when correlated with entropy
--   and encoded chunk patterns.
--
-- Logic:
--   Count DNS queries and unique query names per source IP.
--   Window: 5 minutes
--   Threshold: 25+ queries and 20+ unique names
--
-- Window Type: TUMBLE

INSERT INTO signals
SELECT
    'DNS_QUERY_BURST' AS signal_type,
    src_ip,
    COUNT(*) AS query_count,
    COUNT(DISTINCT query) AS unique_queries,
    TUMBLE_END(event_time, INTERVAL '5' MINUTE) AS window_end,
    CASE
        WHEN COUNT(*) >= 40 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    protocol = 'DNS'
    AND dest_port = 53
    AND (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
GROUP BY
    src_ip,
    TUMBLE(event_time, INTERVAL '5' MINUTE)
HAVING
    COUNT(*) >= 25
    AND COUNT(DISTINCT query) >= 20;

-- Production Notes:
-- 1. Baseline query rates per subnet and role.
-- 2. Suppress known recursive resolvers and DNS security tools.
-- 3. Track NXDOMAIN ratio and response sizes for additional confidence.
