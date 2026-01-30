-- Signal: Port Scan Detection
-- Detects when a source IP connects to many destination ports

-- Purpose:
-- Identifies network reconnaissance behavior (port scanning)
-- Common in lateral movement before privilege escalation

-- Logic:
-- Count unique destination ports per source IP
-- Window: 60 seconds (sliding, updates every 10s)
-- Threshold: >20 unique ports = scanning behavior

-- Window Type: HOP (sliding window)
-- HOP(event_time, slide_interval, window_size)
-- Updates every 10 seconds, looks back 60 seconds

INSERT INTO signals
SELECT
    'PORT_SCAN' AS signal_type,
    src_ip,
    COUNT(DISTINCT dest_port) AS unique_ports,
    HOP_END(event_time, INTERVAL '10' SECOND, INTERVAL '60' SECOND) AS window_end,
    CASE
        WHEN COUNT(DISTINCT dest_port) > 50 THEN 'CRITICAL'
        WHEN COUNT(DISTINCT dest_port) > 30 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    -- Only internal source IPs
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
GROUP BY
    src_ip,
    HOP(event_time, INTERVAL '10' SECOND, INTERVAL '60' SECOND)
HAVING
    COUNT(DISTINCT dest_port) > 20;

-- Production Notes:
-- 1. Adjust threshold based on network baseline
-- 2. Whitelist known vulnerability scanners
-- 3. Consider time-of-day patterns
-- 4. In production, signals go to Kafka topic
