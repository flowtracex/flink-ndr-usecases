-- Signal: Command Exchange Pattern Detection
-- Detects request-response patterns typical of C2 frameworks

-- Purpose:
-- Identifies interactive command-and-control sessions
-- Detects small request, larger response patterns

-- Logic:
-- Track bidirectional flows with asymmetric byte patterns
-- Small outbound (command), larger inbound (response/payload)
-- Window: 2 minutes (captures command sequences)
-- Threshold: 3+ request-response pairs

-- Window Type: SESSION (session-based aggregation)
-- Groups by connection tuple

INSERT INTO signals
SELECT
    'COMMAND_EXCHANGE' AS signal_type,
    src_ip,
    dest_ip,
    dest_port,
    COUNT(*) AS exchange_count,
    AVG(bytes_sent) AS avg_request_size,
    AVG(bytes_received) AS avg_response_size,
    SUM(bytes_sent) AS total_sent,
    SUM(bytes_received) AS total_received,
    -- Response-to-request ratio
    CASE 
        WHEN SUM(bytes_sent) > 0 
        THEN CAST(SUM(bytes_received) AS DOUBLE) / SUM(bytes_sent)
        ELSE 0
    END AS response_ratio,
    SESSION_END(event_time, INTERVAL '2' MINUTE) AS window_end,
    CASE
        WHEN COUNT(*) >= 10 THEN 'CRITICAL'
        WHEN COUNT(*) >= 5 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    -- Only outbound connections
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
    AND NOT (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
    -- Has bidirectional traffic
    AND bytes_sent > 0 
    AND bytes_received > 0
GROUP BY
    src_ip,
    dest_ip,
    dest_port,
    SESSION(event_time, INTERVAL '2' MINUTE)
HAVING
    COUNT(*) >= 3
    AND
    -- Small requests, larger responses (typical C2 pattern)
    AVG(bytes_sent) < 500 
    AND 
    AVG(bytes_received) > AVG(bytes_sent) * 2
    AND
    -- Response-to-request ratio > 3:1
    (CAST(SUM(bytes_received) AS DOUBLE) / SUM(bytes_sent)) > 3.0;

-- Production Notes:
-- 1. Adjust byte thresholds based on network baseline
-- 2. Whitelist interactive services (SSH, RDP sessions)
-- 3. Consider packet timing (rapid back-and-forth)
-- 4. Use protocol analysis for encrypted channels
-- 5. Correlate with DNS queries to same destination
