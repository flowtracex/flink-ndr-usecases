-- Signal: Persistent Destination Detection
-- Detects repeated connections to rare external endpoints

-- Purpose:
-- Identifies C2 infrastructure (same IP contacted repeatedly)
-- Filters out common legitimate destinations

-- Logic:
-- Count connections per src-dest pair
-- Check destination rarity (few internal hosts contact it)
-- Window: 10 minutes (captures sustained communication)
-- Threshold: 5+ connections to rare destination

-- Window Type: HOP (sliding window)
-- Updates every 1 minute, looks back 10 minutes

INSERT INTO signals
SELECT
    'PERSISTENT_DESTINATION' AS signal_type,
    src_ip,
    dest_ip,
    dest_port,
    COUNT(*) AS connection_count,
    COUNT(DISTINCT src_ip) OVER (PARTITION BY dest_ip) AS internal_hosts_contacting,
    SUM(bytes_sent) AS total_bytes_sent,
    SUM(bytes_received) AS total_bytes_received,
    HOP_END(event_time, INTERVAL '1' MINUTE, INTERVAL '10' MINUTE) AS window_end,
    CASE
        WHEN COUNT(*) >= 20 THEN 'CRITICAL'
        WHEN COUNT(*) >= 10 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    -- Only outbound connections
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
    AND NOT (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
    -- Exclude known legitimate services (production: use allowlist)
    AND dest_port NOT IN (80, 443, 53, 123) -- HTTP, HTTPS, DNS, NTP
GROUP BY
    src_ip,
    dest_ip,
    dest_port,
    HOP(event_time, INTERVAL '1' MINUTE, INTERVAL '10' MINUTE)
HAVING
    COUNT(*) >= 5
    AND
    -- Destination is rare (contacted by <5 internal hosts)
    COUNT(DISTINCT src_ip) OVER (PARTITION BY dest_ip) < 5;

-- Production Notes:
-- 1. Maintain allowlist of known cloud services (AWS, Azure, GCP ranges)
-- 2. Use threat intel feeds to flag known malicious IPs
-- 3. Consider ASN reputation scoring
-- 4. Track newly registered domains (NRD) for additional context
-- 5. Combine with DGA detection for higher confidence
