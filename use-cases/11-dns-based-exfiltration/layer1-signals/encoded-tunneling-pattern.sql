-- Signal: Encoded / Tunneling Pattern Detection (S3)
-- Detects repeated encoded chunks sent to the same domain.
--
-- Purpose:
--   Covert DNS channels often send many unique encoded subdomains to one
--   attacker-controlled registered domain.
--
-- Logic:
--   Group by source IP and registered domain.
--   Window: 10 minutes
--   Threshold: 12+ unique encoded chunks

INSERT INTO signals
SELECT
    'ENCODED_TUNNELING_PATTERN' AS signal_type,
    src_ip,
    registered_domain AS tunnel_domain,
    COUNT(DISTINCT left_label) AS encoded_chunk_count,
    LISTAGG(DISTINCT query_type, ',') AS query_types,
    HOP_END(event_time, INTERVAL '2' MINUTE, INTERVAL '10' MINUTE) AS window_end,
    CASE
        WHEN COUNT(DISTINCT left_label) >= 20 THEN 'CRITICAL'
        ELSE 'HIGH'
    END AS severity
FROM dns_features
WHERE
    protocol = 'DNS'
    AND query_type IN ('A', 'TXT', 'NULL')
    AND LENGTH(left_label) >= 24
    AND left_label REGEXP '^[a-z0-9]{24,}$'
    AND (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
GROUP BY
    src_ip,
    registered_domain,
    HOP(event_time, INTERVAL '2' MINUTE, INTERVAL '10' MINUTE)
HAVING
    COUNT(DISTINCT left_label) >= 12;

-- Production Notes:
-- 1. Track registered_domain through DNS parsing/enrichment.
-- 2. Alert faster for TXT/NULL records because they are common in tunnels.
-- 3. Correlate with proxy/firewall logs to identify the process or user.
