-- Signal: High-Entropy DNS Query Detection (S2)
-- Detects random-looking DNS labels that resemble encoded data.
--
-- Purpose:
--   DNS exfiltration frequently places base32/base64-like chunks in
--   subdomains, creating long labels with high character entropy.
--
-- Logic:
--   Inspect the left-most DNS label.
--   Window: 5 minutes
--   Threshold: 10+ long labels with entropy >= 3.5
--
-- ML: Rule-based in this demo; production can add Isolation Forest features.

INSERT INTO signals
SELECT
    'HIGH_ENTROPY_DNS' AS signal_type,
    src_ip,
    COUNT(*) AS suspicious_query_count,
    AVG(label_entropy) AS avg_entropy,
    HOP_END(event_time, INTERVAL '1' MINUTE, INTERVAL '5' MINUTE) AS window_end,
    CASE
        WHEN COUNT(*) >= 20 THEN 'CRITICAL'
        ELSE 'HIGH'
    END AS severity
FROM dns_features
WHERE
    protocol = 'DNS'
    AND LENGTH(left_label) >= 24
    AND label_entropy >= 3.5
    AND (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
GROUP BY
    src_ip,
    HOP(event_time, INTERVAL '1' MINUTE, INTERVAL '5' MINUTE)
HAVING
    COUNT(*) >= 10;

-- Production Notes:
-- 1. Compute entropy in Flink UDF or an enrichment job.
-- 2. Maintain allowlists for legitimate telemetry domains.
-- 3. Combine with domain age, NXDOMAIN ratio, and TXT response behavior.
