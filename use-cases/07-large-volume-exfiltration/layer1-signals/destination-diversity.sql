-- Signal: Destination Diversity Anomaly Detection (S3)
-- Detects connections to multiple unusual external IPs
--
-- Purpose:
--   Attackers often use multiple drop sites for redundancy
--   Legitimate users typically connect to consistent external services
--   High destination diversity = suspicious behavior
--
-- Logic:
--   Count unique external destination IPs per source
--   Filter for uncommon/suspicious destinations
--   Window: 10 minutes (sliding)
--   Threshold: 5+ unique external IPs
--
-- Window Type: HOP (sliding window)
--   Updates every 2 minutes, looks back 10 minutes
--
-- ML: ⚠️ Partial (could use clustering for destination patterns)

INSERT INTO signals
SELECT
    'DESTINATION_DIVERSITY' AS signal_type,
    src_ip,
    
    COUNT(DISTINCT dest_ip) AS unique_destinations,
    COUNT(DISTINCT 
        CASE 
            WHEN dest_port = 443 THEN dest_ip 
        END
    ) AS https_destinations,
    
    COUNT(DISTINCT 
        CASE 
            WHEN dest_port = 80 THEN dest_ip 
        END
    ) AS http_destinations,
    
    -- Geographic diversity (if GeoIP data available)
    -- COUNT(DISTINCT country_code) AS unique_countries,
    
    SUM(bytes_transferred) AS total_bytes_sent,
    COUNT(*) AS connection_count,
    
    -- Destination pattern score
    CASE
        WHEN COUNT(DISTINCT dest_ip) > 20 THEN 'VERY_HIGH'
        WHEN COUNT(DISTINCT dest_ip) > 10 THEN 'HIGH'
        WHEN COUNT(DISTINCT dest_ip) > 5 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS diversity_level,
    
    HOP_END(event_time, INTERVAL '2' MINUTE, INTERVAL '10' MINUTE) AS window_end,
    
    CASE
        WHEN COUNT(DISTINCT dest_ip) > 15 THEN 'HIGH'
        WHEN COUNT(DISTINCT dest_ip) > 10 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS severity

FROM network_events

WHERE
    -- Internal source IPs
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
    
    -- External destination IPs only
    AND NOT (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
    
    -- Exclude known CDNs and cloud providers (simplified)
    -- Production: Use comprehensive whitelist
    AND NOT (
        dest_ip LIKE '13.%'     -- AWS
        OR dest_ip LIKE '52.%'  -- AWS
        OR dest_ip LIKE '3.%'   -- AWS
        OR dest_ip LIKE '40.%'  -- Azure
        OR dest_ip LIKE '104.%' -- Azure/Google
        OR dest_ip LIKE '172.217.%' -- Google
        OR dest_ip LIKE '142.250.%' -- Google
    )
    
    -- Outbound traffic only
    AND bytes_transferred > 100000  -- >100KB per connection

GROUP BY
    src_ip,
    HOP(event_time, INTERVAL '2' MINUTE, INTERVAL '10' MINUTE)

HAVING
    -- Trigger when connecting to 5+ unique external IPs
    COUNT(DISTINCT dest_ip) >= 5
    
    -- AND total bytes sent is significant
    AND SUM(bytes_transferred) > 50000000;  -- >50MB total

-- Production Notes:
-- 1. **Destination Intelligence**:
--    - Integrate threat intelligence feeds
--    - Track newly registered domains (NRDs)
--    - Flag destinations with low reputation scores
--    - Use passive DNS data for domain-to-IP mapping
--
-- 2. **Whitelist Management**:
--    - Comprehensive CDN/cloud provider list
--    - SaaS applications (O365, Salesforce, etc.)
--    - Software update servers
--    - Corporate VPN exit points
--    - Per-user whitelist for legitimate tools
--
-- 3. **Context Enrichment**:
--    - Add GeoIP data (country, ASN, org)
--    - Check if destination is on known bad IP lists
--    - Analyze domain reputation if DNS logs available
--    - Track first-seen timestamps for destinations
--
-- 4. **Pattern Analysis** (ML enhancement):
--    - Cluster destinations by ASN/geography
--    - Detect coordinated multi-destination uploads
--    - Identify "spray and pray" exfiltration patterns
--    - Learn per-user destination patterns
--
-- 5. **Correlation Hints**:
--    - High diversity + high volume (S2) = stronger signal
--    - Diversity after staging (S1) = very suspicious
--    - Off-hours diversity = escalate severity
--
-- 6. **Performance Optimization**:
--    - Pre-filter CDN traffic upstream (Kafka filtering)
--    - Use bloom filters for whitelist checks
--    - Partition by src_ip for parallel processing
--    - Cache GeoIP/threat intel lookups (Redis)