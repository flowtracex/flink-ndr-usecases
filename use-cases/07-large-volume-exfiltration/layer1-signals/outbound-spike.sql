-- Signal: Outbound Volume Spike Detection (S2) 🔴 CRITICAL
-- ML-based anomaly detection using volume baselines
--
-- Purpose:
--   Detects sudden increase in outbound data transfer
--   Primary indicator of data exfiltration in progress
--
-- Logic:
--   Track outbound bytes per source IP
--   Compare against baseline (Isolation Forest in Python layer)
--   Window: 5 minutes (sliding, updates every 1 min)
--   Threshold: >3 std deviations OR >1GB absolute
--
-- Window Type: HOP (sliding window)
--   Updates every 1 minute, looks back 5 minutes
--
-- ML: ✅ YES - Isolation Forest detects volume anomalies
--     (Baseline learning happens in correlation layer)

INSERT INTO signals
SELECT
    'OUTBOUND_SPIKE' AS signal_type,
    src_ip,
    
    -- Upload metrics
    SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) AS bytes_uploaded,
    COUNT(CASE WHEN is_outbound = true THEN 1 END) AS upload_count,
    
    -- Download metrics (for ratio calculation)
    SUM(CASE WHEN is_outbound = false THEN bytes_transferred ELSE 0 END) AS bytes_downloaded,
    
    -- Upload/Download ratio
    CASE
        WHEN SUM(CASE WHEN is_outbound = false THEN bytes_transferred ELSE 0 END) > 0
        THEN SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) * 1.0 
             / SUM(CASE WHEN is_outbound = false THEN bytes_transferred ELSE 0 END)
        ELSE 999.0  -- Upload-only traffic
    END AS upload_ratio,
    
    -- Unique destinations
    COUNT(DISTINCT dest_ip) AS unique_destinations,
    
    -- Baseline (simplified - production uses historical ML model)
    50000000.0 AS baseline_bytes,    -- 50MB baseline
    25000000.0 AS baseline_stddev,   -- 25MB stddev
    
    -- Deviation score (for ML correlation)
    (SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) - 50000000.0) 
        / 25000000.0 AS deviation_score,
    
    HOP_END(event_time, INTERVAL '1' MINUTE, INTERVAL '5' MINUTE) AS window_end,
    
    -- Dynamic severity based on volume
    CASE
        WHEN SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) > 2000000000 THEN 'CRITICAL'  -- >2GB
        WHEN SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) > 1000000000 THEN 'HIGH'      -- >1GB
        WHEN SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) > 500000000 THEN 'MEDIUM'     -- >500MB
        ELSE 'LOW'
    END AS severity

FROM network_events

WHERE
    -- Internal source IPs
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
    
    -- External destination IPs (outbound traffic)
    AND NOT (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
    
    -- Common exfiltration protocols
    AND (
        dest_port = 80      -- HTTP
        OR dest_port = 443  -- HTTPS
        OR dest_port = 22   -- SSH/SCP
        OR dest_port = 21   -- FTP
        OR dest_port = 53   -- DNS (tunneling)
    )

GROUP BY
    src_ip,
    HOP(event_time, INTERVAL '1' MINUTE, INTERVAL '5' MINUTE)

HAVING
    -- Trigger conditions:
    -- Option 1: Absolute volume threshold
    SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) > 1000000000  -- >1GB
    
    -- Option 2: Statistical anomaly (>3 std deviations)
    OR (SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) - 50000000.0) 
        / 25000000.0 > 3.0
    
    -- Option 3: High upload ratio (upload >> download)
    OR (
        CASE
            WHEN SUM(CASE WHEN is_outbound = false THEN bytes_transferred ELSE 0 END) > 0
            THEN SUM(CASE WHEN is_outbound = true THEN bytes_transferred ELSE 0 END) * 1.0 
                 / SUM(CASE WHEN is_outbound = false THEN bytes_transferred ELSE 0 END)
            ELSE 999.0
        END > 10.0  -- Upload is 10x download
    );

-- Production Notes:
-- 1. **Isolation Forest Integration**:
--    - Features: bytes_uploaded, upload_ratio, unique_destinations, time_of_day
--    - Train on 7 days of historical data per IP
--    - Retrain daily to adapt to legitimate changes
--
-- 2. **Baseline Learning**:
--    - Per-IP baselines (not global)
--    - Account for user roles (dev vs HR has different patterns)
--    - Time-of-day normalization (business hours vs off-hours)
--
-- 3. **Whitelist Considerations**:
--    - Backup systems (Veeam, Commvault, etc.)
--    - Cloud sync clients (OneDrive, Dropbox, Google Drive)
--    - Software updates and patch downloads
--    - CDN/mirror traffic
--
-- 4. **Alert Suppression**:
--    - Deduplicate repeated spikes from same IP (1-hour window)
--    - Correlate with S1 (staging) for higher confidence
--
-- 5. **Enrichment**:
--    - Add user/asset context
--    - Check destination IP reputation (threat intel)
--    - Analyze file types if available (files.log)
--
-- 6. **Performance**:
--    - Use incremental aggregation for large datasets
--    - Pre-filter internal traffic in Kafka consumers
--    - Partition by src_ip for parallel processing