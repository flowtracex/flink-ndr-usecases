-- Signal: Data Staging Behavior Detection (S1)
-- Detects internal data aggregation before exfiltration
--
-- Purpose:
--   Identifies when a host is accumulating/staging large amounts of data locally
--   Common precursor to data exfiltration attacks
--
-- Logic:
--   Track internal file transfers and data writes
--   Aggregate total bytes per source IP
--   Window: 5 minutes (tumbling)
--   Threshold: >500MB staged data
--
-- Window Type: TUMBLE (discrete time buckets)
--   Non-overlapping 5-minute windows
--
-- ML: ⚠️ Partial (volume-based, could use IF in production)

INSERT INTO signals
SELECT
    'DATA_STAGING' AS signal_type,
    src_ip,
    SUM(bytes_transferred) AS total_bytes_staged,
    COUNT(DISTINCT dest_ip) AS unique_internal_destinations,
    COUNT(*) AS transfer_count,
    
    -- Simplified baseline (production: learn from history)
    100000000.0 AS baseline_bytes,  -- 100MB baseline
    50000000.0 AS baseline_stddev,   -- 50MB stddev
    
    (SUM(bytes_transferred) - 100000000.0) / 50000000.0 AS deviation_score,
    
    TUMBLE_END(event_time, INTERVAL '5' MINUTE) AS window_end,
    
    CASE
        WHEN SUM(bytes_transferred) > 1000000000 THEN 'HIGH'        -- >1GB
        WHEN SUM(bytes_transferred) > 500000000 THEN 'MEDIUM'       -- >500MB
        ELSE 'LOW'
    END AS severity

FROM network_events

WHERE
    -- Only internal-to-internal traffic
    (src_ip LIKE '10.%' OR src_ip LIKE '172.16.%' OR src_ip LIKE '192.168.%')
    AND (dest_ip LIKE '10.%' OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '192.168.%')
    
    -- File transfer protocols
    AND (
        dest_port = 445   -- SMB file shares
        OR dest_port = 22 -- SCP/SFTP
        OR dest_port = 21 -- FTP
        OR dest_port = 2049 -- NFS
    )
    
    -- Minimum transfer size (filter noise)
    AND bytes_transferred > 1000000  -- >1MB per transfer

GROUP BY
    src_ip,
    TUMBLE(event_time, INTERVAL '5' MINUTE)

HAVING
    -- Trigger when >500MB staged in 5 minutes
    SUM(bytes_transferred) > 500000000;

-- Production Notes:
-- 1. Baseline should be learned per IP from historical data
-- 2. Account for legitimate bulk file operations (backups, imaging)
-- 3. Whitelist known file servers and backup systems
-- 4. Consider file type analysis (many small vs few large files)
-- 5. In production, integrate with file.log for better context
-- 6. Could use Isolation Forest to detect anomalous staging patterns