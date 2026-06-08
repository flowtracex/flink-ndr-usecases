-- Signal: Backup Server Contact Detection (S1)
-- Detects hosts contacting backup or snapshot infrastructure.
--
-- Purpose:
--   Ransomware operators often look for backup servers before encryption
--   so they can impair recovery.
--
-- Logic:
--   Count unique backup/snapshot targets contacted by source IP.
--   Window: 5 minutes
--   Threshold: 2+ backup targets

INSERT INTO signals
SELECT
    'BACKUP_SERVER_CONTACT' AS signal_type,
    src_ip,
    COUNT(DISTINCT dest_ip) AS backup_target_count,
    TUMBLE_END(event_time, INTERVAL '5' MINUTE) AS window_end,
    'HIGH' AS severity
FROM network_events
WHERE
    (dest_role LIKE '%backup%' OR dest_role LIKE '%snapshot%')
    OR service IN ('veeam', 'commvault', 'netbackup', 'rubrik')
    OR dest_port IN (9392, 10001)
GROUP BY
    src_ip,
    TUMBLE(event_time, INTERVAL '5' MINUTE)
HAVING
    COUNT(DISTINCT dest_ip) >= 2;

-- Production Notes:
-- 1. Maintain an asset inventory of backup servers and repositories.
-- 2. Tune by role because backup admins and backup proxies are expected.
-- 3. Correlate with identity context for privileged account validation.
