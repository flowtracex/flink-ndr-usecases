-- Signal: Destructive Recovery Action Detection (S3)
-- Detects backup deletion, snapshot deletion, or backup service disruption.
--
-- Purpose:
--   Recovery impairment is a strong ransomware precursor. Attackers try
--   to remove restore paths before encryption starts.
--
-- Logic:
--   Count destructive backup/snapshot actions per source IP.
--   Window: 5 minutes
--   Threshold: 2+ destructive actions

INSERT INTO signals
SELECT
    'DESTRUCTIVE_RECOVERY_ACTION' AS signal_type,
    src_ip,
    COUNT(*) AS destructive_action_count,
    LISTAGG(DISTINCT action, ',') AS actions_list,
    TUMBLE_END(event_time, INTERVAL '5' MINUTE) AS window_end,
    'CRITICAL' AS severity
FROM network_events
WHERE
    action IN (
        'delete_snapshot',
        'delete_backup',
        'disable_backup_job',
        'stop_backup_service',
        'purge_restore_point'
    )
    AND (dest_role LIKE '%backup%' OR dest_role LIKE '%snapshot%')
GROUP BY
    src_ip,
    TUMBLE(event_time, INTERVAL '5' MINUTE)
HAVING
    COUNT(*) >= 2;

-- Production Notes:
-- 1. Treat this as high-risk even if the action fails.
-- 2. Correlate with EDR process telemetry when available.
-- 3. Alert immediately for non-backup-admin identities.
