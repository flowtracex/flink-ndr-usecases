-- Signal: Admin / Management Protocol Use (S2)
-- Detects administrative access to backup infrastructure.
--
-- Purpose:
--   Attackers commonly use RDP, SMB, WinRM, SSH, and RPC to control
--   backup servers or issue remote commands.
--
-- Logic:
--   Count distinct admin services used by a source IP against backup assets.
--   Window: 5 minutes
--   Threshold: 2+ admin protocols

INSERT INTO signals
SELECT
    'ADMIN_MANAGEMENT_PROTOCOL' AS signal_type,
    src_ip,
    COUNT(DISTINCT dest_port) AS admin_service_count,
    LISTAGG(DISTINCT service, ',') AS services_list,
    HOP_END(event_time, INTERVAL '1' MINUTE, INTERVAL '5' MINUTE) AS window_end,
    'HIGH' AS severity
FROM network_events
WHERE
    dest_port IN (22, 135, 445, 3389, 5985, 5986)
    AND (dest_role LIKE '%backup%' OR dest_role LIKE '%snapshot%')
GROUP BY
    src_ip,
    HOP(event_time, INTERVAL '1' MINUTE, INTERVAL '5' MINUTE)
HAVING
    COUNT(DISTINCT dest_port) >= 2;

-- Production Notes:
-- 1. Suppress known jump hosts and backup management servers.
-- 2. Increase severity for non-admin workstations.
-- 3. Join with authentication logs for account context.
