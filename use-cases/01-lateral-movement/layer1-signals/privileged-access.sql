-- Signal: Privileged Service Access Detection
-- Detects access to administrative services

-- Purpose:
-- Identifies use of privileged protocols (SMB, RDP, SSH)
-- Common in lateral movement and privilege escalation

-- Logic:
-- Track connections to privileged ports
-- Window: 60 seconds (sliding)
-- Threshold: 2+ different privileged services

-- Privileged Services:
-- Port 22: SSH (Linux/Unix remote access)
-- Port 445: SMB (Windows file sharing, admin shares)
-- Port 3389: RDP (Remote Desktop Protocol)
-- Port 5985/5986: WinRM (Windows Remote Management)

INSERT INTO signals
SELECT
    'PRIVILEGED_ACCESS' AS signal_type,
    src_ip,
    COUNT(DISTINCT dest_port) AS unique_services,
    LISTAGG(DISTINCT 
        CASE dest_port
            WHEN 22 THEN 'SSH'
            WHEN 445 THEN 'SMB'
            WHEN 3389 THEN 'RDP'
            WHEN 5985 THEN 'WinRM'
            WHEN 5986 THEN 'WinRM-HTTPS'
        END,
        ','
    ) AS services_list,
    COUNT(DISTINCT dest_ip) AS unique_destinations,
    HOP_END(event_time, INTERVAL '10' SECOND, INTERVAL '60' SECOND) AS window_end,
    CASE
        WHEN COUNT(DISTINCT dest_port) >= 3 THEN 'CRITICAL'
        WHEN COUNT(DISTINCT dest_port) = 2 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS severity
FROM network_events
WHERE
    -- Filter privileged service ports
    dest_port IN (22, 445, 3389, 5985, 5986)
    AND (
        -- Only internal source IPs
        src_ip LIKE '10.%'
        OR src_ip LIKE '172.16.%'
        OR src_ip LIKE '192.168.%'
    )
GROUP BY
    src_ip,
    HOP(event_time, INTERVAL '10' SECOND, INTERVAL '60' SECOND)
HAVING
    -- Trigger when 2+ different services accessed
    COUNT(DISTINCT dest_port) >= 2
    OR
    -- OR same service to 3+ destinations
    COUNT(DISTINCT dest_ip) >= 3;

-- Production Notes:
-- 1. Whitelist known admin workstations/subnets
-- 2. Filter IT automation tools (Ansible, Puppet, etc.)
-- 3. Consider time-of-day (after-hours = higher severity)
-- 4. Correlate with authentication logs for added context
-- 5. Track service account usage separately
