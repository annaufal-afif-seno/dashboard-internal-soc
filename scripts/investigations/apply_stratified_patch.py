import os

def patch_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Find reconstruct_attack_paths
    fn_start = code.find('def reconstruct_attack_paths(')
    if fn_start == -1:
        print(f"Could not find reconstruct_attack_paths in {file_path}")
        return

    # 1. Update classify_stage inside reconstruct_attack_paths
    old_classify = """        def classify_stage(rule_id, desc, cat):
            desc_l = (desc or '').lower()
            cat_l = (cat or '').lower()
            if any(k in desc_l for k in ['recon', 'scan', 'probing', 'nikto', 'nmap', 'directory traversal']) or 'discovery' in cat_l:
                return 1, 'Reconnaissance', 'T1595', 'purple'
            if any(k in desc_l for k in ['400', '403', '404', '500', 'web', 'nginx', 'apache', 'sql', 'injection', 'xss']) or 'web' in cat_l:
                return 2, 'Initial Access & Web Exploitation', 'T1190', 'amber'
            if any(k in desc_l for k in ['sudo', 'root', 'privilege', 'pam', 'session opened', 'authentication success', 'uid=0']) or 'privilege' in cat_l:
                return 3, 'Execution & Privilege Escalation', 'T1548.003', 'indigo'
            if any(k in desc_l for k in ['systemd', 'service', 'cron', 'persist', 'checksum', 'integrity', 'syscheck', 'rotated', 'failure']) or 'persistence' in cat_l:
                return 4, 'Persistence & Defense Evasion', 'T1543.002', 'rose'
            return 5, 'Action on Objectives & System Anomaly', 'T1082', 'cyan'"""

    new_classify = """        def classify_stage(rule_id, desc, cat, full_log=''):
            desc_l = (desc or '').lower()
            cat_l = (cat or '').lower()
            log_l = (full_log or '').lower()
            if 'mdl_user' in log_l or rule_id in (31103, 31164) or 'exfiltration' in cat_l:
                return 5, 'Data Exfiltration (Database Query)', 'T1041', 'red'
            if any(k in desc_l for k in ['cron', 'persist', 'checksum', 'integrity', 'syscheck', 'dpkg', 'rotated']) or any(k in log_l for k in ['packagekitd', 'gs-netcat', 'kcached']) or rule_id in (2832, 550, 40704, 2902, 2904) or 'persistence' in cat_l:
                return 4, 'Persistence & Backdoor Deployment', 'T1543.002', 'rose'
            if any(k in desc_l for k in ['sudo', 'rootcheck', 'missed the password', 'change uid', 'authentication success', 'root', 'privilege']) or any(k in log_l for k in ['test_aead', '-perm -4000', 'whoami', 'x=id']) or rule_id in (510, 5402, 5407, 5301, 5501, 5502, 5503, 5715) or 'privilege' in cat_l:
                return 3, 'Execution & Privilege Escalation', 'T1548.003', 'indigo'
            if any(k in desc_l for k in ['attack', 'shell.php', 'cgi-bin', 'web', 'nginx', 'apache', 'injection']) or any(k in log_l for k in ['uid.html', 'cf.py', 'question.php']) or rule_id in (31106, 31514, 31104, 31516, 31430, 31110) or 'web' in cat_l:
                return 2, 'Initial Access & Web Exploitation', 'T1190', 'amber'
            return 1, 'Reconnaissance & Vulnerability Scanning', 'T1595', 'purple'"""

    # 2. Update loop calling classify_stage
    old_call = """        for r in rows:
            s_num, s_name, mitre, col = classify_stage(r['rule_id'], r['rule_description'], r['category'])
            r['stage_num'] = s_num
            r['stage_name'] = s_name
            r['mitre'] = mitre
            r['color'] = col"""

    new_call = """        for r in rows:
            s_num, s_name, mitre, col = classify_stage(r['rule_id'], r['rule_description'], r['category'], r.get('full_log', ''))
            r['stage_num'] = s_num
            r['stage_name'] = s_name
            r['mitre'] = mitre
            r['color'] = col"""

    # 3. Update query in reconstruct_attack_paths to use stratified sampling
    old_query_block = """            query = f\"\"\"
                SELECT 
                    r.event_id AS id,
                    r.timestamp,
                    to_char(r.timestamp AT TIME ZONE 'Asia/Jakarta', 'Mon DD, HH24:MI:SS') || ' WIB' AS timestamp_formatted,
                    COALESCE(n.rule_id, 0) AS rule_id,
                    COALESCE(n.rule_level, 3) AS rule_level,
                    COALESCE(n.rule_description, 'Security event') AS rule_description,
                    COALESCE(r.agent_name, r.destination_ip, 'unknown') AS target,
                    COALESCE(r.source_ip, 'proc:' || COALESCE(r.decoder_name, 'internal')) AS actor,
                    COALESCE(r.tenant_id, 'DEFAULT') AS tenant_id,
                    COALESCE(
                        (SELECT array_to_string(n.mitre_attack_ids, ', ') WHERE array_length(n.mitre_attack_ids, 1) > 0),
                        CASE 
                            WHEN n.rule_id IN (31533, 533) THEN 'T1498'
                            WHEN n.rule_id IN (31101, 31301, 31410, 31151, 31516) THEN 'T1190'
                            WHEN n.rule_id IN (5501, 5715) THEN 'T1078'
                            WHEN n.rule_id IN (5502, 5503) THEN 'T1110'
                            WHEN n.rule_id = 5402 THEN 'T1548.003'
                            WHEN n.rule_id = 40704 THEN 'T1543.002'
                            WHEN n.rule_id = 591 THEN 'T1136'
                            ELSE 'T1082'
                        END
                    ) AS mitre,
                    COALESCE(
                        (SELECT a2.category FROM suppression.aggregated_alerts a2 WHERE a2.rule_id = n.rule_id LIMIT 1),
                        CASE 
                            WHEN n.rule_id IN (31533, 533) THEN 'DISCOVERY'
                            WHEN n.rule_id IN (31101, 31301, 31410, 31151, 31516) THEN 'WEB_OPERATIONAL'
                            WHEN n.rule_id IN (5501, 5715) THEN 'AUTH_SUCCESS'
                            WHEN n.rule_id IN (5502, 5503) THEN 'AUTH_FAILURE'
                            WHEN n.rule_id = 5402 THEN 'PRIVILEGE_ESCALATION'
                            WHEN n.rule_id = 40704 THEN 'PERSISTENCE'
                            WHEN n.rule_id = 591 THEN 'DEFENSE_EVASION'
                            ELSE 'SYSTEM_HEALTH'
                        END
                    ) AS category,
                    COALESCE(r.raw_payload::text, '') AS full_log
                FROM telemetry.raw_events r
                LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
                WHERE {where_sql}
                ORDER BY r.timestamp DESC
                LIMIT %s;
            \"\"\"
            params.append(limit_events)"""

    new_query_block = """            query = f\"\"\"
                WITH tagged_events AS (
                    SELECT 
                        r.event_id AS id,
                        r.timestamp,
                        to_char(r.timestamp AT TIME ZONE 'Asia/Jakarta', 'Mon DD, HH24:MI:SS') || ' WIB' AS timestamp_formatted,
                        COALESCE(n.rule_id, 0) AS rule_id,
                        COALESCE(n.rule_level, 3) AS rule_level,
                        COALESCE(n.rule_description, 'Security event') AS rule_description,
                        COALESCE(r.agent_name, r.destination_ip, 'unknown') AS target,
                        COALESCE(r.source_ip, 'proc:' || COALESCE(r.decoder_name, 'internal')) AS actor,
                        COALESCE(r.tenant_id, 'DEFAULT') AS tenant_id,
                        COALESCE(
                            (SELECT array_to_string(n.mitre_attack_ids, ', ') WHERE array_length(n.mitre_attack_ids, 1) > 0),
                            CASE 
                                WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 'T1041'
                                WHEN n.rule_id IN (2832, 550, 40704, 2902, 2904) OR r.raw_payload::text ILIKE '%%packagekitd%%' OR r.raw_payload::text ILIKE '%%gs-netcat%%' THEN 'T1543.002'
                                WHEN n.rule_id IN (510, 5402, 5403, 5407, 5301, 5501, 5502, 5503, 5715, 5760) OR r.raw_payload::text ILIKE '%%test_aead%%' OR r.raw_payload::text ILIKE '%%-perm -4000%%' THEN 'T1548.003'
                                WHEN n.rule_id IN (31106, 31514, 31104, 31516, 31430, 31110, 31101, 31301) OR r.raw_payload::text ILIKE '%%uid.html%%' OR r.raw_payload::text ILIKE '%%cf.py%%' OR r.raw_payload::text ILIKE '%%question.php%%' THEN 'T1190'
                                WHEN n.rule_id IN (31533, 533, 31151) THEN 'T1595'
                                ELSE 'T1082'
                            END
                        ) AS mitre,
                        COALESCE(
                            (SELECT a2.category FROM suppression.aggregated_alerts a2 WHERE a2.rule_id = n.rule_id LIMIT 1),
                            CASE 
                                WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 'EXFILTRATION'
                                WHEN n.rule_id IN (2832, 550, 40704) THEN 'PERSISTENCE'
                                WHEN n.rule_id IN (5402, 5407, 5301, 510) THEN 'PRIVILEGE_ESCALATION'
                                WHEN n.rule_id IN (31106, 31514, 31104, 31516) THEN 'WEB_ATTACK'
                                WHEN n.rule_id IN (31533, 31151) THEN 'DISCOVERY'
                                ELSE 'WEB_OPERATIONAL'
                            END
                        ) AS category,
                        COALESCE(r.raw_payload::text, '') AS full_log,
                        ROW_NUMBER() OVER (
                            PARTITION BY (
                                CASE 
                                    WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 5
                                    WHEN n.rule_id IN (2832, 550, 40704, 2902, 2904) OR r.raw_payload::text ILIKE '%%packagekitd%%' OR r.raw_payload::text ILIKE '%%gs-netcat%%' THEN 4
                                    WHEN n.rule_id IN (510, 5402, 5403, 5407, 5301, 5501, 5502, 5503, 5715, 5760) OR r.raw_payload::text ILIKE '%%test_aead%%' OR r.raw_payload::text ILIKE '%%-perm -4000%%' THEN 3
                                    WHEN n.rule_id IN (31106, 31514, 31104, 31516, 31430, 31110, 31101, 31301) OR r.raw_payload::text ILIKE '%%uid.html%%' OR r.raw_payload::text ILIKE '%%cf.py%%' OR r.raw_payload::text ILIKE '%%question.php%%' THEN 2
                                    ELSE 1
                                END
                            ), n.rule_id
                            ORDER BY r.timestamp ASC
                        ) as rank_in_stage
                    FROM telemetry.raw_events r
                    LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
                    WHERE {where_sql}
                )
                SELECT * FROM tagged_events
                WHERE rank_in_stage <= 60
                ORDER BY timestamp ASC
                LIMIT %s;
            \"\"\"
            params.append(limit_events)"""

    if old_classify in code:
        code = code.replace(old_classify, new_classify)
        print(f"Patched classify_stage in {file_path}")
    else:
        print(f"classify_stage target not found in {file_path}")

    if old_call in code:
        code = code.replace(old_call, new_call)
        print(f"Patched classify_stage call in {file_path}")
    else:
        print(f"classify_stage call target not found in {file_path}")

    if old_query_block in code:
        code = code.replace(old_query_block, new_query_block)
        print(f"Patched query block in {file_path}")
    else:
        print(f"query block target not found in {file_path}")

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(code)

patch_file(r"c:\Users\Pongo\Downloads\wazuh alert grouping -\pipeline\api.py")
patch_file(r"c:\Users\Pongo\Downloads\wazuh alert grouping -\backend\pipeline\api.py")
print("Done patching.")
