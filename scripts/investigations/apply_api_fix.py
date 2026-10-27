path1 = r"c:\Users\Pongo\Downloads\wazuh alert grouping -\pipeline\api.py"
path2 = r"c:\Users\Pongo\Downloads\wazuh alert grouping -\backend\pipeline\api.py"

old_target = """                else:  # victim
                    where_clauses.append(\"\"\"
                        (r.agent_name ILIKE %s OR similarity(COALESCE(r.agent_name, ''), %s) > 0.25 
                         OR r.destination_ip ILIKE %s OR r.event_id ILIKE %s OR n.rule_id::text = %s)
                    \"\"\")
                    params.extend([q_like, q_clean, q_like, q_like, q_clean])"""

new_target = """                else:  # victim
                    where_clauses.append(\"\"\"
                        (r.agent_name ILIKE %s 
                         OR r.destination_ip ILIKE %s OR r.event_id ILIKE %s OR n.rule_id::text = %s)
                    \"\"\")
                    params.extend([q_like, q_like, q_like, q_clean])"""

for p in [path1, path2]:
    try:
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()
        if old_target in content:
            content = content.replace(old_target, new_target)
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Updated {p}")
        else:
            print(f"Target not found in {p}")
    except Exception as e:
        print(f"Error on {p}: {e}")
