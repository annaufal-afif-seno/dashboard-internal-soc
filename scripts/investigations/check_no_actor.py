import psycopg2
from psycopg2 import extras

conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

where_cond = "actor IS NULL OR actor = ''"

cur.execute(f"""
    SELECT tenant_id as name, count(*) as cnt
    FROM suppression.aggregated_alerts
    WHERE {where_cond}
    GROUP BY 1 ORDER BY cnt DESC;
""")
print("Real Tenants for NO_ACTOR:")
for r in cur.fetchall():
    print(" ", r)

cur.execute(f"""
    SELECT 'Rule ' || rule_id as name, count(*) as cnt
    FROM suppression.aggregated_alerts
    WHERE {where_cond}
    GROUP BY 1 ORDER BY cnt DESC LIMIT 10;
""")
print("\nReal Rules for NO_ACTOR:")
for r in cur.fetchall():
    print(" ", r)

cur.execute(f"""
    SELECT agent_id as name, count(*) as cnt
    FROM suppression.aggregated_alerts
    WHERE {where_cond}
    GROUP BY 1 ORDER BY cnt DESC LIMIT 10;
""")
print("\nReal Agents for NO_ACTOR:")
for r in cur.fetchall():
    print(" ", r)
