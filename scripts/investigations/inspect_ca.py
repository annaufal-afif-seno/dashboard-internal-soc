with open('frontend/src/components/clusteringDatasets.js', 'r', encoding='utf-8') as f:
    text = f.read()

import re
matches = list(re.finditer(r'"cluster-activity":\s*\[(.*?)\]', text, re.DOTALL))
print('Total occurrences of cluster-activity in clusteringDatasets.js:', len(matches))
for i, m in enumerate(matches[:6]):
    print(f"--- MATCH {i+1} ---")
    lines = [x.strip() for x in m.group(1).split('\n') if x.strip()]
    for l in lines[:4]:
        print(" ", l)
