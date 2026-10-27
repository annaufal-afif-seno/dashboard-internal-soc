target_file = r"c:\Users\Pongo\Downloads\wazuh alert grouping -\frontend\src\components\ThreatCampaignEntityTable.jsx"

with open(target_file, "r", encoding="utf-8") as f:
    content = f.read()

# Replace badge display
old_badge = """                            <span className="text-[11px] text-slate-400 font-medium">
                              {pat.stages_count} tahapan • {pat.cluster_alerts?.length || 60} alert
                            </span>"""

new_badge = """                            {(() => {
                              const totalEv = pat.steps?.reduce((acc, s) => acc + (s.event_count || 0), 0) || pat.cluster_alerts?.length || 60;
                              return (
                                <span className="text-[11px] text-slate-400 font-medium">
                                  {pat.stages_count} tahapan • {totalEv.toLocaleString()} alert terdeteksi
                                </span>
                              );
                            })()}"""

# Replace footer text
old_footer = """                    Tabel di bawah otomatis memfilter <strong>{activeClusterPattern ? '60 alert' : 'seluruh aktivitas'}</strong> dari rantai pola serangan ini."""
new_footer = """                    Tabel di bawah otomatis memfilter <strong>{activeClusterPattern ? `${activeClusterPattern.cluster_alerts?.length || 60} alert representatif` : 'seluruh aktivitas'}</strong> dari total {activeClusterPattern?.steps?.reduce((acc, s) => acc + (s.event_count || 0), 0)?.toLocaleString() || '60'} alert pada rangkaian pola serangan ini."""

if old_badge in content:
    content = content.replace(old_badge, new_badge)
    print("Replaced badge!")
else:
    print("Old badge not found directly")

if old_footer in content:
    content = content.replace(old_footer, new_footer)
    print("Replaced footer!")
else:
    print("Old footer not found directly")

with open(target_file, "w", encoding="utf-8") as f:
    f.write(content)
print("Finished updating ThreatCampaignEntityTable.jsx")
