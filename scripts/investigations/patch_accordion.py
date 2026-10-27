import re

def update_threat_campaigns_view(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()

    # 1. Update lucide-react imports to include ChevronDown, ChevronUp
    if 'ChevronDown' not in code:
        code = code.replace(
            "ChevronLeft, ChevronRight,",
            "ChevronDown, ChevronUp, ChevronLeft, ChevronRight,"
        )

    # 2. In fetchCampaigns, do NOT auto-select list[0].cluster_id
    old_auto_select = """      // Select first cluster if available or keep current if present
      if (list.length > 0) {
        if (!selectedClusterId || !list.some(c => c.cluster_id === selectedClusterId)) {
          setSelectedClusterId(list[0].cluster_id);
        }
      }"""
    new_auto_select = """      // Keep selectedClusterId only if already chosen and still present in list
      if (list.length > 0 && selectedClusterId) {
        if (!list.some(c => c.cluster_id === selectedClusterId)) {
          setSelectedClusterId(null);
        }
      }"""
    code = code.replace(old_auto_select, new_auto_select)

    # Also handle if CRLF
    code = code.replace(old_auto_select.replace('\n', '\r\n'), new_auto_select.replace('\n', '\r\n'))

    # 3. Add toggleCampaign function if not present
    toggle_fn = """  const toggleCampaign = (clusterId) => {
    if (selectedClusterId === clusterId) {
      setSelectedClusterId(null);
      setSelectedAlert(null);
    } else {
      setSelectedClusterId(clusterId);
      setSelectedAlert(null);
      setSelectedCategory('ALL');
      setCurrentPage(1);
    }
  };
"""
    if 'const toggleCampaign' not in code:
        code = code.replace("  const filterBarRef = useRef(null);", "  const filterBarRef = useRef(null);\n" + toggle_fn)

    # 4. Extract the forensic table block from the right column
    # Notice: Right column starts around:
    # {/* RIGHT COLUMN: FORENSIC EVIDENCE TABLE
    # and ends before:
    # </div>\n    </div>\n  );\n}
    
    # Let's inspect where table block starts:
    m_table = re.search(r'\{\s*\/\*\s*RIGHT COLUMN: FORENSIC EVIDENCE TABLE[\s\S]*?\{\s*selectedCampaign\s*\?\s*\(\s*<div className="flex gap-4 items-start">([\s\S]*?)<\/div>\s*\)\s*:\s*\([\s\S]*?<\/div>\s*\}\s*<\/div>\s*<\/div>\s*(?=\s*<\/div>\s*\n\s*\);\s*\n\})', code)
    if not m_table:
        print("ERROR: Could not locate table block via regex in", filepath)
        return False

    inner_table_and_drawer = m_table.group(1).strip()

    # Now let's construct the new full-width container
    new_main_workspace = '''      {/* DETECTED CAMPAIGNS WORKSPACE (Full Width Accordion) */}
      <div className={`p-4 rounded-xl border ${
        isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className={`text-sm font-bold uppercase tracking-wider font-mono ${isDark ? 'text-white' : 'text-slate-900'}`}>
              Detected Campaigns ({filteredCampaigns.length})
            </h2>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Klik salah satu kotak kampanye untuk melihat atau menyembunyikan rantai aktivitas serangan dan bukti forensik di bawahnya.
            </p>
          </div>

          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Cari ID, host, status, atau judul..."
              className={`w-full pl-9 pr-3 py-1.5 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                isDark 
                  ? 'bg-[#111827] border-slate-700 text-slate-100 placeholder-slate-500' 
                  : 'bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400'
              }`}
            />
          </div>
        </div>

        {loading && campaigns.length === 0 ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-2">
            <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
            <span>Memuat daftar kampanye serangan...</span>
          </div>
        ) : filteredCampaigns.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            Tidak ada kampanye yang cocok dengan pencarian.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredCampaigns.map((c) => {
              const isSelected = c.cluster_id === selectedClusterId;
              const isThreat = c.cluster_status === 'CONFIRMED_THREAT';
              const isInvestigation = c.cluster_status === 'UNDER_INVESTIGATION';
              const isBenign = c.cluster_status === 'FALSE_CORRELATION';
              const phase = c.causality_dag?.incident_phase || (isBenign ? 'BENIGN_OPERATIONAL' : 'POST_COMPROMISE');
              const icsScore = c.causality_dag?.incident_confidence_score ?? (isBenign ? 7 : 85);

              return (
                <div
                  key={c.cluster_id}
                  className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                    isSelected
                      ? (isDark 
                          ? 'bg-[#0f172a] border-cyan-500/70 shadow-lg ring-1 ring-cyan-500/30' 
                          : 'bg-slate-50 border-cyan-500 shadow-md ring-1 ring-cyan-400/50')
                      : (isDark 
                          ? 'bg-[#0b101d] border-slate-800 hover:border-slate-700 hover:bg-[#0e1526]' 
                          : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50 shadow-2xs')
                  }`}
                >
                  {/* Clickable Header Box for Campaign */}
                  <div
                    onClick={() => toggleCampaign(c.cluster_id)}
                    className="p-4 cursor-pointer select-none group"
                    title={isSelected ? "Klik kotak ini untuk menutup" : "Klik kotak ini untuk membuka rantai serangan di bawah"}
                  >
                    <div className="flex items-center justify-between gap-3 mb-1.5 flex-wrap">
                      <div className="flex items-center gap-2.5">
                        <span className={`font-mono font-bold text-sm tracking-tight ${
                          isSelected 
                            ? 'text-cyan-400' 
                            : (isDark ? 'text-white group-hover:text-cyan-300' : 'text-slate-900 group-hover:text-blue-600')
                        }`}>
                          {c.cluster_id}
                        </span>

                        <div className="flex items-center gap-1.5 font-mono text-[10px]">
                          <span className={`px-2 py-0.5 rounded font-bold ${
                            isThreat 
                              ? 'bg-red-500/10 text-red-500 border border-red-500/20' 
                              : isInvestigation 
                              ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20' 
                              : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
                          }`}>
                            {isThreat ? 'THREAT' : isInvestigation ? 'INVESTIGATING' : 'BENIGN NOISE'}
                          </span>
                          <span className="px-1.5 py-0.5 rounded font-semibold text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 border border-cyan-500/20">
                            {c.tenant_id}
                          </span>
                        </div>
                      </div>

                      {/* Right Indicator: Chevron + Status Text */}
                      <div className="flex items-center gap-2">
                        <span className={`text-[11px] font-mono hidden sm:inline ${
                          isSelected ? 'text-cyan-400 font-bold' : 'text-slate-400 group-hover:text-slate-300'
                        }`}>
                          {isSelected ? 'Tutup Rantai Serangan' : 'Buka Rantai Serangan'}
                        </span>
                        <div className={`p-1 rounded-md transition-colors ${
                          isSelected 
                            ? 'bg-cyan-500/20 text-cyan-400' 
                            : 'bg-slate-800/40 text-slate-400 group-hover:bg-slate-700/60 group-hover:text-slate-200'
                        }`}>
                          {isSelected ? (
                            <ChevronUp className="w-4 h-4" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Campaign Title */}
                    <div className={`text-xs font-semibold mb-2 ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                      {c.campaign_title}
                    </div>

                    {/* Campaign Meta & Metrics */}
                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono flex-wrap gap-2 pt-2 border-t border-slate-700/20">
                      <div className="flex items-center gap-3">
                        <span>
                          Target: <strong className={`font-mono font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>{c.target_host}</strong>
                        </span>
                        <span>&bull;</span>
                        <span className={`font-mono font-bold ${
                          phase === 'POST_COMPROMISE'
                            ? 'text-red-600 dark:text-red-400'
                            : phase === 'ACTIVE_INTRUSION'
                            ? 'text-orange-600 dark:text-orange-400'
                            : phase === 'PRECURSOR_PROBING'
                            ? 'text-cyan-600 dark:text-cyan-400'
                            : 'text-slate-500'
                        }`}>
                          {phase}
                        </span>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="text-cyan-500 font-bold" title="Incident Confidence Score">
                          ICS {icsScore}%
                        </span>
                        <span>&bull;</span>
                        <span className={isThreat ? 'text-red-500 font-bold' : isInvestigation ? 'text-orange-500 font-bold' : 'text-slate-500 font-bold'} title="Incident Severity Score">
                          ISS {c.campaign_risk_score}
                        </span>
                        <span>&bull;</span>
                        <span>{c.total_distinct_actors || 1} Actors</span>
                        <span>&bull;</span>
                        <span className="font-bold text-slate-300 dark:text-slate-200">
                          {(c.total_raw_events_count || 0).toLocaleString()} Raw Logs
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* UNDERNEATH THAT CAMPAIGN BOX (di bawah kotak tersebut): The Forensic Table and Details */}
                  {isSelected && (
                    <div 
                      onClick={(e) => e.stopPropagation()} 
                      className={`p-4 border-t transition-all ${
                        isDark ? 'border-slate-800 bg-[#070b14]' : 'border-slate-200 bg-slate-50/70'
                      }`}
                    >
                      <div className="flex gap-4 items-start">
                        ''' + inner_table_and_drawer + '''
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>'''

    # Now replace the whole block from {/* MAIN 2-COLUMN WORKSPACE */} to the end of the 2-column container
    pattern_whole = r'\{\s*\/\*\s*MAIN 2-COLUMN WORKSPACE\s*\*\/\}[\s\S]*?<\/div>\s*<\/div>\s*(?=\s*<\/div>\s*\n\s*\);\s*\n\})'
    code, count = re.subn(pattern_whole, new_main_workspace, code)
    if count == 0:
        print("ERROR: Could not replace MAIN 2-COLUMN WORKSPACE in", filepath)
        return False

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(code)
    print(f"Successfully updated {filepath}!")
    return True

for p in ['dashboard/src/components/ThreatCampaignsView.jsx', 'frontend/src/components/ThreatCampaignsView.jsx']:
    update_threat_campaigns_view(p)
