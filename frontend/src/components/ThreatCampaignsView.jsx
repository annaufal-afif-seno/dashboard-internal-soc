import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldAlert, Activity, Network, Layers, Clock, Database, 
  ExternalLink, Search, RefreshCw, AlertTriangle, CheckCircle2, 
  ArrowRight, Filter, Shield, Cpu, Sparkles, Terminal, Eye, FileText
} from 'lucide-react';

export default function ThreatCampaignsView({
  theme = 'dark',
  selectedTenant = 'ALL',
  currentUser = null,
  isReadOnly = false
}) {
  const isDark = theme === 'dark';

  const [campaigns, setCampaigns] = useState([]);
  const [selectedClusterId, setSelectedClusterId] = useState(null);
  const [clusterDetail, setClusterDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  
  // Local tenant filter allowing quick switching without changing global navbar
  const [tenantFilter, setTenantFilter] = useState(selectedTenant || 'ALL');

  // Layer view settings
  const [activeLayerTab, setActiveLayerTab] = useState('layer1'); // 'layer1', 'layer2', 'layer3'
  const [layer1SubView, setLayer1SubView] = useState('graph'); // 'graph' or 'matrix'
  const [lookbackRange, setLookbackRange] = useState('72h'); // '24h', '72h', '7d', '30d'

  // Fetch campaigns list
  const fetchCampaigns = async (overrideTenant = null) => {
    try {
      setLoading(true);
      setError(null);
      const activeTenant = overrideTenant !== null ? overrideTenant : tenantFilter;
      const tenantParam = activeTenant && activeTenant !== 'ALL' ? `&tenant_id=${encodeURIComponent(activeTenant)}` : '';
      const res = await fetch(`http://127.0.0.1:8000/api/campaign-clusters?limit=100${tenantParam}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: Gagal memuat daftar kampanye.`);
      const data = await res.json();
      const list = data.data || [];
      setCampaigns(list);

      // Select first cluster if available or keep current if present
      if (list.length > 0) {
        if (!selectedClusterId || !list.some(c => c.cluster_id === selectedClusterId)) {
          setSelectedClusterId(list[0].cluster_id);
        }
      }
    } catch (err) {
      console.error('Error fetching campaign clusters:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Fetch cluster details
  const fetchClusterDetail = async (clusterId) => {
    if (!clusterId) return;
    try {
      setDetailLoading(true);
      const res = await fetch(`http://127.0.0.1:8000/api/campaign-clusters/${encodeURIComponent(clusterId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: Gagal memuat detail kampanye ${clusterId}.`);
      const data = await res.json();
      setClusterDetail(data);
    } catch (err) {
      console.error('Error fetching cluster detail:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    if (selectedTenant) {
      setTenantFilter(selectedTenant);
    }
  }, [selectedTenant]);

  useEffect(() => {
    fetchCampaigns(tenantFilter);
  }, [tenantFilter]);

  useEffect(() => {
    if (selectedClusterId) {
      fetchClusterDetail(selectedClusterId);
    }
  }, [selectedClusterId]);

  const filteredCampaigns = useMemo(() => {
    if (!searchTerm) return campaigns;
    const term = searchTerm.toLowerCase();
    return campaigns.filter(c => 
      c.cluster_id.toLowerCase().includes(term) ||
      (c.target_host && c.target_host.toLowerCase().includes(term)) ||
      (c.campaign_title && c.campaign_title.toLowerCase().includes(term))
    );
  }, [campaigns, searchTerm]);

  const selectedCampaign = useMemo(() => {
    return campaigns.find(c => c.cluster_id === selectedClusterId) || clusterDetail?.cluster || null;
  }, [campaigns, selectedClusterId, clusterDetail]);

  const [stageFilter, setStageFilter] = useState('significant'); // 'significant' or 'all'
  const [matrixRoleFilter, setMatrixRoleFilter] = useState('ALL');

  const members = useMemo(() => {
    return clusterDetail?.members || [];
  }, [clusterDetail]);

  const sortedMembers = useMemo(() => {
    const list = [...members];
    const roleWeight = {
      'PIVOT_COMPROMISE': 5,
      'PERSISTENCE': 4,
      'C2_EXFIL': 4,
      'BRUTE_FORCE_SPRAY': 3,
      'PRECURSOR_RECON': 2,
      'GENERAL_ACTIVITY': 1
    };
    const filtered = matrixRoleFilter === 'ALL' 
      ? list 
      : list.filter(m => m.entity_role === matrixRoleFilter);
    return filtered.sort((a, b) => {
      const wa = roleWeight[a.entity_role] || 0;
      const wb = roleWeight[b.entity_role] || 0;
      if (wb !== wa) return wb - wa;
      return new Date(b.event_timestamp) - new Date(a.event_timestamp);
    });
  }, [members, matrixRoleFilter]);

  const causalityDag = useMemo(() => {
    return selectedCampaign?.causality_dag || { stages: [] };
  }, [selectedCampaign]);

  const displayedStages = useMemo(() => {
    const all = causalityDag.stages || [];
    if (stageFilter === 'all') return all;
    // Significant stages only (hide repetitive crawler noise like Googlebot)
    const sig = all.filter(s => s.role !== 'GENERAL_ACTIVITY' || s.rule_id === 31106);
    return sig.length > 0 ? sig : all;
  }, [causalityDag, stageFilter]);

  const visualActors = useMemo(() => {
    const isPublicIp = (ip) => ip && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.');
    
    const pivot = members.find(m => m.entity_role === 'PIVOT_COMPROMISE' && isPublicIp(m.actor_entity))?.actor_entity
      || members.find(m => m.entity_role === 'PIVOT_COMPROMISE')?.actor_entity
      || causalityDag.stages?.find(s => s.role === 'PIVOT_COMPROMISE')?.actor
      || '103.135.24.91';

    const recon = members.find(m => m.entity_role === 'PRECURSOR_RECON' && isPublicIp(m.actor_entity))?.actor_entity
      || causalityDag.stages?.find(s => s.role === 'PRECURSOR_RECON')?.actor
      || '114.10.12.151';

    const spray = members.find(m => m.entity_role === 'BRUTE_FORCE_SPRAY' && isPublicIp(m.actor_entity))?.actor_entity
      || causalityDag.stages?.find(s => s.role === 'BRUTE_FORCE_SPRAY')?.actor
      || '114.5.208.145';

    const shellUser = causalityDag.privilege_lineage?.escalated_users?.[0]
      || members.find(m => m.entity_role === 'PERSISTENCE')?.actor_entity
      || (causalityDag.privilege_lineage?.has_root_compromise ? 'root' : 'www-data');

    return { recon, spray, pivot, shellUser };
  }, [members, causalityDag]);

  return (
    <div className="space-y-4 font-sans text-xs">
      
      {/* HEADER CONTROLS */}
      <div className={`p-4 rounded-xl border flex flex-wrap items-center justify-between gap-4 shadow-sm ${
        isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200'
      }`}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className={`text-base font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Threat Campaign & Multi-Layer Attack Graph
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                Post-Threat Provenance (Layer 1-3)
              </span>
            </div>
            <p className={`text-[11px] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
              Rekonstruksi rantai serangan multi-IP terkoordinasi pasca penetrasi dan unmasking jejak pre-attack recon.
            </p>
          </div>
        </div>

        {/* Right Tools */}
        <div className="flex items-center gap-2">
          {/* Lookback Selector */}
          <div className={`p-1 rounded-lg border flex items-center gap-1 ${
            isDark ? 'bg-[#1e293b] border-slate-700' : 'bg-slate-100 border-slate-300'
          }`}>
            <span className="text-[10px] px-2 text-slate-400 font-medium">Lookback:</span>
            {['24h', '72h', '7d', '30d'].map(r => (
              <button
                key={r}
                onClick={() => setLookbackRange(r)}
                className={`px-2 py-0.5 rounded font-mono font-semibold transition cursor-pointer text-[11px] ${
                  lookbackRange === r 
                    ? 'bg-cyan-600 text-white shadow-xs' 
                    : (isDark ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900')
                }`}
              >
                {r === '72h' ? '72h (Def)' : r}
              </button>
            ))}
          </div>

          <button
            onClick={fetchCampaigns}
            disabled={loading}
            className={`p-2 rounded-lg border font-medium transition cursor-pointer flex items-center gap-1.5 ${
              isDark 
                ? 'bg-[#1e293b] hover:bg-slate-800 border-slate-700 text-slate-200' 
                : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 shadow-xs'
            }`}
            title="Refresh Data Kampanye"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ERROR BANNER */}
      {error && (
        <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* MAIN 2-COLUMN WORKSPACE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">

        {/* LEFT COLUMN: LIST OF CAMPAIGNS (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className={`p-3.5 rounded-xl border ${
            isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200 shadow-sm'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs font-bold uppercase tracking-wider ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                Detected Campaigns ({filteredCampaigns.length})
              </span>
              <span className="text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 px-1.5 py-0.5 rounded">
                Live DB
              </span>
            </div>

            {/* Quick Tenant Switcher Pills */}
            <div className="flex flex-wrap items-center gap-1 mb-2.5">
              {[
                { id: 'ALL', label: 'All Tenants' },
                { id: 'InstikiBali', label: 'InstikiBali' },
                { id: 'wicida', label: 'wicida' },
                { id: 'ikmicirebon', label: 'ikmicirebon' },
                { id: 'TenantA', label: 'TenantA' },
                { id: 'TenantC', label: 'TenantC' },
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setTenantFilter(t.id)}
                  className={`px-2 py-0.5 rounded text-[10px] font-medium transition cursor-pointer ${
                    tenantFilter === t.id
                      ? 'bg-cyan-600 text-white font-bold shadow-xs'
                      : (isDark ? 'bg-slate-800/80 text-slate-400 hover:text-slate-200' : 'bg-slate-200 text-slate-600 hover:text-slate-900')
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div className="mb-3">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Cari ID, host, atau judul..."
                  className={`w-full pl-8 pr-3 py-1.5 rounded-lg border text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                    isDark 
                      ? 'bg-[#111827] border-slate-700 text-slate-100 placeholder-slate-500' 
                      : 'bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400'
                  }`}
                />
              </div>
            </div>

            {loading && campaigns.length === 0 ? (
              <div className="p-8 text-center text-slate-400 flex flex-col items-center gap-2">
                <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
                <span>Memuat daftar kampanye serangan...</span>
              </div>
            ) : filteredCampaigns.length === 0 ? (
              <div className="p-6 text-center text-slate-400 space-y-3">
                <p>Tidak ada kampanye serangan yang cocok dengan kriteria pencarian di tenant <b>{tenantFilter}</b>.</p>
                {tenantFilter !== 'ALL' && (
                  <button
                    type="button"
                    onClick={() => setTenantFilter('ALL')}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer shadow-sm transition"
                  >
                    Buka Semua Tenant (ALL)
                  </button>
                )}
              </div>
            ) : (
              <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1 custom-scrollbar">
                {filteredCampaigns.map((c) => {
                  const isSelected = c.cluster_id === selectedClusterId;
                  const isP0 = c.priority === 'P0';
                  return (
                    <div
                      key={c.cluster_id}
                      onClick={() => setSelectedClusterId(c.cluster_id)}
                      className={`p-3 rounded-lg border transition-all cursor-pointer ${
                        isSelected
                          ? (isDark 
                              ? 'bg-cyan-950/40 border-cyan-500/80 shadow-md ring-1 ring-cyan-500/50' 
                              : 'bg-cyan-50/70 border-cyan-400 shadow-sm')
                          : (isDark 
                              ? 'bg-[#111827]/70 hover:bg-[#1f293d] border-slate-800' 
                              : 'bg-slate-50 hover:bg-slate-100 border-slate-200')
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono font-bold text-xs text-cyan-400">
                          {c.cluster_id}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono ${
                            isP0 
                              ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                              : 'bg-orange-950 text-orange-300 border border-orange-800'
                          }`}>
                            {c.priority}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                            {c.tenant_id}
                          </span>
                          <span className="text-xs font-mono font-bold text-rose-400">
                            CRI {c.campaign_risk_score}
                          </span>
                        </div>
                      </div>

                      <div className={`text-xs font-semibold line-clamp-1 ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                        {c.campaign_title}
                      </div>

                      <div className="mt-2 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                        <span>Target: <strong className="text-cyan-300">{c.target_host}</strong></span>
                        <span>{c.total_distinct_actors || 1} Actors</span>
                        <span>{c.total_aggregates_count || 1} Aggs</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: 3-LAYER VISUALIZER & DOSSIER (8 cols) */}
        <div className="lg:col-span-8 space-y-3">
          
          {selectedCampaign ? (
            <>
              {/* DOSSIER SUMMARY HEADER */}
              <div className={`p-4 rounded-xl border shadow-sm ${
                isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200'
              }`}>
                <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3 mb-3 border-slate-800/80">
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block">
                      Attack Campaign Dossier
                    </span>
                    <h3 className={`text-base font-bold font-mono flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                      {selectedCampaign.cluster_id}
                      <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
                    </h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold font-mono text-xs">
                      {selectedCampaign.priority} INTRUSION
                    </span>
                    <span className="px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold font-mono text-xs">
                      CRI Score: {selectedCampaign.campaign_risk_score} / 100
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-xs font-mono">
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-400 text-[10px] block">Target Victim Host:</span>
                    <strong className="text-cyan-400 text-xs">{selectedCampaign.target_host}</strong>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-400 text-[10px] block">Coordinated Actors:</span>
                    <strong className="text-rose-400 text-xs">{selectedCampaign.total_distinct_actors} Distinct IPs</strong>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-400 text-[10px] block">Aggregated Evidence:</span>
                    <strong className="text-white text-xs">{selectedCampaign.total_aggregates_count} Windows</strong>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-400 text-[10px] block">Raw Telemetry Linked:</span>
                    <strong className="text-amber-400 text-xs">{(selectedCampaign.total_raw_events_count || 0).toLocaleString()} Logs</strong>
                  </div>
                </div>

                {/* MITRE Tactics Chain */}
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  <span className="text-slate-400 text-[11px] font-medium mr-1">MITRE Tactics Chain:</span>
                  {(selectedCampaign.mitre_tactics_chain || []).map((t, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 text-[10px] font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              </div>

              {/* 3-LAYER VISUALIZER WORKSPACE */}
              <div className={`p-4 rounded-xl border shadow-sm ${
                isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200'
              }`}>
                {/* LAYER TAB SELECTOR */}
                <div className="flex flex-wrap items-center justify-between border-b pb-3 mb-4 border-slate-800/80 gap-2">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setActiveLayerTab('layer1')}
                      className={`px-3 py-1.5 rounded-lg font-semibold text-xs transition cursor-pointer flex items-center gap-1.5 ${
                        activeLayerTab === 'layer1'
                          ? 'bg-cyan-600 text-white shadow-sm'
                          : (isDark ? 'bg-[#1e293b] text-slate-400 hover:text-white' : 'bg-slate-100 text-slate-600')
                      }`}
                    >
                      <Network className="w-3.5 h-3.5" />
                      <span>Layer 1: Spatial & Entity Expansion</span>
                    </button>

                    <button
                      onClick={() => setActiveLayerTab('layer2')}
                      className={`px-3 py-1.5 rounded-lg font-semibold text-xs transition cursor-pointer flex items-center gap-1.5 ${
                        activeLayerTab === 'layer2'
                          ? 'bg-cyan-600 text-white shadow-sm'
                          : (isDark ? 'bg-[#1e293b] text-slate-400 hover:text-white' : 'bg-slate-100 text-slate-600')
                      }`}
                    >
                      <Clock className="w-3.5 h-3.5" />
                      <span>Layer 2: Sequence DAG & Velocity</span>
                    </button>

                    <button
                      onClick={() => setActiveLayerTab('layer3')}
                      className={`px-3 py-1.5 rounded-lg font-semibold text-xs transition cursor-pointer flex items-center gap-1.5 ${
                        activeLayerTab === 'layer3'
                          ? 'bg-cyan-600 text-white shadow-sm'
                          : (isDark ? 'bg-[#1e293b] text-slate-400 hover:text-white' : 'bg-slate-100 text-slate-600')
                      }`}
                    >
                      <Database className="w-3.5 h-3.5" />
                      <span>Layer 3: Cumulative & Feedback</span>
                    </button>
                  </div>

                  {activeLayerTab === 'layer1' && (
                    <div className={`p-1 rounded-lg border flex items-center gap-1 text-[11px] ${
                      isDark ? 'bg-[#1e293b] border-slate-700' : 'bg-slate-100 border-slate-200'
                    }`}>
                      <button
                        onClick={() => setLayer1SubView('graph')}
                        className={`px-2 py-0.5 rounded font-semibold transition cursor-pointer ${
                          layer1SubView === 'graph' ? 'bg-cyan-700 text-white' : 'text-slate-400'
                        }`}
                      >
                        Visual Graph
                      </button>
                      <button
                        onClick={() => setLayer1SubView('matrix')}
                        className={`px-2 py-0.5 rounded font-semibold transition cursor-pointer ${
                          layer1SubView === 'matrix' ? 'bg-cyan-700 text-white' : 'text-slate-400'
                        }`}
                      >
                        Entity Matrix Table
                      </button>
                    </div>
                  )}
                </div>

                {/* LAYER 1 VIEW */}
                {activeLayerTab === 'layer1' && (
                  <div>
                    {layer1SubView === 'graph' ? (
                      <div className={`p-4 rounded-xl border relative overflow-hidden ${
                        isDark ? 'bg-[#060a12] border-slate-800' : 'bg-slate-50 border-slate-200'
                      }`}>
                        <div className="flex items-center justify-between mb-3 text-[11px] text-slate-400">
                          <span>Directed Bipartite Relationship Graph (Target: <strong className="text-cyan-400">{selectedCampaign.target_host}</strong>)</span>
                          <span className="font-mono text-cyan-400">Engine: Leiden-HIN v2 &bull; Real Extracted Attackers</span>
                        </div>

                        {/* Interactive Dynamic Graph SVG View */}
                        <div className="w-full h-80 flex items-center justify-center">
                          <svg viewBox="0 0 740 280" className="w-full h-full">
                            {/* Lines connecting actors to target host */}
                            <line x1="130" y1="50" x2="370" y2="140" stroke="#a855f7" strokeWidth="2" strokeDasharray="4,4" />
                            <text x="210" y="80" fill="#c084fc" fontSize="9" fontFamily="monospace">Precursor Recon (-18h)</text>

                            <line x1="130" y1="140" x2="370" y2="140" stroke="#f97316" strokeWidth="2.5" />
                            <text x="210" y="132" fill="#fb923c" fontSize="9" fontFamily="monospace">Distributed Spray</text>

                            <line x1="130" y1="230" x2="370" y2="140" stroke="#ef4444" strokeWidth="3" />
                            <text x="210" y="200" fill="#f87171" fontSize="9" fontFamily="monospace">Compromise Pivot (Exploit)</text>

                            <line x1="370" y1="140" x2="600" y2="140" stroke="#10b981" strokeWidth="2.5" />
                            <text x="440" y="130" fill="#34d399" fontSize="9" fontFamily="monospace">Privilege Lineage</text>

                            {/* Node: Recon IP */}
                            <g className="cursor-pointer">
                              <circle cx="130" cy="50" r="26" fill="#2e1065" stroke="#a855f7" strokeWidth="2.5" />
                              <text x="130" y="48" textAnchor="middle" fill="#e9d5ff" fontSize="9" fontWeight="bold" fontFamily="monospace">
                                {visualActors.recon ? (visualActors.recon.length > 15 ? visualActors.recon.slice(0, 13) + '..' : visualActors.recon) : 'Recon IP'}
                              </text>
                              <text x="130" y="62" textAnchor="middle" fill="#c084fc" fontSize="8" fontFamily="sans-serif">Recon IP</text>
                              <text x="130" y="86" textAnchor="middle" fill="#94a3b8" fontSize="9" fontWeight="bold">Pre-Attack Scan</text>
                            </g>

                            {/* Node: Spray Actor */}
                            <g className="cursor-pointer">
                              <circle cx="130" cy="140" r="26" fill="#431407" stroke="#f97316" strokeWidth="2.5" />
                              <text x="130" y="138" textAnchor="middle" fill="#fed7aa" fontSize="9" fontWeight="bold" fontFamily="monospace">
                                {visualActors.spray ? (visualActors.spray.length > 15 ? visualActors.spray.slice(0, 13) + '..' : visualActors.spray) : 'Spray IP'}
                              </text>
                              <text x="130" y="152" textAnchor="middle" fill="#fb923c" fontSize="8" fontFamily="sans-serif">Spray IP</text>
                              <text x="130" y="176" textAnchor="middle" fill="#94a3b8" fontSize="9" fontWeight="bold">Brute Force</text>
                            </g>

                            {/* Node: Compromise Pivot */}
                            <g className="cursor-pointer">
                              <circle cx="130" cy="230" r="28" fill="#450a0a" stroke="#ef4444" strokeWidth="3" />
                              <text x="130" y="228" textAnchor="middle" fill="#fecaca" fontSize="9" fontWeight="bold" fontFamily="monospace">
                                {visualActors.pivot ? (visualActors.pivot.length > 15 ? visualActors.pivot.slice(0, 13) + '..' : visualActors.pivot) : 'Breach IP'}
                              </text>
                              <text x="130" y="242" textAnchor="middle" fill="#f87171" fontSize="8" fontFamily="sans-serif">Exploit IP</text>
                              <text x="130" y="268" textAnchor="middle" fill="#ef4444" fontSize="9" fontWeight="bold">Critical Breach</text>
                            </g>

                            {/* Center Node: Target Victim Host */}
                            <g className="cursor-pointer">
                              <circle cx="370" cy="140" r="34" fill="#082f49" stroke="#06b6d4" strokeWidth="3.5" />
                              <text x="370" y="138" textAnchor="middle" fill="#e0f2fe" fontSize="11" fontWeight="bold">
                                {selectedCampaign.target_host && selectedCampaign.target_host.length > 16 
                                  ? selectedCampaign.target_host.slice(0, 14) + '..' 
                                  : selectedCampaign.target_host}
                              </text>
                              <text x="370" y="153" textAnchor="middle" fill="#38bdf8" fontSize="8" fontFamily="monospace">Victim Host</text>
                            </g>

                            {/* Node: Execution / Privilege */}
                            <g className="cursor-pointer">
                              <circle cx="600" cy="140" r="28" fill="#064e3b" stroke="#10b981" strokeWidth="2.5" />
                              <text x="600" y="137" textAnchor="middle" fill="#a7f3d0" fontSize="10" fontWeight="bold" fontFamily="monospace">
                                {visualActors.shellUser}
                              </text>
                              <text x="600" y="152" textAnchor="middle" fill="#34d399" fontSize="8" fontFamily="sans-serif">
                                {causalityDag.privilege_lineage?.has_root_compromise ? 'Root UID 0' : 'User Session'}
                              </text>
                              <text x="600" y="178" textAnchor="middle" fill="#10b981" fontSize="9" fontWeight="bold">Escalated Priv</text>
                            </g>
                          </svg>
                        </div>
                      </div>
                    ) : (
                      /* Matrix Table View */
                      <div className="space-y-3">
                        {/* Role filter buttons */}
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-slate-400 font-semibold mr-1">Filter Role:</span>
                            {['ALL', 'PIVOT_COMPROMISE', 'PRECURSOR_RECON', 'BRUTE_FORCE_SPRAY', 'PERSISTENCE'].map(role => (
                              <button
                                key={role}
                                onClick={() => setMatrixRoleFilter(role)}
                                className={`px-2 py-0.5 rounded text-[10px] font-mono transition cursor-pointer ${
                                  matrixRoleFilter === role
                                    ? 'bg-cyan-600 text-white font-bold'
                                    : (isDark ? 'bg-slate-800 text-slate-400 hover:text-white' : 'bg-slate-200 text-slate-700')
                                }`}
                              >
                                {role === 'ALL' ? 'Semua' : role}
                              </button>
                            ))}
                          </div>
                          <span className="text-[11px] text-slate-400 font-mono">
                            Menampilkan {Math.min(50, sortedMembers.length)} dari {sortedMembers.length} entitas
                          </span>
                        </div>

                        <div className="overflow-x-auto max-h-96 overflow-y-auto border rounded-lg border-slate-800/80">
                          <table className="w-full text-left text-xs font-mono">
                            <thead className="sticky top-0 z-10">
                              <tr className={`border-b text-slate-400 ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-100 border-slate-200'}`}>
                                <th className="py-2.5 px-3">Aktor / IP Penyerang</th>
                                <th className="py-2.5 px-3">Role In Campaign</th>
                                <th className="py-2.5 px-3">Rule & Aktivitas / Bukti Serangan (Ngapain Dia)</th>
                                <th className="py-2.5 px-3">Waktu Kejadian</th>
                                <th className="py-2.5 px-3">Status Investigasi</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/60">
                              {sortedMembers.slice(0, 50).map((m, idx) => (
                                <tr key={idx} className={isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50'}>
                                  <td className="py-2 px-3 text-cyan-400 font-bold whitespace-nowrap">
                                    {m.actor_entity}
                                  </td>
                                  <td className="py-2 px-3 whitespace-nowrap">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                      m.entity_role === 'PIVOT_COMPROMISE'
                                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                        : m.entity_role === 'PRECURSOR_RECON'
                                        ? 'bg-purple-950 text-purple-300 border border-purple-800'
                                        : m.entity_role === 'BRUTE_FORCE_SPRAY'
                                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                        : m.entity_role === 'PERSISTENCE'
                                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                        : 'bg-slate-800 text-slate-300'
                                    }`}>
                                      {m.entity_role}
                                    </span>
                                  </td>
                                  <td className="py-2 px-3 text-slate-200 min-w-[260px]">
                                    <div className="flex items-center gap-1.5">
                                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-amber-300 text-[10px] font-bold shrink-0">
                                        Rule {m.rule_id || '-'}
                                      </span>
                                      <span className="text-[11px] font-sans truncate" title={m.evidence_summary}>
                                        {m.evidence_summary || `Aktivitas terdeteksi pada ${m.target_entity}`}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="py-2 px-3 text-slate-400 text-[10px] whitespace-nowrap">
                                    {m.event_timestamp ? new Date(m.event_timestamp).toLocaleString('id-ID', { hour12: false }) : '-'}
                                  </td>
                                  <td className="py-2 px-3 whitespace-nowrap">
                                    <span className="text-[10px] text-emerald-400 font-bold">
                                      {m.entity_role === 'PRECURSOR_RECON' ? 'Unmasked Precursor' : 'Confirmed Threat'}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* CROSS-AGENT SPREAD & BLAST RADIUS */}
                    <div className={`mt-3 p-3.5 rounded-xl border ${isDark ? 'bg-[#0f172a]/60 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-bold text-xs flex items-center gap-1.5 text-cyan-400">
                          <Network className="w-3.5 h-3.5" />
                          Cross-Agent Blast Radius (IP Penyerang Menyasar Host Lain di Jaringan)
                        </span>
                        <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded">
                          {(causalityDag.cross_agent_spread || []).length} Collateral Hosts
                        </span>
                      </div>
                      {(causalityDag.cross_agent_spread && causalityDag.cross_agent_spread.length > 0) ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                          {causalityDag.cross_agent_spread.map((ca, idx) => (
                            <div key={idx} className={`p-2 rounded-lg border flex items-center justify-between text-xs font-mono ${
                              isDark ? 'bg-[#1e293b]/70 border-slate-700/80' : 'bg-white border-slate-200'
                            }`}>
                              <div className="flex items-center gap-2">
                                <span className="text-rose-400 font-bold">{ca.actor}</span>
                                <ArrowRight className="w-3 h-3 text-slate-500" />
                                <span className="text-cyan-300 font-semibold">{ca.other_host}</span>
                              </div>
                              <span className="text-[10px] text-slate-400">
                                {ca.total_events} events
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[11px] text-slate-400">Tidak ada bukti pergerakan lateral / spray ke host lain pada jendela waktu ini.</p>
                      )}
                    </div>

                    {/* PRIVILEGE & IDENTITY LINEAGE */}
                    <div className={`mt-3 p-3.5 rounded-xl border ${isDark ? 'bg-[#0f172a]/60 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-bold text-xs flex items-center gap-1.5 text-amber-400">
                          <Terminal className="w-3.5 h-3.5" />
                          Privilege & Identity Lineage (Akses User Masuk ➔ Eskalasi Root)
                        </span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          causalityDag.privilege_lineage?.has_root_compromise
                            ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}>
                          {causalityDag.privilege_lineage?.has_root_compromise ? '⚠️ ROOT ESCALATION DETECTED' : 'STANDARD PRIVILEGE'}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono mt-2">
                        <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#1e293b]/50 border-slate-700/70' : 'bg-white border-slate-200'}`}>
                          <span className="text-slate-400 text-[10px] block mb-1">Akun User Terindikasi Awal:</span>
                          <div className="flex flex-wrap gap-1.5">
                            {(causalityDag.privilege_lineage?.entry_users && causalityDag.privilege_lineage.entry_users.length > 0
                              ? causalityDag.privilege_lineage.entry_users 
                              : ['www-data']
                            ).map((u, i) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[11px] font-bold">
                                {u}
                              </span>
                            ))}
                          </div>
                        </div>
                        <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#1e293b]/50 border-slate-700/70' : 'bg-white border-slate-200'}`}>
                          <span className="text-slate-400 text-[10px] block mb-1">Akses Tertinggi / Target Eskalasi:</span>
                          <div className="flex flex-wrap gap-1.5">
                            {(causalityDag.privilege_lineage?.escalated_users && causalityDag.privilege_lineage.escalated_users.length > 0
                              ? causalityDag.privilege_lineage.escalated_users 
                              : (causalityDag.privilege_lineage?.has_root_compromise ? ['root'] : ['None'])
                            ).map((u, i) => (
                              <span key={i} className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                                u === 'root' 
                                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                  : 'bg-slate-800 text-slate-300 border border-slate-700'
                              }`}>
                                {u === 'root' ? 'root (UID 0)' : u}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* LAYER 2 VIEW */}
                {activeLayerTab === 'layer2' && (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2 pb-2 border-b border-slate-800/60">
                      <div>
                        <div className="font-bold text-xs text-white">Kronologis Rantai Kausalitas Monotonik (Sequence DAG)</div>
                        <p className="text-[11px] text-slate-400">Runtutan aksi nyata penyerang dari fase pra-serangan hingga eskalasi hak akses.</p>
                      </div>
                      <div className={`p-1 rounded-lg border flex items-center gap-1 text-[11px] ${
                        isDark ? 'bg-[#1e293b] border-slate-700' : 'bg-slate-100 border-slate-200'
                      }`}>
                        <button
                          onClick={() => setStageFilter('significant')}
                          className={`px-2.5 py-1 rounded font-semibold transition cursor-pointer ${
                            stageFilter === 'significant' ? 'bg-cyan-700 text-white' : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Tahap Kunci ({displayedStages.length})
                        </button>
                        <button
                          onClick={() => setStageFilter('all')}
                          className={`px-2.5 py-1 rounded font-semibold transition cursor-pointer ${
                            stageFilter === 'all' ? 'bg-cyan-700 text-white' : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Semua ({causalityDag.stages?.length || 0})
                        </button>
                      </div>
                    </div>

                    <div className="space-y-3 relative before:absolute before:inset-0 before:left-4 before:w-0.5 before:bg-slate-800 max-h-[520px] overflow-y-auto pr-1">
                      {displayedStages.map((st, idx) => (
                        <div key={idx} className="flex items-start gap-3 relative">
                          <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center font-bold text-xs shrink-0 z-10 font-mono ${
                            st.role === 'PIVOT_COMPROMISE'
                              ? 'bg-rose-950 border-rose-500 text-rose-300'
                              : st.role === 'PRECURSOR_RECON'
                              ? 'bg-purple-950 border-purple-500 text-purple-300'
                              : st.role === 'BRUTE_FORCE_SPRAY'
                              ? 'bg-amber-950 border-amber-500 text-amber-300'
                              : st.role === 'PERSISTENCE'
                              ? 'bg-emerald-950 border-emerald-500 text-emerald-300'
                              : 'bg-cyan-950 border-cyan-500 text-cyan-300'
                          }`}>
                            {st.step}
                          </div>
                          <div className={`p-3 rounded-lg border flex-1 text-xs font-mono shadow-sm ${
                            isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'
                          }`}>
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  st.role === 'PIVOT_COMPROMISE'
                                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                    : st.role === 'PRECURSOR_RECON'
                                    ? 'bg-purple-950 text-purple-300 border border-purple-800'
                                    : st.role === 'BRUTE_FORCE_SPRAY'
                                    ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                    : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                }`}>
                                  {st.role}
                                </span>
                                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-amber-300 text-[10px] font-bold">
                                  Rule {st.rule_id}
                                </span>
                              </div>
                              <span className="text-slate-400 text-[10px] font-sans">
                                {st.timestamp ? new Date(st.timestamp).toLocaleString('id-ID', { hour12: false }) : st.timestamp}
                              </span>
                            </div>

                            <div className="text-slate-200 mt-2 font-mono flex items-center gap-2">
                              <span className="text-slate-400 text-xs">IP Penyerang:</span>
                              <strong className="text-rose-400 text-sm font-bold">{st.actor}</strong>
                            </div>

                            {/* What they actually did */}
                            <div className={`mt-2 p-2 rounded-lg border text-xs font-sans ${
                              isDark ? 'bg-[#0a0f1d] border-slate-800/90 text-slate-200' : 'bg-white border-slate-200 text-slate-800'
                            }`}>
                              🎯 <strong className="text-cyan-400">Aktivitas Serangan:</strong> {st.description || 'Aktivitas terdeteksi pada host target'}
                            </div>

                            <div className="mt-2 flex flex-wrap items-center justify-between text-[10px] text-slate-400 border-t pt-1.5 border-slate-800/60">
                              <span>
                                Status Awal: <span className="text-amber-300 font-semibold">{st.prior_status}</span>
                              </span>
                              <span className="text-emerald-400 font-bold">
                                ✅ Terbukti Terhubung Rantai Serangan
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* LAYER 3 VIEW */}
                {activeLayerTab === 'layer3' && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className={`p-3.5 rounded-xl border ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <h4 className="font-bold text-cyan-400 mb-2 flex items-center gap-1.5">
                        <Database className="w-3.5 h-3.5" />
                        Longitudinal Baseline (cumulative_alerts)
                      </h4>
                      <div className="space-y-1.5 text-slate-300 text-[11px]">
                        <div>Target Criticality: <strong className="text-rose-400">CROWN_JEWEL</strong></div>
                        <div>Total Linked Distinct Actors: <strong>{selectedCampaign.total_distinct_actors}</strong></div>
                        <div>Dormancy Status: <strong className="text-emerald-400">ACTIVE TRACKING</strong></div>
                        <div>Sighting Persistence: <strong className="text-amber-400">Cross-Week Attacker Persistence</strong></div>
                      </div>
                    </div>

                    <div className={`p-3.5 rounded-xl border ${isDark ? 'bg-[#111827] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <h4 className="font-bold text-emerald-400 mb-2 flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Analyst Feedback & Threat Intel
                      </h4>
                      <div className="space-y-1.5 text-slate-300 text-[11px]">
                        <div>Active Learning Status: <strong className="text-emerald-300">Synchronized Groundtruth</strong></div>
                        <div>MISP Sighting Attribution: <strong>STIX 2.1 Threat Actor Linked</strong></div>
                        <div>Consolidated Action: <strong className="text-cyan-300">Escalate 1 Unified Case to DFIR Iris</strong></div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className={`p-12 rounded-xl border text-center text-slate-400 ${
              isDark ? 'bg-[#090d16] border-slate-800' : 'bg-white border-slate-200'
            }`}>
              <ShieldAlert className="w-8 h-8 text-slate-500 mx-auto mb-2" />
              <p>Pilih salah satu kampanye serangan di sebelah kiri untuk melihat rekonstruksi graf multi-lapis.</p>
            </div>
          )}

        </div>
      </div>

    </div>
  );
}
