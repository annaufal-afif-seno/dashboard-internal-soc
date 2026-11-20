import React, { useState, useMemo } from 'react';
import { 
  Layers, 
  Search, 
  RefreshCw, 
  Copy, 
  ChevronRight, 
  ChevronDown, 
  ExternalLink,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

// Custom Tooltip Donut Chart
const DonutTooltip = ({ active, payload, isDark }) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className={`px-2.5 py-1.5 rounded-lg text-xs font-mono border shadow-xl ${
        isDark ? 'bg-slate-900 border-slate-700 text-white' : 'bg-white border-slate-200 text-slate-800'
      }`}>
        <div className="flex items-center gap-1.5 pb-1 border-b border-slate-700/50">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: data.payload.color || data.color }} />
          <span className="font-bold">{data.name}</span>
        </div>
        <div className="flex justify-between gap-3 mt-1 text-[11px]">
          <span className="text-slate-400">Porsi:</span>
          <span className="font-bold text-emerald-400">{data.value}%</span>
        </div>
      </div>
    );
  }
  return null;
};

export default function LeafGroupRollupOverview({
  theme = 'dark',
  selectedTenant = 'ALL',
  timeRange = 'today',
  currentUser = null
}) {
  const isDark = theme === 'dark';

  // Dual-mode state: 'leaf' vs 'rollup' (Identik dengan 'interval' vs 'cumulative')
  const [mode, setMode] = useState('leaf'); // 'leaf' | 'rollup'
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRowId, setExpandedRowId] = useState('lg-0');

  // KPI Metrics (Diambil dari real engine 30k)
  const leafMetrics = {
    totalGroups: '122,288',
    totalAlerts: '303,906',
    avgCompression: '2.49x',
    activeWindows: '14 Open'
  };

  const rollupMetrics = {
    totalParents: '649',
    childLeavesMerged: '250,404',
    avgNoiseReduction: '92.4%',
    peakCampaign: '96 Leaves'
  };

  // Sample real data for UI Demonstration
  const leafItems = [
    {
      id: 'APX-LG-9919ED50401D',
      rawId: 'lg-0',
      timeRange: 'Nov 18, 14:10:02 - 14:22:15 WIB',
      category: 'generic_rule',
      weight: 10,
      agent: 'grafana-public-240',
      actor: 'Internal/Local',
      ruleId: '40704',
      ruleDesc: 'Systemd service entered failed state',
      alertCount: 1,
      status: 'CLOSED',
      parentRollup: 'APX-RO-34D42881C7F3',
      events: [
        { id: '1792084961.98270122', time: '14:10:02', agent: 'grafana-public-240', actor: '127.0.0.1', rule: '40704', log: 'systemd[1]: grafana-server.service: Main process exited, code=exited, status=1/FAILURE' }
      ]
    },
    {
      id: 'APX-LG-B74A89102C31',
      rawId: 'lg-1',
      timeRange: 'Nov 18, 14:05:11 - 14:19:40 WIB',
      category: 'web_attack',
      weight: 80,
      agent: 'srv-web-prod-01',
      actor: '192.168.1.105',
      ruleId: '31101',
      ruleDesc: 'SQL Injection attempt detected in URI query',
      alertCount: 248,
      status: 'CLOSED',
      parentRollup: 'APX-RO-77BF1234EE09',
      events: [
        { id: '1792084880.102918', time: '14:05:11', agent: 'srv-web-prod-01', actor: '192.168.1.105', rule: '31101', log: 'GET /index.php?id=1%20UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1 403' }
      ]
    },
    {
      id: 'APX-LG-1109C48AA207',
      rawId: 'lg-2',
      timeRange: 'Nov 18, 14:15:00 - 14:28:30 WIB',
      category: 'auth_bruteforce',
      weight: 70,
      agent: 'srv-auth-sso',
      actor: '10.0.8.44',
      ruleId: '5710',
      ruleDesc: 'SSHD authentication failed for multiple users',
      alertCount: 512,
      status: 'CLOSED',
      parentRollup: 'APX-RO-5591A012BC11',
      events: [
        { id: '1792085112.449102', time: '14:15:00', agent: 'srv-auth-sso', actor: '10.0.8.44', rule: '5710', log: 'Failed password for invalid user admin from 10.0.8.44 port 49281 ssh2' }
      ]
    }
  ];

  const rollupItems = [
    {
      id: 'APX-RO-34D42881C7F3',
      rawId: 'ro-0',
      timeRange: 'Nov 18, 14:10:02 - 14:32:45 WIB',
      ruleName: 'High-Volume Rule Storm',
      ruleNum: 'Rule #7',
      category: 'generic_rule',
      invariants: 'Target: grafana-public-240',
      childLeavesCount: 96,
      totalAlerts: 1280,
      reductionPct: '99.0%',
      escalationStatus: 'ELEVATED_TO_INCIDENT',
      childLeaves: [
        { id: 'APX-LG-9919ED50401D', cat: 'generic_rule', count: 1, desc: 'Rule 40704 (Systemd Service Failure)', window: '14:10 - 14:22' },
        { id: 'APX-LG-88FE100234AA', cat: 'app_error_log', count: 18, desc: 'Rule 1002 (Syslog Disk Threshold)', window: '14:30 - 14:30' },
        { id: 'APX-LG-77CC01889921', cat: 'generic_rule', count: 45, desc: 'Rule 40705 (Systemd Unit Reload Failed)', window: '14:12 - 14:25' }
      ]
    },
    {
      id: 'APX-RO-77BF1234EE09',
      rawId: 'ro-1',
      timeRange: 'Nov 18, 14:05:11 - 14:25:00 WIB',
      ruleName: 'Multi-Vector Web Attack',
      ruleNum: 'Rule #2',
      category: 'web_attack',
      invariants: 'Actor: 192.168.1.105 → Target: srv-web-prod',
      childLeavesCount: 14,
      totalAlerts: 640,
      reductionPct: '97.8%',
      escalationStatus: 'ELEVATED_TO_INCIDENT',
      childLeaves: [
        { id: 'APX-LG-B74A89102C31', cat: 'web_attack', count: 248, desc: 'SQL Injection Query String', window: '14:05 - 14:19' }
      ]
    }
  ];

  // Chart datasets
  const leafCategoryData = [
    { name: 'generic_rule', value: 45, color: '#3b82f6' },
    { name: 'web_attack', value: 25, color: '#10b981' },
    { name: 'auth_bruteforce', value: 18, color: '#f59e0b' },
    { name: 'vuln_detected', value: 12, color: '#8b5cf6' }
  ];

  const rollupRulesData = [
    { name: 'Rule Storm (#7)', value: 40, color: '#8b5cf6' },
    { name: 'Multi-Vector Web (#2)', value: 28, color: '#3b82f6' },
    { name: 'Bulk Vuln Host (#1)', value: 20, color: '#10b981' },
    { name: 'Password Spray (#4)', value: 12, color: '#f59e0b' }
  ];

  return (
    <div className={`p-4 space-y-4 ${isDark ? 'bg-[#070b14] text-slate-100' : 'bg-slate-50 text-slate-900'}`}>
      
      {/* Header & Mode Switcher (Identik dengan Interval vs Cumulative) */}
      <div className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-sm ${
        isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'
      }`}>
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-blue-600/10 border border-blue-500/30 text-blue-400">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-tight">Leaf Group & Roll-Up Clustering</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Apex v4.0 Pipeline
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Dual-level clustering: reduksi homogen mikro (Leaf Group) dan meta-agregasi kampanye makro (Roll-Up).
            </p>
          </div>
        </div>

        {/* Toggle Mode Button: Leaf Group vs Roll-Up */}
        <div className={`p-1 rounded-xl border flex items-center gap-1 ${
          isDark ? 'bg-slate-900 border-slate-700/80' : 'bg-slate-100 border-slate-300'
        }`}>
          <button
            onClick={() => setMode('leaf')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all duration-200 cursor-pointer ${
              mode === 'leaf'
                ? 'bg-blue-600 text-white shadow-sm border border-blue-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            🍃 Leaf Group (Identik)
          </button>
          <button
            onClick={() => setMode('rollup')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all duration-200 cursor-pointer ${
              mode === 'rollup'
                ? 'bg-purple-600 text-white shadow-sm border border-purple-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            📦 Roll-Up (15 Aturan)
          </button>
        </div>
      </div>

      {/* 4 KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {mode === 'leaf' ? (
          <>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Total Leaf Groups</div>
              <div className="text-xl font-bold font-mono text-white mt-0.5">{leafMetrics.totalGroups}</div>
              <div className="text-[10px] text-emerald-400 mt-1">100% Deterministic SHA-256</div>
            </div>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Raw Alerts Terkompresi</div>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-0.5">{leafMetrics.totalAlerts}</div>
              <div className="text-[10px] text-slate-400 mt-1">Rata-rata {leafMetrics.avgCompression} alert/leaf</div>
            </div>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Jendela Geser Aktif (Open)</div>
              <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">{leafMetrics.activeWindows}</div>
              <div className="text-[10px] text-amber-300 mt-1">Sliding Idle 15 Menit</div>
            </div>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Terserap ke Roll-Up</div>
              <div className="text-xl font-bold font-mono text-purple-400 mt-0.5">5,880 (19.6%)</div>
              <div className="text-[10px] text-purple-300 mt-1">Terbagi dalam 36 Parents</div>
            </div>
          </>
        ) : (
          <>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Parent Roll-Up Terbentuk</div>
              <div className="text-xl font-bold font-mono text-purple-400 mt-0.5">{rollupMetrics.totalParents}</div>
              <div className="text-[10px] text-purple-300 mt-1">15 Aturan Multi-Vektor</div>
            </div>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Child Leaves Terserap</div>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">{rollupMetrics.childLeavesMerged}</div>
              <div className="text-[10px] text-slate-400 mt-1">Lineage Silsilah Lengkap</div>
            </div>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Rasio Reduksi Noise Rata-rata</div>
              <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{rollupMetrics.avgNoiseReduction}</div>
              <div className="text-[10px] text-emerald-400 mt-1">Efisiensi Triage Tinggi</div>
            </div>
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
              <div className="text-xs text-slate-400">Kampanye Paling Masif</div>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-0.5">{rollupMetrics.peakCampaign}</div>
              <div className="text-[10px] text-cyan-300 mt-1">1,280 Alerts in 1 Event</div>
            </div>
          </>
        )}
      </div>

      {/* Visualisasi Donut Charts (Row 1: 3 charts) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={`p-3.5 rounded-xl border shadow-sm ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              {mode === 'leaf' ? 'Distribusi Kategori Serangan' : 'Distribusi 15 Aturan Roll-Up'}
            </span>
            <span className="text-[10px] font-mono text-blue-400">Chart 1</span>
          </div>
          <div className="h-28 flex items-center">
            <ResponsiveContainer width="45%" height="100%">
              <PieChart>
                <Pie
                  data={mode === 'leaf' ? leafCategoryData : rollupRulesData}
                  cx="50%"
                  cy="50%"
                  innerRadius={25}
                  outerRadius={45}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {(mode === 'leaf' ? leafCategoryData : rollupRulesData).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<DonutTooltip isDark={isDark} />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="w-[55%] space-y-1 text-[11px] font-mono">
              {(mode === 'leaf' ? leafCategoryData : rollupRulesData).map((d, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 truncate">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                    <span className="truncate">{d.name}</span>
                  </div>
                  <span className="font-bold text-slate-300">{d.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Chart 2: Top Target / Invariant */}
        <div className={`p-3.5 rounded-xl border shadow-sm ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              {mode === 'leaf' ? 'Top Target Asset (Agent)' : 'Dimensi Kunci Invarian'}
            </span>
            <span className="text-[10px] font-mono text-emerald-400">Chart 2</span>
          </div>
          <div className="h-28 flex items-center justify-center text-xs text-slate-400 font-mono">
            {mode === 'leaf' ? 'grafana-public-240 (50%) | srv-web (30%)' : 'Target Invariant (65%) | Attacker (35%)'}
          </div>
        </div>

        {/* Chart 3: Top Actor / Reduksi Noise */}
        <div className={`p-3.5 rounded-xl border shadow-sm ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              {mode === 'leaf' ? 'Top Attacker / Source IP' : 'Tingkat Reduksi Noise'}
            </span>
            <span className="text-[10px] font-mono text-amber-400">Chart 3</span>
          </div>
          <div className="h-28 flex items-center justify-center text-xs text-slate-400 font-mono">
            {mode === 'leaf' ? 'Internal (40%) | 192.168.1.105 (35%)' : '> 95% Reduksi (75%) | 80-95% (18%)'}
          </div>
        </div>
      </div>

      {/* Data Table */}
      <div className={`rounded-xl border shadow-sm overflow-hidden ${isDark ? 'bg-[#0a0e1a] border-slate-800' : 'bg-white border-slate-200'}`}>
        <div className={`p-3.5 border-b flex items-center justify-between gap-4 ${isDark ? 'bg-[#070b14] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold">
              {mode === 'leaf' ? 'Daftar Leaf Groups (Homogeneous Micro-Clusters)' : 'Daftar Parent Roll-Up Groups (Meta-Campaign Clusters)'}
            </span>
          </div>
          <div className="w-72 relative">
            <input
              type="text"
              placeholder="Search ID, Rule, Agent, IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#090d16] border border-blue-500/50 rounded-full h-8 px-3 text-xs text-slate-200 focus:outline-none"
            />
          </div>
        </div>

        <div className="overflow-x-auto w-full">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className={`border-b text-[11px] font-bold uppercase tracking-wider ${isDark ? 'bg-slate-900/80 border-slate-800 text-slate-400' : 'bg-slate-100 border-slate-200 text-slate-600'}`}>
                <th className="w-8 px-2 py-3 text-center"></th>
                <th className="px-3 py-3 whitespace-nowrap">Rentang Waktu</th>
                <th className="px-3 py-3 whitespace-nowrap">{mode === 'leaf' ? 'Leaf Group ID' : 'Roll-Up ID'}</th>
                <th className="px-3 py-3 whitespace-nowrap">{mode === 'leaf' ? 'Kategori & Bobot' : 'Nama Aturan Roll-Up'}</th>
                <th className="px-3 py-3 whitespace-nowrap">{mode === 'leaf' ? 'Target Agent' : 'Kunci Invarian'}</th>
                <th className="px-3 py-3 whitespace-nowrap">{mode === 'leaf' ? 'Actor IP' : 'Child Leaves'}</th>
                <th className="px-2 py-3 text-center whitespace-nowrap">{mode === 'leaf' ? 'Alerts' : 'Total Alerts'}</th>
                <th className="px-3 py-3 text-center whitespace-nowrap">{mode === 'leaf' ? 'Parent Roll-Up' : 'Reduksi Noise'}</th>
                <th className="px-3 py-3 text-right whitespace-nowrap">Aksi</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {mode === 'leaf' ? (
                leafItems.map(item => (
                  <React.Fragment key={item.rawId}>
                    <tr
                      onClick={() => setExpandedRowId(expandedRowId === item.rawId ? null : item.rawId)}
                      className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${expandedRowId === item.rawId ? 'bg-blue-900/15 border-l-4 border-l-blue-500' : ''}`}
                    >
                      <td className="w-8 px-2 py-2.5 text-center text-slate-400">
                        {expandedRowId === item.rawId ? <ChevronDown className="w-4 h-4 text-blue-400 mx-auto" /> : <ChevronRight className="w-4 h-4 mx-auto" />}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate-300">{item.timeRange}</td>
                      <td className="px-3 py-2.5 font-mono text-xs font-bold text-blue-400">{item.id}</td>
                      <td className="px-3 py-2.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30">
                          {item.category} ({item.weight})
                        </span>
                      </td>
                      <td className="px-3 py-2.5 font-medium text-slate-200">{item.agent}</td>
                      <td className="px-3 py-2.5 font-mono text-slate-300">{item.actor}</td>
                      <td className="px-2 py-2.5 text-center font-mono font-bold text-amber-300">{item.alertCount}</td>
                      <td className="px-3 py-2.5 text-center font-mono">
                        {item.parentRollup !== '-' ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/30">
                            {item.parentRollup}
                          </span>
                        ) : '-'}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <button className="px-2 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Detail</button>
                      </td>
                    </tr>
                    {expandedRowId === item.rawId && (
                      <tr className="bg-[#050811]">
                        <td colSpan={9} className="p-3">
                          <div className="p-3 rounded-lg border border-slate-800 bg-[#070b14]">
                            <div className="text-xs font-mono font-bold text-blue-400 mb-2">RAW WAZUH EVENTS DALAM LEAF INI</div>
                            <table className="w-full text-[11px] font-mono">
                              <thead>
                                <tr className="text-slate-500 border-b border-slate-800">
                                  <th className="py-1">ALERT ID</th>
                                  <th className="py-1">TIME</th>
                                  <th className="py-1">AGENT</th>
                                  <th className="py-1">ACTOR</th>
                                  <th className="py-1">PAYLOAD</th>
                                </tr>
                              </thead>
                              <tbody>
                                {item.events.map((ev, i) => (
                                  <tr key={i} className="border-b border-slate-800/40">
                                    <td className="py-1 text-blue-400 font-bold">{ev.id}</td>
                                    <td className="py-1 text-slate-400">{ev.time}</td>
                                    <td className="py-1 text-slate-300">{ev.agent}</td>
                                    <td className="py-1 text-slate-300">{ev.actor}</td>
                                    <td className="py-1 text-slate-300 break-all">{ev.log}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))
              ) : (
                rollupItems.map(item => (
                  <React.Fragment key={item.rawId}>
                    <tr
                      onClick={() => setExpandedRowId(expandedRowId === item.rawId ? null : item.rawId)}
                      className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${expandedRowId === item.rawId ? 'bg-purple-900/15 border-l-4 border-l-purple-500' : ''}`}
                    >
                      <td className="w-8 px-2 py-2.5 text-center text-slate-400">
                        {expandedRowId === item.rawId ? <ChevronDown className="w-4 h-4 text-purple-400 mx-auto" /> : <ChevronRight className="w-4 h-4 mx-auto" />}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate-300">{item.timeRange}</td>
                      <td className="px-3 py-2.5 font-mono text-xs font-bold text-purple-400">{item.id}</td>
                      <td className="px-3 py-2.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/40">
                          {item.ruleName}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 font-medium text-amber-300">{item.invariants}</td>
                      <td className="px-3 py-2.5 font-mono font-bold text-emerald-400">{item.childLeavesCount} Leaves</td>
                      <td className="px-2 py-2.5 text-center font-mono font-bold text-slate-200">{item.totalAlerts}</td>
                      <td className="px-3 py-2.5 text-center font-mono">
                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          {item.reductionPct}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <button className="px-2.5 py-1 rounded bg-purple-900/40 text-purple-300 border border-purple-700/60 text-xs">Tree View ↗</button>
                      </td>
                    </tr>
                    {expandedRowId === item.rawId && (
                      <tr className="bg-[#050811]">
                        <td colSpan={9} className="p-3">
                          <div className="p-3 rounded-lg border border-purple-500/30 bg-[#070b14]">
                            <div className="text-xs font-mono font-bold text-purple-400 mb-2">
                              CHILD LEAF GROUPS DISERAP DALAM PARENT INI ({item.childLeavesCount} LEAVES)
                            </div>
                            <table className="w-full text-[11px] font-mono">
                              <thead>
                                <tr className="text-slate-500 border-b border-slate-800">
                                  <th className="py-1">CHILD LEAF ID</th>
                                  <th className="py-1">KATEGORI</th>
                                  <th className="py-1 text-center">ALERTS</th>
                                  <th className="py-1">DESKRIPSI AKTIVITAS</th>
                                  <th className="py-1">WAKTU AKTIF</th>
                                </tr>
                              </thead>
                              <tbody>
                                {item.childLeaves.map((ch, i) => (
                                  <tr key={i} className="border-b border-slate-800/40">
                                    <td className="py-1 text-blue-400 font-bold">🍃 {ch.id}</td>
                                    <td className="py-1 text-slate-300">{ch.cat}</td>
                                    <td className="py-1 text-center text-cyan-300 font-bold">{ch.count}</td>
                                    <td className="py-1 text-slate-200">{ch.desc}</td>
                                    <td className="py-1 text-slate-400">{ch.window}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
