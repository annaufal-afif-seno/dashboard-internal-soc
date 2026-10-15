import React, { useState, useEffect } from 'react';
import { Layers, Database, Search, Filter, RefreshCw } from 'lucide-react';

export default function TelemetryDataExplorer({ initialTab = 'aggregates' }) {
  const [activeTab, setActiveTab] = useState(initialTab);

  useEffect(() => {
    if (initialTab) setActiveTab(initialTab);
  }, [initialTab]);
  
  const [aggregates, setAggregates] = useState([]);
  const [aggsTotal, setAggsTotal] = useState(18467);
  const [aggsLoading, setAggsLoading] = useState(false);
  const [aggsPage, setAggsPage] = useState(1);
  const [aggsSearch, setAggsSearch] = useState('');
  const [aggsCategory, setAggsCategory] = useState('ALL');
  const [aggsTenant, setAggsTenant] = useState('ALL');

  const [cumulative, setCumulative] = useState([]);
  const [cumTotal, setCumTotal] = useState(2532);
  const [cumLoading, setCumLoading] = useState(false);
  const [cumPage, setCumPage] = useState(1);
  const [cumSearch, setCumSearch] = useState('');

  const pageSize = 20;

  const fetchAggregates = async () => {
    try {
      setAggsLoading(true);
      const offset = (aggsPage - 1) * pageSize;
      let url = `http://localhost:8000/api/telemetry/aggregates?limit=${pageSize}&offset=${offset}`;
      if (aggsCategory !== 'ALL') url += `&category=${aggsCategory}`;
      if (aggsTenant !== 'ALL') url += `&tenant=${aggsTenant}`;
      if (aggsSearch.trim()) url += `&search=${encodeURIComponent(aggsSearch.trim())}`;

      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setAggregates(data.aggregates || []);
        setAggsTotal(data.total || 0);
      }
    } catch (err) {
      console.warn('Fetch aggregates warning:', err);
    } finally {
      setAggsLoading(false);
    }
  };

  const fetchCumulative = async () => {
    try {
      setCumLoading(true);
      const offset = (cumPage - 1) * pageSize;
      let url = `http://localhost:8000/api/telemetry/cumulative?limit=${pageSize}&offset=${offset}`;
      if (cumSearch.trim()) url += `&search=${encodeURIComponent(cumSearch.trim())}`;

      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setCumulative(data.cumulative || []);
        setCumTotal(data.total || 0);
      }
    } catch (err) {
      console.warn('Fetch cumulative warning:', err);
    } finally {
      setCumLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'aggregates') {
      fetchAggregates();
    } else {
      fetchCumulative();
    }
  }, [activeTab, aggsPage, aggsCategory, aggsTenant, cumPage]);

  return (
    <div className="max-w-7xl mx-auto space-y-4">
      {/* Header & Mode Switcher */}
      <div className="flex items-center justify-between flex-wrap gap-3 pb-1 border-b border-slate-800/60">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 tracking-tight flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-400" />
            <span>Telemetry & Alert Normalization Explorer</span>
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Audit forensik data hasil agregasi jendela geser 15 menit dan profil kumulatif seumur hidup.
          </p>
        </div>

        <div className="flex items-center gap-1 bg-[#090d16] p-1 rounded-lg border border-slate-800/80">
          <button
            onClick={() => setActiveTab('aggregates')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium flex items-center gap-2 transition-colors cursor-pointer ${
              activeTab === 'aggregates'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Alert Agregat (15-Min)</span>
            <span className="font-mono text-[10px] text-slate-400">
              ({aggsTotal.toLocaleString()})
            </span>
          </button>

          <button
            onClick={() => setActiveTab('cumulative')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium flex items-center gap-2 transition-colors cursor-pointer ${
              activeTab === 'cumulative'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Kumulatif (Lifelong)</span>
            <span className="font-mono text-[10px] text-slate-400">
              ({cumTotal.toLocaleString()})
            </span>
          </button>
        </div>
      </div>

      {/* VIEW 1: AGGREGATED ALERTS (15-MIN SLIDING WINDOW) */}
      {activeTab === 'aggregates' && (
        <div className="bg-[#0a0e1a] border border-slate-800/80 rounded-xl overflow-hidden space-y-0">
          {/* Filter Bar */}
          <div className="p-3 border-b border-slate-800/70 flex items-center justify-between flex-wrap gap-2.5 bg-[#090d16]/60">
            <div className="relative flex-1 min-w-[220px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={aggsSearch}
                onChange={(e) => { setAggsSearch(e.target.value); setAggsPage(1); }}
                onKeyDown={(e) => e.key === 'Enter' && fetchAggregates()}
                placeholder="Search actor, target, rule SID, IoA..."
                className="w-full bg-[#070b14] border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-2 text-xs">
              <select
                value={aggsCategory}
                onChange={(e) => { setAggsCategory(e.target.value); setAggsPage(1); }}
                className="bg-[#070b14] border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-blue-500 font-mono text-[11px]"
              >
                <option value="ALL">All Categories</option>
                <option value="AUTH_FAILURE">AUTH_FAILURE</option>
                <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
                <option value="CLOUD_CONTAINER">CLOUD_CONTAINER</option>
                <option value="COMMAND_AND_CONTROL">COMMAND_AND_CONTROL</option>
                <option value="CONFIGURATION_ASSESSMENT">CONFIGURATION_ASSESSMENT</option>
                <option value="CREDENTIAL_ACCESS">CREDENTIAL_ACCESS</option>
                <option value="DEFENSE_EVASION">DEFENSE_EVASION</option>
                <option value="DISCOVERY">DISCOVERY</option>
                <option value="EXECUTION">EXECUTION</option>
                <option value="EXFILTRATION">EXFILTRATION</option>
                <option value="FILE_INTEGRITY">FILE_INTEGRITY</option>
                <option value="INITIAL_ACCESS">INITIAL_ACCESS</option>
                <option value="LATERAL_MOVEMENT">LATERAL_MOVEMENT</option>
                <option value="MALWARE">MALWARE</option>
                <option value="OTHER">OTHER</option>
                <option value="PERSISTENCE">PERSISTENCE</option>
                <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
                <option value="RANSOMWARE">RANSOMWARE</option>
                <option value="SYSTEM_HEALTH">SYSTEM_HEALTH</option>
                <option value="VULNERABILITY">VULNERABILITY</option>
                <option value="WEB_ATTACK">WEB_ATTACK</option>
                <option value="WEB_OPERATIONAL">WEB_OPERATIONAL</option>
              </select>

              <select
                value={aggsTenant}
                onChange={(e) => { setAggsTenant(e.target.value); setAggsPage(1); }}
                className="bg-[#070b14] border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-blue-500 font-mono text-[11px]"
              >
                <option value="ALL">All Tenants</option>
                <option value="DEFAULT">DEFAULT</option>
                <option value="PRODUCTION">PRODUCTION</option>
                <option value="CORPORATE">CORPORATE</option>
                <option value="DMZ">DMZ</option>
              </select>

              <button
                onClick={fetchAggregates}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${aggsLoading ? 'animate-spin' : ''}`} />
                <span>Search</span>
              </button>
            </div>
          </div>

          {/* Aggregates Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800/80 bg-[#090d16]/50 font-mono">
                  <th className="py-2.5 px-4">RULE SID & NAME</th>
                  <th className="py-2.5 px-3">CATEGORY</th>
                  <th className="py-2.5 px-3">ACTOR (SOURCE IP)</th>
                  <th className="py-2.5 px-3">TARGET HOST</th>
                  <th className="py-2.5 px-3">TENANT</th>
                  <th className="py-2.5 px-3 text-center">EVENTS</th>
                  <th className="py-2.5 px-4 text-right">WINDOW END</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40 font-mono text-xs">
                {aggsLoading ? (
                  <tr>
                    <td colSpan="7" className="py-12 text-center text-slate-400">
                      <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2 text-slate-400" />
                      Loading aggregated telemetry flows...
                    </td>
                  </tr>
                ) : aggregates.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="py-12 text-center text-slate-400">
                      No aggregated alerts match the selected criteria.
                    </td>
                  </tr>
                ) : (
                  aggregates.map((row) => (
                    <tr key={row.aggregation_id} className="hover:bg-slate-800/20 transition-colors">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-sky-400 font-bold text-[11px]">
                            {row.rule_id}
                          </span>
                          <span className="font-sans font-medium text-slate-200 text-xs truncate max-w-xs" title={row.rule_description}>
                            {row.rule_description}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-3">
                        <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-900 border border-slate-800 text-slate-400">
                          {row.category}
                        </span>
                      </td>

                      <td className="py-3 px-3 text-slate-300">
                        {row.actor || 'Internal / N/A'}
                      </td>

                      <td className="py-3 px-3 text-slate-200 font-medium">
                        {row.target || '-'}
                      </td>

                      <td className="py-3 px-3 text-slate-400 text-[11px]">
                        {row.tenant_id}
                      </td>

                      <td className="py-3 px-3 text-center">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-200 font-semibold">
                          {row.event_count}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-right text-slate-400 text-[11px]">
                        {row.window_end}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="p-3 border-t border-slate-800/70 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing <span className="text-slate-200 font-mono">{(aggsPage - 1) * pageSize + 1}</span> to <span className="text-slate-200 font-mono">{Math.min(aggsPage * pageSize, aggsTotal)}</span> of <span className="text-slate-200 font-mono">{aggsTotal.toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setAggsPage(p => Math.max(1, p - 1))}
                disabled={aggsPage === 1}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-30 text-xs font-medium cursor-pointer"
              >
                Prev
              </button>
              <span className="font-mono text-[11px] px-2">
                Page {aggsPage} / {Math.max(1, Math.ceil(aggsTotal / pageSize))}
              </span>
              <button
                onClick={() => setAggsPage(p => p + 1)}
                disabled={aggsPage * pageSize >= aggsTotal}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-30 text-xs font-medium cursor-pointer"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: CUMULATIVE ALERTS (LIFELONG FINGERPRINT) */}
      {activeTab === 'cumulative' && (
        <div className="bg-[#0a0e1a] border border-slate-800/80 rounded-xl overflow-hidden space-y-0">
          {/* Filter Bar */}
          <div className="p-3 border-b border-slate-800/70 flex items-center justify-between flex-wrap gap-2.5 bg-[#090d16]/60">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={cumSearch}
                onChange={(e) => { setCumSearch(e.target.value); setCumPage(1); }}
                onKeyDown={(e) => e.key === 'Enter' && fetchCumulative()}
                placeholder="Search actor, target, rule SID, IoA..."
                className="w-full bg-[#070b14] border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <button
              onClick={fetchCumulative}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${cumLoading ? 'animate-spin' : ''}`} />
              <span>Search</span>
            </button>
          </div>

          {/* Cumulative Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800/80 bg-[#090d16]/50 font-mono">
                  <th className="py-2.5 px-4">RULE SID & NAME</th>
                  <th className="py-2.5 px-3">CATEGORY</th>
                  <th className="py-2.5 px-3">ACTOR</th>
                  <th className="py-2.5 px-3">TARGET</th>
                  <th className="py-2.5 px-3">TOTAL EVENTS</th>
                  <th className="py-2.5 px-3">FIRST SEEN</th>
                  <th className="py-2.5 px-4 text-right">LAST SEEN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40 font-mono text-xs">
                {cumLoading ? (
                  <tr>
                    <td colSpan="7" className="py-12 text-center text-slate-400">
                      <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2 text-slate-400" />
                      Loading lifelong cumulative alerts...
                    </td>
                  </tr>
                ) : cumulative.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="py-12 text-center text-slate-400">
                      No cumulative records found.
                    </td>
                  </tr>
                ) : (
                  cumulative.map((row) => (
                    <tr key={row.cumulative_id} className="hover:bg-slate-800/20 transition-colors">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-purple-400 font-bold text-[11px]">
                            {row.rule_id}
                          </span>
                          <span className="font-sans font-medium text-slate-200 text-xs truncate max-w-xs" title={row.rule_description}>
                            {row.rule_description}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-3">
                        <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-900 border border-slate-800 text-slate-400">
                          {row.category}
                        </span>
                      </td>

                      <td className="py-3 px-3 text-slate-300">
                        {row.actor || 'Internal / N/A'}
                      </td>

                      <td className="py-3 px-3 text-slate-200 font-medium">
                        {row.target || '-'}
                      </td>

                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-200 font-semibold">
                          {row.total_event_count.toLocaleString()}
                        </span>
                      </td>

                      <td className="py-3 px-3 text-slate-400 text-[11px]">
                        {row.first_seen_at ? new Date(row.first_seen_at).toLocaleDateString() : '-'}
                      </td>

                      <td className="py-3 px-4 text-right text-slate-400 text-[11px]">
                        {row.last_seen_at ? new Date(row.last_seen_at).toLocaleDateString() : '-'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="p-3 border-t border-slate-800/70 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing <span className="text-slate-200 font-mono">{(cumPage - 1) * pageSize + 1}</span> to <span className="text-slate-200 font-mono">{Math.min(cumPage * pageSize, cumTotal)}</span> of <span className="text-slate-200 font-mono">{cumTotal.toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setCumPage(p => Math.max(1, p - 1))}
                disabled={cumPage === 1}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-30 text-xs font-medium cursor-pointer"
              >
                Prev
              </button>
              <span className="font-mono text-[11px] px-2">
                Page {cumPage} / {Math.max(1, Math.ceil(cumTotal / pageSize))}
              </span>
              <button
                onClick={() => setCumPage(p => p + 1)}
                disabled={cumPage * pageSize >= cumTotal}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-30 text-xs font-medium cursor-pointer"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
